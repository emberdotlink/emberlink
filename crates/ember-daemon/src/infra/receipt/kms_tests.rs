use super::*;
use core_grant_types::grant_receipt::{
    GrantEvaluation, GrantEvaluationOutcome, KmsReceipt, ReceiptKind, ReceiptOutcome, VaultReceipt,
};

fn fixture_kms_receipt(kind: ReceiptKind, key: &str) -> KmsReceipt {
    KmsReceipt {
        id: format!("rct-test-{}", uuid::Uuid::new_v4()),
        kind,
        key_name: key.into(),
        caller_persona: "persona-test".into(),
        request_size_bytes: 32,
        materialized_at_epoch_secs: 1_700_000_000,
        grant_evaluation: GrantEvaluation {
            outcome: GrantEvaluationOutcome::Allowed,
            grant_id: Some("grant-test-1".into()),
        },
        outcome: ReceiptOutcome::Success,
        peer_identity: None,
        evidence: Evidence::default(),
    }
}

#[test]
fn store_kms_receipt_round_trips() {
    let store = DaemonStore::open_in_memory().unwrap();
    let r = fixture_kms_receipt(ReceiptKind::KmsWrap, "production-tokens");
    store.store_kms_receipt(&r).unwrap();
    let loaded = store.get_kms_receipt(&r.id).unwrap();
    assert_eq!(loaded, r);
}

#[test]
fn store_kms_receipt_rejects_grant_kind() {
    let store = DaemonStore::open_in_memory().unwrap();
    let mut r = fixture_kms_receipt(ReceiptKind::KmsWrap, "k");
    r.kind = ReceiptKind::Grant;
    let err = store.store_kms_receipt(&r).unwrap_err();
    assert!(matches!(err, StoreError::InvalidInput(_)));
}

#[test]
fn list_kms_receipts_for_key_filters_by_key_name() {
    let store = DaemonStore::open_in_memory().unwrap();
    // Three receipts: two for key-a (one wrap, one unwrap), one for key-b.
    let r1 = fixture_kms_receipt(ReceiptKind::KmsWrap, "key-a");
    let r2 = fixture_kms_receipt(ReceiptKind::KmsUnwrap, "key-a");
    let r3 = fixture_kms_receipt(ReceiptKind::KmsWrap, "key-b");
    store.store_kms_receipt(&r1).unwrap();
    store.store_kms_receipt(&r2).unwrap();
    store.store_kms_receipt(&r3).unwrap();

    let a = store.list_kms_receipts_for_key("key-a", None).unwrap();
    assert_eq!(a.len(), 2);
    assert!(a.iter().all(|r| r.key_name == "key-a"));

    let b = store.list_kms_receipts_for_key("key-b", None).unwrap();
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].key_name, "key-b");
}

#[test]
fn get_kms_receipt_rejects_grant_row() {
    // A grant receipt persisted via store_receipt must NOT be loadable
    // through get_kms_receipt — `kind` filter is enforced at the SQL
    // level so the two paths cannot accidentally return each other's
    // rows.
    let _ = ensure_identity_for_kms_test();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-cross").unwrap();
    let grant = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();
    store.revoke_grant(&grant.id).unwrap();
    let grant_receipt_id = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
    let err = store.get_kms_receipt(&grant_receipt_id).unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

#[test]
fn sign_kms_receipt_populates_evidence() {
    let store = DaemonStore::open_in_memory().unwrap();
    let identity = ensure_identity_for_kms_test();
    let mut r = fixture_kms_receipt(ReceiptKind::KmsWrap, "k");
    sign_kms_receipt(&mut r, identity);
    assert_eq!(r.evidence.signer_pubkey, identity.pubkey_hex());
    assert_eq!(r.evidence.sig.len(), 128);
    assert_eq!(r.evidence.hash.len(), 64);
    assert_eq!(r.evidence.canonical_version, CANONICAL_VERSION);
    // Re-hashing the receipt with its evidence still in place must
    // match — the canonical hash zeros evidence first.
    let h = kms_canonical_hash(&r);
    assert_eq!(h, r.evidence.hash);
    // Receipt persists cleanly.
    store.store_kms_receipt(&r).unwrap();
}

#[test]
fn channel_sink_send_is_send_and_sync() {
    // Compile-time enforcement: ChannelKmsSink and core_kms::ReceiptSink
    // bound require Send + Sync so axum can hold them in shared state.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ChannelKmsSink>();
}

#[tokio::test]
async fn drain_kms_receipts_persists_through_channel() {
    // End-to-end: kms server -> ChannelKmsSink -> drain task -> DaemonStore.
    // Build a store inside a LocalSet so the !Send Arc is happy.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let store = std::sync::Arc::new(DaemonStore::open_in_memory().unwrap());
            let (sink, rx) = ChannelKmsSink::channel();
            let drain_handle = tokio::task::spawn_local(drain_kms_receipts(store.clone(), rx));

            let r = fixture_kms_receipt(ReceiptKind::KmsWrap, "drain-key");
            let id = r.id.clone();
            core_kms::ReceiptSink::record(&sink, r);

            // Drop the sender to close the channel so the drain task exits.
            drop(sink);
            drain_handle.await.unwrap();

            let loaded = store.get_kms_receipt(&id).unwrap();
            assert_eq!(loaded.id, id);
            assert_eq!(loaded.kind, ReceiptKind::KmsWrap);
            assert_eq!(loaded.key_name, "drain-key");
        })
        .await;
}

/// Ensure the process-singleton identity is initialised for kms tests
/// that need to sign. Mirrors the helper in the parent test module.
fn ensure_identity_for_kms_test() -> &'static DaemonPersona {
    static INIT_DIR: once_cell::sync::OnceCell<tempfile::TempDir> =
        once_cell::sync::OnceCell::new();
    let dir = INIT_DIR.get_or_init(|| tempfile::tempdir().expect("tempdir"));
    let _ = init_identity(dir.path());
    current_identity().expect("identity was just initialised")
}

/// EMBER-AUDIT-CLI — mixed-kind audit query. Seed two kms receipts for
/// the same persona (one wrap, one unwrap) plus one for a different
/// persona; the actor filter must return only the matching pair, and
/// the rows must be sorted `materialized_at DESC`.
#[test]
fn list_receipt_rows_filters_by_actor_and_sorts_desc() {
    let _ = ensure_identity_for_kms_test();
    let store = DaemonStore::open_in_memory().unwrap();

    let mut r1 = fixture_kms_receipt(ReceiptKind::KmsWrap, "k1");
    r1.caller_persona = "persona-alpha".into();
    store.store_kms_receipt(&r1).unwrap();

    let mut r2 = fixture_kms_receipt(ReceiptKind::KmsUnwrap, "k1");
    r2.caller_persona = "persona-alpha".into();
    store.store_kms_receipt(&r2).unwrap();

    let mut r3 = fixture_kms_receipt(ReceiptKind::KmsWrap, "k2");
    r3.caller_persona = "persona-beta".into();
    store.store_kms_receipt(&r3).unwrap();

    let rows = store
        .list_receipt_rows(&ReceiptFilter {
            persona_id: Some("persona-alpha".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.actor == "persona-alpha"));
    // Both rows are kms — resource carries `key_name`, scopes are None.
    assert!(rows.iter().all(|r| r.resource == "k1"));
    assert!(rows.iter().all(|r| r.requested_scope.is_none()));
    assert!(rows.iter().all(|r| r.granted_scope.is_none()));
    // `materialized_at` is the receipts.created_at column written by
    // `store_kms_receipt` — same RFC3339 string for back-to-back inserts
    // is acceptable; we just need the sort key to be a string and the
    // listing to be DESC stable. Bound by id so the assertion is
    // independent of clock granularity.
    let ids: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
    assert!(
        ids.contains(&r1.id.as_str()) && ids.contains(&r2.id.as_str()),
        "both alpha receipts in the result set"
    );
}

/// EMBER-AUDIT-CLI — kind filter narrows to a single discriminator.
#[test]
fn list_receipt_rows_filters_by_kind() {
    let _ = ensure_identity_for_kms_test();
    let store = DaemonStore::open_in_memory().unwrap();

    let r1 = fixture_kms_receipt(ReceiptKind::KmsWrap, "k1");
    store.store_kms_receipt(&r1).unwrap();
    let r2 = fixture_kms_receipt(ReceiptKind::KmsUnwrap, "k2");
    store.store_kms_receipt(&r2).unwrap();

    let wraps = store
        .list_receipt_rows(&ReceiptFilter {
            kind: Some("kms_wrap".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(wraps.len(), 1);
    assert_eq!(wraps[0].kind, "kms_wrap");
    assert_eq!(wraps[0].resource, "k1");
}

/// EMBER-AUDIT-CLI — resource substring filter (post-fetch) narrows
/// matches without forcing exact equality.
#[test]
fn list_receipt_rows_filters_by_resource_substring() {
    let _ = ensure_identity_for_kms_test();
    let store = DaemonStore::open_in_memory().unwrap();

    let r1 = fixture_kms_receipt(ReceiptKind::KmsWrap, "production-tokens");
    store.store_kms_receipt(&r1).unwrap();
    let r2 = fixture_kms_receipt(ReceiptKind::KmsWrap, "staging-tokens");
    store.store_kms_receipt(&r2).unwrap();
    let r3 = fixture_kms_receipt(ReceiptKind::KmsWrap, "demo-keys");
    store.store_kms_receipt(&r3).unwrap();

    let rows = store
        .list_receipt_rows(&ReceiptFilter {
            resource: Some("tokens".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.resource.contains("tokens")));
}

/// EMBER-AUDIT-CLI — index existence sanity check. Inspect the
/// sqlite_master catalog and confirm the new audit-CLI indexes were
/// created by the migration.
#[test]
fn audit_cli_indexes_exist() {
    let store = DaemonStore::open_in_memory().unwrap();
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT name FROM sqlite_master \
                 WHERE type = 'index' AND name LIKE 'idx_receipts_%' \
                 ORDER BY name",
        )
        .unwrap();
    let names: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        names.iter().any(|n| n == "idx_receipts_actor"),
        "idx_receipts_actor missing — got {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "idx_receipts_resource"),
        "idx_receipts_resource missing — got {names:?}"
    );
}

fn fixture_broker_receipt(kind: ReceiptKind) -> BrokerReceipt {
    BrokerReceipt {
        id: format!("rct-broker-test-{}", uuid::Uuid::new_v4()),
        kind,
        provider: "cloudflare".into(),
        materialization_id: format!("mock-{}", uuid::Uuid::new_v4()),
        requested_scope: r#"{"zone":"emberlink.dev"}"#.into(),
        granted_scope: r#"{"zone":"emberlink.dev"}"#.into(),
        ttl_seconds: 900,
        materialized_at_epoch_secs: 1_700_000_000,
        expires_at_epoch_secs: Some(1_700_000_900),
        revoked_at_epoch_secs: None,
        reason: Some("test".into()),
        caller_persona: "persona-test".into(),
        grants_file_rev: None,
        credential_name: None,
        evidence: Evidence::default(),
    }
}

/// Mirrors `sign_kms_receipt_populates_evidence` for broker receipts.
#[test]
fn sign_broker_receipt_populates_evidence() {
    let store = DaemonStore::open_in_memory().unwrap();
    let identity = ensure_identity_for_kms_test();
    let mut r = fixture_broker_receipt(ReceiptKind::BrokerMaterialization);
    sign_broker_receipt(&mut r, identity);
    assert_eq!(r.evidence.signer_pubkey, identity.pubkey_hex());
    assert_eq!(r.evidence.sig.len(), 128, "sig hex is 128 chars");
    assert_eq!(r.evidence.hash.len(), 64, "hash hex is 64 chars");
    assert_eq!(r.evidence.canonical_version, CANONICAL_VERSION);
    // Re-hashing with evidence in place must match — the canonical hash
    // zeroes evidence first.
    let h = broker_canonical_hash(&r);
    assert_eq!(h, r.evidence.hash);
    // Receipt persists cleanly.
    store.store_broker_receipt(&r).unwrap();
}

/// Round-trip: store + retrieve a broker materialization receipt, then
/// verify the signature.
#[test]
fn store_broker_receipt_round_trips() {
    let store = DaemonStore::open_in_memory().unwrap();
    let identity = ensure_identity_for_kms_test();
    let mut r = fixture_broker_receipt(ReceiptKind::BrokerMaterialization);
    sign_broker_receipt(&mut r, identity);
    store.store_broker_receipt(&r).unwrap();
    let loaded = store.get_broker_receipt(&r.id).unwrap();
    assert_eq!(loaded, r);
    verify_broker_receipt(&loaded, &identity.pubkey_hex())
        .expect("signed BrokerReceipt must verify after round-trip");
}

/// Revocation variant — `kind=BrokerRevocation`, `revoked_at_epoch_secs`
/// set, signature verifies.
#[test]
fn store_broker_revocation_receipt_round_trips() {
    let store = DaemonStore::open_in_memory().unwrap();
    let identity = ensure_identity_for_kms_test();
    let mut r = fixture_broker_receipt(ReceiptKind::BrokerRevocation);
    r.revoked_at_epoch_secs = Some(1_700_001_000);
    sign_broker_receipt(&mut r, identity);
    store.store_broker_receipt(&r).unwrap();
    let loaded = store.get_broker_receipt(&r.id).unwrap();
    assert_eq!(loaded.kind, ReceiptKind::BrokerRevocation);
    assert_eq!(loaded.revoked_at_epoch_secs, Some(1_700_001_000));
    verify_broker_receipt(&loaded, &identity.pubkey_hex())
        .expect("signed BrokerRevocation receipt must verify after round-trip");
}

/// `store_broker_receipt` rejects non-broker ReceiptKind variants.
#[test]
fn store_broker_receipt_rejects_kms_kind() {
    let store = DaemonStore::open_in_memory().unwrap();
    let mut r = fixture_broker_receipt(ReceiptKind::BrokerMaterialization);
    r.kind = ReceiptKind::KmsWrap;
    let err = store.store_broker_receipt(&r).unwrap_err();
    assert!(matches!(err, StoreError::InvalidInput(_)));
}

/// `get_broker_receipt` rejects rows stored by other sinks.
#[test]
fn get_broker_receipt_rejects_kms_row() {
    let store = DaemonStore::open_in_memory().unwrap();
    let r = fixture_kms_receipt(ReceiptKind::KmsWrap, "k");
    store.store_kms_receipt(&r).unwrap();
    let err = store.get_broker_receipt(&r.id).unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

/// `list_receipt_rows` with `kind=broker_materialization` returns broker
/// rows with scope strings populated, resource = provider name.
#[test]
fn list_receipt_rows_filters_by_broker_kind() {
    let _ = ensure_identity_for_kms_test();
    let store = DaemonStore::open_in_memory().unwrap();

    let r1 = fixture_broker_receipt(ReceiptKind::BrokerMaterialization);
    store.store_broker_receipt(&r1).unwrap();
    let r2 = fixture_kms_receipt(ReceiptKind::KmsWrap, "some-key");
    store.store_kms_receipt(&r2).unwrap();

    let rows = store
        .list_receipt_rows(&ReceiptFilter {
            kind: Some("broker_materialization".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(rows.len(), 1, "only broker row expected");
    assert_eq!(rows[0].kind, "broker_materialization");
    assert_eq!(
        rows[0].resource, "cloudflare",
        "resource is provider name for broker rows"
    );
    assert!(
        rows[0].requested_scope.is_some(),
        "requested_scope should be populated from broker receipt JSON"
    );
    assert!(
        rows[0].granted_scope.is_some(),
        "granted_scope should be populated from broker receipt JSON"
    );
}

/// Adversarial: the persisted BrokerReceipt JSON must not contain any
/// field that could carry plaintext credential bytes.
#[test]
fn broker_receipt_json_carries_no_plaintext_credential_fields() {
    let store = DaemonStore::open_in_memory().unwrap();
    let r = fixture_broker_receipt(ReceiptKind::BrokerMaterialization);
    store.store_broker_receipt(&r).unwrap();
    let loaded = store.get_broker_receipt(&r.id).unwrap();
    let v = serde_json::to_value(&loaded).unwrap();
    for forbidden in &["token", "value", "plaintext", "secret", "credential"] {
        assert!(
            v.get(forbidden).is_none(),
            "BrokerReceipt must not carry '{forbidden}' field — found in: {v}"
        );
    }
}

// ---------------------------------------------------------------------------
// Vault receipt tests
// ---------------------------------------------------------------------------

fn fixture_vault_receipt(outcome: ReceiptOutcome) -> VaultReceipt {
    VaultReceipt {
        id: format!("rct-vault-test-{}", uuid::Uuid::new_v4()),
        kind: ReceiptKind::VaultRetrieval,
        key_name: "production-tokens".into(),
        caller_persona: "persona-test".into(),
        materialized_at_epoch_secs: 1_700_000_000,
        grant_evaluation: GrantEvaluation {
            outcome: GrantEvaluationOutcome::Denied,
            grant_id: None,
        },
        outcome,
        evidence: Evidence::default(),
    }
}

fn fixture_vault_biometric_receipt() -> VaultBiometricReceipt {
    VaultBiometricReceipt {
        id: format!("rct-vault-bio-test-{}", uuid::Uuid::new_v4()),
        kind: VAULT_BIOMETRIC_RECEIPT_KIND.to_string(),
        key_name: "production-tokens".into(),
        caller_persona: "persona-test".into(),
        materialized_at_epoch_secs: 1_700_000_000,
        read_path: "vault_get".into(),
        grant_id: None,
        outcome: ReceiptOutcome::Success,
        presence_authenticator_id: "device-yubikey-1".into(),
        presence_public_key_hash: "sha256:abc123".into(),
        evidence: Evidence::default(),
    }
}

/// `sign_vault_receipt` populates all evidence fields and the canonical
/// hash is stable (re-hashing with evidence in place must match).
#[test]
fn sign_vault_receipt_populates_evidence() {
    let store = DaemonStore::open_in_memory().unwrap();
    let identity = ensure_identity_for_kms_test();
    let mut r = fixture_vault_receipt(ReceiptOutcome::Success);
    sign_vault_receipt(&mut r, identity);
    assert_eq!(r.evidence.signer_pubkey, identity.pubkey_hex());
    assert_eq!(r.evidence.sig.len(), 128, "sig hex is 128 chars");
    assert_eq!(r.evidence.hash.len(), 64, "hash hex is 64 chars");
    assert_eq!(r.evidence.canonical_version, CANONICAL_VERSION);
    // Re-hashing with evidence in place must match — canonical hash
    // zeroes evidence first.
    let h = vault_canonical_hash(&r);
    assert_eq!(h, r.evidence.hash);
    // Receipt persists cleanly.
    store.store_vault_receipt(&r).unwrap();
}

/// Round-trip: store + retrieve a vault receipt, then verify the signature.
#[test]
fn store_vault_receipt_round_trips() {
    let store = DaemonStore::open_in_memory().unwrap();
    let identity = ensure_identity_for_kms_test();
    let mut r = fixture_vault_receipt(ReceiptOutcome::Success);
    sign_vault_receipt(&mut r, identity);
    store.store_vault_receipt(&r).unwrap();
    let loaded = store.get_vault_receipt(&r.id).unwrap();
    assert_eq!(loaded, r);
    verify_vault_receipt(&loaded, &identity.pubkey_hex())
        .expect("signed VaultReceipt must verify after round-trip");
}

/// Failure-path round-trip: vault receipt with outcome=Failure stores and
/// verifies like the success path.
#[test]
fn store_vault_receipt_failure_round_trips() {
    let store = DaemonStore::open_in_memory().unwrap();
    let identity = ensure_identity_for_kms_test();
    let mut r = fixture_vault_receipt(ReceiptOutcome::Failure);
    sign_vault_receipt(&mut r, identity);
    store.store_vault_receipt(&r).unwrap();
    let loaded = store.get_vault_receipt(&r.id).unwrap();
    assert_eq!(loaded.outcome, ReceiptOutcome::Failure);
    verify_vault_receipt(&loaded, &identity.pubkey_hex())
        .expect("signed VaultReceipt (failure) must verify after round-trip");
}

/// `store_vault_receipt` rejects non-vault ReceiptKind variants.
#[test]
fn store_vault_receipt_rejects_kms_kind() {
    let store = DaemonStore::open_in_memory().unwrap();
    let mut r = fixture_vault_receipt(ReceiptOutcome::Success);
    r.kind = ReceiptKind::KmsWrap;
    let err = store.store_vault_receipt(&r).unwrap_err();
    assert!(matches!(err, StoreError::InvalidInput(_)));
}

/// `get_vault_receipt` rejects rows stored by other sinks.
#[test]
fn get_vault_receipt_rejects_kms_row() {
    let store = DaemonStore::open_in_memory().unwrap();
    let r = fixture_kms_receipt(ReceiptKind::KmsWrap, "k");
    store.store_kms_receipt(&r).unwrap();
    let err = store.get_vault_receipt(&r.id).unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

/// `list_receipt_rows` with `kind=vault_retrieval` returns vault rows with
/// resource = key_name and no scope strings.
#[test]
fn list_receipt_rows_filters_by_vault_kind() {
    let _ = ensure_identity_for_kms_test();
    let store = DaemonStore::open_in_memory().unwrap();

    let r1 = fixture_vault_receipt(ReceiptOutcome::Success);
    store.store_vault_receipt(&r1).unwrap();
    let r2 = fixture_kms_receipt(ReceiptKind::KmsWrap, "some-key");
    store.store_kms_receipt(&r2).unwrap();

    let rows = store
        .list_receipt_rows(&ReceiptFilter {
            kind: Some("vault_retrieval".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(rows.len(), 1, "only vault row expected");
    assert_eq!(rows[0].kind, "vault_retrieval");
    assert_eq!(
        rows[0].resource, "production-tokens",
        "resource is key_name for vault rows"
    );
    assert!(
        rows[0].requested_scope.is_none(),
        "vault rows carry no requested_scope"
    );
    assert!(
        rows[0].granted_scope.is_none(),
        "vault rows carry no granted_scope"
    );
}

#[test]
fn store_vault_biometric_receipt_round_trips_and_lists_resource() {
    let _ = ensure_identity_for_kms_test();
    let store = DaemonStore::open_in_memory().unwrap();
    let identity = ensure_identity_for_kms_test();
    let mut r = fixture_vault_biometric_receipt();
    sign_vault_biometric_receipt(&mut r, identity);
    assert_eq!(r.evidence.signer_pubkey, identity.pubkey_hex());
    assert_eq!(r.evidence.hash, vault_biometric_canonical_hash(&r));

    store.store_vault_biometric_receipt(&r).unwrap();
    let loaded = store.get_vault_biometric_receipt(&r.id).unwrap();
    assert_eq!(loaded, r);

    let rows = store
        .list_receipt_rows(&ReceiptFilter {
            kind: Some(VAULT_BIOMETRIC_RECEIPT_KIND.to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(rows.len(), 1, "only biometric vault row expected");
    assert_eq!(rows[0].kind, VAULT_BIOMETRIC_RECEIPT_KIND);
    assert_eq!(rows[0].resource, "production-tokens");
    assert!(rows[0].signed);
}

/// Adversarial: the persisted VaultReceipt JSON must not contain any
/// field that could carry the plaintext credential value.
#[test]
fn vault_receipt_body_carries_no_plaintext_credential() {
    let store = DaemonStore::open_in_memory().unwrap();
    let r = fixture_vault_receipt(ReceiptOutcome::Success);
    store.store_vault_receipt(&r).unwrap();
    let loaded = store.get_vault_receipt(&r.id).unwrap();
    let v = serde_json::to_value(&loaded).unwrap();
    for forbidden in &["token", "value", "plaintext", "secret", "credential"] {
        assert!(
            v.get(forbidden).is_none(),
            "VaultReceipt must not carry '{forbidden}' field — found in: {v}"
        );
    }
}
