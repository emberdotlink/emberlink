use crate::infra::receipt::issue::{
    issue_service_installed_receipt, issue_service_uninstalled_receipt,
};
use crate::infra::store::DaemonStore;
use core_crypto::FixtureSigner;
use core_events::receipt::envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
use core_events::receipt::{
    RECEIPT_KIND_SERVICE_INSTALLED_V1, RECEIPT_KIND_SERVICE_UNINSTALLED_V1, ServiceInstalledBody,
    ServiceUninstalledBody,
};

fn insert_v2_row(
    store: &DaemonStore,
    id: &str,
    kind: &str,
    grant_id: &str,
    envelope: &ReceiptEnvelope,
) {
    let json = serde_json::to_string(envelope).unwrap();
    store
        .conn()
        .execute(
            "INSERT INTO receipts (id, grant_id, persona_id, terminal_reason, \
                 created_at, receipt_json, signer_pubkey, kind) \
                 VALUES (?1, ?2, '', '', '2026-01-01T00:00:00Z', ?3, '', ?4)",
            rusqlite::params![id, grant_id, json, kind],
        )
        .unwrap();
}

fn minimal_envelope(kind: &str) -> ReceiptEnvelope {
    ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: kind.to_string(),
        receipt_id: format!("rct-{kind}-test"),
        daemon_root_id: "daemon-root-test".to_string(),
        traceparent: None,
        termination_authority: TerminationAuthority::DaemonPersona,
        presence_kind: None,
        body: serde_json::json!({"test": true}),
        signature: None,
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    }
}

fn service_installed_envelope() -> ReceiptEnvelope {
    let signer = FixtureSigner::new("service-installed-receipt");
    issue_service_installed_receipt(
        &ServiceInstalledBody {
            plugin_address: "registry.ember.systems/ember-systems/ember-gh".into(),
            plugin_version: "0.3.0".into(),
            publisher_id: "publisher-root-001".into(),
            installed_by_persona_id: "persona-installer-001".into(),
            installation_policy: serde_json::json!({"approval": "explicit"}),
            service_label: Some("GitHub".into()),
        },
        "daemon-root-test",
        &signer,
    )
    .unwrap()
}

fn service_uninstalled_envelope() -> ReceiptEnvelope {
    let signer = FixtureSigner::new("service-uninstalled-receipt");
    issue_service_uninstalled_receipt(
        &ServiceUninstalledBody {
            plugin_address: "registry.ember.systems/ember-systems/ember-gh".into(),
            plugin_version: "0.3.0".into(),
            publisher_id: "publisher-root-001".into(),
            uninstalled_by_persona_id: "persona-installer-001".into(),
            uninstall_reason: "operator_removed".into(),
            service_label: Some("GitHub".into()),
        },
        "daemon-root-test",
        &signer,
    )
    .unwrap()
}

#[test]
fn list_receipts_v2_envelopes_returns_matching_grant() {
    let store = DaemonStore::open_in_memory().unwrap();
    let envelope = minimal_envelope("broker.materialization");
    insert_v2_row(
        &store,
        "rct-v2-1",
        "broker.materialization",
        "grant-abc",
        &envelope,
    );

    let results = store
        .list_receipts_v2_envelopes(&["grant-abc".to_string()])
        .unwrap();
    assert_eq!(results.len(), 1, "expected one v2 envelope");
    let (id, kind, grant_id, _env) = &results[0];
    assert_eq!(id, "rct-v2-1");
    assert_eq!(kind, "broker.materialization");
    assert_eq!(grant_id, "grant-abc");
}

#[test]
fn list_receipts_v2_envelopes_excludes_spawn_witness() {
    let store = DaemonStore::open_in_memory().unwrap();
    let sw_envelope = minimal_envelope(core_events::receipt::RECEIPT_KIND_SPAWN_WITNESS);
    insert_v2_row(
        &store,
        "rct-sw-1",
        core_events::receipt::RECEIPT_KIND_SPAWN_WITNESS,
        "grant-xyz",
        &sw_envelope,
    );
    // spawn.witness row must be excluded even though grant_id matches.
    let results = store
        .list_receipts_v2_envelopes(&["grant-xyz".to_string()])
        .unwrap();
    assert!(
        results.is_empty(),
        "spawn.witness must be excluded from list_receipts_v2_envelopes"
    );
}

#[test]
fn list_receipts_v2_envelopes_excludes_v1_rows() {
    let store = DaemonStore::open_in_memory().unwrap();
    // Insert a v1-style row (kind without a dot).
    store
            .conn()
            .execute(
                "INSERT INTO receipts (id, grant_id, persona_id, terminal_reason, \
                 created_at, receipt_json, signer_pubkey, kind) \
                 VALUES ('rct-v1-1', 'grant-v1', '', '', '2026-01-01T00:00:00Z', '{}', '', 'grant')",
                [],
            )
            .unwrap();
    let results = store
        .list_receipts_v2_envelopes(&["grant-v1".to_string()])
        .unwrap();
    assert!(
        results.is_empty(),
        "v1 rows (underscore/bare kind) must not appear in v2 listing"
    );
}

#[test]
fn list_receipts_v2_envelopes_empty_grant_ids_returns_empty() {
    let store = DaemonStore::open_in_memory().unwrap();
    let results = store.list_receipts_v2_envelopes(&[]).unwrap();
    assert!(results.is_empty());
}

#[test]
fn list_receipts_v2_envelopes_ignores_non_matching_grant() {
    let store = DaemonStore::open_in_memory().unwrap();
    let envelope = minimal_envelope("broker.materialization");
    insert_v2_row(
        &store,
        "rct-v2-miss",
        "broker.materialization",
        "grant-other",
        &envelope,
    );

    let results = store
        .list_receipts_v2_envelopes(&["grant-abc".to_string()])
        .unwrap();
    assert!(results.is_empty(), "non-matching grant_id must not appear");
}

#[test]
fn store_service_receipt_v2_persists_install_receipt_and_registration() {
    let store = DaemonStore::open_in_memory().unwrap();
    let envelope = service_installed_envelope();

    store.store_service_receipt_v2(&envelope).unwrap();

    let (kind, persona_id, terminal_reason): (String, String, String) = store
        .conn()
        .query_row(
            "SELECT kind, persona_id, terminal_reason FROM receipts WHERE id = ?1",
            rusqlite::params![envelope.receipt_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(kind, RECEIPT_KIND_SERVICE_INSTALLED_V1);
    assert_eq!(persona_id, "persona-installer-001");
    assert_eq!(
        terminal_reason,
        "registry.ember.systems/ember-systems/ember-gh"
    );

    let registration: (String, String, String, String, String, String, Option<String>) = store
            .conn()
            .query_row(
                "SELECT plugin_address, plugin_version, publisher_id, installed_by, state, install_receipt_hash, service_label \
                 FROM service_registrations \
                 WHERE plugin_address = ?1 AND plugin_version = ?2",
                rusqlite::params![
                    "registry.ember.systems/ember-systems/ember-gh",
                    "0.3.0"
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .unwrap();
    assert_eq!(
        registration,
        (
            "registry.ember.systems/ember-systems/ember-gh".to_string(),
            "0.3.0".to_string(),
            "publisher-root-001".to_string(),
            "persona-installer-001".to_string(),
            "installed".to_string(),
            envelope.receipt_id.clone(),
            Some("GitHub".to_string()),
        )
    );
}

#[test]
fn store_service_receipt_v2_marks_existing_registration_uninstalled() {
    let store = DaemonStore::open_in_memory().unwrap();
    let installed = service_installed_envelope();
    let uninstalled = service_uninstalled_envelope();

    store.store_service_receipt_v2(&installed).unwrap();
    store.store_service_receipt_v2(&uninstalled).unwrap();

    let (state, install_receipt_hash): (String, String) = store
        .conn()
        .query_row(
            "SELECT state, install_receipt_hash FROM service_registrations \
                 WHERE plugin_address = ?1 AND plugin_version = ?2",
            rusqlite::params!["registry.ember.systems/ember-systems/ember-gh", "0.3.0"],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, "uninstalled");
    assert_eq!(install_receipt_hash, installed.receipt_id);

    let (kind, persona_id): (String, String) = store
        .conn()
        .query_row(
            "SELECT kind, persona_id FROM receipts WHERE id = ?1",
            rusqlite::params![uninstalled.receipt_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(kind, RECEIPT_KIND_SERVICE_UNINSTALLED_V1);
    assert_eq!(persona_id, "persona-installer-001");
}

#[test]
fn store_service_receipt_v2_rejects_uninstall_without_registration() {
    let store = DaemonStore::open_in_memory().unwrap();
    let envelope = service_uninstalled_envelope();

    let err = store.store_service_receipt_v2(&envelope).unwrap_err();
    assert!(matches!(err, crate::infra::store::StoreError::NotFound));
}
