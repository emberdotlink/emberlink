use super::*;
use std::rc::Rc;

#[tokio::test]
async fn recovery_action_receipt_dispatch_signs_and_logs() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-diagnose-test",
            "surface": "lifecycle",
            "verb": "diagnose",
            "target_kind": "local-machine",
            "target_id": "local-machine",
            "requested_action": "ember recover vault --dry-run",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "outcome": "planned",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#recovery-lifecycle-plane",
            "adr_refs": ["ADR 195"],
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["kind"], json!(RECEIPT_KIND_RECOVERY_ACTION));
    assert!(
        result["receipt_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()),
        "receipt_id must be non-empty: {result}"
    );
    assert_eq!(result["persisted"], json!(true));
    assert_eq!(
        result["envelope"]["kind"],
        json!(RECEIPT_KIND_RECOVERY_ACTION)
    );
    let body: RecoveryActionBody = serde_json::from_value(result["envelope"]["body"].clone())
        .expect("recovery.action body must deserialize");
    assert!(body.validate().is_ok());
    assert_eq!(body.verb, "diagnose");
}

#[tokio::test]
async fn recovery_action_receipt_is_visible_to_receipt_get_and_list() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-receipt-visible-test",
            "surface": "lifecycle",
            "verb": "daemon",
            "target_kind": "launchdaemon",
            "target_id": "sh.emberlink.daemon",
            "requested_action": "launchctl kickstart -k system/sh.emberlink.daemon",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "operator_confirmation_token_hash": null,
            "operator_persona_id": null,
            "authority_evidence": {
                "scope": "daemon_crash",
                "before_state": "exited",
                "after_state": "running",
                "log_excerpt_hash": "blake3:3333333333333333",
                "launchctl_label": "sh.emberlink.daemon",
                "launchctl_target": "system/sh.emberlink.daemon",
                "socket_path": "/Library/Application Support/Emberlink/run/daemon.sock",
                "log_path": "/var/log/emberd.err",
            },
            "outcome": "executed",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#f-daemon-1",
            "adr_refs": ["ADR 161", "ADR 195"],
        }),
    )
    .await
    .unwrap();
    let receipt_id = result["receipt_id"]
        .as_str()
        .expect("receipt_id")
        .to_string();

    let fetched = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "receipt.get",
        &json!({ "id": receipt_id }),
    )
    .await
    .unwrap();
    assert_eq!(fetched["receipt_id"], result["receipt_id"]);
    assert_eq!(fetched["kind"], json!(RECEIPT_KIND_RECOVERY_ACTION));
    assert_eq!(fetched["body"]["verb"], json!("daemon"));
    assert_eq!(fetched["body"]["outcome"], json!("executed"));

    let listed = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "receipt.list",
        &json!({
            "kind": RECEIPT_KIND_RECOVERY_ACTION,
            "since": "1970-01-01T00:00:00Z"
        }),
    )
    .await
    .unwrap();
    let rows = listed.as_array().expect("receipt.list rows");
    assert!(
        rows.iter()
            .any(|row| row["receipt_id"] == json!(receipt_id)),
        "recovery.action receipt should be listed: {rows:?}"
    );
}

#[tokio::test]
async fn recovery_action_receipt_accepts_daemon_crash_executed_receipt() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-daemon-crash-test",
            "surface": "lifecycle",
            "verb": "daemon",
            "target_kind": "launchdaemon",
            "target_id": "sh.emberlink.daemon",
            "requested_action": "launchctl kickstart -k system/sh.emberlink.daemon",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "operator_confirmation_token_hash": null,
            "operator_persona_id": null,
            "authority_evidence": {
                "scope": "daemon_crash",
                "before_state": "exited",
                "after_state": "running",
                "log_excerpt_hash": "blake3:3333333333333333",
                "launchctl_label": "sh.emberlink.daemon",
                "launchctl_target": "system/sh.emberlink.daemon",
                "socket_path": "/home/tester/.ember/run/daemon.sock",
                "log_path": "/var/log/emberd.err",
            },
            "outcome": "executed",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#f-daemon-1",
            "adr_refs": ["ADR 161", "ADR 195"],
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["kind"], json!(RECEIPT_KIND_RECOVERY_ACTION));
    let body: RecoveryActionBody = serde_json::from_value(result["envelope"]["body"].clone())
        .expect("recovery.action body must deserialize");
    assert!(body.validate().is_ok());
    assert_eq!(body.verb, "daemon");
    assert_eq!(body.target_kind, "launchdaemon");
    assert_eq!(body.outcome, "executed");
    assert_eq!(body.authority_evidence["scope"], json!("daemon_crash"));
    assert_eq!(body.authority_evidence["before_state"], json!("exited"));
    assert_eq!(body.authority_evidence["after_state"], json!("running"));
    assert_eq!(
        body.authority_evidence["log_excerpt_hash"],
        json!("blake3:3333333333333333")
    );
}

#[tokio::test]
async fn recovery_action_receipt_accepts_daemon_bootstrap_executed_receipt() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-daemon-bootstrap-test",
            "surface": "lifecycle",
            "verb": "daemon",
            "target_kind": "launchdaemon",
            "target_id": "sh.emberlink.daemon",
            "requested_action": "launchctl bootstrap system /Library/LaunchDaemons/sh.emberlink.daemon.plist; launchctl kickstart -k system/sh.emberlink.daemon",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "operator_confirmation_token_hash": null,
            "operator_persona_id": null,
            "authority_evidence": {
                "scope": "daemon_crash",
                "before_state": "missing",
                "after_state": "running",
                "log_excerpt_hash": "blake3:3333333333333333",
                "launchctl_label": "sh.emberlink.daemon",
                "launchctl_target": "system/sh.emberlink.daemon",
                "socket_path": "/Library/Application Support/Emberlink/run/daemon.sock",
                "log_path": "/var/log/emberd.err",
                "launchctl_bootstrap_performed": true,
                "plist_path": "/Library/LaunchDaemons/sh.emberlink.daemon.plist",
            },
            "outcome": "executed",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#f-daemon-1",
            "adr_refs": ["ADR 161", "ADR 195"],
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["kind"], json!(RECEIPT_KIND_RECOVERY_ACTION));
    let body: RecoveryActionBody = serde_json::from_value(result["envelope"]["body"].clone())
        .expect("recovery.action body must deserialize");
    assert!(body.validate().is_ok());
    assert_eq!(body.verb, "daemon");
    assert_eq!(body.target_kind, "launchdaemon");
    assert_eq!(
        body.requested_action,
        "launchctl bootstrap system /Library/LaunchDaemons/sh.emberlink.daemon.plist; launchctl kickstart -k system/sh.emberlink.daemon"
    );
    assert_eq!(body.outcome, "executed");
    assert_eq!(body.authority_evidence["scope"], json!("daemon_crash"));
    assert_eq!(body.authority_evidence["before_state"], json!("missing"));
    assert_eq!(body.authority_evidence["after_state"], json!("running"));
    assert_eq!(
        body.authority_evidence["launchctl_bootstrap_performed"],
        json!(true)
    );
    assert_eq!(
        body.authority_evidence["plist_path"],
        json!("/Library/LaunchDaemons/sh.emberlink.daemon.plist")
    );
}

#[tokio::test]
async fn recovery_action_receipt_rejects_connectonly_executed_receipts() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-executed-test",
            "surface": "lifecycle",
            "verb": "diagnose",
            "target_kind": "local-machine",
            "target_id": "local-machine",
            "requested_action": "executed mutation without daemon action",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "outcome": "executed",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#recovery-lifecycle-plane",
            "adr_refs": ["ADR 195"],
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32602);
    assert!(
        err.1.contains("'outcome' must be 'planned'"),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
async fn recovery_action_receipt_accepts_audit_chain_planned_receipt() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-audit-chain-test",
            "surface": "lifecycle",
            "verb": "audit-chain",
            "target_kind": "audit-chain",
            "target_id": "local-audit-chain",
            "requested_action": "truncate-after-row",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "operator_confirmation_token_hash": "blake3:3333333333333333",
            "operator_persona_id": null,
            "outcome": "planned",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#audit-chain-lifecycle-recovery",
            "adr_refs": ["ADR 195", "ADR 174", "ADR 176"],
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["kind"], json!(RECEIPT_KIND_RECOVERY_ACTION));
    assert!(
        result["receipt_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()),
        "receipt_id must be non-empty: {result}"
    );
    assert_eq!(result["envelope"]["body"]["verb"], json!("audit-chain"));
    assert_eq!(
        result["envelope"]["body"]["operator_confirmation_token_hash"],
        json!("blake3:3333333333333333")
    );
}

#[tokio::test]
async fn recovery_action_receipt_accepts_persona_planned_receipt() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-persona-restore-test",
            "surface": "lifecycle",
            "verb": "persona",
            "target_kind": "persona",
            "target_id": "persona-revoked-clean",
            "requested_action": "restore",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "operator_confirmation_token_hash": "blake3:3333333333333333",
            "operator_persona_id": "persona-operator",
            "authority_evidence": {
                "probe_rpc": "recover_persona_restore_status",
                "diagnostic_code": "eligible_pending_mutation_rpc",
                "decision": "requires-dedicated-mutation-rpc",
                "can_restore": false,
                "restore_eligibility_proven": false,
                "successor_enrollment_required": false,
                "evidence_floor": "restore proves the ADR 190/195 runtime predicate inside a dedicated daemon mutation RPC; a read-only probe never un-revokes a terminal durable persona",
            },
            "outcome": "planned",
            "related_receipt_ids": ["receipt-persona-source"],
            "runbook_ref": "docs/runbook/recovery.md#persona-lifecycle-recovery",
            "adr_refs": ["ADR 195", "ADR 205", "ADR 206", "ADR 211"],
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["kind"], json!(RECEIPT_KIND_RECOVERY_ACTION));
    assert_eq!(result["envelope"]["body"]["verb"], json!("persona"));
    assert_eq!(result["envelope"]["body"]["target_kind"], json!("persona"));
    assert_eq!(result["envelope"]["body"]["outcome"], json!("planned"));
    assert_eq!(
        result["envelope"]["body"]["authority_evidence"]["probe_rpc"],
        json!("recover_persona_restore_status")
    );
    assert_eq!(
        result["envelope"]["body"]["authority_evidence"]["diagnostic_code"],
        json!("eligible_pending_mutation_rpc")
    );
    assert_eq!(
        result["envelope"]["body"]["authority_evidence"]["can_restore"],
        json!(false)
    );
    assert_eq!(
        result["envelope"]["body"]["authority_evidence"]["restore_eligibility_proven"],
        json!(false)
    );
}

#[tokio::test]
async fn recovery_action_receipt_accepts_grant_refused_receipt() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-grant-abandon-test",
            "surface": "lifecycle",
            "verb": "grant",
            "target_kind": "grant",
            "target_id": "grant-with-missing-link",
            "requested_action": "abandon",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "operator_confirmation_token_hash": null,
            "operator_persona_id": null,
            "outcome": "refused",
            "abandon_reason": "missing embed-canonical chain evidence",
            "related_receipt_ids": ["receipt-grant-origin"],
            "runbook_ref": "docs/runbook/recovery.md#grant-lifecycle-recovery",
            "adr_refs": ["ADR 195", "ADR 205", "ADR 206", "ADR 211"],
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["kind"], json!(RECEIPT_KIND_RECOVERY_ACTION));
    assert_eq!(result["envelope"]["body"]["verb"], json!("grant"));
    assert_eq!(result["envelope"]["body"]["target_kind"], json!("grant"));
    assert_eq!(result["envelope"]["body"]["outcome"], json!("refused"));
}

#[tokio::test]
async fn recovery_action_receipt_accepts_grant_rebuild_chain_refused_receipt() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-grant-rebuild-test",
            "surface": "lifecycle",
            "verb": "grant",
            "target_kind": "grant",
            "target_id": "grant-with-missing-origin-history",
            "requested_action": "rebuild-chain",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "operator_confirmation_token_hash": null,
            "operator_persona_id": null,
            "authority_evidence": {
                "probe_rpc": "recover_grant_rebuild_chain_status",
                "diagnostic_code": "signed_origin_journal_unavailable",
                "decision": "refuse",
                "can_rebuild": false,
                "materialized_chain_verifies": false,
                "signed_origin_journal_available": false,
                "evidence_floor": "rebuild-chain refuses unless the daemon can prove signed grant-origin/history evidence; scalar grant rows are not rebuild evidence",
            },
            "outcome": "refused",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#grant-lifecycle-recovery",
            "adr_refs": ["ADR 195", "ADR 205", "ADR 206", "ADR 211"],
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["kind"], json!(RECEIPT_KIND_RECOVERY_ACTION));
    assert_eq!(result["envelope"]["body"]["verb"], json!("grant"));
    assert_eq!(
        result["envelope"]["body"]["requested_action"],
        json!("rebuild-chain")
    );
    assert_eq!(result["envelope"]["body"]["outcome"], json!("refused"));
    assert_eq!(
        result["envelope"]["body"]["authority_evidence"]["probe_rpc"],
        json!("recover_grant_rebuild_chain_status")
    );
    assert_eq!(
        result["envelope"]["body"]["authority_evidence"]["diagnostic_code"],
        json!("signed_origin_journal_unavailable")
    );
    assert_eq!(
        result["envelope"]["body"]["authority_evidence"]["can_rebuild"],
        json!(false)
    );
    assert_eq!(
        result["envelope"]["body"]["authority_evidence"]["signed_origin_journal_available"],
        json!(false)
    );
}

#[tokio::test]
async fn recovery_action_receipt_rejects_executed_persona_receipts() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-persona-executed-test",
            "surface": "lifecycle",
            "verb": "persona",
            "target_kind": "persona",
            "target_id": "persona-target",
            "requested_action": "restore",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "outcome": "executed",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#persona-lifecycle-recovery",
            "adr_refs": ["ADR 195", "ADR 205", "ADR 206", "ADR 211"],
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32602);
    assert!(
        err.1
            .contains("persona outcome must be 'planned' or 'refused'; executed"),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
async fn recovery_action_receipt_accepts_vault_rotate_planned_receipt() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // Mirrors `recover vault rotate-key` dry-run: a planned receipt for the
    // vault target carrying the operator confirmation token hash.
    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-vault-rotate-test",
            "surface": "lifecycle",
            "verb": "vault",
            "target_kind": "vault",
            "target_id": "local-vault",
            "requested_action": "rotate-key",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "operator_confirmation_token_hash": "blake3:3333333333333333",
            "operator_persona_id": null,
            "outcome": "planned",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#vault-lifecycle-recovery",
            "adr_refs": ["ADR 195", "ADR 094"],
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["kind"], json!(RECEIPT_KIND_RECOVERY_ACTION));
    assert!(
        result["receipt_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()),
        "receipt_id must be non-empty: {result}"
    );
    assert_eq!(result["envelope"]["body"]["verb"], json!("vault"));
    assert_eq!(result["persisted"], json!(true));
}

#[tokio::test]
async fn recovery_action_receipt_accepts_vault_backup_executed_receipt() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // Mirrors `recover vault verify-backup`: a read-only verification that
    // ran to completion ('executed') against the 'vault-backup' target.
    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-vault-backup-test",
            "surface": "lifecycle",
            "verb": "vault",
            "target_kind": "vault-backup",
            "target_id": "local-vault-backup",
            "requested_action": "verify-backup",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "operator_confirmation_token_hash": null,
            "operator_persona_id": null,
            "outcome": "executed",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#vault-lifecycle-recovery",
            "adr_refs": ["ADR 195", "ADR 094"],
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["envelope"]["body"]["verb"], json!("vault"));
    assert_eq!(result["envelope"]["body"]["outcome"], json!("executed"));
}

#[tokio::test]
async fn recovery_action_receipt_accepts_trust_list_audit_receipt() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // Mirrors `recover trust list-audit`: a read-only audit listing.
    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-trust-list-test",
            "surface": "lifecycle",
            "verb": "trust",
            "target_kind": "trust-list",
            "target_id": "local-trust-list",
            "requested_action": "list-audit",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "outcome": "executed",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#trust-lifecycle-recovery",
            "adr_refs": ["ADR 195"],
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["envelope"]["body"]["verb"], json!("trust"));
    assert!(
        result["receipt_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()),
        "receipt_id must be non-empty: {result}"
    );
}

#[tokio::test]
async fn recovery_action_receipt_rejects_executed_grant_rebuild_chain_receipts() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-grant-rebuild-test",
            "surface": "lifecycle",
            "verb": "grant",
            "target_kind": "grant",
            "target_id": "grant-with-missing-origin-history",
            "requested_action": "rebuild-chain",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "operator_confirmation_token_hash": "blake3:3333333333333333",
            "operator_persona_id": null,
            "outcome": "executed",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#grant-lifecycle-recovery",
            "adr_refs": ["ADR 195", "ADR 205", "ADR 206", "ADR 211"],
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32602);
    assert!(
        err.1.contains("dedicated daemon mutation RPC"),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
async fn recover_grant_abandon_executes_with_operator_presence_provenance() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(Rc::new(test_vault()));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let persona = store.create_persona("recover-grant-abandon").unwrap();
    let grant = store
        .create_grant(&persona.id, "token", "read", Some(3600))
        .unwrap();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recover_grant_abandon",
        &json!({
            "recovery_id": "recover-grant-abandon-test",
            "surface": "lifecycle",
            "verb": "grant",
            "target_kind": "grant",
            "target_id": grant.id.clone(),
            "requested_action": "abandon",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "operator_confirmation_token_hash": "blake3:3333333333333333",
            "operator_persona_id": null,
            "outcome": "executed",
            "abandon_reason": "missing embed-canonical chain evidence",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#grant-lifecycle-recovery",
            "adr_refs": ["ADR 195", "ADR 205", "ADR 206", "ADR 211"],
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["envelope"]["body"]["verb"], json!("grant"));
    assert_eq!(result["envelope"]["body"]["outcome"], json!("executed"));
    assert_eq!(
        result["envelope"]["body"]["authority_evidence"]["daemon_rpc"],
        json!("recover_grant_abandon")
    );
    assert_eq!(
        result["envelope"]["body"]["authority_evidence"]["authority_class"],
        json!("OperatorPresence")
    );
    let abandoned = store.get_grant(grant.id.as_str()).unwrap();
    assert_eq!(abandoned.status, "abandoned");
    assert!(
        abandoned.receipt_id.is_some(),
        "grant abandon must write terminal receipt provenance"
    );
}

#[tokio::test]
async fn recover_grant_rebuild_chain_status_refuses_corrupt_blocks_without_journal() {
    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(Rc::new(test_vault()));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let persona = store.create_persona("recover-grant-rebuild").unwrap();
    let grant = store
        .create_grant(&persona.id, "token", "read", Some(3600))
        .unwrap();
    store
        .conn()
        .execute(
            "UPDATE grants SET blocks_json = ?1 WHERE id = ?2",
            rusqlite::params!["not-json", grant.id.as_str()],
        )
        .unwrap();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recover_grant_rebuild_chain_status",
        &json!({ "id": grant.id }),
    )
    .await
    .unwrap();

    assert_eq!(result["kind"], json!("grant_rebuild_chain_status"));
    assert_eq!(
        result["diagnostic_code"],
        json!("signed_origin_journal_unavailable")
    );
    assert_eq!(result["can_rebuild"], json!(false));
    assert_eq!(result["blocks_json_present"], json!(true));
    assert_eq!(result["blocks_json_deserializes"], json!(false));
    assert!(
        result["diagnostics"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item
                .as_str()
                .is_some_and(|text| text.starts_with("blocks_json_invalid_json")))),
        "expected invalid-json diagnostic: {result}"
    );
}

#[tokio::test]
async fn recover_persona_restore_status_refuses_terminal_persona() {
    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(Rc::new(test_vault()));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let persona = store
        .create_persona("recover-persona-restore-terminal")
        .unwrap();
    store.revoke_persona(&persona.id).unwrap();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recover_persona_restore_status",
        &json!({ "id": persona.id }),
    )
    .await
    .unwrap();

    assert_eq!(result["kind"], json!("persona_restore_status"));
    assert_eq!(result["diagnostic_code"], json!("persona_terminal"));
    assert_eq!(result["can_restore"], json!(false));
    assert_eq!(result["restore_eligibility_proven"], json!(false));
    assert_eq!(result["durable_persona_terminal"], json!(true));
    assert_eq!(result["successor_enrollment_required"], json!(true));
}

#[tokio::test]
async fn recover_persona_restore_status_reports_active_pending_mutation_rpc() {
    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(Rc::new(test_vault()));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let persona = store
        .create_persona("recover-persona-restore-active")
        .unwrap();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recover_persona_restore_status",
        &json!({ "id": persona.id }),
    )
    .await
    .unwrap();

    assert_eq!(result["kind"], json!("persona_restore_status"));
    assert_eq!(
        result["diagnostic_code"],
        json!("eligible_pending_mutation_rpc")
    );
    // The read-only probe is never authority: it cannot restore and never
    // proves eligibility, even for an active durable persona.
    assert_eq!(result["can_restore"], json!(false));
    assert_eq!(result["restore_eligibility_proven"], json!(false));
    assert_eq!(result["durable_persona_active"], json!(true));
    assert_eq!(result["successor_enrollment_required"], json!(false));
}

#[tokio::test]
async fn recovery_action_receipt_refuses_to_execute_grant_abandon() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(Rc::new(test_vault()));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let persona = store.create_persona("recover-grant-abandon").unwrap();
    let grant = store
        .create_grant(&persona.id, "token", "read", Some(3600))
        .unwrap();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-grant-abandon-test",
            "surface": "lifecycle",
            "verb": "grant",
            "target_kind": "grant",
            "target_id": grant.id.clone(),
            "requested_action": "abandon",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "operator_confirmation_token_hash": "blake3:3333333333333333",
            "operator_persona_id": null,
            "outcome": "executed",
            "abandon_reason": "missing embed-canonical chain evidence",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#grant-lifecycle-recovery",
            "adr_refs": ["ADR 195", "ADR 205", "ADR 206", "ADR 211"],
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32602);
    assert!(
        err.1.contains("recover_grant_abandon"),
        "unexpected error: {err:?}"
    );
    let unchanged = store.get_grant(grant.id.as_str()).unwrap();
    assert_eq!(unchanged.status, "active");
    assert!(
        unchanged.receipt_id.is_none(),
        "ConnectOnly receipt lane must not write terminal provenance"
    );
}

#[tokio::test]
async fn recover_persona_abandon_executes_with_operator_presence_provenance() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(Rc::new(test_vault()));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let persona = store.create_persona("recover-persona-abandon").unwrap();
    let grant = store
        .create_grant(&persona.id, "token", "read", Some(3600))
        .unwrap();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recover_persona_abandon",
        &json!({
            "recovery_id": "recover-persona-abandon-test",
            "surface": "lifecycle",
            "verb": "persona",
            "target_kind": "persona",
            "target_id": persona.id.clone(),
            "requested_action": "abandon",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "operator_confirmation_token_hash": "blake3:3333333333333333",
            "operator_persona_id": null,
            "outcome": "executed",
            "abandon_reason": "operator declared runtime identity unrecoverable",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#persona-lifecycle-recovery",
            "adr_refs": ["ADR 195", "ADR 206", "ADR 211"],
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["envelope"]["body"]["verb"], json!("persona"));
    assert_eq!(result["envelope"]["body"]["outcome"], json!("executed"));
    assert_eq!(
        result["envelope"]["body"]["authority_evidence"]["daemon_rpc"],
        json!("recover_persona_abandon")
    );
    assert_eq!(
        result["envelope"]["body"]["authority_evidence"]["authority_class"],
        json!("OperatorPresence")
    );
    let abandoned = store.get_persona(&persona.id).unwrap();
    assert_eq!(abandoned.status, "revoked");
    let cascaded = store.get_grant(grant.id.as_str()).unwrap();
    assert_eq!(
        cascaded.status, "revoked",
        "persona abandon must cascade-revoke active grants"
    );
}

#[tokio::test]
async fn recover_persona_abandon_refuses_terminal_persona() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(Rc::new(test_vault()));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let persona = store
        .create_persona("recover-terminal-persona-abandon")
        .unwrap();
    store.revoke_persona(&persona.id).unwrap();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recover_persona_abandon",
        &json!({
            "recovery_id": "recover-terminal-persona-abandon-test",
            "surface": "lifecycle",
            "verb": "persona",
            "target_kind": "persona",
            "target_id": persona.id.clone(),
            "requested_action": "abandon",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "operator_confirmation_token_hash": "blake3:3333333333333333",
            "operator_persona_id": null,
            "outcome": "executed",
            "abandon_reason": "operator declared runtime identity unrecoverable",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#persona-lifecycle-recovery",
            "adr_refs": ["ADR 195", "ADR 206", "ADR 211"],
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32030);
    assert!(
        err.1.contains("already terminal"),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
async fn recovery_action_receipt_refuses_to_execute_persona_abandon() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(Rc::new(test_vault()));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let persona = store.create_persona("recover-persona-abandon").unwrap();
    let grant = store
        .create_grant(&persona.id, "token", "read", Some(3600))
        .unwrap();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-persona-abandon-test",
            "surface": "lifecycle",
            "verb": "persona",
            "target_kind": "persona",
            "target_id": persona.id.clone(),
            "requested_action": "abandon",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "operator_confirmation_token_hash": "blake3:3333333333333333",
            "operator_persona_id": null,
            "outcome": "executed",
            "abandon_reason": "operator declared runtime identity unrecoverable",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#persona-lifecycle-recovery",
            "adr_refs": ["ADR 195", "ADR 206", "ADR 211"],
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32602);
    assert!(
        err.1.contains("recover_persona_abandon"),
        "unexpected error: {err:?}"
    );
    let unchanged = store.get_persona(&persona.id).unwrap();
    assert_eq!(unchanged.status, "active");
    let grant = store.get_grant(grant.id.as_str()).unwrap();
    assert_eq!(
        grant.status, "active",
        "ConnectOnly receipt lane must not cascade-revoke persona grants"
    );
}

/// Pin: grant rebuild-chain `executed` is structurally refused at v0.3.0.
///
/// No signed grant-origin/history journal substrate exists. Building one is
/// multi-PR + new ADR (v0.3.1+). The daemon has no mutation RPC for
/// rebuild-chain; `abandon` is the mutating recourse. This test breaks if
/// someone adds a mutation path without re-deciding the disposition.
#[tokio::test]
async fn rebuild_chain_executed_is_structurally_refused_no_mutation_rpc_exists() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "pin-rebuild-chain-probe-only",
            "surface": "lifecycle",
            "verb": "grant",
            "target_kind": "grant",
            "target_id": "grant-structural-refusal-pin",
            "requested_action": "rebuild-chain",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "outcome": "executed",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#grant-rebuild-chain-probe-only-at-v030",
            "adr_refs": ["ADR 195"],
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(
        err.0, -32602,
        "rebuild-chain executed must be -32602 (no mutation RPC); \
         if this changed, the v0.3.0 probe-only disposition was re-decided"
    );
    assert!(
        err.1.contains("dedicated daemon mutation RPC"),
        "expected the canonical 'no daemon mutation path' message, got: {err:?}"
    );
}

/// Pin: persona restore `executed` is structurally refused at v0.3.0.
///
/// Runtime Personas are ephemeral session-scoped state. Damaged Runtime
/// Persona state is recovered by `abandon` + opening a fresh session under
/// the same Durable Persona. The daemon has no mutation RPC for
/// persona-restore; the probe stays for routing terminal Durables to
/// `ember device enroll`. This test breaks if someone adds a mutation path
/// without re-deciding the disposition.
#[tokio::test]
async fn restore_persona_executed_is_structurally_refused_runtime_personas_are_ephemeral() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "pin-persona-restore-probe-only",
            "surface": "lifecycle",
            "verb": "persona",
            "target_kind": "persona",
            "target_id": "persona-structural-refusal-pin",
            "requested_action": "restore",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "outcome": "executed",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#persona-restore-probe-only-at-v030",
            "adr_refs": ["ADR 195"],
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(
        err.0, -32602,
        "persona restore executed must be -32602 (no mutation RPC); \
         if this changed, the v0.3.0 probe-only disposition was re-decided"
    );
    assert!(
        err.1
            .contains("persona outcome must be 'planned' or 'refused'; executed"),
        "expected the canonical 'no daemon mutation path' message, got: {err:?}"
    );
}

#[tokio::test]
async fn recovery_action_receipt_rejects_executed_vault_rotation() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // A ConnectOnly recovery receipt must not claim an executed MEK
    // rotation; that primitive (ADR 198) routes through its own path.
    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-vault-rotate-executed-test",
            "surface": "lifecycle",
            "verb": "vault",
            "target_kind": "vault",
            "target_id": "local-vault",
            "requested_action": "rotate-key",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "outcome": "executed",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#vault-lifecycle-recovery",
            "adr_refs": ["ADR 195", "ADR 094", "ADR 198"],
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32602);
    assert!(
        err.1.contains("vault rotation cannot report 'executed'"),
        "unexpected error: {err:?}"
    );
}

// ----- F-AUTHORITY-1 recovery.action receipts (workflow grant extend) -----

#[tokio::test]
async fn recovery_action_receipt_accepts_grant_extend_planned_receipt() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-authority-f1-test",
            "surface": "lifecycle",
            "verb": "grant",
            "target_kind": "grant",
            "target_id": "grant-workflow-test",
            "requested_action": "extend",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "operator_confirmation_token_hash": null,
            "operator_persona_id": null,
            "authority_evidence": {
                "extend_add_ttl_secs": 14400,
                "extend_prior_expires_at": "2026-06-12T00:00:00Z",
                "extend_new_expires_at": "2026-06-12T04:00:00Z",
            },
            "outcome": "planned",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#f-authority-1--delegated-authority-expired-during-long-running-agent-call",
            "adr_refs": ["ADR 158", "ADR 161", "ADR 195", "ADR 200", "ADR 206"],
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["kind"], json!(RECEIPT_KIND_RECOVERY_ACTION));
    assert_eq!(result["envelope"]["body"]["verb"], json!("grant"));
    assert_eq!(
        result["envelope"]["body"]["requested_action"],
        json!("extend")
    );
    assert_eq!(result["envelope"]["body"]["outcome"], json!("planned"));
    assert_eq!(
        result["envelope"]["body"]["authority_evidence"]["extend_add_ttl_secs"],
        json!(14400)
    );
}

#[tokio::test]
async fn recovery_action_receipt_rejects_executed_grant_extend() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recover_grant_abandon",
        &json!({
            "recovery_id": "recover-authority-f1-execute-test",
            "surface": "lifecycle",
            "verb": "grant",
            "target_kind": "grant",
            "target_id": "grant-workflow-test",
            "requested_action": "extend",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "outcome": "executed",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#f-authority-1--delegated-authority-expired-during-long-running-agent-call",
            "adr_refs": ["ADR 158", "ADR 161", "ADR 195"],
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32602);
    assert!(
        err.1.contains("grant abandon")
            || err.1.contains("requires verb='grant'")
            || err.1.contains("must route through"),
        "unexpected error: {err:?}"
    );
}

// ----- F-AUTHORITY-2 recovery.action receipts (PAM presence fallback) -----

#[tokio::test]
async fn recovery_action_receipt_accepts_authority_pam_fallback_planned_receipt() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-authority-f2-test",
            "surface": "lifecycle",
            "verb": "authority",
            "target_kind": "presence-fallback",
            "target_id": "presence-fallback",
            "requested_action": "pam-fallback",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "operator_confirmation_token_hash": null,
            "operator_persona_id": null,
            "authority_evidence": {
                "presence_factor": "pam",
                "presence_fallback_reason": "Touch ID sensor not responding",
                "presence_fallback_ttl_secs": 86400,
                "evidence_floor": "the recovery action records intent only; the per-op presence gate (ADR 200/206) still selects the actual factor at widening time",
            },
            "outcome": "planned",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#f-authority-2--touch-id-hardware-failed-sensor-dead-finger-unrecognizable",
            "adr_refs": ["ADR 136", "ADR 161", "ADR 195", "ADR 200", "ADR 206"],
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["kind"], json!(RECEIPT_KIND_RECOVERY_ACTION));
    assert_eq!(result["envelope"]["body"]["verb"], json!("authority"));
    assert_eq!(
        result["envelope"]["body"]["target_kind"],
        json!("presence-fallback")
    );
    assert_eq!(
        result["envelope"]["body"]["requested_action"],
        json!("pam-fallback")
    );
    assert_eq!(result["envelope"]["body"]["outcome"], json!("planned"));
    assert_eq!(
        result["envelope"]["body"]["authority_evidence"]["presence_factor"],
        json!("pam")
    );
}

#[tokio::test]
async fn recovery_action_receipt_rejects_authority_executed_outcome() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-authority-f2-execute-test",
            "surface": "lifecycle",
            "verb": "authority",
            "target_kind": "presence-fallback",
            "target_id": "presence-fallback",
            "requested_action": "pam-fallback",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "outcome": "executed",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#f-authority-2--touch-id-hardware-failed-sensor-dead-finger-unrecognizable",
            "adr_refs": ["ADR 161"],
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32602);
    assert!(
        err.1.contains("authority outcome"),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
async fn recovery_action_receipt_rejects_authority_unknown_target_kind() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "recovery_action_receipt",
        &json!({
            "recovery_id": "recover-authority-f2-wrong-target-test",
            "surface": "lifecycle",
            "verb": "authority",
            "target_kind": "delegated-authority",
            "target_id": "presence-fallback",
            "requested_action": "pam-fallback",
            "prior_state_digest": "blake3:1111111111111111",
            "dry_run_digest": "blake3:2222222222222222",
            "outcome": "planned",
            "related_receipt_ids": [],
            "runbook_ref": "docs/runbook/recovery.md#f-authority-2--touch-id-hardware-failed-sensor-dead-finger-unrecognizable",
            "adr_refs": ["ADR 161"],
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32602);
    assert!(
        err.1
            .contains("authority target_kind must be 'presence-fallback'"),
        "unexpected error: {err:?}"
    );
}
