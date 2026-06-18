use super::*;

struct QuarantineTestGuard {
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl Drop for QuarantineTestGuard {
    fn drop(&mut self) {
        crate::infra::handler::force_quarantine_latch_for_test(false);
    }
}

fn quarantine_test_guard() -> QuarantineTestGuard {
    let guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    crate::infra::handler::force_quarantine_latch_for_test(false);
    QuarantineTestGuard { _guard: guard }
}

#[tokio::test]
async fn audit_repair_chain_prepare_derives_signing_payload_in_quarantine() {
    let _guard = quarantine_test_guard();

    let dir = tempfile::tempdir().unwrap();
    crate::infra::receipt::init_identity(dir.path()).expect("init daemon identity");
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    crate::infra::audit::append_audit_event_with_chain(
        &store,
        Some("agent-audit-prepare"),
        "audit.prepare.fixture",
        None,
        "ok",
        None,
    )
    .expect("append chained audit row");
    let (from_row_id, row_hash): (i64, String) = store
        .conn()
        .query_row(
            "SELECT id, row_hash FROM audit_log WHERE row_hash IS NOT NULL ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let fingerprint = crate::infra::receipt::current_identity()
        .expect("identity current")
        .identity_root_fingerprint();

    crate::infra::handler::force_quarantine_latch_for_test(true);
    let prepared = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "audit_repair_chain_prepare",
        &json!({ "from_row_id": from_row_id }),
    )
    .await
    .expect("prepare must succeed while quarantined");
    crate::infra::handler::force_quarantine_latch_for_test(false);

    let canonical =
        crate::infra::audit::canonical_repair_intent_bytes(from_row_id, &row_hash, &fingerprint);
    assert_eq!(prepared["ok"], json!(true));
    assert_eq!(
        prepared["schema"],
        json!("emberlink.audit_repair_chain_prepare.v1")
    );
    assert_eq!(prepared["from_row_id"], json!(from_row_id));
    assert_eq!(prepared["repair_kind"], json!("truncate"));
    assert_eq!(prepared["current_chain_tip_hash"], json!(row_hash));
    assert_eq!(
        prepared["daemon_identity_root_fingerprint"],
        json!(fingerprint)
    );
    assert_eq!(
        prepared["canonical_bytes_hex"],
        json!(hex::encode(&canonical))
    );
    assert_eq!(prepared["canonical_bytes_len"], json!(canonical.len()));
    assert_eq!(
        prepared["audit_repair_chain_params"]["operator_signature_hex"],
        serde_json::Value::Null
    );
    assert_eq!(
        prepared["audit_repair_chain_params"]["operator_pubkey"],
        serde_json::Value::Null
    );
}

#[tokio::test]
async fn audit_repair_chain_prepare_refuses_missing_row() {
    let _guard = quarantine_test_guard();

    let dir = tempfile::tempdir().unwrap();
    crate::infra::receipt::init_identity(dir.path()).expect("init daemon identity");
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    crate::infra::handler::force_quarantine_latch_for_test(true);
    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "audit_repair_chain_prepare",
        &json!({ "from_row_id": 999 }),
    )
    .await
    .expect_err("missing row must refuse");
    crate::infra::handler::force_quarantine_latch_for_test(false);

    assert_eq!(err.0, -32602);
    assert!(
        err.1.contains("from_row_id 999"),
        "error should name the missing row: {}",
        err.1
    );
}

#[tokio::test]
async fn audit_query_reflects_credential_access() {
    let _guard = quarantine_test_guard();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "agent-epsilon"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "audit-token", "value": "v"}),
    )
    .await
    .unwrap();

    dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "audit-token", "scope": "read", "force": true}),
        )
        .await.unwrap();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "use_credential",
        &json!({"persona_id": persona_id, "credential_name": "audit-token"}),
    )
    .await
    .unwrap();

    let log = dispatch_method(&store, &vault, &policy, &rl, "audit_query", &json!({}))
        .await
        .unwrap();
    let arr = log.as_array().unwrap();
    // Three rows (timestamp DESC): credential.access, grant.issued, grant.minted.
    // grant.minted is emitted inside create_grant_with_budget before the handler
    // emits grant.issued, so it is the oldest.
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["action"], json!("credential.access"));
    assert_eq!(arr[0]["outcome"], json!("allowed"));
    assert_eq!(arr[1]["action"], json!("grant.issued"));
    assert_eq!(arr[1]["outcome"], json!("allowed"));
    assert_eq!(arr[2]["action"], json!("grant.minted"));
    assert_eq!(arr[2]["outcome"], json!("minted"));
}

#[tokio::test]
async fn audit_log_query_returns_details_and_exact_id_match() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let first_id = store
        .log_event(
            Some("persona-a"),
            "grant.issued",
            Some("repo:alpha"),
            "allowed",
            Some(r#"{"note":"first"}"#),
        )
        .unwrap();
    let _second_id = store
        .log_event(
            Some("persona-a"),
            "grant.revoked",
            Some("repo:beta"),
            "denied",
            Some(r#"{"note":"second"}"#),
        )
        .unwrap();

    let log = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "audit_log_query",
        &json!({
            "id": first_id,
            "persona_id": "persona-a",
        }),
    )
    .await
    .unwrap();
    let arr = log.as_array().expect("audit_log_query returns array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], json!(first_id));
    assert_eq!(arr[0]["action"], json!("grant.issued"));
    assert_eq!(arr[0]["details"], json!(r#"{"note":"first"}"#));
}

#[tokio::test]
async fn audit_explain_returns_current_state_projection() {
    let _guard = quarantine_test_guard();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = PolicyEngine::new(PolicyConfig {
        rules: vec![PolicyRule {
            action: ActionSelector::named("credential.access"),
            risk: RiskLevel::High,
            requirement: ApprovalRequirement::Required,
            tier: Some(Tier::Tier1),
        }],
        default_requirement: ApprovalRequirement::Auto,
        default_risk: RiskLevel::Low,
    });
    let rl = test_rate_limiter();

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "agent-zeta"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "audit-token", "value": "v"}),
    )
    .await
    .unwrap();

    dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "audit-token", "scope": "read", "force": true}),
        )
        .await
        .unwrap();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "use_credential",
        &json!({"persona_id": persona_id, "credential_name": "audit-token"}),
    )
    .await
    .unwrap();

    let audit = dispatch_method(&store, &vault, &policy, &rl, "audit_query", &json!({}))
        .await
        .unwrap();
    let event_id = audit.as_array().unwrap()[0]["id"].as_i64().unwrap();

    let explain = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "audit_explain",
        &json!({ "id": event_id }),
    )
    .await
    .unwrap();
    assert_eq!(explain["event"]["id"], json!(event_id));
    assert_eq!(explain["event"]["action"], json!("credential.access"));
    assert_eq!(explain["current_grant"]["scope"], json!("read"));
    assert_eq!(explain["current_policy"]["requirement"], json!("required"));
    assert_eq!(explain["current_policy"]["risk"], json!("high"));
    assert!(
        explain["note"]
            .as_str()
            .expect("note string")
            .contains("Current-state explanation")
    );
}

#[tokio::test]
async fn receipt_tree_dispatch_returns_rooted_tree_export() {
    let _guard = quarantine_test_guard();
    let dir = tempfile::tempdir().unwrap();
    let _ = crate::infra::receipt::init_identity(dir.path()).unwrap();

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "tree-root"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "tree-token", "value": "v"}),
    )
    .await
    .unwrap();

    let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "tree-token", "scope": "read", "force": true}),
        )
        .await
        .unwrap();
    let grant_id = grant["id"].as_str().unwrap();

    let tree = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "receipt_tree",
        &json!({ "grant_id": grant_id }),
    )
    .await
    .unwrap();
    assert_eq!(tree["root_grant_id"], json!(grant_id));
    assert_eq!(tree["version"], json!("v2"));
    assert_eq!(tree["grants"].as_array().unwrap().len(), 1);
    assert!(tree["daemon_pubkey_hex"].as_str().unwrap().len() >= 64);
}

#[tokio::test]
async fn get_receipt_and_list_receipts_round_trip() {
    let _quarantine_guard = quarantine_test_guard();
    let _identity_guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "rcpt-alpha"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap().to_string();
    let grant = dispatch_method(
            &store, &vault, &policy, &rl, "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "rcpt-cred", "scope": "push", "force": true}),
        ).await.unwrap();
    let grant_id = grant["id"].as_str().unwrap().to_string();
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "revoke_grant",
        &json!({"id": grant_id}),
    )
    .await
    .unwrap();

    // list_receipts (no filter) returns our receipt.
    let list = dispatch_method(&store, &vault, &policy, &rl, "list_receipts", &json!({}))
        .await
        .unwrap();
    let arr = list.as_array().expect("array");
    assert!(!arr.is_empty(), "receipt should be emitted on revoke");
    let rid = arr[0]["id"].as_str().unwrap().to_string();
    assert_eq!(arr[0]["grant_id"].as_str().unwrap(), grant_id);

    // get_receipt returns the full signed body.
    let r = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "get_receipt",
        &json!({"id": rid}),
    )
    .await
    .unwrap();
    assert_eq!(r["id"].as_str().unwrap(), rid);
    assert_eq!(r["evidence"]["canonical_version"].as_u64().unwrap(), 1);
    assert_eq!(r["evidence"]["sig"].as_str().unwrap().len(), 128);

    let dotted_list = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "receipt.list",
        &json!({
            "persona_id": persona_id,
            "kind": "grant",
            "since": "1970-01-01T00:00:00Z"
        }),
    )
    .await
    .unwrap();
    let dotted_arr = dotted_list.as_array().expect("receipt.list array");
    assert_eq!(dotted_arr.len(), 1);
    assert_eq!(dotted_arr[0]["id"].as_str().unwrap(), rid);
    assert_eq!(dotted_arr[0]["grant_id"].as_str().unwrap(), grant_id);

    let dotted_get = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "receipt.get",
        &json!({"receipt_id": rid}),
    )
    .await
    .unwrap();
    assert_eq!(dotted_get["id"].as_str().unwrap(), rid);
    assert_eq!(
        dotted_get["evidence"]["canonical_version"]
            .as_u64()
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn receipt_dot_list_returns_persisted_json_with_filters() {
    let _guard = quarantine_test_guard();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let raw_a = json!({
        "version": "2",
        "kind": "broker.mint",
        "receipt_id": "rct-v2-a",
        "persona_id": "persona-a",
        "body": { "provider": "github" }
    });
    let raw_b = json!({
        "version": "2",
        "kind": "kms.decrypt",
        "receipt_id": "rct-v2-b",
        "persona_id": "persona-b",
        "body": { "operation": "decrypt" }
    });
    store
        .conn()
        .execute(
            "INSERT INTO receipts \
             (id, grant_id, persona_id, terminal_reason, created_at, receipt_json, signer_pubkey, kind) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                "rct-v2-a",
                "grant-a",
                "persona-a",
                "success",
                "2026-06-01T00:00:00Z",
                raw_a.to_string(),
                "signer-a",
                "broker.mint",
            ],
        )
        .unwrap();
    store
        .conn()
        .execute(
            "INSERT INTO receipts \
             (id, grant_id, persona_id, terminal_reason, created_at, receipt_json, signer_pubkey, kind) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                "rct-v2-b",
                "grant-b",
                "persona-b",
                "success",
                "2026-06-02T00:00:00Z",
                raw_b.to_string(),
                "signer-b",
                "kms.decrypt",
            ],
        )
        .unwrap();

    let filtered = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "receipt.list",
        &json!({
            "persona": "persona-a",
            "kind": "broker.mint",
            "since": "2026-01-01T00:00:00Z",
            "before": "2026-12-31T00:00:00Z"
        }),
    )
    .await
    .unwrap();
    let rows = filtered.as_array().expect("receipt.list rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], raw_a);

    let fetched = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "receipt.get",
        &json!({"id": "rct-v2-a"}),
    )
    .await
    .unwrap();
    assert_eq!(fetched, raw_a);
}

#[tokio::test]
async fn get_receipt_unknown_id_returns_32004() {
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
        "get_receipt",
        &json!({"id": "rct-nonexistent"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32004);
}

#[tokio::test]
async fn get_receipt_accepts_terminal_grant_id() {
    let _quarantine_guard = quarantine_test_guard();
    let _identity_guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "rcpt-beta"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap().to_string();
    let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "rcpt-cred", "scope": "push", "force": true}),
        )
        .await
        .unwrap();
    let grant_id = grant["id"].as_str().unwrap().to_string();
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "revoke_grant",
        &json!({"id": grant_id}),
    )
    .await
    .unwrap();

    let receipt = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "get_receipt",
        &json!({"id": grant_id}),
    )
    .await
    .unwrap();
    assert_eq!(receipt["grant_id"].as_str().unwrap(), grant_id);
    assert_eq!(
        receipt["evidence"]["canonical_version"].as_u64().unwrap(),
        1
    );
}

#[tokio::test]
async fn get_receipt_active_grant_without_terminal_receipt_returns_32004() {
    let _guard = quarantine_test_guard();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "rcpt-gamma"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap().to_string();
    let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "rcpt-cred", "scope": "push", "force": true}),
        )
        .await
        .unwrap();
    let grant_id = grant["id"].as_str().unwrap().to_string();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "get_receipt",
        &json!({"id": grant_id}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32004);
    assert!(
        err.1.contains("has not reached terminal state"),
        "error must explain active grants have no terminal receipt yet: {}",
        err.1
    );
}

#[tokio::test]
async fn team0_get_receipt_scopes_direct_and_terminal_lookup_to_trusted_principal() {
    let _quarantine_guard = quarantine_test_guard();
    let _identity_guard = setup_receipt_identity();
    let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let owner = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "team0-rct-owner"}),
    )
    .await
    .unwrap();
    let owner_id = owner["id"].as_str().unwrap().to_string();
    let other = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "team0-rct-other"}),
    )
    .await
    .unwrap();
    let other_id = other["id"].as_str().unwrap().to_string();

    let owner_grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": owner_id, "credential_name": "rcpt-cred", "scope": "push", "force": true}),
        )
        .await
        .unwrap();
    let owner_grant_id = owner_grant["id"].as_str().unwrap().to_string();
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "revoke_grant",
        &json!({"id": owner_grant_id}),
    )
    .await
    .unwrap();

    let other_grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": other_id, "credential_name": "rcpt-cred", "scope": "push", "force": true}),
        )
        .await
        .unwrap();
    let other_grant_id = other_grant["id"].as_str().unwrap().to_string();
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "revoke_grant",
        &json!({"id": other_grant_id}),
    )
    .await
    .unwrap();

    let owner_receipt_id = store
        .get_grant(&owner_grant_id)
        .unwrap()
        .receipt_id
        .expect("owner terminal receipt");
    let other_receipt_id = store
        .get_grant(&other_grant_id)
        .unwrap()
        .receipt_id
        .expect("other terminal receipt");

    let ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 1000,
            pid: Some(91_008),
        }),
        owner["id"].as_str().unwrap().to_string(),
    );

    let owner_receipt = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx.clone(),
        "get_receipt",
        &json!({"id": owner_receipt_id}),
    )
    .await
    .unwrap();
    assert_eq!(owner_receipt["grant_id"], json!(owner_grant_id));

    let direct_err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx.clone(),
        "get_receipt",
        &json!({"id": other_receipt_id}),
    )
    .await
    .unwrap_err();
    assert_eq!(direct_err.0, -32004);

    let terminal_err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "get_receipt",
        &json!({"id": other_grant_id}),
    )
    .await
    .unwrap_err();
    assert_eq!(terminal_err.0, -32004);
}

#[tokio::test]
async fn list_receipts_persona_filter_narrows_results() {
    let _quarantine_guard = quarantine_test_guard();
    let _identity_guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let a = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "lra"}),
    )
    .await
    .unwrap();
    let b = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "lrb"}),
    )
    .await
    .unwrap();
    let aid = a["id"].as_str().unwrap().to_string();
    let bid = b["id"].as_str().unwrap().to_string();
    for pid in [&aid, &bid] {
        let g = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": pid, "credential_name": "c", "scope": "r", "force": true}),
        )
        .await
        .unwrap();
        let gid = g["id"].as_str().unwrap().to_string();
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "revoke_grant",
            &json!({"id": gid}),
        )
        .await
        .unwrap();
    }
    let all = dispatch_method(&store, &vault, &policy, &rl, "list_receipts", &json!({}))
        .await
        .unwrap();
    let just_a = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "list_receipts",
        &json!({"persona_id": aid}),
    )
    .await
    .unwrap();
    assert_eq!(all.as_array().unwrap().len(), 2);
    assert_eq!(just_a.as_array().unwrap().len(), 1);
    assert_eq!(just_a[0]["summary"]["persona_id"].as_str().unwrap(), aid);
}

/// EMBER-AUDIT-CLI integration test: emit synthetic kms_wrap receipts
/// for two actors, then verify `receipt_query` filters by actor and kind.
#[tokio::test]
async fn receipt_query_filters_by_actor_and_kind() {
    use crate::infra::receipt::ReceiptFilter;
    use core_grant_types::grant_receipt::{
        Evidence, GrantEvaluation, GrantEvaluationOutcome, KmsReceipt, ReceiptKind, ReceiptOutcome,
    };

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // Create two personas.
    let actor_a = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "audit-actor-a"}),
    )
    .await
    .unwrap();
    let actor_a_id = actor_a["id"].as_str().unwrap().to_string();

    let actor_b = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "audit-actor-b"}),
    )
    .await
    .unwrap();
    let actor_b_id = actor_b["id"].as_str().unwrap().to_string();

    let eval_denied = GrantEvaluation {
        outcome: GrantEvaluationOutcome::Denied,
        grant_id: None,
    };

    // Insert a synthetic kms_wrap receipt for actor_a.
    let kms_a = KmsReceipt {
        id: "kms-wrap-audit-a".to_string(),
        kind: ReceiptKind::KmsWrap,
        key_name: "test-key".to_string(),
        caller_persona: actor_a_id.clone(),
        request_size_bytes: 32,
        materialized_at_epoch_secs: 0,
        grant_evaluation: eval_denied.clone(),
        outcome: ReceiptOutcome::Success,
        peer_identity: None,
        evidence: Evidence::default(),
    };
    store.store_kms_receipt(&kms_a).unwrap();

    // Insert a synthetic kms_wrap receipt for actor_b.
    let kms_b = KmsReceipt {
        id: "kms-wrap-audit-b".to_string(),
        kind: ReceiptKind::KmsWrap,
        key_name: "test-key".to_string(),
        caller_persona: actor_b_id.clone(),
        request_size_bytes: 32,
        materialized_at_epoch_secs: 0,
        grant_evaluation: eval_denied,
        outcome: ReceiptOutcome::Success,
        peer_identity: None,
        evidence: Evidence::default(),
    };
    store.store_kms_receipt(&kms_b).unwrap();

    // receipt_query with no filter returns both.
    let all = dispatch_method(&store, &vault, &policy, &rl, "receipt_query", &json!({}))
        .await
        .unwrap();
    assert_eq!(all.as_array().unwrap().len(), 2, "no filter → both rows");

    // receipt_query filtered to actor_a returns exactly one row.
    let actor_a_rows = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "receipt_query",
        &json!({"actor": actor_a_id}),
    )
    .await
    .unwrap();
    let arr = actor_a_rows.as_array().unwrap();
    assert_eq!(arr.len(), 1, "actor filter → one row for actor_a");
    assert_eq!(arr[0]["actor"].as_str().unwrap(), actor_a_id.as_str());

    // receipt_query filtered to kind=kms_wrap returns both (no actor filter).
    let kms_rows = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "receipt_query",
        &json!({"kind": "kms_wrap"}),
    )
    .await
    .unwrap();
    assert_eq!(
        kms_rows.as_array().unwrap().len(),
        2,
        "kind=kms_wrap → both rows"
    );

    // Validate via store directly (acceptance: per-actor indexes confirmed).
    let direct = store
        .query_receipts(&ReceiptFilter {
            persona_id: Some(actor_b_id.clone()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(direct.len(), 1);
    assert_eq!(direct[0].actor, actor_b_id);
    assert_eq!(direct[0].kind, "kms_wrap");
}

#[tokio::test]
async fn team0_receipt_query_defaults_to_trusted_principal() {
    use core_grant_types::grant_receipt::{
        Evidence, GrantEvaluation, GrantEvaluationOutcome, KmsReceipt, ReceiptKind, ReceiptOutcome,
    };

    let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let actor_a_id = "persona-team0-actor-a".to_string();
    let actor_b_id = "persona-team0-actor-b".to_string();
    let eval_denied = GrantEvaluation {
        outcome: GrantEvaluationOutcome::Denied,
        grant_id: None,
    };

    for actor in [&actor_a_id, &actor_b_id] {
        let receipt = KmsReceipt {
            id: format!("rct-{actor}"),
            kind: ReceiptKind::KmsWrap,
            key_name: "test-key".to_string(),
            caller_persona: actor.to_string(),
            request_size_bytes: 32,
            materialized_at_epoch_secs: 0,
            grant_evaluation: eval_denied.clone(),
            outcome: ReceiptOutcome::Success,
            peer_identity: None,
            evidence: Evidence::default(),
        };
        store.store_kms_receipt(&receipt).unwrap();
    }

    let ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 1000,
            pid: Some(91_005),
        }),
        actor_a_id.clone(),
    );
    let rows = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx.clone(),
        "receipt_query",
        &json!({}),
    )
    .await
    .unwrap();
    let arr = rows.as_array().expect("receipt_query rows");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["actor"], json!(actor_a_id));

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "receipt_query",
        &json!({"actor": actor_b_id}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32004);
}

#[tokio::test]
async fn team0_audit_query_defaults_to_trusted_principal() {
    let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let actor_a = "persona-team0-audit-a".to_string();
    let actor_b = "persona-team0-audit-b".to_string();
    store
        .log_event(
            Some(&actor_a),
            "credential.access",
            Some("team0-audit-a"),
            "allowed",
            None,
        )
        .unwrap();
    store
        .log_event(
            Some(&actor_b),
            "credential.access",
            Some("team0-audit-b"),
            "allowed",
            None,
        )
        .unwrap();

    let ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 1000,
            pid: Some(91_010),
        }),
        actor_a.clone(),
    );
    let rows = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx.clone(),
        "audit_query",
        &json!({}),
    )
    .await
    .unwrap();
    let arr = rows.as_array().expect("audit_query rows");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["agent_id"], json!(actor_a));

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "audit_query",
        &json!({"agent_id": actor_b}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32004);
}
