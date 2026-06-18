use super::*;

// -----------------------------------------------------------------
// `grant_status` + `list_grants` persona filter + `use_credential`
// by grant_id - added for TODO 69I.1 so the agent runtime has a
// daemon-side surface that matches its protocol shape.
// -----------------------------------------------------------------

#[tokio::test]
async fn grant_status_finds_live_grant_by_id() {
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
        &json!({"name": "gs-a"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();
    let grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({"persona_id": persona_id, "credential_name": "key", "scope": "r", "force": true}),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "grant_status",
        &json!({"id": grant_id, "persona_id": persona_id}),
    )
    .await
    .unwrap();
    assert_eq!(result["kind"], "grant");
    assert_eq!(result["id"], json!(grant_id));
    assert_eq!(result["persona_id"], json!(persona_id));
    assert_eq!(result["scope"], "r");
    assert_eq!(
        result["live_lease"],
        json!(true),
        "grant_status must expose ADR 211 lease liveness, not just durable row status"
    );
}

#[tokio::test]
async fn grant_status_surfaces_reserved_cents_for_payment_statements() {
    use core_grant_types::{Condition, ResourceSelector, ResourceType, StatementProposal};

    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(std::rc::Rc::new(test_vault()));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "gs-payment"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap().to_string();

    let created = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_composite_grant",
        &json!({
            "persona_id": persona_id.clone(),
            "credential_name": "payment/clearbit",
            "scope": "payment:charge",
            "ttl_secs": 3600,
            "statements": [
                StatementProposal {
                    resource_type: ResourceType::Payment,
                    credential_name: "payment/clearbit".to_string(),
                    actions: vec!["payment:charge".to_string()],
                    resource: ResourceSelector::Any,
                    budget: Some(core_grant_types::Budget {
                        cents: Some(25_000),
                        ..Default::default()
                    }),
                    conditions: vec![
                        Condition::MerchantAllowlist {
                            merchants: vec!["clearbit".to_string()],
                        },
                        Condition::Range {
                            field: "amount_cents".to_string(),
                            min: Some(0),
                            max: Some(4_900),
                        },
                    ],
                }
            ],
        }),
    )
    .await
    .unwrap();
    let grant_id = created["id"].as_str().unwrap();

    // ADR191_PAYMENT_BUILD_AHEAD: drive the reservation through the preserved
    // payment lane directly (the COHORT-A-2 `evaluate_tool_call` RPC that used
    // to enter it was retired). `grant_status` must still surface the resulting
    // `reserved_cents` projection.
    let decision = store
        .reserve_payment_tool_call(
            &persona_id,
            "payment:charge",
            &json!({
                "attempt_id": "attempt-reserved-1",
                "vendor": "clearbit",
                "amount_cents": 4_900
            }),
            None,
            Some(grant_id),
        )
        .unwrap();
    assert!(decision.permit);

    let status = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "grant_status",
        &json!({"id": grant_id, "persona_id": persona_id.clone()}),
    )
    .await
    .unwrap();
    let statements = status["statements"]
        .as_array()
        .expect("grant_status statements array");
    assert_eq!(statements.len(), 1);
    assert_eq!(statements[0]["resource_type"], json!("payment"));
    assert_eq!(statements[0]["reserved_cents"], json!(4_900));
}

#[tokio::test]
async fn grant_status_rejects_mismatched_persona() {
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
        &json!({"name": "gs-owner"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();
    let grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({"persona_id": persona_id, "credential_name": "key", "scope": "r", "force": true}),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();

    // A caller pinning a different persona must be rejected - this is
    // the cross-persona probe defense.
    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "grant_status",
        &json!({"id": grant_id, "persona_id": "persona-other"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32002);
}

#[tokio::test]
async fn grant_status_finds_pending_approval_by_id() {
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
        &json!({"name": "appr-owner"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();
    let req = store
        .submit_approval(
            persona_id,
            "cred",
            "read",
            None,
            "credential.access.cred",
            "medium",
        )
        .unwrap();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "grant_status",
        &json!({"id": req.id}),
    )
    .await
    .unwrap();
    assert_eq!(result["kind"], "approval");
    assert_eq!(result["id"], json!(req.id));
    assert_eq!(result["status"], "pending");
}

#[tokio::test]
async fn grant_status_unknown_id_returns_not_found() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "grant_status",
        &json!({"id": "nonexistent"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32004);
}

#[tokio::test]
async fn team0_grant_status_defaults_to_trusted_principal_for_grants() {
    let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let owner = store.create_persona("team0-grant-owner").unwrap();
    let other = store.create_persona("team0-grant-other").unwrap();
    let owner_grant = store
        .create_grant(&owner.id, "cred-a", "read", None)
        .unwrap();
    let other_grant = store
        .create_grant(&other.id, "cred-b", "read", None)
        .unwrap();

    let ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 1000,
            pid: Some(91_006),
        }),
        owner.id.clone(),
    );

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx.clone(),
        "grant_status",
        &json!({"id": owner_grant.id}),
    )
    .await
    .unwrap();
    assert_eq!(result["kind"], "grant");
    assert_eq!(result["persona_id"], json!(owner.id));

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "grant_status",
        &json!({"id": other_grant.id}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32004);
}

#[tokio::test]
async fn team0_grant_status_refuses_other_principal_approval() {
    let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let owner = store.create_persona("team0-approval-owner").unwrap();
    let other = store.create_persona("team0-approval-other").unwrap();
    let approval = store
        .submit_approval(
            &other.id,
            "cred",
            "read",
            None,
            "credential.access.cred",
            "medium",
        )
        .unwrap();

    let ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 1000,
            pid: Some(91_007),
        }),
        owner.id,
    );

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "grant_status",
        &json!({"id": approval.id}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32004);
}

#[tokio::test]
async fn list_grants_filters_by_persona_id() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let p1 = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "p1"}),
    )
    .await
    .unwrap();
    let p2 = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "p2"}),
    )
    .await
    .unwrap();
    let p1_id = p1["id"].as_str().unwrap();
    let p2_id = p2["id"].as_str().unwrap();
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({"persona_id": p1_id, "credential_name": "k1", "scope": "r", "force": true}),
    )
    .await
    .unwrap();
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({"persona_id": p2_id, "credential_name": "k2", "scope": "r", "force": true}),
    )
    .await
    .unwrap();

    // Bare call without persona_id is now refused - cross-persona
    // enumeration via the unauthenticated socket is an info disclosure.
    let err = dispatch_method(&store, &vault, &policy, &rl, "list_grants", &json!({}))
        .await
        .unwrap_err();
    assert_eq!(err.0, -32602);

    let only_p1 = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "list_grants",
        &json!({"persona_id": p1_id}),
    )
    .await
    .unwrap();
    let arr = only_p1.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["persona_id"], json!(p1_id));
    assert_eq!(arr[0]["credential_name"], "k1");
}

#[tokio::test]
async fn list_grants_without_persona_id_returns_32602() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(&store, &vault, &policy, &rl, "list_grants", &json!(null))
        .await
        .unwrap_err();
    assert_eq!(err.0, -32602);
    assert!(
        err.1.contains("persona_id"),
        "error should mention persona_id, got: {}",
        err.1
    );
}

#[tokio::test]
async fn list_grants_without_persona_id_in_empty_object_returns_32602() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(&store, &vault, &policy, &rl, "list_grants", &json!({}))
        .await
        .unwrap_err();
    assert_eq!(err.0, -32602);
}

#[tokio::test]
async fn list_grants_with_persona_id_returns_only_that_personas_grants() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let persona_a = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "list-grants-persona-a"}),
    )
    .await
    .unwrap();
    let persona_a_id = persona_a["id"].as_str().unwrap();

    let persona_b = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "list-grants-persona-b"}),
    )
    .await
    .unwrap();
    let persona_b_id = persona_b["id"].as_str().unwrap();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_a_id,
            "credential_name": "cred-a",
            "scope": "read",
            "force": true,
        }),
    )
    .await
    .unwrap();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_b_id,
            "credential_name": "cred-b",
            "scope": "read",
            "force": true,
        }),
    )
    .await
    .unwrap();

    let list_a = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "list_grants",
        &json!({"persona_id": persona_a_id}),
    )
    .await
    .unwrap();
    let arr_a = list_a.as_array().unwrap();
    assert_eq!(arr_a.len(), 1, "persona_a should see exactly 1 grant");
    assert_eq!(arr_a[0]["persona_id"], json!(persona_a_id));
    assert_eq!(arr_a[0]["credential_name"], json!("cred-a"));

    let list_b = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "list_grants",
        &json!({"persona_id": persona_b_id}),
    )
    .await
    .unwrap();
    let arr_b = list_b.as_array().unwrap();
    assert_eq!(arr_b.len(), 1, "persona_b should see exactly 1 grant");
    assert_eq!(arr_b[0]["persona_id"], json!(persona_b_id));
    assert_eq!(arr_b[0]["credential_name"], json!("cred-b"));
}

#[tokio::test]
async fn team0_list_grants_defaults_to_trusted_principal_and_refuses_mismatch() {
    let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let persona_a = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "team0-grant-a"}),
    )
    .await
    .unwrap();
    let persona_a_id = persona_a["id"].as_str().unwrap().to_string();

    let persona_b = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "team0-grant-b"}),
    )
    .await
    .unwrap();
    let persona_b_id = persona_b["id"].as_str().unwrap().to_string();

    for (persona_id, credential_name) in [(&persona_a_id, "cred-a"), (&persona_b_id, "cred-b")] {
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": credential_name,
                "scope": "read",
                "force": true,
            }),
        )
        .await
        .unwrap();
    }

    let ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 1000,
            pid: Some(91_003),
        }),
        persona_a_id.clone(),
    );
    let list = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx.clone(),
        "list_grants",
        &json!({}),
    )
    .await
    .unwrap();
    let arr = list.as_array().expect("grant list array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["persona_id"], json!(persona_a_id));

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "list_grants",
        &json!({"persona_id": persona_b_id}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32004);
    assert!(
        err.1.contains("trusted principal"),
        "mismatch should mention trusted principal: {}",
        err.1
    );
}

#[tokio::test]
async fn list_operator_grants_returns_cross_persona_view_and_active_filter() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // list_operator_grants is OperatorPresence-class. The
    // dispatch_method_with_source shim synthesizes a peer +
    // presence_token under #[cfg(test)], but the unlocked-session
    // gate still applies - move presence to Unlocked so the test
    // reaches the cross-persona projection it asserts on.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let p1 = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "operator-p1"}),
    )
    .await
    .unwrap();
    let p2 = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "operator-p2"}),
    )
    .await
    .unwrap();
    let p1_id = p1["id"].as_str().unwrap();
    let p2_id = p2["id"].as_str().unwrap();

    let g1 = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({"persona_id": p1_id, "credential_name": "k1", "scope": "r", "force": true}),
    )
    .await
    .unwrap();
    let g2 = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({"persona_id": p2_id, "credential_name": "k2", "scope": "r", "force": true}),
    )
    .await
    .unwrap();
    let g2_id = g2["id"].as_str().unwrap();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "revoke_grant",
        &json!({"id": g2_id}),
    )
    .await
    .unwrap();

    let active_only = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Socket,
        "list_operator_grants",
        &json!({"active_only": true}),
    )
    .await
    .unwrap();
    let active_arr = active_only.as_array().unwrap();
    assert_eq!(active_arr.len(), 1);
    assert_eq!(active_arr[0]["id"], g1["id"]);
    assert_eq!(active_arr[0]["persona_id"], json!(p1_id));

    let all = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Socket,
        "list_operator_grants",
        &json!({"active_only": false}),
    )
    .await
    .unwrap();
    let all_arr = all.as_array().unwrap();
    assert_eq!(all_arr.len(), 2);
    assert!(
        all_arr
            .iter()
            .any(|g| g["id"] == g1["id"] && g["status"] == json!("active"))
    );
    assert!(
        all_arr
            .iter()
            .any(|g| g["id"] == g2["id"] && g["status"] == json!("revoked"))
    );
}

#[tokio::test]
async fn detect_anomalies_returns_empty_on_fresh_store() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let result = dispatch_method(&store, &vault, &policy, &rl, "detect_anomalies", &json!({}))
        .await
        .unwrap();
    assert!(result.is_array());
    assert_eq!(result.as_array().unwrap().len(), 0);
}

// FLAKE (2026-05-27, observed under host-mode session-enrollment work,
// pre-existing on origin/main): fails non-deterministically under full
// `cargo test -p ember-daemon --lib` ordering with `-32030 vs -32001`
// assertion. Passes in isolation. Cause: cross-test contamination of
// global operator-presence state by sibling tests that take
// `PROCESS_TEST_LOCK` but mutate `crate::trust::presence`'s globals
// without restoring them. Follow-up: harden `mark_unlocked` /
// `test_state_guard` so the guard restores all touched state on drop.
#[tokio::test]
async fn team0_detect_anomalies_requires_operator_presence_token() {
    // ADR 206 slice 4 C: a presence token (or an open §4 window) authorizes;
    // with NO token AND a LOCKED §4 window the OperatorPresence method fails
    // closed.
    let _presence_test_guard = crate::trust::presence::test_state_guard();

    let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    for _ in 0..4 {
        store
            .log_event(Some("agent-x"), "credential.access", None, "denied", None)
            .unwrap();
    }

    // No token + LOCKED §4 window → fail closed.
    crate::trust::presence::lock();
    let no_token_ctx = RequestContext {
        source: DispatchSource::Socket,
        peer: Some(PeerCred {
            uid: 501,
            pid: Some(1234),
        }),
        principal: None,
        sessions_dir: None,
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: None,
        presence_token: None,
        bypass_binary_pin_gate_for_test: false,
    };
    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        no_token_ctx,
        "detect_anomalies",
        &json!({}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32001);

    // Token + open §4 window → authorized.
    crate::trust::presence::mark_unlocked();
    let with_token_ctx = RequestContext {
        source: DispatchSource::Socket,
        peer: Some(PeerCred {
            uid: 501,
            pid: Some(1234),
        }),
        principal: None,
        sessions_dir: None,
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: None,
        presence_token: Some(test_presence_token(501)),
        bypass_binary_pin_gate_for_test: false,
    };
    let rows = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        with_token_ctx,
        "detect_anomalies",
        &json!({}),
    )
    .await
    .unwrap();
    assert!(!rows.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn detect_anomalies_finds_high_denial_rate() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    // Log enough denied events to trigger anomaly
    for _ in 0..4 {
        store
            .log_event(Some("agent-x"), "credential.access", None, "denied", None)
            .unwrap();
    }
    let result = dispatch_method(&store, &vault, &policy, &rl, "detect_anomalies", &json!({}))
        .await
        .unwrap();
    let arr = result.as_array().unwrap();
    assert!(!arr.is_empty());
}

// FLAKE (2026-05-27, see team0_detect_anomalies_requires_operator_presence_token):
// same cross-test contamination of global operator-presence state. Both
// tests share the same fragility — fixing one will likely fix both.
#[tokio::test]
async fn team0_grant_summary_requires_operator_presence_token() {
    // ADR 206 slice 4 C: the §4 unlock window replaces the deleted native
    // auto-unlock. A presence token (or an open §4 window) authorizes; with
    // NO token AND a LOCKED window the OperatorPresence method fails closed.
    let _presence_test_guard = crate::trust::presence::test_state_guard();

    let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // No token + LOCKED §4 window → fail closed.
    crate::trust::presence::lock();
    let no_token_ctx = RequestContext {
        source: DispatchSource::Socket,
        peer: Some(PeerCred {
            uid: 501,
            pid: Some(1234),
        }),
        principal: None,
        sessions_dir: None,
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: None,
        presence_token: None,
        bypass_binary_pin_gate_for_test: false,
    };
    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        no_token_ctx,
        "grant_summary",
        &json!({}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32001);

    // Token + open §4 window → authorized.
    crate::trust::presence::mark_unlocked();
    let with_token_ctx = RequestContext {
        source: DispatchSource::Socket,
        peer: Some(PeerCred {
            uid: 501,
            pid: Some(1234),
        }),
        principal: None,
        sessions_dir: None,
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: None,
        presence_token: Some(test_presence_token(501)),
        bypass_binary_pin_gate_for_test: false,
    };
    let summary = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        with_token_ctx,
        "grant_summary",
        &json!({}),
    )
    .await
    .unwrap();
    assert!(summary.get("active").is_some());
    assert!(summary.get("expired").is_some());
    assert!(summary.get("revoked").is_some());
}

// --- grant_budget_status (P69K-F1) -------------------------------------

/// Helper: seed a 3-statement grant via the low-level composite-grant
/// API so we can assert the MCP budget-status projection without
/// relying on the proxy to mutate usage.
fn seed_budget_grant(store: &DaemonStore, persona_id: &str, credential_name: &str) -> String {
    use core_grant_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};
    let grant = store
        .create_grant(persona_id, credential_name, "*", None)
        .unwrap();
    let root = store.persona_root_keypair(persona_id).unwrap();
    let statements = vec![
        Statement {
            sid: "S1".into(),
            resource_type: ResourceType::Session,
            actions: vec!["generic:write".into()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                tokens: Some(20_000),
                cents: Some(100),
                ..Default::default()
            }),
            usage: Usage::default(),
            conditions: Vec::new(),
            can_delegate: None,
        },
        Statement {
            sid: "S2".into(),
            resource_type: ResourceType::Payment,
            actions: vec!["payment:charge".into()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                cents: Some(500),
                ..Default::default()
            }),
            usage: Usage::default(),
            conditions: Vec::new(),
            can_delegate: None,
        },
        Statement {
            sid: "S3".into(),
            resource_type: ResourceType::Time,
            actions: vec!["session:start".into()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                wall_clock_secs: Some(3_600),
                ..Default::default()
            }),
            usage: Usage::default(),
            conditions: Vec::new(),
            can_delegate: None,
        },
    ];
    let ag = crate::trust::grant::access_grant_from_statements(
        &grant.id,
        persona_id,
        credential_name,
        statements,
        0,
        None,
        &root,
    )
    .unwrap();
    store.overwrite_grant_blocks(&grant.id, &ag).unwrap();
    grant.id
}

#[tokio::test]
async fn grant_budget_status_returns_per_statement_shape() {
    // A 3-statement composite grant surfaces three entries in the
    // response, each carrying sid + resource_type + budget + usage +
    // percent_used. With a stubbed 50% usage on S1, percent_used
    // reflects it - the MCP client can render a runway view without
    // walking the block chain itself.
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let persona = store.create_persona("budget-status").unwrap();
    let grant_id = seed_budget_grant(&store, &persona.id, "cred-a");

    // Drive S1 to 10_000 tokens (50%) and 50 cents (50%).
    let delta = store
        .increment_statement_usage(
            &grant_id,
            "S1",
            core_grant_types::Usage {
                tokens: 10_000,
                cents: 50,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(delta.current.tokens, 10_000);

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "grant_budget_status",
        &json!({"grant_id": grant_id}),
    )
    .await
    .unwrap();

    assert_eq!(result["grant_id"].as_str().unwrap(), grant_id);
    assert_eq!(result["status"].as_str().unwrap(), "active");
    let statements = result["statements"].as_array().unwrap();
    assert_eq!(statements.len(), 3, "three-statement grant");

    let s1 = &statements[0];
    assert_eq!(s1["sid"], "S1");
    assert_eq!(s1["resource_type"], "session");
    assert_eq!(s1["usage"]["tokens"], 10_000);
    assert_eq!(s1["percent_used"]["tokens"], 50);
    assert_eq!(s1["percent_used"]["cents"], 50);
    // runway is reserved for a future burn-rate projection.
    assert!(s1["estimated_runway_seconds"].is_null());
    assert_eq!(s1["has_budget_remaining"], true);

    // S2 has no usage, should be 0% on its set axis.
    let s2 = &statements[1];
    assert_eq!(s2["sid"], "S2");
    assert_eq!(s2["percent_used"]["cents"], 0);
}

#[tokio::test]
async fn grant_budget_status_unknown_grant_returns_not_found() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "grant_budget_status",
        &json!({"grant_id": "grant-nonexistent"}),
    )
    .await
    .unwrap_err();
    // Consistent with `get_receipt` / `grant_status` not-found shape:
    // -32004 is the daemon's NotFound code for MCP.
    assert_eq!(err.0, -32004);
    assert!(err.1.contains("grant-nonexistent"));
}

#[tokio::test]
async fn grant_budget_status_missing_grant_id_returns_invalid_params() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "grant_budget_status",
        &json!({}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32602);
    assert!(err.1.contains("grant_id"));
}

#[tokio::test]
async fn grant_budget_status_reflects_revoked_status() {
    // When the grant envelope is revoked, the budget-status projection
    // surfaces the terminal state to the caller instead of lying that
    // it's still active.
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let persona = store.create_persona("revoked-status").unwrap();
    let grant_id = seed_budget_grant(&store, &persona.id, "cred-r");
    store.revoke_grant(&grant_id).unwrap();
    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "grant_budget_status",
        &json!({"grant_id": grant_id}),
    )
    .await
    .unwrap();
    assert_eq!(result["status"].as_str().unwrap(), "revoked");
}

#[tokio::test]
async fn team0_grant_budget_status_scopes_to_trusted_principal() {
    let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let owner = store.create_persona("team0-budget-owner").unwrap();
    let other = store.create_persona("team0-budget-other").unwrap();
    let owner_grant_id = seed_budget_grant(&store, &owner.id, "cred-a");
    let other_grant_id = seed_budget_grant(&store, &other.id, "cred-b");

    let ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 1000,
            pid: Some(91_009),
        }),
        owner.id.clone(),
    );

    let owner_status = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx.clone(),
        "grant_budget_status",
        &json!({"grant_id": owner_grant_id}),
    )
    .await
    .unwrap();
    assert_eq!(owner_status["status"], "active");

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "grant_budget_status",
        &json!({"grant_id": other_grant_id}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32004);
}
