use super::*;

#[tokio::test]
async fn sandbox_list_dispatches_for_operator_socket() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    store.create_sandbox("alpha", "ubuntu:24.04").unwrap();

    // sandbox_list is OperatorPresence-class. Satisfy the
    // presence-token + unlocked-session gates so the happy-path
    // projection under test is reachable. Previously this test
    // was an intermittent pass because sibling tests' unrelated
    // mark_unlocked left presence Unlocked through this test's
    // window; with cross-module serialization the prior accidental
    // pass no longer occurs and the test needs explicit setup.
    ensure_test_authority_bridge_env();
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let ctx = RequestContext::socket(Some(PeerCred {
        uid: 1000,
        pid: Some(80_101),
    }))
    .with_presence_token(Some(test_presence_token(1000)));
    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "sandbox_list",
        &serde_json::Value::Null,
    )
    .await
    .unwrap();

    let sandboxes = result
        .as_array()
        .expect("sandbox_list must return an array");
    assert_eq!(sandboxes.len(), 1);
    assert_eq!(sandboxes[0]["name"], json!("alpha"));
    assert_eq!(sandboxes[0]["image"], json!("ubuntu:24.04"));
}

#[tokio::test]
async fn sandbox_exec_requires_caller_persona_when_socket_pid_is_unenrolled() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let sandbox = store
        .create_sandbox_with_opts(
            &crate::infra::sandbox::SandboxCreateOpts {
                name: "alpha".to_string(),
                image: "ubuntu:24.04".to_string(),
                owner_persona_id: Some("persona-owner".to_string()),
                ..Default::default()
            },
            None,
        )
        .unwrap();

    ensure_test_authority_bridge_env();
    // sandbox_exec is OperatorPresence-class. Satisfy the
    // presence-token + unlocked-session gates so the test reaches
    // the caller_persona_id-required assertion under test.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let ctx = RequestContext::socket(Some(PeerCred {
        uid: 1000,
        pid: Some(80_102),
    }))
    .with_presence_token(Some(test_presence_token(1000)));
    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "sandbox_exec",
        &json!({
            "id_or_name": sandbox.id,
            "command": ["echo", "hello"],
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32602);
    assert!(
        err.1.contains("caller_persona_id"),
        "missing explicit fallback should mention caller_persona_id, got: {}",
        err.1
    );
}

#[tokio::test]
async fn sandbox_run_dispatches_without_composite_grant() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    std::fs::create_dir_all(&sessions_dir).unwrap();

    // ADR 216 S4 — sandbox dispatch requires bridge CA in store.
    let ca =
        crate::infra::runtime::load_or_mint_bridge_ca(root.path(), &vault).expect("test bridge CA");
    store.set_bridge_ca(ca);

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "sandbox_run",
        &json!({
            "sandbox": {
                "name": "run-test",
                "image": "ubuntu:24.04",
                "privileged": false,
                "volumes": [],
                "user": null,
                "network": null,
                "unsafe_root": false,
                "workspace_from": null,
                "extra_env": [],
                "owner_persona_id": "persona-owner"
            },
            "statements": [],
            "ttl_secs": null,
            "credential_resource": null,
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["sandbox"]["name"], json!("run-test"));
    assert_eq!(result["sandbox"]["image"], json!("ubuntu:24.04"));
    assert_eq!(result["grant"], json!("NotRequested"));
}
