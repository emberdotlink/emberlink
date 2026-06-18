use super::*;

#[tokio::test]
async fn headless_status_reports_active_enrollment_metadata() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    let data_dir = root.path().join("data");
    std::fs::create_dir_all(&sessions_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let device = crate::infra::attested_device::AttestedDevice {
        enrollment_id: "enroll-test-1".to_string(),
        persona: "main".to_string(),
        account: "main".to_string(),
        enrolled_at: std::time::SystemTime::now(),
        expiry: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        template_snapshot_hash: "snapshot-test-1".to_string(),
        delegated_authority_refs: vec!["github".to_string()],
        delegated_material: core_events::receipt::HeadlessDelegatedMaterial::default(),
        attested_device_ref: format!(
            "keychain:{}:main",
            crate::infra::attested_device::KEYCHAIN_SERVICE
        ),
    };
    device.store_active(&data_dir).unwrap();

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "headless_status",
        &json!({}),
    )
    .await
    .unwrap();

    assert_eq!(
        result["active_enrollment"]["enrollment_id"],
        json!("enroll-test-1")
    );
    assert_eq!(result["active_enrollment"]["persona"], json!("main"));
    assert!(
        result["active_enrollment"]["duration_remaining_seconds"]
            .as_u64()
            .unwrap_or_default()
            > 0,
        "status should surface a positive remaining duration"
    );
}

#[tokio::test]
async fn team0_headless_status_requires_operator_presence_token() {
    // ADR 206 slice 4 C: a presence token (or an open §4 window) authorizes;
    // with NO token AND a LOCKED §4 window the OperatorPresence method fails
    // closed.
    let _presence_test_guard = crate::trust::presence::test_state_guard();

    let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    let data_dir = root.path().join("data");
    std::fs::create_dir_all(&sessions_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let device = crate::infra::attested_device::AttestedDevice {
        enrollment_id: "enroll-team0-1".to_string(),
        persona: "main".to_string(),
        account: "main".to_string(),
        enrolled_at: std::time::SystemTime::now(),
        expiry: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        template_snapshot_hash: "snapshot-team0-1".to_string(),
        delegated_authority_refs: vec!["github".to_string()],
        delegated_material: core_events::receipt::HeadlessDelegatedMaterial::default(),
        attested_device_ref: format!(
            "keychain:{}:main",
            crate::infra::attested_device::KEYCHAIN_SERVICE
        ),
    };
    device.store_active(&data_dir).unwrap();

    // No token + LOCKED §4 window → fail closed.
    crate::trust::presence::lock();
    let mut no_token_ctx = RequestContext::socket(Some(PeerCred {
        uid: 501,
        pid: Some(1234),
    }));
    no_token_ctx.sessions_dir = Some(sessions_dir.clone());
    no_token_ctx.presence_token = None;
    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        no_token_ctx,
        "headless_status",
        &json!({}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32001);

    // Token + open §4 window → authorized.
    crate::trust::presence::mark_unlocked();
    let mut with_token_ctx = RequestContext::socket(Some(PeerCred {
        uid: 501,
        pid: Some(1234),
    }));
    with_token_ctx.sessions_dir = Some(sessions_dir);
    with_token_ctx.presence_token = Some(test_presence_token(501));
    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        with_token_ctx,
        "headless_status",
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(
        result["active_enrollment"]["enrollment_id"],
        json!("enroll-team0-1")
    );
}

#[tokio::test]
async fn headless_revoke_without_active_enrollment_returns_false() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    std::fs::create_dir_all(&sessions_dir).unwrap();

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "headless_revoke",
        &json!({}),
    )
    .await
    .unwrap();

    assert_eq!(result["revoked"], json!(false));
    assert_eq!(result["active_enrollment"], json!(null));
}

#[tokio::test]
async fn headless_enroll_installs_local_broker_authority_subset() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let runtime_vault = std::rc::Rc::new(Vault::new([0x61u8; 32]));
    store.set_vault(std::rc::Rc::clone(&runtime_vault));
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "aws-sts/access-key-id",
            b"AKIA-ENROLL",
            None,
        )
        .unwrap();
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "aws-sts/secret-access-key",
            b"secret-enroll",
            None,
        )
        .unwrap();
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "aws-sts/region",
            b"us-east-1",
            None,
        )
        .unwrap();
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "aws-sts/default-role-arn",
            b"arn:aws:iam::123456789012:role/demo",
            None,
        )
        .unwrap();
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "misc/not-enrolled",
            b"ignore-me",
            None,
        )
        .unwrap();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    let data_dir = root.path().join("data");
    std::fs::create_dir_all(&sessions_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "headless_enroll",
        &json!({
            "persona_id": "headless-enroll-missing-tasks",
            "duration_seconds": 3600,
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(result.0, -32602);
    assert!(
        result
            .1
            .contains("bounded headless enrollment requires a non-empty 'tasks' declaration")
    );
    assert!(
        crate::infra::attested_device::AttestedDevice::load_active(&data_dir)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn headless_enroll_narrows_to_manifest_declared_authority_refs_when_queue_is_complete() {
    use zeroize::Zeroize as _;

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let runtime_vault = std::rc::Rc::new(Vault::new([0x41u8; 32]));
    store.set_vault(std::rc::Rc::clone(&runtime_vault));
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "github/apps/ember/install-123/private-key",
            b"gh-private-key",
            None,
        )
        .unwrap();
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "github/apps/ember/install-123/app-id",
            b"123",
            None,
        )
        .unwrap();
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "github/apps/ember/install-123/installation-id",
            b"456",
            None,
        )
        .unwrap();
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "aws-sts/access-key-id",
            b"AKIA-IGNORE",
            None,
        )
        .unwrap();
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "aws-sts/secret-access-key",
            b"secret-ignore",
            None,
        )
        .unwrap();
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "aws-sts/region",
            b"us-east-1",
            None,
        )
        .unwrap();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    let data_dir = root.path().join("data");
    std::fs::create_dir_all(&sessions_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();
    crate::infra::receipt::init_identity(&data_dir).unwrap();

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "headless_enroll",
        &json!({
            "persona_id": "headless-enroll-github-narrow",
            "duration_seconds": 3600,
            "tasks": [
                {
                    "task_id": "AP-1",
                    "constructs": ["ember-gh.pr_merge"],
                }
            ],
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["enrolled"], json!(true));
    assert_eq!(result["authority_refs"], json!(["github"]));
    assert!(
        result["template_snapshot_hash"]
            .as_str()
            .unwrap_or_default()
            .len()
            == 64
    );
    assert!(
        result["delegated_material"]
            .as_object()
            .map(|value| value.is_empty())
            .unwrap_or(false)
    );
    let mut authority_keys = result["authority_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    authority_keys.sort();
    assert_eq!(
        authority_keys,
        vec![
            "github/apps/ember/install-123/app-id".to_string(),
            "github/apps/ember/install-123/installation-id".to_string(),
            "github/apps/ember/install-123/private-key".to_string(),
        ]
    );

    let device = crate::infra::attested_device::AttestedDevice::load_active(&data_dir)
        .unwrap()
        .expect("active enrollment stored");
    assert_eq!(
        result["template_snapshot_hash"],
        json!(device.template_snapshot_hash)
    );
    let mut headless_mek = device.unwrap_mek().unwrap();
    let headless_vault = Vault::new(headless_mek);
    headless_mek.zeroize();

    let mut headless_keys = crate::infra::headless_scope::list_headless_keys(&store).unwrap();
    headless_keys.sort();
    assert_eq!(headless_keys, authority_keys);
    assert_eq!(
        headless_vault
            .get(
                crate::infra::vault::VaultScope::Headless,
                &store,
                "github/apps/ember/install-123/private-key",
            )
            .unwrap()
            .as_slice(),
        b"gh-private-key"
    );
    assert!(matches!(
        headless_vault.get(
            crate::infra::vault::VaultScope::Headless,
            &store,
            "aws-sts/access-key-id",
        ),
        Err(crate::infra::vault::VaultError::NotFound)
    ));

    crate::infra::attested_device::AttestedDevice::revoke_active(
        &data_dir,
        Some(&device.enrollment_id),
    )
    .unwrap();
}

#[tokio::test]
async fn headless_enroll_reports_runtime_kms_requirement_for_pulumi_queue() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let runtime_vault = std::rc::Rc::new(Vault::new([0x51u8; 32]));
    store.set_vault(std::rc::Rc::clone(&runtime_vault));
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "github/apps/ember/install-123/private-key",
            b"gh-private-key",
            None,
        )
        .unwrap();
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "github/apps/ember/install-123/app-id",
            b"123",
            None,
        )
        .unwrap();
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "github/apps/ember/install-123/installation-id",
            b"456",
            None,
        )
        .unwrap();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    let data_dir = root.path().join("data");
    std::fs::create_dir_all(&sessions_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "headless_enroll",
        &json!({
            "persona_id": "headless-enroll-pulumi-runtime-kms",
            "duration_seconds": 3600,
            "tasks": [
                {
                    "task_id": "AP-1",
                    "constructs": ["ember-pulumi.up"],
                }
            ],
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(result.0, -32000);
    assert!(
        result
            .1
            .contains("unmet headless requirements [\"runtime_kms\"]")
    );
    assert!(
        crate::infra::attested_device::AttestedDevice::load_active(&data_dir)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn headless_enroll_reports_env_passthrough_requirement_for_kubectl_queue() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let runtime_vault = std::rc::Rc::new(Vault::new([0x71u8; 32]));
    store.set_vault(std::rc::Rc::clone(&runtime_vault));
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "aws-sts/access-key-id",
            b"AKIA-ENROLL",
            None,
        )
        .unwrap();
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "aws-sts/secret-access-key",
            b"secret-enroll",
            None,
        )
        .unwrap();
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "aws-sts/region",
            b"us-east-1",
            None,
        )
        .unwrap();
    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            &store,
            "aws-sts/default-role-arn",
            b"arn:aws:iam::123456789012:role/demo",
            None,
        )
        .unwrap();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    let data_dir = root.path().join("data");
    std::fs::create_dir_all(&sessions_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();
    let kubeconfig = root.path().join("kubeconfig");
    std::fs::write(&kubeconfig, b"apiVersion: v1\nclusters: []\n").unwrap();
    // SAFETY: test-scoped environment mutation for the delegated material snapshot path.
    unsafe {
        std::env::set_var("KUBECONFIG", &kubeconfig);
    }
    crate::infra::receipt::init_identity(&data_dir).unwrap();

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "headless_enroll",
        &json!({
            "persona_id": "headless-enroll-kubectl-file-env",
            "duration_seconds": 3600,
            "tasks": [
                {
                    "task_id": "AP-1",
                    "constructs": ["ember-kubectl.apply"],
                }
            ],
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["enrolled"], json!(true));
    assert_eq!(result["authority_refs"], json!([]));
    assert_eq!(
        result["delegated_material"]["file_env"],
        json!(["KUBECONFIG"])
    );
    assert!(
        result["template_snapshot_hash"]
            .as_str()
            .unwrap_or_default()
            .len()
            == 64
    );

    let mut authority_keys = result["authority_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    authority_keys.sort();
    assert!(authority_keys.is_empty());

    let device = crate::infra::attested_device::AttestedDevice::load_active(&data_dir)
        .unwrap()
        .expect("active enrollment stored");
    assert_eq!(
        device.delegated_material.file_env,
        vec!["KUBECONFIG".to_string()]
    );
    let mut headless_keys = crate::infra::headless_scope::list_headless_keys(&store).unwrap();
    headless_keys.sort();
    assert_eq!(
        headless_keys,
        vec![crate::infra::headless_scope::file_material_key(
            "KUBECONFIG"
        )]
    );
    assert_eq!(
        result["template_snapshot_hash"],
        json!(device.template_snapshot_hash)
    );

    crate::infra::attested_device::AttestedDevice::revoke_active(
        &data_dir,
        Some(&device.enrollment_id),
    )
    .unwrap();
}

#[tokio::test]
async fn headless_revoke_prunes_headless_scope_rows() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    let data_dir = root.path().join("data");
    std::fs::create_dir_all(&sessions_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let device = crate::infra::attested_device::AttestedDevice::enroll_active(
        &data_dir,
        "test-headless-revoke-prune",
        std::time::Duration::from_secs(3600),
        &[0x81u8; 32],
    )
    .unwrap();

    let seed_vault = Vault::new([0x55u8; 32]);
    seed_vault
        .add(
            crate::infra::vault::VaultScope::Headless,
            &store,
            "svc/revoked-headless",
            b"stale",
            None,
        )
        .unwrap();
    assert_eq!(
        crate::infra::headless_scope::list_headless_keys(&store).unwrap(),
        vec!["svc/revoked-headless".to_string()]
    );

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "headless_revoke",
        &json!({"enrollment_id": device.enrollment_id}),
    )
    .await
    .unwrap();

    assert_eq!(result["revoked"], json!(true));
    assert!(
        crate::infra::headless_scope::list_headless_keys(&store)
            .unwrap()
            .is_empty(),
        "headless_revoke must prune the headless vault subset after deleting the active enrollment"
    );
}

// ─── HEADLESS-PREFLIGHT-LAYER1-CONSTRUCTS-PHASE2 ────────────────────
//
// PREFLIGHT-LAYER1-WIRED
//
// Coverage for the `headless_preflight_layer1` dispatch arm. The
// resolver itself is exhaustively unit-tested in
// `crates/core-construct-runtime/src/preflight.rs::tests`; these tests cover the
// wire-shape contract (param parsing, JSON gap shape) and confirm the
// bundled cohort-A registry loads without an explicit `tasks.toml`
// dependency.

#[tokio::test]
async fn team0_headless_preflight_gaps_refuses_principal_mismatch() {
    let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 1000,
            pid: Some(91_007),
        }),
        "persona-trusted".to_string(),
    );
    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "headless_preflight_gaps",
        &json!({
            "persona": "persona-other",
            "since_seconds": 60,
        }),
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

/// Acceptance criterion: a task that declares a Construct whose action
/// the (empty) persona template does not grant produces a non-empty
/// gap list.
#[tokio::test]
async fn headless_preflight_layer1_emits_gap_for_unsatisfied_construct() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let params = json!({
        "tasks": [
            {
                "task_id": "TASK-AP-PR-MERGE",
                "constructs": ["ember-gh.pr_merge"],
            }
        ],
        "template": [],
    });

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "headless_preflight_layer1",
        &params,
    )
    .await
    .expect("layer1 dispatch should succeed");

    let gaps = result.as_array().expect("result is a JSON array");
    assert_eq!(gaps.len(), 1, "expected one gap, got: {result}");
    assert_eq!(gaps[0]["task_id"].as_str(), Some("TASK-AP-PR-MERGE"));
    assert_eq!(gaps[0]["identifier"].as_str(), Some("ember-gh.pr_merge"));
    assert!(gaps[0]["scope"].is_null());
}

/// Template that allows the declared permission → no gap.
#[tokio::test]
async fn headless_preflight_layer1_template_allows_means_no_gap() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let params = json!({
        "tasks": [
            {
                "task_id": "TASK-AP-PR-MERGE",
                "constructs": ["ember-gh.pr_merge"],
            }
        ],
        "template": ["ember-gh.pr_merge"],
    });

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "headless_preflight_layer1",
        &params,
    )
    .await
    .expect("layer1 dispatch should succeed");

    let gaps = result.as_array().expect("result is a JSON array");
    assert!(gaps.is_empty(), "expected no gaps, got: {result}");
}

/// Missing `tasks` param → `-32602` (invalid params).
#[tokio::test]
async fn headless_preflight_layer1_missing_tasks_returns_invalid_params() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "headless_preflight_layer1",
        &json!({}),
    )
    .await
    .expect_err("missing tasks should fail");
    assert_eq!(err.0, -32602);
    assert!(err.1.contains("'tasks'"), "error mentions tasks: {}", err.1);
}

/// Empty `tasks` array → empty gap list (no error).
#[tokio::test]
async fn headless_preflight_layer1_empty_tasks_yields_empty_gaps() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "headless_preflight_layer1",
        &json!({ "tasks": [] }),
    )
    .await
    .expect("empty tasks must succeed");
    let gaps = result.as_array().expect("array result");
    assert!(gaps.is_empty());
}

/// Unknown construct names are silently skipped — the resolver's
/// "best-effort predictive layer" contract.
#[tokio::test]
async fn headless_preflight_layer1_unknown_construct_silently_skipped() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let params = json!({
        "tasks": [
            {
                "task_id": "TASK-UNKNOWN",
                "constructs": ["ember-nonexistent.do_thing"],
            }
        ],
        "template": [],
    });

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "headless_preflight_layer1",
        &params,
    )
    .await
    .expect("unknown construct must not error");
    let gaps = result.as_array().expect("array result");
    assert!(gaps.is_empty(), "unknown construct yields no gap: {result}");
}

/// The bundled cohort-A manifest registry includes the load-bearing
/// `ember-gh` and `ember-kubectl` constructs the brief calls out.
#[test]
fn bundled_construct_registry_includes_cohort_a_tools() {
    let registry = preflight::bundled_construct_registry().expect("registry loads");
    assert!(
        registry.contains_key("ember-gh"),
        "registry missing ember-gh: {:?}",
        registry.keys().collect::<Vec<_>>()
    );
    assert!(
        registry.contains_key("ember-kubectl"),
        "registry missing ember-kubectl: {:?}",
        registry.keys().collect::<Vec<_>>()
    );
    // The kubectl manifest uses the tool-prefixed action-key shape,
    // exercising the resolver's short-name-prepended fallback.
    let kubectl = &registry["ember-kubectl"];
    assert!(
        kubectl.action_keys.iter().any(|k| k == "kubectl.apply"),
        "kubectl.apply key present: {:?}",
        kubectl.action_keys
    );
}
