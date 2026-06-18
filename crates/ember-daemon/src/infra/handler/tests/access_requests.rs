use super::*;

const GH_PR_LIST_ACTION_REF: &str = "registry.ember.systems/ember-systems/ember-gh/pr_list@v1";
const GH_REPO_DELETE_ACTION_REF: &str =
    "registry.ember.systems/ember-systems/ember-gh/repo_delete@v1";

fn auto_policy_for(action: &str) -> PolicyEngine {
    PolicyEngine::new(PolicyConfig {
        rules: vec![PolicyRule {
            action: ActionSelector::parse(action).expect("valid action selector"),
            risk: RiskLevel::Low,
            requirement: ApprovalRequirement::Auto,
            tier: None,
        }],
        ..PolicyConfig::default()
    })
}

fn deny_policy_for(action: &str) -> PolicyEngine {
    PolicyEngine::new(PolicyConfig {
        rules: vec![PolicyRule {
            action: ActionSelector::parse(action).expect("valid action selector"),
            risk: RiskLevel::Critical,
            requirement: ApprovalRequirement::Denied,
            tier: None,
        }],
        ..PolicyConfig::default()
    })
}

#[tokio::test]
async fn manifest_request_uses_provided_policy() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let custom = deny_policy_for(GH_PR_LIST_ACTION_REF);
    let rl = test_rate_limiter();

    let persona = dispatch_method(
        &store,
        &vault,
        &custom,
        &rl,
        "create_persona",
        &json!({"name": "custom-policy"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let result = dispatch_method(
        &store,
        &vault,
        &custom,
        &rl,
        "request_access",
        &json!({
            "persona_id": persona_id,
            "credential_name": "some-key",
            "action_ref": GH_PR_LIST_ACTION_REF,
            "target": {"kind": "github_repo", "repo": "octo/repo"},
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["status"], "denied");
    assert_eq!(result["decision"], "deny");
}

#[tokio::test]
async fn grant_issuance_logged_to_audit() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = auto_policy_for(GH_PR_LIST_ACTION_REF);
    let rl = test_rate_limiter();

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "audit-issuance"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    // request_access with auto-approve policy creates a grant.
    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "request_access",
        &json!({
            "persona_id": persona_id,
            "credential_name": "audit-cred",
            "action_ref": GH_PR_LIST_ACTION_REF,
            "resource_id": "octo/repo",
        }),
    )
    .await
    .unwrap();
    assert_eq!(result["status"], "approved");
    let grant_id = result["grant_id"].as_str().unwrap();

    let entries = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("grant.issued".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert!(
        !entries.is_empty(),
        "expected at least one grant.issued audit row"
    );
    let entry = entries.iter().find(|e| {
        e.details
            .as_ref()
            .map(|d| d.contains(grant_id))
            .unwrap_or(false)
    });
    assert!(
        entry.is_some(),
        "audit row should reference the new grant_id"
    );
    let entry = entry.unwrap();
    assert_eq!(entry.action, "grant.issued");
    assert_eq!(entry.outcome, "allowed");
    assert_eq!(entry.agent_id.as_deref(), Some(persona_id));
    assert_eq!(entry.credential.as_deref(), Some("audit-cred"));
}

#[tokio::test]
async fn manifest_action_ref_auto_request_mints_need_statements_for_typed_target() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = auto_policy_for(GH_PR_LIST_ACTION_REF);
    let rl = test_rate_limiter();

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "manifest-auto"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "request_access",
        &json!({
            "persona_id": persona_id,
            "credential_name": "github-token",
            "action_ref": GH_PR_LIST_ACTION_REF,
            "target": {"kind": "github_repo", "provider": "github", "repo": "octo/repo"},
            "ttl_secs": 600
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["status"], "approved", "got: {result}");
    assert_eq!(result["decision"], "auto_approve");
    assert_eq!(result["action_ref"], GH_PR_LIST_ACTION_REF);
    assert_eq!(result["need_source"], "manifest");
    assert_eq!(result["target_source"], "target.github_repo");
    assert_eq!(
        result["need"],
        json!(["github:metadata:read", "github:pull_request:read"])
    );

    let grant_id = result["grant_id"].as_str().unwrap();
    let grant = store.get_access_grant(grant_id).unwrap();
    let statements: Vec<_> = grant.statements().map(|(_, stmt)| stmt.clone()).collect();
    assert_eq!(
        statements.len(),
        2,
        "grant should preserve one statement per need atom"
    );
    assert_eq!(statements[0].actions, vec!["github:metadata:read"]);
    assert_eq!(statements[1].actions, vec!["github:pull_request:read"]);
    for stmt in &statements {
        assert_eq!(
            stmt.resource_type,
            core_grant_types::ResourceType::Credential
        );
        assert_eq!(
            stmt.resource,
            core_grant_types::ResourceSelector::Exact {
                value: "octo/repo".to_string()
            }
        );
    }
}

#[tokio::test]
async fn manifest_action_ref_rejects_removed_action_and_scope_fields() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = auto_policy_for(GH_PR_LIST_ACTION_REF);
    let rl = test_rate_limiter();

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "manifest-reject-old-fields"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let action_err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "request_access",
        &json!({
            "persona_id": persona_id,
            "credential_name": "github-token",
            "action_ref": GH_PR_LIST_ACTION_REF,
            "action": "caller.supplied.action",
            "target": {"kind": "github_repo", "repo": "octo/repo"}
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(action_err.0, -32602);
    assert!(
        action_err.1.contains("no longer accepts 'action'"),
        "error should reject removed action field: {action_err:?}"
    );

    let scope_err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "request_access",
        &json!({
            "persona_id": persona_id,
            "credential_name": "github-token",
            "action_ref": GH_PR_LIST_ACTION_REF,
            "scope": "github:repo:octo/repo"
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(scope_err.0, -32602);
    assert!(
        scope_err.1.contains("no longer accepts 'scope'"),
        "error should reject removed scope field: {scope_err:?}"
    );
}

#[tokio::test]
async fn manifest_action_ref_requires_resource_id_or_typed_target() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = auto_policy_for(GH_PR_LIST_ACTION_REF);
    let rl = test_rate_limiter();

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "manifest-missing-target"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "request_access",
        &json!({
            "persona_id": persona_id,
            "credential_name": "github-token",
            "action_ref": GH_PR_LIST_ACTION_REF
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32602);
    assert!(
        err.1.contains("resource_id") && err.1.contains("target"),
        "error should require target selector: {err:?}"
    );
}

#[tokio::test]
async fn manifest_action_ref_required_request_submits_composite_approval() {
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
        &json!({"name": "manifest-pending"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "request_access",
        &json!({
            "persona_id": persona_id,
            "credential_name": "github-token",
            "action_ref": GH_PR_LIST_ACTION_REF,
            "target": {"kind": "github_repo", "repo": "octo/repo"}
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["status"], "pending", "got: {result}");
    assert_eq!(result["decision"], "require_approval");
    assert_eq!(result["action_ref"], GH_PR_LIST_ACTION_REF);
    assert_eq!(result["need_source"], "manifest");

    let approval_id = result["approval_id"].as_str().unwrap();
    let approval = store.get_approval(approval_id).unwrap();
    assert_eq!(approval.action, GH_PR_LIST_ACTION_REF);
    let statements = approval
        .composite_statements
        .expect("manifest request should carry typed statements");
    assert_eq!(statements.len(), 2);
    assert_eq!(statements[0].actions, vec!["github:metadata:read"]);
    assert_eq!(statements[1].actions, vec!["github:pull_request:read"]);
}

#[tokio::test]
async fn manifest_action_ref_with_missing_need_fails_closed() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = auto_policy_for(GH_REPO_DELETE_ACTION_REF);
    let rl = test_rate_limiter();

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "manifest-missing-need"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "request_access",
        &json!({
            "persona_id": persona_id,
            "credential_name": "github-token",
            "action_ref": GH_REPO_DELETE_ACTION_REF,
            "target": {"kind": "github_repo", "repo": "octo/repo"}
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32602);
    assert!(
        err.1.contains("declares no need"),
        "error should name missing manifest need: {err:?}"
    );
}

#[tokio::test]
async fn manifest_action_ref_standing_grant_bypasses_deny_policy() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = deny_policy_for(GH_PR_LIST_ACTION_REF);
    let rl = test_rate_limiter();

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "manifest-standing"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();
    store
        .create_standing_grant(
            persona_id,
            &ActionSelector::parse(GH_PR_LIST_ACTION_REF).unwrap(),
            "*",
            None,
        )
        .unwrap();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "request_access",
        &json!({
            "persona_id": persona_id,
            "credential_name": "github-token",
            "action_ref": GH_PR_LIST_ACTION_REF,
            "target": {"kind": "github_repo", "repo": "octo/repo"}
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["status"], "approved", "got: {result}");
    assert_eq!(result["source"], "standing_grant");
    assert_eq!(result["action_ref"], GH_PR_LIST_ACTION_REF);
    let grant = store
        .get_access_grant(result["grant_id"].as_str().unwrap())
        .unwrap();
    assert_eq!(grant.statement_count(), 2);
}

#[tokio::test]
async fn request_access_blocking_is_not_a_daemon_method() {
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
        &json!({"name": "blocker"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "request_access_blocking",
        &json!({
            "persona_id": persona_id,
            "action": "test.action",
            "timeout_secs": 1,
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32601);
    assert!(
        err.1.contains("Method not found"),
        "removed method must fall through to unknown-method dispatch: {err:?}"
    );
}

#[tokio::test]
async fn request_access_denies_when_rate_limit_exceeded() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = auto_policy_for(GH_PR_LIST_ACTION_REF);
    // Tight limiter: exactly 1 request per persona+action in a 60s window.
    let rl = RefCell::new(RateLimiter::new(1, 60));

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "rate-limited"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    // First manifest request goes through and mints a composite grant.
    let first = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "request_access",
        &json!({
            "persona_id": persona_id,
            "credential_name": "some-key",
            "action_ref": GH_PR_LIST_ACTION_REF,
            "resource_id": "octo/repo",
        }),
    )
    .await
    .unwrap();
    assert_eq!(first["status"], "approved");

    // Snapshot approvals count before the second rate-limited call.
    let pending_before = store.list_pending_approvals().unwrap();

    let second = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "request_access",
        &json!({
            "persona_id": persona_id,
            "credential_name": "some-key",
            "action_ref": GH_PR_LIST_ACTION_REF,
            "resource_id": "octo/repo",
        }),
    )
    .await
    .unwrap();
    assert_eq!(second["status"], "denied");
    assert_eq!(second["reason"], "rate_spike");
    // The response must not leak a matched rule. Only the rate-limit fact is
    // surfaced.
    assert!(second.get("matched_rule").is_none());

    // Policy must not have been evaluated: no new approval submitted.
    let pending_after = store.list_pending_approvals().unwrap();
    assert_eq!(pending_before.len(), pending_after.len());
}

// ---- COHORT-A-4: await_approval block-and-poll RPC -----------------

#[tokio::test]
async fn await_approval_returns_approved_when_resolved_mid_poll() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // Mint persona + pending approval row directly.
    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "ap4-approve"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let approval = store
        .submit_approval(persona_id, "cred-x", "read", None, "Bash", "low")
        .unwrap();
    let approval_id = approval.id.clone();

    // Resolve the approval before the poll fires. The dispatch call below will
    // hit the resolved state on its first get_approval lookup.
    store
        .resolve_approval(
            &approval_id,
            &crate::trust::approval::ApprovalOutcome::Approved,
        )
        .unwrap();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "await_approval",
        &json!({"request_id": approval_id, "timeout_secs": 2}),
    )
    .await
    .unwrap();

    assert_eq!(
        result["decision"]["kind"],
        json!("approved"),
        "got: {result}"
    );
}

#[tokio::test]
async fn await_approval_returns_denied_when_resolved_denied() {
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
        &json!({"name": "ap4-deny"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let approval = store
        .submit_approval(persona_id, "cred-y", "read", None, "Bash", "high")
        .unwrap();
    let approval_id = approval.id.clone();

    store
        .resolve_approval(
            &approval_id,
            &crate::trust::approval::ApprovalOutcome::Denied {
                reason: "operator declined".to_string(),
            },
        )
        .unwrap();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "await_approval",
        &json!({"request_id": approval_id, "timeout_secs": 2}),
    )
    .await
    .unwrap();

    assert_eq!(result["decision"]["kind"], json!("denied"), "got: {result}");
    assert!(
        result["decision"]["reason"]
            .as_str()
            .unwrap_or("")
            .contains("operator declined"),
        "got: {result}"
    );
}

#[tokio::test]
async fn await_approval_returns_timed_out_after_deadline() {
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
        &json!({"name": "ap4-timeout"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let approval = store
        .submit_approval(persona_id, "cred-z", "read", None, "Bash", "med")
        .unwrap();
    let approval_id = approval.id.clone();

    // Do not resolve; let the deadline fire. timeout_secs=0 short-circuits
    // after the first poll cycle so the test does not spend wall-clock time.
    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "await_approval",
        &json!({"request_id": approval_id, "timeout_secs": 0}),
    )
    .await
    .unwrap();

    assert_eq!(
        result["decision"]["kind"],
        json!("timed_out"),
        "got: {result}"
    );
}

#[tokio::test]
async fn await_approval_unknown_request_returns_32004() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "await_approval",
        &json!({"request_id": "approval-does-not-exist", "timeout_secs": 1}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32004, "got: {err:?}");
}

#[tokio::test]
async fn await_approval_missing_request_id_returns_32602() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "await_approval",
        &json!({"timeout_secs": 1}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32602, "got: {err:?}");
}

#[tokio::test]
async fn team0_await_approval_refuses_other_principals_request() {
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
        &json!({"name": "team0-await-a"}),
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
        &json!({"name": "team0-await-b"}),
    )
    .await
    .unwrap();
    let persona_b_id = persona_b["id"].as_str().unwrap().to_string();

    let approval = store
        .submit_approval(&persona_b_id, "cred-b", "read", None, "Bash", "high")
        .unwrap();
    store
        .resolve_approval(
            &approval.id,
            &crate::trust::approval::ApprovalOutcome::Approved,
        )
        .unwrap();

    let ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 1000,
            pid: Some(91_005),
        }),
        persona_a_id,
    );
    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "await_approval",
        &json!({"request_id": approval.id, "timeout_secs": 0}),
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
async fn team0_await_approval_refuses_without_trusted_principal() {
    let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
    clear_pid_persona_registry();
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
        &json!({"name": "team0-await-missing-principal"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();
    let approval = store
        .submit_approval(persona_id, "cred", "read", None, "Bash", "high")
        .unwrap();

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        RequestContext::socket(Some(PeerCred {
            uid: 1000,
            pid: Some(91_006),
        })),
        "await_approval",
        &json!({"request_id": approval.id, "timeout_secs": 0}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32004);
    assert!(
        err.1.contains("trusted enrolled principal"),
        "missing-principal refusal should mention trusted principal: {}",
        err.1
    );
}
