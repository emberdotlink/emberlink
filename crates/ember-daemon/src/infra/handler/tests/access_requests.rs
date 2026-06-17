use super::*;

#[tokio::test]
async fn dispatch_method_uses_provided_policy() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    // Custom policy: deny "test.action" explicitly.
    let custom = PolicyEngine::new(PolicyConfig {
        rules: vec![PolicyRule {
            action: ActionSelector::named("test.action"),
            risk: RiskLevel::High,
            requirement: ApprovalRequirement::Denied,
            tier: None,
        }],
        ..PolicyConfig::default()
    });
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
            "scope": "read",
            "action": "test.action",
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
    let policy = test_policy();
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
            "scope": "read",
            "action": "deploy.staging",
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
async fn request_access_blocking_timeout() {
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

    // Request with 1 second timeout; nobody will approve.
    let result = dispatch_method(
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
    .unwrap();

    assert_eq!(result["status"], "timeout");
}

#[tokio::test]
async fn request_access_denies_when_rate_limit_exceeded() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
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

    // First request goes through. "deploy.staging" is auto-approved under the
    // default policy, so a grant is created.
    let first = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "request_access",
        &json!({
            "persona_id": persona_id,
            "credential_name": "some-key",
            "scope": "read",
            "action": "deploy.staging",
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
            "scope": "read",
            "action": "deploy.staging",
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

// ---- implementation-note-62: await_approval block-and-poll RPC -----------------

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
