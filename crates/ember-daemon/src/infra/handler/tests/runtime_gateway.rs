use super::*;

// COHORT-A-V03-T3-FIX-PROXY-URL-WIRE: daemon-side T2 (updated for
// COHORT-A-V03-T3-FIX-PROXY-URL-VIA-REQUEST-CONTEXT) — register_session
// response must include the real LLM proxy URL from RequestContext.
#[tokio::test]
async fn register_session_response_includes_real_proxy_url() {
    let _id_dir = setup_receipt_identity();

    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(std::rc::Rc::new(test_vault()));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let sessions_root = tempfile::TempDir::new().unwrap();
    let sessions_dir = sessions_root.path().to_path_buf();

    let expected_proxy_url = "http://127.0.0.1:61169";

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "proxy-url-test-persona"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let created = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "claude-code-default-v1",
            "scope": "claude-code",
            "ttl_secs": 3600,
            "max_delegation_depth": 1,
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = created["id"].as_str().unwrap().to_string();
    store
        .apply_grant_shape_to_grant(
            &grant_id,
            &GrantShapeFields {
                max_delegation_depth: Some(1),
                max_uses_per_hour: None,
                allowed_hours_start: None,
                allowed_hours_end: None,
                allowed_targets: None,
                budget: None,
                max_children_per_day: None,
                auto_delegate_scope_template: None,
            },
        )
        .expect("test anthropic grant must be runtime-delegable");

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir.clone());
    // Wire the URL via RequestContext — the correct path after
    // COHORT-A-V03-T3-FIX-PROXY-URL-VIA-REQUEST-CONTEXT.
    ctx.llm_proxy_url = Some(expected_proxy_url.to_string());

    let reg = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "proxy-url-test-persona",
            "launcher_pid": std::process::id(),
        }),
    )
    .await
    .unwrap();

    let got_proxy_url = reg["proxy_url"]
        .as_str()
        .expect("proxy_url must be present in response");
    assert_eq!(
        got_proxy_url, expected_proxy_url,
        "register_session must return the real LLM proxy URL from RequestContext, not the 8484 fallback"
    );
    assert_ne!(
        got_proxy_url, "http://127.0.0.1:8484",
        "proxy_url must not be the hardcoded 8484 fallback when ctx.llm_proxy_url is set"
    );
}

// COHORT-A-V03-T3-FIX-PROXY-URL-VIA-REQUEST-CONTEXT: T2 test —
// register_session must read the LLM proxy URL from RequestContext,
// NOT from std::env::var. The env var may be absent or stale due to
// Rust 2024 std::env::set_var cross-thread visibility hazard (tokio
// worker threads may not observe a set_var from the startup thread).
// The fix in #2389 relied on set_var; this test proves the correct fix.
//
// Key assertion: even if EMBER_PROXY_URL is set to a DIFFERENT (wrong)
// value in the environment, the response uses the URL from RequestContext.
#[tokio::test]
async fn register_session_response_uses_request_context_proxy_url() {
    let _id_dir = setup_receipt_identity();

    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(std::rc::Rc::new(test_vault()));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let sessions_root = tempfile::TempDir::new().unwrap();
    let sessions_dir = sessions_root.path().to_path_buf();

    // Deliberately set EMBER_PROXY_URL to a wrong value to prove the
    // handler does NOT read it. RequestContext plumbing should win.
    // SAFETY: test-only; value is removed after the test.
    unsafe {
        std::env::set_var("EMBER_PROXY_URL", "http://127.0.0.1:8484");
    }

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "ctx-proxy-url-test-persona"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "claude-code-default-v1",
            "scope": "claude-code",
            "ttl_secs": 3600,
            "max_delegation_depth": 1,
            "force": true,
        }),
    )
    .await
    .unwrap();

    // Populate RequestContext with the real URL — this is what
    // SocketListener.with_llm_proxy_url wires in production.
    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir.clone());
    // COHORT-A-V03-T3-FIX-PROXY-URL-VIA-REQUEST-CONTEXT: this URL must
    // appear in the response; the env var ("8484") must be ignored.
    ctx.llm_proxy_url = Some("http://127.0.0.1:55555".to_string());

    let reg = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "ctx-proxy-url-test-persona",
            "launcher_pid": std::process::id(),
        }),
    )
    .await
    .unwrap();

    // Restore env so subsequent tests are not polluted.
    unsafe {
        std::env::remove_var("EMBER_PROXY_URL");
    }

    let got_proxy_url = reg["proxy_url"]
        .as_str()
        .expect("proxy_url must be present in response");
    assert_eq!(
        got_proxy_url, "http://127.0.0.1:55555",
        "register_session must use ctx.llm_proxy_url from RequestContext, not env::var"
    );
    assert_ne!(
        got_proxy_url, "http://127.0.0.1:8484",
        "register_session must ignore EMBER_PROXY_URL env var; RequestContext wins"
    );
}

#[tokio::test]
async fn register_session_response_includes_anthropic_gateway_bundle_for_composite_grant() {
    use crate::trust::approval::ApprovalOutcome;
    use core_grant_types::{GrantProposal, StatementProposal};

    let _id_dir = setup_receipt_identity();

    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(std::rc::Rc::new(test_vault()));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let sessions_root = tempfile::TempDir::new().unwrap();
    let sessions_dir = sessions_root.path().to_path_buf();

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "anthropic-gateway-persona"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap().to_string();

    let proposal = GrantProposal {
        persona_id: persona_id.clone(),
        statements: vec![
            StatementProposal {
                resource_type: core_grant_types::ResourceType::Credential,
                credential_name: "anthropic/api/key/test-api".to_string(),
                actions: vec!["credential:read".to_string()],
                resource: core_grant_types::ResourceSelector::Exact {
                    value: "anthropic/api/key/test-api".to_string(),
                },
                budget: None,
                conditions: vec![],
            },
            StatementProposal {
                resource_type: core_grant_types::ResourceType::Session,
                credential_name: "anthropic/api/key/test-api".to_string(),
                actions: vec!["llm:generate".to_string()],
                resource: core_grant_types::ResourceSelector::Glob {
                    pattern: "anthropic/*".to_string(),
                },
                budget: Some(core_grant_types::Budget {
                    tokens: Some(20_000),
                    ..Default::default()
                }),
                conditions: vec![],
            },
        ],
        expires_at: Some(3600),
        label: Some("claude-code-anthropic-session".to_string()),
        skill_ref: None,
        note: None,
    };

    let approval = store
        .propose_grant_typed(&proposal, "credential.access", "high")
        .unwrap();
    store
        .resolve_approval(&approval.id, &ApprovalOutcome::Approved)
        .unwrap();
    let grant = store
        .evaluate_grant(&persona_id, "anthropic/api/key/test-api")
        .expect("approved proposal must materialize an active anthropic grant");
    store
        .apply_grant_shape_to_grant(
            &grant.id,
            &GrantShapeFields {
                max_delegation_depth: Some(1),
                max_uses_per_hour: None,
                allowed_hours_start: None,
                allowed_hours_end: None,
                allowed_targets: None,
                budget: None,
                max_children_per_day: None,
                auto_delegate_scope_template: None,
            },
        )
        .expect("approved anthropic grant must become runtime-delegable");

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);
    ctx.llm_proxy_url = Some("http://127.0.0.1:61169".to_string());

    let reg = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "anthropic-gateway-persona",
            "launcher_pid": std::process::id(),
        }),
    )
    .await
    .unwrap();

    let runtime_grant_id = reg["grant_id"].as_str().expect("runtime grant id");
    assert_ne!(runtime_grant_id, grant.id);
    assert_eq!(
        reg["anthropic_base_url"],
        json!("http://127.0.0.1:61169"),
        "register_session must return the daemon proxy URL as ANTHROPIC_BASE_URL for composite Anthropic sessions"
    );
    let runtime_grant = store
        .get_grant(runtime_grant_id)
        .expect("runtime child grant must exist");
    assert_eq!(
        runtime_grant.parent_grant_id.as_deref(),
        Some(grant.id.as_str())
    );
    let headers = reg["anthropic_custom_headers"]
        .as_str()
        .expect("anthropic_custom_headers must be present");
    let attachment_id = reg["attachment_id"].as_str().expect("attachment id");
    let endpoint_token = reg["attachment_endpoint_token"]
        .as_str()
        .expect("attachment endpoint token");
    assert!(
        !headers.contains("X-Ember-Persona:"),
        "gateway headers must not pin authority to a spawn-time persona header: {headers}"
    );
    assert!(
        headers.contains("X-Ember-Credential: anthropic/api/key/test-api"),
        "gateway headers must pin the anthropic credential: {headers}"
    );
    assert!(
        headers.contains("X-Ember-Target: https://api.anthropic.com"),
        "gateway headers must pin the Anthropic target: {headers}"
    );
    assert!(
        headers.contains(&format!("X-Ember-Attachment-Id: {attachment_id}")),
        "gateway headers must carry the stable attachment endpoint id: {headers}"
    );
    assert!(
        headers.contains(&format!("X-Ember-Endpoint-Token: {endpoint_token}")),
        "gateway headers must carry the attachment endpoint token: {headers}"
    );
    assert_eq!(
        reg["authority_endpoint"]["attachment_id"],
        json!(attachment_id),
        "register_session must surface attachment authority coordinates"
    );
    assert_eq!(reg["attachment_state"], json!("active"));
}

#[tokio::test]
async fn create_composite_grant_rpc_materializes_canonical_chain() {
    use core_grant_types::{ResourceSelector, ResourceType, StatementProposal};

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
        &json!({"name": "direct-composite-persona"}),
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
            "persona_id": persona_id,
            "credential_name": "anthropic/api/key/test-api",
            "scope": "claude-code-default-v1",
            "ttl_secs": 3600,
            "statements": [
                StatementProposal {
                    resource_type: ResourceType::Credential,
                    credential_name: "anthropic/api/key/test-api".to_string(),
                    actions: vec!["credential:read".to_string()],
                    resource: ResourceSelector::Exact {
                        value: "anthropic/api/key/test-api".to_string(),
                    },
                    budget: None,
                    conditions: vec![],
                },
                StatementProposal {
                    resource_type: ResourceType::Session,
                    credential_name: "anthropic/api/key/test-api".to_string(),
                    actions: vec!["llm:generate".to_string()],
                    resource: ResourceSelector::Glob {
                        pattern: "anthropic/*".to_string(),
                    },
                    budget: None,
                    conditions: vec![],
                }
            ]
        }),
    )
    .await
    .unwrap();
    let grant_id = created["id"].as_str().unwrap().to_string();

    let status = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "grant_status",
        &json!({"id": grant_id}),
    )
    .await
    .unwrap();
    let statements = status["statements"]
        .as_array()
        .expect("grant_status statements array");
    assert_eq!(
        statements.len(),
        2,
        "direct composite RPC must persist the full statement chain"
    );

    let audit = store
        .query_audit(&crate::infra::audit::AuditFilter::default())
        .unwrap();
    let minted = audit
        .iter()
        .find(|entry| {
            entry.action == "grant.minted"
                && entry
                    .details
                    .as_deref()
                    .is_some_and(|details| details.contains("\"creation_mode\":\"composite\""))
        })
        .expect("expected grant.minted composite audit event");
    let details = minted.details.as_deref().unwrap_or("");
    assert!(
        details.contains("\"statement_count\":2"),
        "grant.minted must record the final composite statement count: {details}"
    );
}

#[tokio::test]
async fn register_session_container_anthropic_lane_refuses_missing_llm_proxy_url() {
    use crate::trust::approval::ApprovalOutcome;
    use core_grant_types::{GrantProposal, ResourceSelector, ResourceType, StatementProposal};

    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(std::rc::Rc::new(test_vault()));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let sessions_root = tempfile::TempDir::new().unwrap();
    let sessions_dir = sessions_root.path().to_path_buf();

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "missing-proxy-persona"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap().to_string();

    let proposal = GrantProposal {
        persona_id: persona_id.clone(),
        statements: vec![
            StatementProposal {
                resource_type: ResourceType::Credential,
                credential_name: "anthropic/api/key/test-api".to_string(),
                actions: vec!["credential:read".to_string()],
                resource: ResourceSelector::Exact {
                    value: "anthropic/api/key/test-api".to_string(),
                },
                budget: None,
                conditions: vec![],
            },
            StatementProposal {
                resource_type: ResourceType::Session,
                credential_name: "anthropic/api/key/test-api".to_string(),
                actions: vec!["llm:generate".to_string()],
                resource: ResourceSelector::Glob {
                    pattern: "anthropic/*".to_string(),
                },
                budget: None,
                conditions: vec![],
            },
        ],
        expires_at: Some(3600),
        label: Some("missing-proxy-anthropic-session".to_string()),
        skill_ref: None,
        note: None,
    };
    let approval = store
        .propose_grant_typed(&proposal, "credential.access", "high")
        .unwrap();
    store
        .resolve_approval(&approval.id, &ApprovalOutcome::Approved)
        .unwrap();
    let grant = store
        .evaluate_grant(&persona_id, "anthropic/api/key/test-api")
        .expect("approved proposal must materialize an active anthropic grant");
    store
        .apply_grant_shape_to_grant(
            &grant.id,
            &GrantShapeFields {
                max_delegation_depth: Some(1),
                max_uses_per_hour: None,
                allowed_hours_start: None,
                allowed_hours_end: None,
                allowed_targets: None,
                budget: None,
                max_children_per_day: None,
                auto_delegate_scope_template: None,
            },
        )
        .expect("test anthropic grant must be runtime-delegable");

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);
    ctx.llm_proxy_url = None;

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "missing-proxy-persona",
            "launcher_pid": std::process::id(),
            "attestation_caller": "claude-code",
            "bridge_client_bundle": true,
        }),
    )
    .await
    .expect_err("container Anthropic sessions must not launch against dead 8484 fallback");

    assert_eq!(err.0, -32000);
    assert!(
        err.1.contains("TCP LLM proxy listener is not configured"),
        "error must name the missing proxy listener: {err:?}"
    );
    assert!(
        err.1.contains("dead 8484 fallback"),
        "error must make the old dead fallback explicit: {err:?}"
    );
}

#[tokio::test]
async fn register_session_prefers_anthropic_gateway_grant_over_plain_default_grant() {
    use core_grant_types::{ResourceSelector, ResourceType, StatementProposal};

    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(std::rc::Rc::new(test_vault()));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let sessions_root = tempfile::TempDir::new().unwrap();
    let sessions_dir = sessions_root.path().to_path_buf();

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "gateway-pref-persona"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap().to_string();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "claude-code-default-v1",
            "scope": "claude-code-default-v1",
            "ttl_secs": 3600,
            "max_delegation_depth": 1,
            "force": true,
        }),
    )
    .await
    .unwrap();

    let composite = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_composite_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "anthropic/api/key/test-api",
            "scope": "claude-code-default-v1",
            "ttl_secs": 3600,
            "max_delegation_depth": 1,
            "statements": [
                StatementProposal {
                    resource_type: ResourceType::Credential,
                    credential_name: "anthropic/api/key/test-api".to_string(),
                    actions: vec!["credential:read".to_string()],
                    resource: ResourceSelector::Exact {
                        value: "anthropic/api/key/test-api".to_string(),
                    },
                    budget: None,
                    conditions: vec![],
                },
                StatementProposal {
                    resource_type: ResourceType::Session,
                    credential_name: "anthropic/api/key/test-api".to_string(),
                    actions: vec!["llm:generate".to_string()],
                    resource: ResourceSelector::Glob {
                        pattern: "anthropic/*".to_string(),
                    },
                    budget: None,
                    conditions: vec![],
                }
            ]
        }),
    )
    .await
    .unwrap();
    let composite_grant_id = composite["id"].as_str().unwrap().to_string();

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);
    ctx.llm_proxy_url = Some("http://127.0.0.1:61169".to_string());

    let reg = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "gateway-pref-persona",
            "launcher_pid": std::process::id(),
        }),
    )
    .await
    .unwrap();

    let runtime_grant_id = reg["grant_id"].as_str().expect("runtime grant id");
    let runtime_grant = store
        .get_grant(runtime_grant_id)
        .expect("runtime child grant must exist");
    assert_eq!(
        runtime_grant.parent_grant_id.as_deref(),
        Some(composite_grant_id.as_str()),
        "register_session must delegate from the gateway-compatible active parent grant"
    );
    assert_eq!(
        reg["anthropic_base_url"],
        json!("http://127.0.0.1:61169"),
        "preferred grant must surface the Anthropic gateway bundle"
    );
}

#[tokio::test]
async fn register_session_prefers_oauth_gateway_grant_when_multiple_gateway_grants_are_active() {
    use core_grant_types::{ResourceSelector, ResourceType, StatementProposal};

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    std::fs::create_dir_all(&sessions_dir).unwrap();

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "gateway-oauth-pref-persona"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let api_grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_composite_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "anthropic/api/key/test-api",
            "scope": "claude-code-default-v1",
            "ttl_secs": 3600,
            "max_delegation_depth": 1,
            "statements": [
                StatementProposal {
                    resource_type: ResourceType::Credential,
                    credential_name: "anthropic/api/key/test-api".to_string(),
                    actions: vec!["credential:read".to_string()],
                    resource: ResourceSelector::Exact {
                        value: "anthropic/api/key/test-api".to_string(),
                    },
                    budget: None,
                    conditions: vec![],
                },
                StatementProposal {
                    resource_type: ResourceType::Session,
                    credential_name: "anthropic/api/key/test-api".to_string(),
                    actions: vec!["llm:generate".to_string()],
                    resource: ResourceSelector::Glob {
                        pattern: "anthropic/*".to_string(),
                    },
                    budget: None,
                    conditions: vec![],
                }
            ]
        }),
    )
    .await
    .unwrap();
    let api_grant_id = api_grant["id"].as_str().unwrap().to_string();

    let oauth_grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_composite_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "anthropic/plan/claude-oauth/test-oauth",
            "scope": "claude-code-default-v1",
            "ttl_secs": 3600,
            "max_delegation_depth": 1,
            "statements": [
                StatementProposal {
                    resource_type: ResourceType::Credential,
                    credential_name: "anthropic/plan/claude-oauth/test-oauth".to_string(),
                    actions: vec!["credential:read".to_string()],
                    resource: ResourceSelector::Exact {
                        value: "anthropic/plan/claude-oauth/test-oauth".to_string(),
                    },
                    budget: None,
                    conditions: vec![],
                },
                StatementProposal {
                    resource_type: ResourceType::Session,
                    credential_name: "anthropic/plan/claude-oauth/test-oauth".to_string(),
                    actions: vec!["llm:generate".to_string()],
                    resource: ResourceSelector::Glob {
                        pattern: "anthropic/*".to_string(),
                    },
                    budget: None,
                    conditions: vec![],
                }
            ]
        }),
    )
    .await
    .unwrap();
    let oauth_grant_id = oauth_grant["id"].as_str().unwrap().to_string();

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);
    ctx.llm_proxy_url = Some("http://127.0.0.1:61169".to_string());

    let reg = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "gateway-oauth-pref-persona",
            "launcher_pid": std::process::id(),
        }),
    )
    .await
    .unwrap();

    assert_ne!(
        api_grant_id, oauth_grant_id,
        "test setup must create distinct gateway grants"
    );
    let runtime_grant_id = reg["grant_id"].as_str().expect("runtime grant id");
    let runtime_grant = store
        .get_grant(runtime_grant_id)
        .expect("runtime child grant must exist");
    assert_eq!(
        runtime_grant.parent_grant_id.as_deref(),
        Some(oauth_grant_id.as_str()),
        "register_session must prefer the OAuth-backed gateway parent grant over the API-key lane"
    );
    assert_eq!(
        reg["anthropic_base_url"],
        json!("http://127.0.0.1:61169"),
        "preferred OAuth grant must still surface the Anthropic gateway bundle"
    );
    assert!(
        reg["anthropic_custom_headers"]
            .as_str()
            .unwrap_or_default()
            .contains("X-Ember-Credential: anthropic/plan/claude-oauth/test-oauth"),
        "the selected gateway bundle must advertise the OAuth credential identity"
    );
}
