use super::*;

fn preflight_connect_only_ctx() -> RequestContext {
    RequestContext {
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
    }
}

fn preflight_gh_action() -> Value {
    json!({
        "service": "ember-gh",
        "action_ref": "registry.ember.systems/ember-systems/ember-gh/pr_create@v1",
        "plugin_address": "registry.ember.systems/ember-systems/ember-gh",
        "default_policy": "prompt",
        "authority_refs": ["github"],
    })
}

fn preflight_gh_pr_create_targeted_action() -> Value {
    let mut action = preflight_gh_action();
    action["target"] = json!({
        "provider": "github",
        "repo": "emberdotlink/emberlink-dev",
        "branch": "feat/resolve-access",
    });
    action
}

fn preflight_gh_pr_create_unsafe_target_action() -> Value {
    let mut action = preflight_gh_action();
    action["target"] = json!({
        "provider": "github",
        "repo": "emberdotlink/emberlink-dev",
        "branch": "main",
        "native_scope": {
            "installation": "all_repos"
        }
    });
    action["service_connection"] = json!({
        "scope": "all_repos"
    });
    action
}

fn preflight_missing_github_service_pr_create_action() -> Value {
    json!({
        "service": "github",
        "default_policy": "prompt",
        "semantic_labels": ["github.pull_request.write"],
        "target": {
            "provider": "github",
            "repo": "emberdotlink/emberlink-dev",
            "branch": "feat/resolve-access",
        },
    })
}

async fn run_preflight(posture: Value, actions: Value) -> Vec<Value> {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();
    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        preflight_connect_only_ctx(),
        "preflight_authority_coverage",
        &json!({ "posture": posture, "actions": actions }),
    )
    .await
    .expect("preflight_authority_coverage dispatch ok");
    result.as_array().expect("array result").clone()
}

#[tokio::test]
async fn preflight_dispatch_prompt_without_grants_under_jit() {
    let rows = run_preflight(
        json!({ "fallback": "jit", "context": "interactive" }),
        json!([preflight_gh_action()]),
    )
    .await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["status"], "prompt");
    assert_eq!(rows[0]["service"], "ember-gh");
    assert_eq!(
        rows[0]["action_ref"],
        "registry.ember.systems/ember-systems/ember-gh/pr_create@v1"
    );
    assert_eq!(rows[0]["material_summary"], "broker: github");
    assert!(rows[0]["next_action"].is_string());
    assert!(rows[0].get("access_resolution_plan").is_none());
}

#[tokio::test]
async fn preflight_dispatch_returns_resolve_access_plan_for_narrow_pr_create() {
    let rows = run_preflight(
        json!({ "fallback": "jit", "context": "interactive" }),
        json!([preflight_gh_pr_create_targeted_action()]),
    )
    .await;
    let plan = &rows[0]["access_resolution_plan"];
    assert_eq!(rows[0]["status"], "prompt");
    assert_eq!(
        plan["denied_action"],
        "registry.ember.systems/ember-systems/ember-gh/pr_create@v1"
    );
    assert_eq!(plan["target"]["kind"], "github_repository_branch");
    assert_eq!(plan["target"]["repo"], "emberdotlink/emberlink-dev");
    assert_eq!(plan["target"]["branch"], "feat/resolve-access");
    assert_eq!(plan["collapse_eligibility"]["eligible"], true);
    assert_eq!(plan["steps"][0]["kind"], "issue_grant");
    assert_eq!(
        plan["steps"][0]["grant_delta"]["statements"][0]["actions"][0],
        "github:metadata:read"
    );
    assert_eq!(
        plan["steps"][0]["grant_delta"]["statements"][1]["actions"][0],
        "github:contents:write"
    );
    assert_eq!(
        plan["steps"][0]["grant_delta"]["statements"][2]["actions"][0],
        "github:pull_request:create"
    );
    assert_eq!(
        plan["steps"][0]["grant_delta"]["statements"][0]["resource"]["kind"],
        "exact"
    );
    assert_eq!(
        plan["steps"][0]["grant_delta"]["statements"][0]["resource"]["value"],
        "emberdotlink/emberlink-dev"
    );
}

#[tokio::test]
async fn preflight_dispatch_returns_blocked_resolve_access_plan_for_unsafe_pr_create() {
    let rows = run_preflight(
        json!({ "fallback": "jit", "context": "interactive" }),
        json!([preflight_gh_pr_create_unsafe_target_action()]),
    )
    .await;
    let plan = &rows[0]["access_resolution_plan"];
    assert_eq!(rows[0]["status"], "prompt");
    assert_eq!(plan["collapse_eligibility"]["eligible"], false);
    assert!(
        plan["reasons"]
            .as_array()
            .expect("reasons array")
            .iter()
            .any(|r| r
                .as_str()
                .is_some_and(|s| s.contains("provider-native scope")))
    );
    assert!(
        plan["reasons"]
            .as_array()
            .expect("reasons array")
            .iter()
            .any(|r| r.as_str().is_some_and(|s| s.contains("protected")))
    );
    assert!(
        plan["reasons"]
            .as_array()
            .expect("reasons array")
            .iter()
            .any(|r| r.as_str().is_some_and(|s| s.contains("Service Connection")))
    );
}

#[tokio::test]
async fn preflight_dispatch_discovers_missing_github_service_for_resolve_access() {
    let rows = run_preflight(
        json!({ "fallback": "jit", "context": "interactive" }),
        json!([preflight_missing_github_service_pr_create_action()]),
    )
    .await;
    let plan = &rows[0]["access_resolution_plan"];
    assert_eq!(rows[0]["status"], "missing");
    assert_eq!(
        plan["denied_action"],
        "registry.ember.systems/ember-systems/ember-gh/pr_create@v1"
    );
    assert_eq!(plan["collapse_eligibility"]["eligible"], false);
    assert_eq!(plan["target_evidence"]["confidence"], "advisory");
    assert_eq!(plan["steps"][0]["kind"], "install_service");
    assert_eq!(
        plan["steps"][0]["service_ref"]["display_name"],
        "GitHub Service"
    );
    assert_eq!(
        plan["steps"][0]["publisher_trust"]["provenance"],
        "bundled Ember Systems Service manifest"
    );
    assert_eq!(plan["steps"][1]["kind"], "connect_service");
    assert_eq!(
        plan["steps"][1]["envelope"]["service_connection"],
        "GitHub Service Connection"
    );
    assert_eq!(plan["steps"][2]["kind"], "issue_grant");
    assert_eq!(
        plan["steps"][2]["grant_delta"]["statements"][0]["actions"][0],
        "github:metadata:read"
    );
    assert_eq!(
        plan["steps"][2]["grant_delta"]["statements"][1]["actions"][0],
        "github:contents:write"
    );
}

#[tokio::test]
async fn preflight_dispatch_deny_without_grants_under_strict() {
    let rows = run_preflight(
        json!({ "fallback": "strict", "context": "interactive" }),
        json!([preflight_gh_action()]),
    )
    .await;
    assert_eq!(rows[0]["status"], "deny");
}

#[tokio::test]
async fn preflight_dispatch_accepts_delegated_delegation_template() {
    // A delegated lane supplies a delegation template name. With no delegable
    // parent grant in the store the intersection is empty, so an out-of-scope
    // gh action denies under strict — and the template name resolves (embedded
    // bundle) without erroring the dispatch.
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();
    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        preflight_connect_only_ctx(),
        "preflight_authority_coverage",
        &json!({
            "posture": { "fallback": "strict", "context": "interactive" },
            "delegation_template": "read-only",
            "actions": [preflight_gh_action()],
        }),
    )
    .await
    .expect("preflight dispatch ok with delegation_template");
    let rows = result.as_array().expect("array result");
    assert_eq!(rows[0]["status"], "deny");
}

#[tokio::test]
async fn preflight_dispatch_accepts_inline_template_scope() {
    // `ember catalog plan` passes its proposed scope inline (no saved
    // template). With no delegable parent grant the intersection is empty, so
    // the gh action denies under strict — proving the inline-scope param is
    // accepted and routes through the delegated (parent ∩ scope) path.
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();
    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        preflight_connect_only_ctx(),
        "preflight_authority_coverage",
        &json!({
            "posture": { "fallback": "strict", "context": "interactive" },
            "inline_template_scope": [
                "registry.ember.systems/ember-systems/ember-gh/pr_create@v1"
            ],
            "actions": [preflight_gh_action()],
        }),
    )
    .await
    .expect("preflight dispatch ok with inline_template_scope");
    let rows = result.as_array().expect("array result");
    assert_eq!(rows[0]["status"], "deny");
}

#[tokio::test]
async fn preflight_dispatch_missing_when_action_ref_absent() {
    let rows = run_preflight(
        json!({ "fallback": "jit", "context": "interactive" }),
        json!([{ "service": "legacy-svc", "default_policy": "permit" }]),
    )
    .await;
    assert_eq!(rows[0]["status"], "missing");
}

#[tokio::test]
async fn preflight_dispatch_rejects_missing_actions_param() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();
    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        preflight_connect_only_ctx(),
        "preflight_authority_coverage",
        &json!({ "posture": { "fallback": "jit" } }),
    )
    .await
    .expect_err("missing 'actions' must be a param error");
    assert_eq!(err.0, -32602);
}
