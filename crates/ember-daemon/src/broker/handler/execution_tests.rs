//! Execution-contract regression tests for broker resolve and broker_exec.
//!
//! These tests share runner manifest, managed-worktree, attachment-session, and
//! construct carrier fixtures. Keeping them in one test Module preserves locality
//! without making the parent broker handler load every execution test fixture.

use super::*;
use core_broker::{BrokerProvider, MockBroker};
use core_event_types::{ActionRef, ExecutionContract};
use rusqlite;

use crate::broker::runners::{
    resolve_binary_from_action_ref_with_manifest, resolve_runner_cwd,
    resolve_workspace_ref_to_path_from_home,
};

use super::exec::{
    allocate_broker_exec_home, check_classification_refusal, reset_broker_exec_inflight_for_test,
};

/// Build a registry containing both Cloudflare and Anthropic mock
/// brokers. Tests use `aws_sts` / `github` / etc. as the
/// "unknown provider" case to keep error-path coverage explicit.
fn fresh_registry() -> BrokerRegistry {
    let mut reg = BrokerRegistry::new();
    reg.register(Box::new(MockBroker::new(BrokerProvider::Cloudflare)));
    reg.register(Box::new(MockBroker::new(BrokerProvider::Anthropic)));
    reg
}

/// Same as `issue_params` but with `caller_persona` set so the HITL poll
/// path (`submit_approval`) has a non-empty persona id. The grant-scope
/// gate's `list_active_grants()` filter returns empty when no matching
/// grant is seeded — the HITL tests skip that gate by NOT seeding a
/// grant; the gate then returns -32003 BEFORE policy evaluation. So
/// HITL tests must seed a matching active grant before issuing.
fn issue_params_hitl(ttl_secs: u64, reason: &str, persona_id: &str) -> Value {
    json!({
        "provider": "anthropic",
        "ttl": ttl_secs,
        "reason": reason,
        "caller_persona": persona_id,
    })
}

fn create_budgeted_anthropic_grant(
    store: &DaemonStore,
    persona_id: &str,
) -> crate::trust::grant::GrantInfo {
    store
        .create_grant_with_budget(
            persona_id,
            "anthropic",
            "dns:edit",
            None,
            Some(core_grant_types::Budget {
                requests: Some(100),
                ..core_grant_types::Budget::default()
            }),
        )
        .expect("create budgeted anthropic grant")
}

/// Return a `PolicyEngine` whose default for `credential.access.*` is
/// `Auto` so tests that do not exercise HITL flow skip the poll loop.
fn auto_policy() -> crate::trust::policy::PolicyEngine {
    use crate::trust::policy::ApprovalRequirement;
    use core_approval::policy::{PolicyConfig, PolicyRule, RiskLevel};
    crate::trust::policy::PolicyEngine::new(PolicyConfig {
        rules: vec![PolicyRule {
            action: core_approval::policy::ActionSelector::named("*"),
            risk: RiskLevel::Low,
            requirement: ApprovalRequirement::Auto,
            tier: None,
        }],
        default_requirement: ApprovalRequirement::Auto,
        default_risk: RiskLevel::Low,
    })
}

fn broker_exec_home_is_sandbox_safe(path: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        path.starts_with("/tmp/emberd-") || path.starts_with("/private/tmp/emberd-")
    }

    #[cfg(not(target_os = "macos"))]
    {
        std::path::Path::new(path).starts_with(std::env::temp_dir())
    }
}

#[tokio::test]
async fn broker_exec_runs_a_simple_command() {
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::scripted(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
        "#!/bin/sh\nprintf 'hello world\\n'\n",
    );
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let req = fixture.exec_request(&["pr", "merge", "123"]);
    let result = handle_broker_exec(None, &store, &req).await;
    let resp_value = result.expect("ok");
    let resp: BrokerExecResponse = serde_json::from_value(resp_value).expect("deserialize");
    assert_eq!(resp.exit_code, 0);
    assert!(resp.success);
    assert_eq!(resp.stdout_tail, "hello world\n");
    assert!(resp.stderr_tail.is_empty());
}

#[tokio::test]
async fn broker_exec_records_inflight_telemetry_when_enabled() {
    let _guard = process_state_test_guard();
    reset_broker_exec_inflight_for_test();
    struct ResetTelemetry;
    impl Drop for ResetTelemetry {
        fn drop(&mut self) {
            let _ = crate::telemetry::measurement::disable_collection_and_purge();
            crate::telemetry::measurement::set_output_dir(None);
            reset_broker_exec_inflight_for_test();
        }
    }
    let _reset = ResetTelemetry;

    let dir = tempfile::tempdir().expect("tempdir");
    crate::telemetry::measurement::set_output_dir(Some(dir.path().to_path_buf()));
    crate::telemetry::measurement::enable_collection();

    let fixture = RunnerFixture::scripted(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_list",
        "#!/bin/sh\nprintf 'listed\\n'\n",
    );
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let req = fixture.exec_request(&["pr", "list", "--limit", "1"]);
    let resp_value = handle_broker_exec(None, &store, &req).await.expect("ok");
    let resp: BrokerExecResponse = serde_json::from_value(resp_value).expect("deserialize");
    assert!(resp.success);

    let csv_path = std::fs::read_dir(dir.path())
        .expect("telemetry dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().and_then(|e| e.to_str()) == Some("csv"))
        .expect("daily telemetry file written");
    let raw = std::fs::read_to_string(csv_path).expect("read telemetry");
    let saw_inflight = raw.lines().any(|line| {
        matches!(
            serde_json::from_str::<crate::telemetry::measurement::SampleRow>(line),
            Ok(crate::telemetry::measurement::SampleRow::InflightSample {
                cohort,
                concurrent,
                ..
            }) if cohort == "dev0" && concurrent >= 1
        )
    });
    assert!(
        saw_inflight,
        "broker_exec dispatch should emit an anonymous inflight telemetry row"
    );
}

#[tokio::test]
async fn broker_exec_prompt_policy_requires_attachment_local_approval_and_consumes_once() {
    use crate::trust::approval::ApprovalOutcome;
    use base64::Engine as _;

    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::scripted(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
        "#!/bin/sh\nprintf 'approved once\\n'\n",
    );
    let wrapped_gh =
        write_fixture_wrapped_binary(&fixture, "gh", "#!/bin/sh\nprintf 'approved once\\n'\n");
    let manifest_toml = v2_carrier_for_test(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        &wrapped_gh,
        "",
        &[("pr_merge", Some("prompt"), None)],
    );
    let construct_toml_bytes =
        base64::engine::general_purpose::STANDARD.encode(manifest_toml.as_bytes());
    let sessions_root = tempfile::tempdir().expect("tempdir");
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let runtime_persona = store
        .create_persona("persona-runtime-approval")
        .expect("create runtime persona");
    make_runtime_attachment_session(
        sessions_root.path(),
        "sess-approval",
        &runtime_persona.id,
        "binding-approval",
        "att-approval",
        "ep-approval",
    );
    let mut req = fixture.exec_request(&["pr", "merge", "123"]);
    req["construct_toml_bytes"] = json!(construct_toml_bytes);
    req["session_id"] = json!("sess-approval");
    req["caller_persona"] = json!(runtime_persona.id);
    req["attachment_id"] = json!("att-approval");
    req["attachment_endpoint_token"] = json!("ep-approval");

    let first = handle_broker_exec_with_sessions(None, &store, Some(sessions_root.path()), &req)
        .await
        .expect("approval-required response");
    assert_eq!(first["approval_required"], json!(true));
    let approval_id = first["approval_request_id"]
        .as_str()
        .expect("approval request id")
        .to_string();
    assert_eq!(
        store
            .get_approval(&approval_id)
            .expect("pending approval")
            .status,
        "pending"
    );

    store
        .resolve_approval(&approval_id, &ApprovalOutcome::Approved)
        .expect("approve decision-only binding");

    let second = handle_broker_exec_with_sessions(None, &store, Some(sessions_root.path()), &req)
        .await
        .expect("approved run");
    let resp: BrokerExecResponse = serde_json::from_value(second.clone()).expect("response");
    assert!(resp.success);
    assert!(!resp.approval_required);
    assert_eq!(resp.stdout_tail, "approved once\n");
    assert_eq!(
        second["authority_ref"],
        json!(format!("approval:{approval_id}"))
    );
    assert_eq!(
        store
            .get_approval(&approval_id)
            .expect("consumed approval")
            .status,
        "consumed"
    );

    let third = handle_broker_exec_with_sessions(None, &store, Some(sessions_root.path()), &req)
        .await
        .expect("fresh approval-required response");
    assert_eq!(third["approval_required"], json!(true));
    let second_approval_id = third["approval_request_id"]
        .as_str()
        .expect("second approval request id");
    assert_ne!(second_approval_id, approval_id);
}

#[tokio::test]
async fn broker_exec_does_not_consume_approval_when_later_refused() {
    use crate::trust::approval::ApprovalOutcome;
    use base64::Engine as _;

    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::scripted(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_create",
        "#!/bin/sh\nprintf 'should not run\\n'\n",
    );
    std::fs::remove_dir_all(fixture.worktree_path.join(".git")).expect("remove fake git dir");
    run_git_in(&fixture.worktree_path, &["init", "-q", "-b", "main"]);
    run_git_in(&fixture.worktree_path, &["config", "user.email", "t@t"]);
    run_git_in(&fixture.worktree_path, &["config", "user.name", "t"]);
    run_git_in(
        &fixture.worktree_path,
        &["config", "commit.gpgsign", "false"],
    );
    std::fs::write(fixture.worktree_path.join("README.md"), "seed\n").unwrap();
    run_git_in(&fixture.worktree_path, &["add", "README.md"]);
    run_git_in(&fixture.worktree_path, &["commit", "-qm", "seed"]);
    run_git_in(
        &fixture.worktree_path,
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    );
    std::fs::write(fixture.worktree_path.join(".classification"), "PUBLIC\n").unwrap();
    run_git_in(&fixture.worktree_path, &["add", ".classification"]);
    run_git_in(&fixture.worktree_path, &["commit", "-qm", "classification"]);
    let wrapped_gh =
        write_fixture_wrapped_binary(&fixture, "gh", "#!/bin/sh\nprintf 'should not run\\n'\n");

    let manifest_toml = v2_carrier_for_test(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        &wrapped_gh,
        "",
        &[("pr_create", Some("prompt"), None)],
    );
    let construct_toml_bytes =
        base64::engine::general_purpose::STANDARD.encode(manifest_toml.as_bytes());
    let sessions_root = tempfile::tempdir().expect("tempdir");
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let runtime_persona = store
        .create_persona("persona-runtime-approval-refusal")
        .expect("create runtime persona");
    make_runtime_attachment_session(
        sessions_root.path(),
        "sess-approval-refusal",
        &runtime_persona.id,
        "binding-approval-refusal",
        "att-approval-refusal",
        "ep-approval-refusal",
    );
    let mut req = fixture.exec_request(&["pr", "create"]);
    req["construct_toml_bytes"] = json!(construct_toml_bytes);
    req["session_id"] = json!("sess-approval-refusal");
    req["caller_persona"] = json!(runtime_persona.id);
    req["attachment_id"] = json!("att-approval-refusal");
    req["attachment_endpoint_token"] = json!("ep-approval-refusal");

    let first = handle_broker_exec_with_sessions(None, &store, Some(sessions_root.path()), &req)
        .await
        .expect("approval-required response");
    let approval_id = first["approval_request_id"]
        .as_str()
        .expect("approval request id")
        .to_string();
    store
        .resolve_approval(&approval_id, &ApprovalOutcome::Approved)
        .expect("approve decision-only binding");

    let (code, msg) =
        handle_broker_exec_with_sessions(None, &store, Some(sessions_root.path()), &req)
            .await
            .expect_err("classification refusal must abort before spawn");
    assert_eq!(code, -32011, "unexpected refusal: {msg}");
    assert_eq!(
        store
            .get_approval(&approval_id)
            .expect("approval must remain available")
            .status,
        "approved"
    );
}

#[tokio::test]
async fn broker_exec_propagates_nonzero_exit() {
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::scripted(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
        "#!/bin/sh\nexit 1\n",
    );
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let req = fixture.exec_request(&["pr", "merge", "123"]);
    let resp_value = handle_broker_exec(None, &store, &req).await.expect("ok");
    let resp: BrokerExecResponse = serde_json::from_value(resp_value).expect("deserialize");
    assert_ne!(resp.exit_code, 0);
    assert!(!resp.success);
}

#[tokio::test]
async fn broker_exec_surfaces_stdout_tail_on_non_pty_path() {
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::scripted(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
        "#!/bin/sh\nprintf 'stdout-visible'\nexit 1\n",
    );
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let req = fixture.exec_request(&["pr", "merge", "123"]);
    let resp_value = handle_broker_exec(None, &store, &req).await.expect("ok");
    assert_eq!(
        resp_value.get("exit_code").and_then(|v| v.as_i64()),
        Some(1),
        "probe command should fail so the output path is observable"
    );
    assert_eq!(
        resp_value.get("stdout_tail").and_then(|v| v.as_str()),
        Some("stdout-visible"),
        "non-PTY broker_exec must preserve child stdout for headless launcher shims"
    );
}

#[test]
fn allocate_broker_exec_home_uses_sandbox_safe_root() {
    let dir = allocate_broker_exec_home().expect("broker_exec HOME tempdir");
    let observed = dir.path().to_string_lossy();
    assert!(
        broker_exec_home_is_sandbox_safe(&observed),
        "broker_exec HOME tempdir must stay under the sandbox-safe temp roots: {observed}"
    );
}

#[tokio::test]
async fn broker_exec_rejects_invalid_env_passthrough_name() {
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
    );
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let mut req = fixture.exec_request(&["pr", "merge", "123"]);
    req["env_passthrough"] = json!(["lowercase_bad"]);
    let result = handle_broker_exec(None, &store, &req).await;
    assert!(result.is_err(), "should reject invalid env name");
}

#[tokio::test]
async fn broker_exec_rejects_missing_nested_execution_contract() {
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let req = serde_json::json!({
        "action_ref": ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_merge",
            "v1"
        ),
        "workspace_ref": "managed_worktree:test",
        "argv": [],
        "env_passthrough": [],
    });

    let (code, msg) = handle_broker_exec(None, &store, &req)
        .await
        .expect_err("broker_exec must require nested execution_contract");

    assert_eq!(code, -32602);
    assert!(
        msg.contains("missing_execution_contract"),
        "error must name the missing nested contract: {msg}"
    );
}

#[tokio::test]
async fn broker_exec_rejects_legacy_binary_field() {
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let req = serde_json::json!({
        "binary": "/usr/bin/true",
        "argv": [],
        "env_passthrough": [],
    });

    let (code, msg) = handle_broker_exec(None, &store, &req)
        .await
        .expect_err("legacy binary must be rejected");

    assert_eq!(code, -32602);
    assert!(
        msg.contains("legacy binary"),
        "error must explain the removed binary field: {msg}"
    );
}

#[tokio::test]
async fn broker_exec_ignores_cwd_when_nested_workspace_ref_is_present() {
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
    );
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let mut req = fixture.exec_request(&["pr", "merge", "123"]);
    req["cwd"] = json!("/tmp");

    let resp_value = handle_broker_exec(None, &store, &req)
        .await
        .expect("cwd must be ignored when nested workspace_ref is present");
    let resp: BrokerExecResponse =
        serde_json::from_value(resp_value).expect("deserialize response");
    assert!(resp.success);

    let rows = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("session.construct_invocation".to_string()),
            ..Default::default()
        })
        .expect("audit query");
    assert_eq!(rows.len(), 1, "one construct invocation receipt expected");
    let details: serde_json::Value =
        serde_json::from_str(rows[0].details.as_deref().unwrap_or("{}")).expect("details");
    assert_eq!(
        details.get("runner_cwd_source"),
        Some(&json!("workspace_ref"))
    );
}

#[tokio::test]
async fn broker_exec_uses_attachment_workspace_binding_without_home_scan_metadata() {
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::scripted(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_list",
        "#!/bin/sh\npwd\n",
    );
    std::fs::remove_file(fixture.worktree_path.join(".agent-session"))
        .expect("remove home-scan metadata");

    let sessions_root = tempfile::tempdir().expect("sessions root");
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let runtime_persona = store
        .create_persona("persona-runtime-workspace-binding")
        .expect("create runtime persona");
    make_runtime_attachment_session_with_workspace(
        sessions_root.path(),
        "sess-workspace-binding",
        &runtime_persona.id,
        "binding-workspace",
        "att-workspace",
        "ep-workspace",
        &fixture.workspace_ref(),
        &fixture.worktree_path,
    );

    let mut req = fixture.exec_request(&["pr", "list", "--limit", "1"]);
    req["session_id"] = json!("sess-workspace-binding");
    req["caller_persona"] = json!(runtime_persona.id);
    req["attachment_id"] = json!("att-workspace");
    req["attachment_endpoint_token"] = json!("ep-workspace");

    let resp_value =
        handle_broker_exec_with_sessions(None, &store, Some(sessions_root.path()), &req)
            .await
            .expect("registered attachment workspace binding should resolve cwd");
    let resp: BrokerExecResponse =
        serde_json::from_value(resp_value).expect("deserialize response");
    assert!(resp.success);
    let canonical_worktree = fixture.worktree_path.canonicalize().expect("canonical");
    assert_eq!(
        resp.stdout_tail.trim(),
        canonical_worktree.to_string_lossy(),
        "runner should execute in the session-registered workspace path"
    );
}

#[test]
fn resolve_runner_cwd_uses_compatibility_cwd_when_workspace_ref_absent() {
    let temp = tempfile::tempdir().expect("tempdir");
    let nested = temp.path().join("nested");
    std::fs::create_dir_all(&nested).expect("create nested dir");

    let (cwd, source) = resolve_runner_cwd(None, Some(nested.to_str().expect("utf-8 path")))
        .expect("compatibility cwd fallback should resolve");

    assert_eq!(
        cwd,
        nested
            .canonicalize()
            .expect("canonical path")
            .to_string_lossy()
            .into_owned()
    );
    assert_eq!(source.as_str(), "compatibility_cwd");
}

struct ProcessStateTestGuard {
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl Drop for ProcessStateTestGuard {
    fn drop(&mut self) {
        crate::infra::handler::force_quarantine_latch_for_test(false);
    }
}

/// Serialize tests that mutate process-global env vars and assert audit rows.
/// The audit quarantine latch is also process-global, so clear it while holding
/// the repo-wide test lock and restore it on drop.
fn process_state_test_guard() -> ProcessStateTestGuard {
    let guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    crate::infra::handler::force_quarantine_latch_for_test(false);
    ProcessStateTestGuard { _guard: guard }
}

fn write_fake_runner_binary(path: &std::path::Path) {
    if std::os::unix::fs::symlink("/usr/bin/true", path).is_err() {
        std::fs::write(path, b"#!/bin/sh\nexec /usr/bin/true \"$@\"\n")
            .expect("write fake runner binary");
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).expect("chmod fake runner binary");
    }
}

fn write_runner_manifest(
    home: &std::path::Path,
    tool_name: &str,
    binary_path: &std::path::Path,
) -> std::path::PathBuf {
    let manifest_dir = home.join(".ember/binaries");
    std::fs::create_dir_all(&manifest_dir).expect("mkdir manifest dir");
    let manifest_path = manifest_dir.join("manifest.toml");
    let manifest_body = format!(
        "\
[[entries]]
tool_name = \"{tool_name}\"
version = \"1.0.0\"
content_hash = \"blake3:test\"
absolute_path = \"{}\"
installed_at = 1735689600
publisher = \"did:emberlink\"
channel = \"bundled\"
",
        binary_path.display()
    );
    std::fs::write(&manifest_path, manifest_body).expect("write runner manifest");
    manifest_path
}

fn write_managed_worktree(home: &std::path::Path, runtime_id: &str) -> std::path::PathBuf {
    let worktree_path = home.join("repo/.ember/worktrees/demo");
    std::fs::create_dir_all(worktree_path.join(".git")).expect("mkdir worktree git dir");
    std::fs::write(
        worktree_path.join(".agent-session"),
        format!(
            "runtime_id: {runtime_id}\nworktree_path: {}\n",
            worktree_path.display()
        ),
    )
    .expect("write managed worktree metadata");
    worktree_path
}

fn write_executable_script(path: &std::path::Path, body: &str) {
    std::fs::write(path, body).expect("write runner script");
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).expect("chmod runner script");
}

struct HomeEnvGuard {
    previous_home: Option<std::ffi::OsString>,
    previous_manifest_path: Option<std::ffi::OsString>,
}

impl HomeEnvGuard {
    fn set(home: &std::path::Path, manifest_path: &std::path::Path) -> Self {
        let previous_home = std::env::var_os("HOME");
        let previous_manifest_path = std::env::var_os("EMBER_MANIFEST_PATH");
        unsafe {
            std::env::set_var("HOME", home);
            std::env::set_var("EMBER_MANIFEST_PATH", manifest_path);
        }
        Self {
            previous_home,
            previous_manifest_path,
        }
    }
}

impl Drop for HomeEnvGuard {
    fn drop(&mut self) {
        match self.previous_home.take() {
            Some(home) => unsafe {
                std::env::set_var("HOME", home);
            },
            None => unsafe {
                std::env::remove_var("HOME");
            },
        }
        match self.previous_manifest_path.take() {
            Some(path) => unsafe {
                std::env::set_var("EMBER_MANIFEST_PATH", path);
            },
            None => unsafe {
                std::env::remove_var("EMBER_MANIFEST_PATH");
            },
        }
    }
}

struct RunnerFixture {
    _home: tempfile::TempDir,
    _home_guard: HomeEnvGuard,
    runtime_id: String,
    binary_path: std::path::PathBuf,
    worktree_path: std::path::PathBuf,
    action_ref: ActionRef,
}

impl RunnerFixture {
    fn symlinked(tool_name: &str, plugin_address: &str, action_key: &str) -> Self {
        Self::new(tool_name, plugin_address, action_key, None)
    }

    fn scripted(
        tool_name: &str,
        plugin_address: &str,
        action_key: &str,
        script_body: &str,
    ) -> Self {
        Self::new(tool_name, plugin_address, action_key, Some(script_body))
    }

    fn new(
        tool_name: &str,
        plugin_address: &str,
        action_key: &str,
        script_body: Option<&str>,
    ) -> Self {
        let home = tempfile::tempdir().expect("tempdir");
        let binary_path = home.path().join(format!("bin/{tool_name}"));
        std::fs::create_dir_all(binary_path.parent().expect("parent")).expect("mkdir bin dir");
        if let Some(script_body) = script_body {
            write_executable_script(&binary_path, script_body);
        } else {
            write_fake_runner_binary(&binary_path);
        }
        let manifest_path = write_runner_manifest(home.path(), tool_name, &binary_path);
        let runtime_id = format!("rt-{}", uuid::Uuid::new_v4().simple());
        let worktree_path = write_managed_worktree(home.path(), &runtime_id);
        let home_guard = HomeEnvGuard::set(home.path(), &manifest_path);

        Self {
            _home: home,
            _home_guard: home_guard,
            runtime_id,
            binary_path,
            worktree_path,
            action_ref: ActionRef::new(plugin_address, action_key, "v1"),
        }
    }

    fn workspace_ref(&self) -> String {
        format!("managed_worktree:{}", self.runtime_id)
    }

    fn execution_contract(&self) -> ExecutionContract {
        let mut execution_contract = ExecutionContract::new(self.action_ref.clone());
        execution_contract.workspace_ref = Some(self.workspace_ref());
        execution_contract
    }

    fn exec_request(&self, argv: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "execution_contract": self.execution_contract(),
            "argv": argv,
            "env_passthrough": [],
        })
    }

    fn lease_request_params(
        &self,
        env_passthrough: &[&str],
        construct_toml_hash_input_len: u64,
    ) -> serde_json::Value {
        serde_json::json!({
            "execution_contract": self.execution_contract(),
            "lease_request": {
                "action_ref": self.action_ref,
                "env_passthrough": env_passthrough,
                "construct_toml_hash_input_len": construct_toml_hash_input_len,
            }
        })
    }
}

fn write_fixture_wrapped_binary(fixture: &RunnerFixture, command: &str, body: &str) -> String {
    let path = fixture
        .binary_path
        .parent()
        .expect("fixture bin parent")
        .join(command);
    write_executable_script(&path, body);
    path.to_string_lossy().into_owned()
}

/// Build a full ADR-196 v2 `construct.toml` carrier for broker-exec tests.
/// The carrier-load seam (`resolve_action_ref`) validates the full manifest
/// fail-closed, so test carriers can no longer be identity-only stubs.
/// `actions` is `(action_key, default_policy, mode)`; the policy fields are
/// emitted only when `Some` (they feed the separate exec-policy parser).
/// `rail_block` is appended verbatim (e.g. `""`, `"[rail]\n"`, or
/// `"[rail]\ntrust_contract = \"ephemeral_sign\"\n"`).
fn v2_carrier_for_test(
    name: &str,
    plugin_address: &str,
    wrapped_binary: &str,
    rail_block: &str,
    actions: &[(&str, Option<&str>, Option<&str>)],
) -> String {
    let mut out = format!(
        "schema_version = \"2\"\n\n\
             [meta]\n\
             name = \"{name}\"\n\
             plugin_address = \"{plugin_address}\"\n\
             plugin_version = \"1.0.0\"\n\
             publisher = \"did:emberlink\"\n\
             provider_kind = \"cli\"\n\
             summary = \"broker-exec test carrier\"\n\
             description = \"Full v2 carrier used by broker-exec tests.\"\n\n\
             [defaults]\n\
             materialization_class = \"brokered_credential\"\n\
             material_classes = [{{ kind = \"broker\", authority_ref = \"test\" }}]\n\
             default_runner_classes = [\"local_trusted\"]\n\n\
             [runtime.cli]\n\
             wrapped_binary = \"{wrapped_binary}\"\n{rail_block}"
    );
    for (key, default, mode) in actions {
        out.push_str(&format!(
            "\n[[actions]]\n\
                 key = \"{key}\"\n\
                 action_version = \"v1\"\n\
                 summary = \"test action\"\n\
                 input_schema = {{ kind = \"argv\", classifier = \"* *\" }}\n\
                 risk_tier = \"medium\"\n\
                 idempotency = \"non_idempotent\"\n\
                 interaction_class = \"inline_interactive\"\n\
                 audit_fields = [\"action_ref\", \"terminal_outcome\"]\n\
                 handler_ref = \"cli:{key}\"\n"
        ));
        if let Some(default) = default {
            out.push_str(&format!("default = \"{default}\"\n"));
        }
        if let Some(mode) = mode {
            out.push_str(&format!("mode = \"{mode}\"\n"));
        }
    }
    out
}

fn make_runtime_attachment_session(
    sessions_dir: &std::path::Path,
    session_id: &str,
    persona: &str,
    binding_id: &str,
    attachment_id: &str,
    endpoint_token: &str,
) {
    use chrono::Utc;
    use core_state::sessions::{AttachmentEndpoint, SessionMeta, SessionStore};

    let store = SessionStore::new(sessions_dir.to_path_buf());
    store
        .create(&SessionMeta {
            session_id: session_id.to_string(),
            persona: persona.to_string(),
            grant_id: "grant_runtime".to_string(),
            started_at: Utc::now(),
            launcher_pid: std::process::id(),
            authority_strict: false,
            delegation_id: None,
            delegation_template: None,
            durable_persona: Some("persona_durable".to_string()),
            caller_binding_id: Some(binding_id.to_string()),
        })
        .expect("create runtime session");
    store
        .write_attachment_endpoint(
            session_id,
            &AttachmentEndpoint::active(attachment_id.to_string(), endpoint_token.to_string()),
        )
        .expect("write attachment endpoint");
}

fn make_runtime_attachment_session_with_workspace(
    sessions_dir: &std::path::Path,
    session_id: &str,
    persona: &str,
    binding_id: &str,
    attachment_id: &str,
    endpoint_token: &str,
    workspace_ref: &str,
    worktree_path: &std::path::Path,
) {
    use core_state::sessions::{SessionStore, SessionWorkspaceBinding};

    make_runtime_attachment_session(
        sessions_dir,
        session_id,
        persona,
        binding_id,
        attachment_id,
        endpoint_token,
    );
    let store = SessionStore::new(sessions_dir.to_path_buf());
    store
        .write_workspace_binding(
            session_id,
            &SessionWorkspaceBinding {
                workspace_ref: workspace_ref.to_string(),
                worktree_path: worktree_path.to_path_buf(),
            },
        )
        .expect("write workspace binding");
}

#[tokio::test]
async fn resolve_refuses_unsigned_script_outside_registered_paths() {
    // T2 acceptance for END-USER-REFUSE flow: registry empty
    // (mimics fresh end-user install). Script outside any registered
    // path → daemon refuses with `authoring_path_not_registered`,
    // emits the refusal Receipt.
    let _guard = process_state_test_guard();
    let tmp = tempfile::tempdir().expect("tempdir");
    let registry_file = tmp.path().join("authoring-paths.toml");
    // Don't write anything — registry file missing → empty registry.
    unsafe {
        std::env::set_var("EMBER_AUTHORING_PATHS_FILE", &registry_file);
    }

    let script = tmp.path().join("hostile.py");
    std::fs::write(&script, b"# unsigned").unwrap();

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let params = serde_json::json!({
        "script_path": script.to_string_lossy(),
        "signed_binary": false,
    });
    let registry = BrokerRegistry::new();
    let result = resolve_with_registry(&registry, &store, &params, None, None).await;
    unsafe {
        std::env::remove_var("EMBER_AUTHORING_PATHS_FILE");
    }
    let (code, msg) = result.expect_err("must refuse");
    assert_eq!(code, -32003, "expected policy-rejected code, got {code}");
    assert!(
        msg.contains("authoring_path_not_registered"),
        "error must name the refusal: {msg}"
    );

    let rows = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("broker.resolve.refused".to_string()),
            ..Default::default()
        })
        .expect("audit query");
    assert_eq!(rows.len(), 1, "refusal Receipt must be emitted");
    assert_eq!(rows[0].outcome, "denied");
}

#[tokio::test]
async fn resolve_accepts_authoring_script_from_registered_path() {
    // T2 acceptance for AUTHOR flow: register `~/code/my-construct/`,
    // run a script in that dir → daemon emits authoring receipt
    // (`authoring = true`). Plaintext wiring still TZ-BROKER-RESOLVE-
    // IMPL so the call returns -32001, but the gate's authoring
    // accept Receipt fires first and is recorded.
    let _guard = process_state_test_guard();
    let tmp = tempfile::tempdir().expect("tempdir");

    // Author registers their worktree.
    let worktree = tmp.path().join("code/my-construct");
    std::fs::create_dir_all(&worktree).unwrap();
    let canonical = std::fs::canonicalize(&worktree).unwrap();
    let registry_file = tmp.path().join("authoring-paths.toml");
    std::fs::write(
        &registry_file,
        format!("paths = [\"{}\"]\n", canonical.display()),
    )
    .unwrap();
    unsafe {
        std::env::set_var("EMBER_AUTHORING_PATHS_FILE", &registry_file);
    }

    // Script lives inside the registered path.
    let script = worktree.join("run.py");
    std::fs::write(&script, b"# author's script").unwrap();

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let params = serde_json::json!({
        "script_path": script.to_string_lossy(),
        "signed_binary": false,
    });
    let registry = BrokerRegistry::new();
    let result = resolve_with_registry(&registry, &store, &params, None, None).await;
    unsafe {
        std::env::remove_var("EMBER_AUTHORING_PATHS_FILE");
    }
    // Plaintext wiring not implemented yet; the call ends in -32001
    // BUT the authoring-accept Receipt was emitted en route.
    let (code, _msg) = result.expect_err("plaintext wiring not yet impl");
    assert_eq!(
        code, -32001,
        "expected NotSupported placeholder, got {code}"
    );

    let rows = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("broker.resolve.authoring".to_string()),
            ..Default::default()
        })
        .expect("audit query");
    assert_eq!(
        rows.len(),
        1,
        "authoring accept Receipt must be emitted before the placeholder error"
    );
    assert_eq!(rows[0].outcome, "allowed");
    // Receipt details must record `authoring = true`.
    let details: serde_json::Value =
        serde_json::from_str(rows[0].details.as_deref().unwrap_or("{}")).unwrap();
    assert_eq!(
        details.get("authoring").and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[tokio::test]
async fn resolve_projects_successful_claim_into_session_and_grant_scopes() {
    let reg = fresh_registry();
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let persona = store.create_persona("resolve-journal-persona").unwrap();
    let grant = create_budgeted_anthropic_grant(&store, &persona.id);
    let issued = issue_with_registry(
        &reg,
        &store,
        &issue_params_hitl(120, "resolve-journal", &persona.id),
        &auto_policy(),
    )
    .await
    .expect("issue should succeed");
    let secret_ref = issued["secret_ref"]
        .as_str()
        .expect("secret_ref must be present")
        .to_string();

    let params = serde_json::json!({
        "secret_ref": secret_ref,
        "caller_persona": persona.id,
        "session_id": "session-journal-1",
        "action_key": "git.push",
    });
    let result = resolve_with_registry(
        &reg,
        &store,
        &params,
        None,
        Some(DelegationReceiptContext::per_action_fallthrough()),
    )
    .await
    .expect("resolve should succeed");
    assert_eq!(
        result["materialization_id"].as_str(),
        params["secret_ref"].as_str()
    );

    let claim_count: i64 = store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM claim_journal_claims WHERE scope_kind = 'session' AND scope_id = 'session-journal-1'",
                [],
                |row| row.get(0),
            )
            .expect("claim count query");
    assert_eq!(
        claim_count, 1,
        "one successful resolve must land one claim journal row"
    );

    let grant_claim_count: i64 = store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM claim_journal_claims WHERE scope_kind = 'grant' AND scope_id = ?1",
                rusqlite::params![grant.id],
                |row| row.get(0),
            )
            .expect("grant claim count query");
    assert_eq!(
        grant_claim_count, 1,
        "one successful resolve must project into the composite grant scope"
    );

    let source_key: String = store
            .conn()
            .query_row(
                "SELECT source_key FROM claim_journal_claims WHERE scope_kind = 'session' AND scope_id = 'session-journal-1'",
                [],
                |row| row.get(0),
            )
            .expect("source_key query");
    assert_eq!(source_key, params["secret_ref"].as_str().unwrap());

    let distinct_audit_event_ids: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(DISTINCT audit_event_id)
                   FROM claim_journal_claims
                  WHERE source_key = ?1",
            rusqlite::params![params["secret_ref"].as_str().unwrap()],
            |row| row.get(0),
        )
        .expect("distinct audit_event_id query");
    assert_eq!(
        distinct_audit_event_ids, 1,
        "session/grant projections must share one audit evidence row"
    );

    let resolve_audit_rows = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("broker.resolve.materialized".to_string()),
            ..Default::default()
        })
        .expect("audit query");
    assert_eq!(resolve_audit_rows.len(), 1);
}

// ---------------------------------------------------------------------
// T-CONSTRUCT-EXEC-ENV-CONSTRUCT-TOML-LOCK — per-action env_passthrough
// ---------------------------------------------------------------------

#[tokio::test]
async fn broker_exec_strips_env_names_not_in_action_allowlist() {
    // T2 acceptance: shim sends env_passthrough=["GH_TOKEN", "PATH"]
    // for action `pr_create` whose construct.toml allowlist is
    // ["GH_TOKEN", "GITHUB_TOKEN", "GH_HOST"]. PATH is not in the
    // per-action allowlist (note: PATH IS in the daemon's hardcoded
    // baseline, which is separate from the per-action passthrough);
    // daemon must strip it from the request's env_passthrough and
    // record `env_passthrough_stripped: ["PATH"]` on the Receipt.
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
    );
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    // Set GH_TOKEN so the daemon has something to pass through.
    // SAFETY: tests run in-process; setting an env var is racy across
    // tests but the value here is a fixture that other tests don't read.
    unsafe {
        std::env::set_var("GH_TOKEN", "ghs_fake");
    }
    let mut req = fixture.exec_request(&["pr", "merge", "123"]);
    req["env_passthrough"] = json!(["GH_TOKEN", "PATH"]);
    req["action_env_allowlist"] = json!(["GH_TOKEN", "GITHUB_TOKEN", "GH_HOST"]);
    let resp_value = handle_broker_exec(None, &store, &req).await.expect("ok");
    let resp: BrokerExecResponse = serde_json::from_value(resp_value).expect("deserialize");
    assert_eq!(resp.exit_code, 0);

    // Inspect the receipt: env_passthrough_stripped must list PATH.
    let rows = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("session.construct_invocation".to_string()),
            ..Default::default()
        })
        .expect("audit query");
    let last = rows.last().expect("must have at least one receipt row");
    let details: serde_json::Value =
        serde_json::from_str(last.details.as_deref().unwrap_or("{}")).expect("details parse");
    let stripped = details
        .get("env_passthrough_stripped")
        .and_then(|v| v.as_array())
        .expect("env_passthrough_stripped must be present");
    let stripped_names: Vec<&str> = stripped.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(stripped_names, vec!["PATH"], "PATH must be stripped");
}

#[tokio::test]
async fn broker_exec_no_strip_when_allowlist_absent() {
    // Backwards-compat: when the request omits action_env_allowlist,
    // the strip path is a no-op and no env_passthrough_stripped field
    // is recorded.
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
    );
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let mut req = fixture.exec_request(&["pr", "merge", "123"]);
    req["env_passthrough"] = json!(["PATH"]);
    let resp_value = handle_broker_exec(None, &store, &req).await.expect("ok");
    let _resp: BrokerExecResponse = serde_json::from_value(resp_value).expect("deserialize");
    let rows = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("session.construct_invocation".to_string()),
            ..Default::default()
        })
        .expect("audit query");
    let last = rows.last().expect("receipt row");
    let details: serde_json::Value =
        serde_json::from_str(last.details.as_deref().unwrap_or("{}")).expect("details parse");
    assert!(
        details.get("env_passthrough_stripped").is_none(),
        "no strip should be recorded when allowlist is absent: {details}"
    );
}

#[tokio::test]
async fn broker_exec_receipt_records_supplied_session_id() {
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
    );
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let mut req = fixture.exec_request(&["pr", "merge", "123"]);
    req["session_id"] = json!("sess-runtime-fixture");

    let resp_value = handle_broker_exec(None, &store, &req).await.expect("ok");
    let _resp: BrokerExecResponse = serde_json::from_value(resp_value).expect("deserialize");

    let rows = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("session.construct_invocation".to_string()),
            ..Default::default()
        })
        .expect("audit query");
    let last = rows.last().expect("receipt row");
    let details: serde_json::Value =
        serde_json::from_str(last.details.as_deref().unwrap_or("{}")).expect("details parse");
    assert_eq!(
        details.get("session_id").and_then(|v| v.as_str()),
        Some("sess-runtime-fixture"),
        "broker_exec receipts must carry the real launcher session id when provided"
    );
}

/// META-BROKER-EXEC-CLEAN-HOME acceptance: the broker_exec child runs
/// with a per-spawn ephemeral HOME (a tempdir owned by the daemon uid),
/// NEVER the operator's HOME inherited from the daemon's launchd env.
/// This is the structural invariant that lets the broker's injected
/// credential be the only auth path the spawned tool can find — without
/// it, tools like `gh` scan the operator's `~/.config/` and either
/// permission-deny (separate-uid daemon) or consume operator-owned
/// credentials, defeating the broker's "only daemon-minted credentials
/// reach the child" invariant.
#[tokio::test]
async fn broker_exec_child_home_is_fresh_tempdir_not_operator_home() {
    let _guard = process_state_test_guard();
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let out_path = std::env::temp_dir().join(format!(
        "broker-exec-home-probe-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let _ = std::fs::remove_file(&out_path);

    // Run a shell that writes $HOME (as the child sees it) to a probe
    // file. Path goes via argv so the shell substitutes its own $HOME
    // — i.e. the env entry the daemon set, not the test process's.
    let fixture = RunnerFixture::scripted(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
        &format!(
            "#!/bin/sh\nprintf '%s' \"$HOME\" > \"{}\"\n",
            out_path.display()
        ),
    );
    let req = fixture.exec_request(&["pr", "merge", "123"]);
    let resp_value = handle_broker_exec(None, &store, &req).await.expect("ok");
    let resp: BrokerExecResponse = serde_json::from_value(resp_value).expect("deserialize");
    assert_eq!(resp.exit_code, 0, "child should exit 0");

    let observed_home =
        std::fs::read_to_string(&out_path).expect("child should have written HOME to probe file");
    let _ = std::fs::remove_file(&out_path);

    let operator_home = std::env::var("HOME").expect("test process HOME");
    assert_ne!(
        observed_home, operator_home,
        "broker_exec child HOME ({observed_home}) MUST NOT equal the daemon's inherited HOME ({operator_home}) — operator config-dir isolation regressed"
    );
    assert!(
        !observed_home.is_empty(),
        "broker_exec child HOME must be set (got empty string)"
    );
    assert!(
        broker_exec_home_is_sandbox_safe(&observed_home),
        "broker_exec child HOME ({observed_home}) should live under the sandbox-safe temp roots"
    );
}

#[tokio::test]
async fn broker_exec_empty_allowlist_strips_all_passthrough() {
    // Strict mode: empty allowlist means every passthrough is stripped.
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
    );
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    // SAFETY: tests run in-process; setting an env var is racy across
    // tests but the value here is a fixture that other tests don't read.
    unsafe {
        std::env::set_var("GH_TOKEN", "ghs_fake");
    }
    let mut req = fixture.exec_request(&["pr", "merge", "123"]);
    req["env_passthrough"] = json!(["GH_TOKEN", "GITHUB_TOKEN"]);
    req["action_env_allowlist"] = json!([]);
    let _resp = handle_broker_exec(None, &store, &req).await.expect("ok");
    let rows = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("session.construct_invocation".to_string()),
            ..Default::default()
        })
        .expect("audit query");
    let last = rows.last().expect("receipt row");
    let details: serde_json::Value =
        serde_json::from_str(last.details.as_deref().unwrap_or("{}")).expect("details parse");
    let stripped = details
        .get("env_passthrough_stripped")
        .and_then(|v| v.as_array())
        .expect("env_passthrough_stripped must be present");
    let stripped_names: Vec<&str> = stripped.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(stripped_names, vec!["GH_TOKEN", "GITHUB_TOKEN"]);
}

#[tokio::test]
async fn broker_exec_refuses_when_shim_claim_disagrees_with_daemon_classifier() {
    // T2 acceptance for T-CONSTRUCT-EXEC-ARGV-CLASSIFIER:
    //   malicious shim sends argv=["repo","delete","--yes"] while
    //   claiming action=gh.pr_create. Even when the binary path is not
    //   in the manifest (so `daemon_action` resolves to None), the
    //   daemon refuses any caller-claimed action that doesn't match
    //   what the daemon classifies — fail-closed prevents trusting the
    //   shim's claim under any circumstance.
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_create",
    );
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let req = fixture.exec_request(&["repo", "delete", "--yes"]);
    let result = handle_broker_exec(None, &store, &req).await;
    let (code, msg) = result.expect_err("must refuse on mismatch");
    assert_eq!(code, -32003, "policy-rejected code expected, got {code}");
    assert!(
        msg.contains("argv_classification_mismatch"),
        "error message must name the mismatch: got {msg}"
    );

    // Mismatch Receipt must be in the audit log with `denied` outcome.
    let rows = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("session.argv_classification_mismatch".to_string()),
            ..Default::default()
        })
        .expect("audit query");
    assert_eq!(rows.len(), 1, "exactly one mismatch receipt expected");
    assert_eq!(rows[0].outcome, "denied");
}

// ---------------------------------------------------------------------
// SCION-FOUNDATION-CONSTRUCT-TOML-EXEC-POLICY — action-level policy
// gating via construct.toml manifest bytes.
// ---------------------------------------------------------------------

#[test]
fn resolve_binary_from_action_ref_with_manifest_uses_plugin_local_tool_name() {
    use crate::binary_manifest::{BinaryDistributionChannel, BinaryManifest, BinaryManifestEntry};

    let manifest = BinaryManifest {
        entries: vec![BinaryManifestEntry {
            tool_name: "ember-gh".to_string(),
            version: "1.0.0".to_string(),
            content_hash: "blake3:test".to_string(),
            absolute_path: std::path::PathBuf::from("/tmp/fake-ember-gh"),
            installed_at: 1735689600,
            publisher: "did:emberlink".to_string(),
            channel: BinaryDistributionChannel::Bundled,
        }],
    };
    let action_ref = ActionRef::new(
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
        "v1",
    );

    let resolved =
        resolve_binary_from_action_ref_with_manifest(&manifest, &action_ref).expect("binary");

    assert_eq!(resolved, std::path::PathBuf::from("/tmp/fake-ember-gh"));
}

#[test]
fn resolve_workspace_ref_to_path_from_home_finds_managed_worktree_metadata() {
    let home = tempfile::tempdir().expect("tempdir");
    let runtime_id = format!("rt-{}", uuid::Uuid::new_v4().simple());
    let worktree = write_managed_worktree(home.path(), &runtime_id);

    let resolved = resolve_workspace_ref_to_path_from_home(
        home.path(),
        &format!("managed_worktree:{runtime_id}"),
    )
    .expect("worktree path");

    assert_eq!(resolved, worktree);
}

#[tokio::test]
async fn resolve_with_registry_accepts_lease_request_without_legacy_binary() {
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
    );

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let registry = BrokerRegistry::new();
    let mut params = fixture.lease_request_params(&["GH_TOKEN"], 64);
    params["execution_contract"]["subject_ref"] = json!("forge:run:resolve-1");
    params["execution_contract"]["coordination_ref"] = json!("forge:workflow_event:resolve-1");

    let result = resolve_with_registry(&registry, &store, &params, None, None).await;

    let result = result.expect("resolve");
    assert_eq!(
        result["binary"],
        json!(fixture.binary_path.to_string_lossy().into_owned())
    );
    assert_eq!(result["env_allowlist"], json!(["GH_TOKEN"]));
    assert_eq!(result["subject_ref"], json!("forge:run:resolve-1"));
    assert_eq!(
        result["coordination_ref"],
        json!("forge:workflow_event:resolve-1")
    );

    let rows = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("broker.resolve.pending".to_string()),
            ..Default::default()
        })
        .expect("audit query");
    assert_eq!(rows.len(), 1, "one pending resolve receipt expected");
    let details: serde_json::Value =
        serde_json::from_str(rows[0].details.as_deref().unwrap_or("{}")).expect("details");
    assert_eq!(
        details.get("runner_binary_source"),
        Some(&json!("action_ref"))
    );
    assert_eq!(details.get("runner_class"), Some(&json!("local_trusted")));
    assert_eq!(
        details.get("subject_ref"),
        Some(&json!("forge:run:resolve-1"))
    );
    assert_eq!(
        details.get("coordination_ref"),
        Some(&json!("forge:workflow_event:resolve-1"))
    );
}

#[tokio::test]
async fn resolve_with_registry_refuses_unenrolled_runner_class() {
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
    );

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let registry = BrokerRegistry::new();
    let params = serde_json::json!({
        "execution_contract": {
            "schema_version": "execution_contract.v1",
            "action_ref": fixture.action_ref,
            "workspace_ref": fixture.workspace_ref(),
            "caller_ref": "session:test",
            "authority_ref": "grant:test",
            "materialization_policy": {
                "exposure": "brokered_env",
                "revocation": "on_exit"
            },
            "runner_policy": {
                "allowed": ["tee_required"],
                "preferred": ["tee_required"]
            },
            "topology_policy": {
                "required": [],
                "preferred": [],
                "forbidden": []
            },
            "interaction_class": "inline_interactive",
            "lease_policy": {
                "single_use": true
            },
            "audit_policy": {
                "receipt_required": true,
                "evidence": ["execution_receipt"]
            }
        },
        "lease_request": {
            "action_ref": fixture.action_ref,
            "env_passthrough": ["GH_TOKEN"],
            "construct_toml_hash_input_len": 64
        }
    });

    let (code, msg) = resolve_with_registry(&registry, &store, &params, None, None)
        .await
        .expect_err("must refuse unavailable runner class at resolve time");
    assert_eq!(code, -32024);
    assert!(
        msg.contains("tee_required"),
        "error must name the unavailable runner class: {msg}"
    );
}

#[tokio::test]
async fn resolve_with_registry_rejects_legacy_lease_request_binary() {
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let registry = BrokerRegistry::new();
    let params = serde_json::json!({
        "lease_request": {
            "binary": "/usr/bin/true",
        }
    });

    let (code, msg) = resolve_with_registry(&registry, &store, &params, None, None)
        .await
        .expect_err("legacy lease_request.binary must be rejected");

    assert_eq!(code, -32602);
    assert!(
        msg.contains("lease_request.binary"),
        "error must name the removed field: {msg}"
    );
}

#[tokio::test]
async fn handle_broker_exec_refuses_action_not_in_manifest() {
    // Build a construct.toml carrier with only `pr_merge` declared.
    // Calling handle_broker_exec with `action_ref.action_key =
    // "pr_delete"` (NOT in the manifest) must be refused with
    // JSON-RPC code -32009 so the structured action-ref gate fails
    // closed on unknown actions.
    use base64::Engine as _;
    let manifest_toml = v2_carrier_for_test(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "gh",
        "",
        &[("pr_merge", None, None)],
    );
    let b64_bytes = base64::engine::general_purpose::STANDARD.encode(manifest_toml.as_bytes());
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_delete",
    );

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let mut req = fixture.exec_request(&[]);
    req["construct_toml_bytes"] = json!(b64_bytes);
    let result = handle_broker_exec(None, &store, &req).await;
    let (code, msg) = result.expect_err("must refuse unknown action_ref");
    assert_eq!(
        code, -32009,
        "expected -32009 (action_ref not in manifest), got {code}: {msg}"
    );
    assert!(
        msg.contains("pr_delete"),
        "error must name the offending action key: got {msg}"
    );
}

#[tokio::test]
async fn handle_broker_exec_accepts_action_in_manifest() {
    // Sibling-case to the refusal test: when action_ref IS declared in
    // the manifest's `[[actions]]` list, the structured gate passes
    // through and the exec proceeds. /bin/true exits 0 and the
    // response carries success=true.
    use base64::Engine as _;
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
    );
    let wrapped_gh = write_fixture_wrapped_binary(&fixture, "gh", "#!/bin/sh\nexit 0\n");
    let manifest_toml = v2_carrier_for_test(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        &wrapped_gh,
        "",
        &[("pr_merge", None, None)],
    );
    let b64_bytes = base64::engine::general_purpose::STANDARD.encode(manifest_toml.as_bytes());

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let mut req = fixture.exec_request(&["pr", "merge", "123"]);
    req["construct_toml_bytes"] = json!(b64_bytes);
    let resp_value = handle_broker_exec(None, &store, &req).await.expect("ok");
    let resp: BrokerExecResponse = serde_json::from_value(resp_value).expect("deserialize");
    assert_eq!(resp.exit_code, 0);
    assert!(resp.success);
}

#[tokio::test]
async fn handle_broker_exec_runs_manifest_wrapped_binary_not_construct_shim() {
    use base64::Engine as _;

    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::scripted(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_list",
        "#!/bin/sh\nprintf 'CONSTRUCT_SHIM\\n'\nexit 88\n",
    );
    let upstream_gh =
        write_fixture_wrapped_binary(&fixture, "gh", "#!/bin/sh\nprintf 'UPSTREAM_GH\\n'\n");
    let manifest_toml = v2_carrier_for_test(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        &upstream_gh,
        "",
        &[("pr_list", None, None)],
    );
    let b64_bytes = base64::engine::general_purpose::STANDARD.encode(manifest_toml.as_bytes());

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let mut req = fixture.exec_request(&["pr", "list", "--limit", "1"]);
    req["construct_toml_bytes"] = json!(b64_bytes);
    let resp_value = handle_broker_exec(None, &store, &req).await.expect("ok");
    let resp: BrokerExecResponse = serde_json::from_value(resp_value).expect("deserialize");
    assert_eq!(resp.exit_code, 0);
    assert!(resp.success);
    assert_eq!(resp.stdout_tail, "UPSTREAM_GH\n");

    let rows = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("session.construct_invocation".to_string()),
            ..Default::default()
        })
        .expect("audit query");
    let last = rows.last().expect("must have construct invocation receipt");
    let details: serde_json::Value =
        serde_json::from_str(last.details.as_deref().unwrap_or("{}")).expect("details parse");
    assert_eq!(
        details.get("runner_binary_source"),
        Some(&json!("wrapped_binary"))
    );
    assert_eq!(details.get("binary"), Some(&json!(upstream_gh.clone())));
    assert_eq!(
        details.get("construct_binary"),
        Some(&json!(fixture.binary_path.to_string_lossy().into_owned()))
    );
    assert_eq!(details.get("calling_shim"), Some(&json!("ember-gh")));
    assert_eq!(details.get("runner_action_key"), Some(&json!("gh.pr_list")));
}

#[tokio::test]
async fn handle_broker_exec_rejects_pty_socket_when_manifest_terminal_mode_piped() {
    use base64::Engine as _;

    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_list",
    );
    let wrapped_gh = write_fixture_wrapped_binary(&fixture, "gh", "#!/bin/sh\nexit 0\n");
    let manifest_toml = v2_carrier_for_test(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        &wrapped_gh,
        "",
        &[("pr_list", None, None)],
    )
    .replace(
        "interaction_class = \"inline_interactive\"\n",
        "interaction_class = \"inline_interactive\"\nterminal_mode = \"piped\"\n",
    );
    let b64_bytes = base64::engine::general_purpose::STANDARD.encode(manifest_toml.as_bytes());

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let mut req = fixture.exec_request(&["pr", "list", "--limit", "1"]);
    req["construct_toml_bytes"] = json!(b64_bytes);
    req["pty_socket_path"] = json!("/tmp/ember-construct-pty-test.sock");

    let (code, msg) = handle_broker_exec(None, &store, &req)
        .await
        .expect_err("terminal_mode=piped must refuse PTY requests");
    assert_eq!(code, -32602);
    assert!(
        msg.contains("terminal_mode=piped"),
        "error must name terminal mode policy: {msg}"
    );
}

#[tokio::test]
async fn handle_broker_exec_accepts_manifest_terminal_mode_piped_without_pty() {
    use base64::Engine as _;

    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_list",
    );
    let wrapped_gh = write_fixture_wrapped_binary(&fixture, "gh", "#!/bin/sh\nexit 0\n");
    let manifest_toml = v2_carrier_for_test(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        &wrapped_gh,
        "",
        &[("pr_list", None, None)],
    )
    .replace(
        "interaction_class = \"inline_interactive\"\n",
        "interaction_class = \"inline_interactive\"\nterminal_mode = \"piped\"\n",
    );
    let b64_bytes = base64::engine::general_purpose::STANDARD.encode(manifest_toml.as_bytes());

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let mut req = fixture.exec_request(&["pr", "list", "--limit", "1"]);
    req["construct_toml_bytes"] = json!(b64_bytes);
    let resp_value = handle_broker_exec(None, &store, &req).await.expect("ok");
    let resp: BrokerExecResponse = serde_json::from_value(resp_value).expect("deserialize");
    assert_eq!(resp.exit_code, 0);
    assert!(resp.success);
}

#[tokio::test]
async fn handle_broker_exec_refuses_carrier_rail_manifest_without_trust_contract() {
    use base64::Engine as _;

    let manifest_toml = v2_carrier_for_test(
        "ember-payments",
        "registry.ember.systems/ember-systems/ember-payments",
        "payments",
        "[rail]\n",
        &[("payment_charge", None, None)],
    );
    let b64_bytes = base64::engine::general_purpose::STANDARD.encode(manifest_toml.as_bytes());
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-payments",
        "registry.ember.systems/ember-systems/ember-payments",
        "payment_charge",
    );

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let mut req = fixture.exec_request(&[]);
    req["construct_toml_bytes"] = json!(b64_bytes);
    let result = handle_broker_exec(None, &store, &req).await;
    let (code, msg) = result.expect_err("must refuse missing rail trust contract");
    assert_eq!(code, -32009);
    assert!(
        msg.contains("rail.trust_contract"),
        "error must name the missing contract field: {msg}"
    );
}

#[tokio::test]
async fn handle_broker_exec_accepts_carrier_rail_manifest_with_trust_contract() {
    use base64::Engine as _;

    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
    );
    let wrapped_gh = write_fixture_wrapped_binary(&fixture, "gh", "#!/bin/sh\nexit 0\n");
    let manifest_toml = v2_carrier_for_test(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        &wrapped_gh,
        "[rail]\ntrust_contract = \"side_channel_reconciliation\"\n",
        &[("pr_merge", None, None)],
    );
    let b64_bytes = base64::engine::general_purpose::STANDARD.encode(manifest_toml.as_bytes());

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let mut req = fixture.exec_request(&["pr", "merge", "123"]);
    req["construct_toml_bytes"] = json!(b64_bytes);
    let resp_value = handle_broker_exec(None, &store, &req).await.expect("ok");
    let resp: BrokerExecResponse = serde_json::from_value(resp_value).expect("deserialize");
    assert_eq!(resp.exit_code, 0);
    assert!(resp.success);
}

#[tokio::test]
async fn handle_broker_exec_accepts_nested_execution_contract_without_legacy_fields() {
    use base64::Engine as _;

    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
    );
    let wrapped_gh = write_fixture_wrapped_binary(&fixture, "gh", "#!/bin/sh\nexit 0\n");
    let manifest_toml = v2_carrier_for_test(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        &wrapped_gh,
        "",
        &[("pr_merge", None, None)],
    );
    let b64_bytes = base64::engine::general_purpose::STANDARD.encode(manifest_toml.as_bytes());

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let req = serde_json::json!({
        "execution_contract": {
            "schema_version": "execution_contract.v1",
            "contract_id": "contract-nested-1",
            "action_ref": fixture.action_ref,
            "workspace_ref": fixture.workspace_ref(),
            "subject_ref": "forge:run:exec-1",
            "coordination_ref": "forge:workflow_event:exec-1",
            "caller_ref": "session:test",
            "authority_ref": "grant:test",
            "materialization_policy": {
                "exposure": "brokered_env",
                "revocation": "on_exit"
            },
            "runner_policy": {
                "allowed": ["local_trusted"],
                "preferred": ["local_trusted"]
            },
            "topology_policy": {
                "required": [],
                "preferred": [],
                "forbidden": []
            },
            "interaction_class": "inline_interactive",
            "lease_policy": {
                "single_use": true
            },
            "audit_policy": {
                "receipt_required": true,
                "evidence": ["execution_receipt"]
            }
        },
        "argv": ["pr", "merge", "123"],
        "env_passthrough": [],
        "construct_toml_bytes": b64_bytes,
    });

    let resp_value = handle_broker_exec(None, &store, &req).await.expect("ok");
    let resp: BrokerExecResponse = serde_json::from_value(resp_value.clone()).expect("deserialize");
    assert_eq!(resp.exit_code, 0);
    assert!(resp.success);
    assert_eq!(resp_value["contract_id"], json!("contract-nested-1"));
    assert_eq!(
        resp_value["execution_contract"]["action_ref"]["action_key"],
        json!("pr_merge")
    );
    assert_eq!(resp_value["workspace_ref"], json!(fixture.workspace_ref()));
    assert_eq!(resp_value["subject_ref"], json!("forge:run:exec-1"));
    assert_eq!(
        resp_value["coordination_ref"],
        json!("forge:workflow_event:exec-1")
    );
    assert_eq!(resp_value["caller_ref"], json!("session:test"));
    assert_eq!(resp_value["authority_ref"], json!("grant:test"));

    let rows = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("session.construct_invocation".to_string()),
            ..Default::default()
        })
        .expect("audit query");
    assert_eq!(rows.len(), 1, "one construct invocation receipt expected");
    let details: serde_json::Value =
        serde_json::from_str(rows[0].details.as_deref().unwrap_or("{}")).expect("details");
    assert_eq!(
        details.get("runner_binary_source"),
        Some(&json!("wrapped_binary"))
    );
    assert_eq!(
        details.get("runner_cwd_source"),
        Some(&json!("workspace_ref"))
    );
    assert_eq!(details.get("runner_class"), Some(&json!("local_trusted")));
    assert_eq!(details.get("subject_ref"), Some(&json!("forge:run:exec-1")));
    assert_eq!(
        details.get("coordination_ref"),
        Some(&json!("forge:workflow_event:exec-1"))
    );
}

#[tokio::test]
async fn handle_broker_exec_rejects_nested_contract_missing_runner_policy_allowed() {
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
    );
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let req = serde_json::json!({
        "execution_contract": {
            "schema_version": "execution_contract.v1",
            "contract_id": "contract-nested-missing-allowed",
            "action_ref": fixture.action_ref,
            "workspace_ref": fixture.workspace_ref(),
            "caller_ref": "session:test",
            "authority_ref": "grant:test",
            "materialization_policy": {
                "exposure": "brokered_env",
                "revocation": "on_exit"
            },
            "runner_policy": {
                "preferred": ["local_trusted"]
            },
            "topology_policy": {
                "required": [],
                "preferred": [],
                "forbidden": []
            },
            "interaction_class": "inline_interactive",
            "lease_policy": {
                "single_use": true
            },
            "audit_policy": {
                "receipt_required": true,
                "evidence": ["execution_receipt"]
            }
        },
        "argv": ["pr", "merge", "123"],
        "env_passthrough": [],
    });

    let (code, msg) = handle_broker_exec(None, &store, &req)
        .await
        .expect_err("must reject missing runner_policy.allowed");
    assert_eq!(code, -32602);
    assert!(
        msg.contains("runner_policy.allowed"),
        "error must name the missing runner_policy.allowed field: {msg}"
    );
}

#[tokio::test]
async fn handle_broker_exec_ignores_conflicting_top_level_action_ref() {
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
    );
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let req = serde_json::json!({
        "execution_contract": {
            "schema_version": "execution_contract.v1",
            "contract_id": "contract-nested-conflict",
            "action_ref": fixture.action_ref,
            "workspace_ref": fixture.workspace_ref(),
            "caller_ref": "session:test",
            "authority_ref": "grant:test",
            "materialization_policy": {
                "exposure": "brokered_env",
                "revocation": "on_exit"
            },
            "runner_policy": {
                "allowed": ["local_trusted"],
                "preferred": ["local_trusted"]
            },
            "topology_policy": {
                "required": [],
                "preferred": [],
                "forbidden": []
            },
            "interaction_class": "inline_interactive",
            "lease_policy": {
                "single_use": true
            },
            "audit_policy": {
                "receipt_required": true,
                "evidence": ["execution_receipt"]
            }
        },
        "action_ref": {
            "plugin_address": "registry.ember.systems/ember-systems/ember-gh",
            "action_key": "repo_view",
            "action_version": "v1"
        },
        "argv": ["pr", "merge", "123"],
        "env_passthrough": [],
    });

    let resp_value = handle_broker_exec(None, &store, &req)
        .await
        .expect("conflicting top-level mirror must be ignored");
    let resp: BrokerExecResponse =
        serde_json::from_value(resp_value.clone()).expect("deserialize response");
    assert!(resp.success);
    assert_eq!(
        resp_value["execution_contract"]["action_ref"]["action_key"],
        json!("pr_merge")
    );
    assert_eq!(resp_value["action_ref"]["action_key"], json!("pr_merge"));
}

#[tokio::test]
async fn handle_broker_exec_refuses_unenrolled_runner_class() {
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
    );
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let req = serde_json::json!({
        "execution_contract": {
            "schema_version": "execution_contract.v1",
            "contract_id": "contract-unavailable-runner",
            "action_ref": fixture.action_ref,
            "workspace_ref": fixture.workspace_ref(),
            "caller_ref": "session:test",
            "authority_ref": "grant:test",
            "materialization_policy": {
                "exposure": "brokered_env",
                "revocation": "on_exit"
            },
            "runner_policy": {
                "allowed": ["tee_required"],
                "preferred": ["tee_required"]
            },
            "topology_policy": {
                "required": [],
                "preferred": [],
                "forbidden": []
            },
            "interaction_class": "inline_interactive",
            "lease_policy": {
                "single_use": true
            },
            "audit_policy": {
                "receipt_required": true,
                "evidence": ["execution_receipt"]
            }
        },
        "argv": ["pr", "merge", "123"],
        "env_passthrough": [],
    });

    let (code, msg) = handle_broker_exec(None, &store, &req)
        .await
        .expect_err("must refuse unavailable runner class");
    assert_eq!(code, -32024);
    assert!(
        msg.contains("tee_required"),
        "error must name the unavailable runner class: {msg}"
    );
}

#[tokio::test]
async fn handle_broker_exec_uses_allowed_runner_when_preferred_unavailable() {
    use base64::Engine as _;

    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
    );
    let wrapped_gh = write_fixture_wrapped_binary(&fixture, "gh", "#!/bin/sh\nexit 0\n");
    let manifest_toml = v2_carrier_for_test(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        &wrapped_gh,
        "",
        &[("pr_merge", None, None)],
    );
    let b64_bytes = base64::engine::general_purpose::STANDARD.encode(manifest_toml.as_bytes());

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let req = serde_json::json!({
        "execution_contract": {
            "schema_version": "execution_contract.v1",
            "contract_id": "contract-preferred-fallback",
            "action_ref": fixture.action_ref,
            "workspace_ref": fixture.workspace_ref(),
            "caller_ref": "session:test",
            "authority_ref": "grant:test",
            "materialization_policy": {
                "exposure": "brokered_env",
                "revocation": "on_exit"
            },
            "runner_policy": {
                "allowed": ["local_trusted", "tee_required"],
                "preferred": ["tee_required"]
            },
            "topology_policy": {
                "required": [],
                "preferred": [],
                "forbidden": []
            },
            "interaction_class": "inline_interactive",
            "lease_policy": {
                "single_use": true
            },
            "audit_policy": {
                "receipt_required": true,
                "evidence": ["execution_receipt"]
            }
        },
        "argv": ["pr", "merge", "123"],
        "env_passthrough": [],
        "construct_toml_bytes": b64_bytes,
    });

    let resp_value = handle_broker_exec(None, &store, &req).await.expect("ok");
    let resp: BrokerExecResponse =
        serde_json::from_value(resp_value).expect("deserialize response");
    assert!(resp.success);

    let rows = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("session.construct_invocation".to_string()),
            ..Default::default()
        })
        .expect("audit query");
    assert_eq!(rows.len(), 1, "one construct invocation receipt expected");
    let details: serde_json::Value =
        serde_json::from_str(rows[0].details.as_deref().unwrap_or("{}")).expect("details");
    assert_eq!(details.get("runner_class"), Some(&json!("local_trusted")));
}

#[tokio::test]
async fn handle_broker_exec_rejects_invalid_base64_construct_toml() {
    // Defense-in-depth: malformed base64 must surface as -32602
    // (params) rather than crashing the daemon.
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
    );
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let mut req = fixture.exec_request(&[]);
    req["construct_toml_bytes"] = json!("this is not base64!!!");
    let result = handle_broker_exec(None, &store, &req).await;
    let (code, _msg) = result.expect_err("must reject malformed base64");
    assert_eq!(code, -32602, "expected -32602 (invalid params), got {code}");
}

#[tokio::test]
async fn handle_broker_exec_skips_gate_when_construct_toml_absent() {
    // Backwards-compat: shims that don't yet send construct_toml_bytes
    // still get through. The legacy argv-classification path remains
    // the sole policy authority in that case.
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-gh",
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
    );
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let req = fixture.exec_request(&["pr", "merge", "123"]);
    let resp_value = handle_broker_exec(None, &store, &req).await.expect("ok");
    let resp: BrokerExecResponse = serde_json::from_value(resp_value).expect("deserialize");
    assert_eq!(resp.exit_code, 0);
}

#[tokio::test]
async fn allowlist_refuses_unbound_remote() {
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-git",
        "registry.ember.systems/ember-systems/ember-git",
        "git.push",
    );
    let work_tree = fixture.worktree_path.as_path();
    std::fs::write(
        work_tree.join(".git").join("config"),
        b"[remote \"origin\"]\n\turl = https://github.com/foo/bar.git\n",
    )
    .expect("write .git/config");

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let persona_id = uuid::Uuid::new_v4().to_string();
    let mut req = fixture.exec_request(&["push", "origin"]);
    req["caller_persona"] = json!(persona_id);
    let result = handle_broker_exec(None, &store, &req).await;
    let (code, msg) = result.expect_err("must refuse unbound remote");
    assert_eq!(
        code, -32007,
        "expected -32007 (binding_not_confirmed), got {code}: {msg}"
    );
}

#[tokio::test]
async fn allowlist_proceeds_with_matching_binding() {
    let _guard = process_state_test_guard();
    let fixture = RunnerFixture::symlinked(
        "ember-git",
        "registry.ember.systems/ember-systems/ember-git",
        "git.push",
    );
    let work_tree = fixture.worktree_path.as_path();
    std::fs::write(
        work_tree.join(".git").join("config"),
        b"[remote \"origin\"]\n\turl = https://github.com/foo/bar.git\n",
    )
    .expect("write .git/config");

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let persona_id = uuid::Uuid::new_v4();
    let wtid = crate::broker::working_tree_id::working_tree_id(work_tree)
        .expect("resolve working tree id");
    crate::broker::bindings::insert(
        &store,
        &crate::broker::bindings::Binding {
            principal_id: persona_id.to_string(),
            working_tree_id: wtid,
            remote_name: "origin".to_string(),
            remote_url: "https://github.com/foo/bar.git".to_string(),
            created_at: 0,
        },
    )
    .expect("insert binding");

    let mut req = fixture.exec_request(&["push", "origin"]);
    req["caller_persona"] = json!(persona_id.to_string());
    let result = handle_broker_exec(None, &store, &req).await;
    if let Err((code, msg)) = result {
        assert_ne!(
            code, -32007,
            "gate must not refuse with matching binding: {msg}"
        );
        assert_ne!(
            code, -32008,
            "gate must not refuse URL drift with matching URL: {msg}"
        );
    }
}

// ─── REL-CLASS-A-CODEOWNERS-LOCK ──────────────────────────────────────

/// Helper: init a tempdir as a git repo with one seed commit on `main`,
/// `origin/main` ref pointing at the same SHA. Returns the path.
fn init_classification_repo() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("tempdir");
    let p = tmp.path();
    let run = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(p)
            .output()
            .expect("git");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&["init", "-q", "-b", "main"]);
    run(&["config", "user.email", "t@t"]);
    run(&["config", "user.name", "t"]);
    run(&["config", "commit.gpgsign", "false"]);
    std::fs::write(p.join("README.md"), b"seed\n").unwrap();
    run(&["add", "README.md"]);
    run(&["commit", "-qm", "seed"]);
    run(&["update-ref", "refs/remotes/origin/main", "HEAD"]);
    tmp
}

fn run_git_in(cwd: &std::path::Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn classification_refusal_returns_none_for_read_only_actions() {
    let tmp = init_classification_repo();
    for verb in [
        "git.status",
        "git.log",
        "git.diff",
        "git.add",
        "kubectl.get",
    ] {
        assert!(
            check_classification_refusal(verb, tmp.path().to_str().unwrap()).is_none(),
            "{verb} must not trigger refusal"
        );
    }
}

#[test]
fn classification_refusal_fires_on_git_commit_with_staged_classification_file() {
    let tmp = init_classification_repo();
    std::fs::create_dir_all(tmp.path().join("crates/foo")).unwrap();
    std::fs::write(tmp.path().join("crates/foo/.classification"), "INTERNAL\n").unwrap();
    run_git_in(tmp.path(), &["add", "crates/foo/.classification"]);

    let result = check_classification_refusal("git.commit", tmp.path().to_str().unwrap());
    let touched = result.expect("git.commit on staged .classification must refuse");
    assert!(
        touched.iter().any(|p| p.ends_with(".classification")),
        "refusal must list the offending file: {touched:?}"
    );
}

#[test]
fn classification_refusal_does_not_fire_on_git_commit_with_normal_staged_file() {
    let tmp = init_classification_repo();
    std::fs::write(tmp.path().join("hello.txt"), "hello\n").unwrap();
    run_git_in(tmp.path(), &["add", "hello.txt"]);

    assert!(
        check_classification_refusal("git.commit", tmp.path().to_str().unwrap()).is_none(),
        "non-classification staged file must not trigger refusal"
    );
}

#[test]
fn classification_refusal_fires_on_git_push_when_commit_touches_classification() {
    let tmp = init_classification_repo();
    std::fs::create_dir_all(tmp.path().join("crates/foo")).unwrap();
    std::fs::write(tmp.path().join("crates/foo/.classification"), "INTERNAL\n").unwrap();
    run_git_in(tmp.path(), &["add", "crates/foo/.classification"]);
    run_git_in(tmp.path(), &["commit", "-qm", "flip class"]);

    let result = check_classification_refusal("git.push", tmp.path().to_str().unwrap());
    assert!(
        result.is_some(),
        "git.push with .classification commit ahead of origin/main must refuse"
    );
}

#[test]
fn classification_refusal_fires_on_gh_pr_create_when_commit_touches_classification() {
    let tmp = init_classification_repo();
    std::fs::write(tmp.path().join(".classification"), "PUBLIC\n").unwrap();
    run_git_in(tmp.path(), &["add", ".classification"]);
    run_git_in(tmp.path(), &["commit", "-qm", "root classification"]);

    let result = check_classification_refusal("gh.pr_create", tmp.path().to_str().unwrap());
    assert!(
        result.is_some(),
        "gh.pr_create with .classification commit ahead of origin/main must refuse"
    );
}

#[test]
fn classification_refusal_does_not_fire_on_git_push_with_clean_history() {
    let tmp = init_classification_repo();
    // No commits ahead of origin/main; git log returns nothing.
    assert!(
        check_classification_refusal("git.push", tmp.path().to_str().unwrap()).is_none(),
        "git.push with no commits ahead must not refuse"
    );
}

#[test]
fn classification_refusal_skips_when_cwd_is_not_a_repo() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // No git init — git commands fail; refusal must be None (don't refuse on inability to verify).
    assert!(
        check_classification_refusal("git.commit", tmp.path().to_str().unwrap()).is_none(),
        "non-repo cwd must not trigger refusal"
    );
}
