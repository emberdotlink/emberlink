use super::*;
use crate::infra::claim_journal::ClaimJournal;
use crate::infra::interactive_unlock;
use crate::infra::rate_limit::RateLimiter;
use crate::infra::store::DaemonStore;
use crate::infra::vault::Vault;
use crate::trust::policy::{
    ActionSelector, ApprovalRequirement, PolicyConfig, PolicyEngine, PolicyRule, RiskLevel, Tier,
};
use serde_json::json;
use std::cell::RefCell;

mod access_requests;
mod agent_persona;
mod audit_receipts;
mod authority;
mod banner;
mod binding_lifecycle;
mod grant_lifecycle;
mod grant_read;
mod grant_use;
mod headless;
mod preflight_dispatch;
mod presence;
mod recovery;
mod runtime_gateway;
mod sandbox_dispatch;
mod session_runtime;
mod subprocess_audit;
mod vault_rpc;

fn test_vault() -> Vault {
    Vault::new([42u8; 32])
}

fn test_policy() -> PolicyEngine {
    PolicyEngine::default()
}

fn test_rate_limiter() -> RefCell<RateLimiter> {
    RefCell::new(RateLimiter::default())
}

// META-AP-DAEMON-PER-METHOD-AUTHORITY-D-4-HANDLER-VALIDATE: mint a
// daemon-identity-signed presence-token for `uid` so tests that
// construct `RequestContext` directly for OperatorPresence-class
// methods continue to pass the gate.
fn test_presence_token(uid: u32) -> crate::auth::presence_token::PresenceToken {
    use crate::auth::presence_token::{ScopeKey, mint};
    use std::time::Duration;
    ensure_test_presence_identity();
    let signer = DaemonIdentityPresenceSigner::current().expect("test presence signer initialised");
    mint(uid, ScopeKey::all(), Duration::from_secs(60), &signer)
}

fn test_presence_token_for_scope(
    uid: u32,
    scope: &str,
) -> crate::auth::presence_token::PresenceToken {
    use crate::auth::presence_token::{ScopeKey, mint};
    use std::time::Duration;
    ensure_test_presence_identity();
    let signer = DaemonIdentityPresenceSigner::current().expect("test presence signer initialised");
    mint(uid, ScopeKey::new(scope), Duration::from_secs(60), &signer)
}

#[tokio::test]
async fn dispatch_broker_resolve_accepts_open_session_runtime_without_presence_token() {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    std::fs::create_dir_all(&sessions_dir).unwrap();

    let session_id = "sess-runtime-resolve";
    let persona_id = "persona-runtime-resolve";
    let socket_path = "/tmp/test-session-runtime-resolve.sock";
    write_open_session_meta(&sessions_dir, session_id, persona_id);
    seed_socket_enrollment_for_test(&store, socket_path, persona_id, 501);

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        session_runtime_socket_ctx(&sessions_dir, socket_path, 501, std::process::id() as i32),
        "broker_resolve",
        &json!({
            "persona_id": persona_id,
            "session_id": session_id,
            "secret_ref": "missing-for-authority-bypass-test",
        }),
    )
    .await;

    match result {
        Ok(_) => {}
        Err((code, msg)) => {
            assert_ne!(
                code, -32001,
                "session-bound broker_resolve should bypass the presence gate; got {msg}"
            );
        }
    }
}

#[tokio::test]
async fn dispatch_broker_exec_accepts_open_session_runtime_without_presence_token() {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    std::fs::create_dir_all(&sessions_dir).unwrap();

    let session_id = "sess-runtime-exec";
    let persona_id = "persona-runtime-exec";
    let socket_path = "/tmp/test-session-runtime-exec.sock";
    write_open_session_meta(&sessions_dir, session_id, persona_id);
    seed_socket_enrollment_for_test(&store, socket_path, persona_id, 501);

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        session_runtime_socket_ctx(&sessions_dir, socket_path, 501, std::process::id() as i32),
        "broker_exec",
        &json!({
            "caller_persona": persona_id,
            "session_id": session_id,
        }),
    )
    .await;

    match result {
        Ok(_) => {}
        Err((code, msg)) => {
            assert_ne!(
                code, -32001,
                "session-bound broker_exec should bypass the presence gate; got {msg}"
            );
        }
    }
}

#[tokio::test]
async fn dispatch_broker_resolve_accepts_open_session_runtime_from_bridge_lane_without_presence_token()
 {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    std::fs::create_dir_all(&sessions_dir).unwrap();

    let session_id = "sess-runtime-bridge-resolve";
    let persona_id = "persona-runtime-bridge-resolve";
    write_open_session_meta(&sessions_dir, session_id, persona_id);

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        session_runtime_bridge_ctx(&sessions_dir, 501, persona_id, session_id),
        "broker_resolve",
        &json!({
            "persona_id": persona_id,
            "session_id": session_id,
            "secret_ref": "missing-for-authority-bypass-test",
        }),
    )
    .await;

    match result {
        Ok(_) => {}
        Err((code, msg)) => {
            assert_ne!(
                code, -32001,
                "bridge session-runtime broker_resolve should bypass the presence gate; got {msg}"
            );
            assert_ne!(
                code, -32401,
                "bridge session-runtime broker_resolve should not hit shared-socket enrollment refusal; got {msg}"
            );
        }
    }
}

#[tokio::test]
async fn dispatch_broker_exec_accepts_open_session_runtime_from_mtls_principal_without_presence_token()
 {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    std::fs::create_dir_all(&sessions_dir).unwrap();

    let session_id = "sess-runtime-mtls-exec";
    let persona_id = "persona-runtime-mtls-exec";
    write_open_session_meta(&sessions_dir, session_id, persona_id);

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        session_runtime_mtls_ctx(&sessions_dir, 501, persona_id, session_id),
        "broker_exec",
        &json!({
            "caller_persona": persona_id,
            "session_id": session_id,
        }),
    )
    .await;

    match result {
        Ok(_) => {}
        Err((code, msg)) => {
            assert_ne!(
                code, -32001,
                "session-bound broker_exec on mTLS lane should bypass the presence gate; got {msg}"
            );
        }
    }
}

#[tokio::test]
async fn dispatch_broker_exec_accepts_open_session_runtime_from_bridge_lane_without_presence_token()
{
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    std::fs::create_dir_all(&sessions_dir).unwrap();

    let session_id = "sess-runtime-bridge-exec";
    let persona_id = "persona-runtime-bridge-exec";
    write_open_session_meta(&sessions_dir, session_id, persona_id);

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        session_runtime_bridge_ctx(&sessions_dir, 501, persona_id, session_id),
        "broker_exec",
        &json!({
            "caller_persona": persona_id,
            "session_id": session_id,
        }),
    )
    .await;

    match result {
        Ok(_) => {}
        Err((code, msg)) => {
            assert_ne!(
                code, -32001,
                "bridge session-runtime broker_exec should bypass the presence gate; got {msg}"
            );
            assert_ne!(
                code, -32401,
                "bridge session-runtime broker_exec should not hit shared-socket enrollment refusal; got {msg}"
            );
        }
    }
}

#[tokio::test]
async fn dispatch_broker_exec_rejects_tokenless_session_runtime_mtls_container_mismatch() {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    std::fs::create_dir_all(&sessions_dir).unwrap();

    let session_id = "sess-runtime-mtls-mismatch";
    let persona_id = "persona-runtime-mtls-mismatch";
    write_open_session_meta(&sessions_dir, session_id, persona_id);
    // Seed the persona row so the F6 persona-existence gate passes and the test
    // exercises its actual subject — the session-runtime presence path (the
    // cert container "sess-other" mismatches the session, so no session-runtime
    // scope is granted → the tokenless call hits the -32001 presence gate).
    // F6's NotFound refusal is covered separately by
    // `bridge_refuses_nonexistent_persona_fail_closed`.
    store
        .conn()
        .execute(
            "INSERT INTO personas (id, name, public_key, created_at, status) \
             VALUES (?1, ?2, 'pk', ?3, 'active')",
            rusqlite::params![persona_id, persona_id, chrono::Utc::now().to_rfc3339()],
        )
        .unwrap();

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        session_runtime_mtls_ctx(&sessions_dir, 501, persona_id, "sess-other"),
        "broker_exec",
        &json!({
            "caller_persona": persona_id,
            "session_id": session_id,
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32001);
    assert!(err.1.contains("missing"));
}

#[tokio::test]
async fn dispatch_broker_resolve_rejects_tokenless_session_runtime_persona_mismatch() {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    std::fs::create_dir_all(&sessions_dir).unwrap();

    let session_id = "sess-runtime-mismatch";
    let session_persona = "persona-runtime-session";
    let requested_persona = "persona-runtime-request";
    let socket_path = "/tmp/test-session-runtime-mismatch.sock";
    write_open_session_meta(&sessions_dir, session_id, session_persona);
    seed_socket_enrollment_for_test(&store, socket_path, requested_persona, 501);

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        session_runtime_socket_ctx(&sessions_dir, socket_path, 501, std::process::id() as i32),
        "broker_resolve",
        &json!({
            "persona_id": requested_persona,
            "session_id": session_id,
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32001);
    assert!(
        err.1.contains("missing"),
        "mismatched session persona must fail closed at the authority gate: {err:?}"
    );
}

#[tokio::test]
async fn dispatch_broker_resolve_rejects_stale_open_session_runtime_without_presence_token() {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    std::fs::create_dir_all(&sessions_dir).unwrap();

    let session_id = "sess-runtime-stale";
    let persona_id = "persona-runtime-stale";
    let socket_path = "/tmp/test-session-runtime-stale.sock";
    write_open_session_meta_with_launcher_pid(&sessions_dir, session_id, persona_id, 0x7FFF_FFFE);
    seed_socket_enrollment_for_test(&store, socket_path, persona_id, 501);

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        session_runtime_socket_ctx(&sessions_dir, socket_path, 501, std::process::id() as i32),
        "broker_resolve",
        &json!({
            "persona_id": persona_id,
            "session_id": session_id,
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32001);
    assert!(
        err.1.contains("missing"),
        "stale open session must fail closed at the authority gate: {err:?}"
    );
}

#[tokio::test]
async fn dispatch_broker_exec_rejects_same_uid_sibling_session_runtime_without_presence_token() {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    std::fs::create_dir_all(&sessions_dir).unwrap();

    let launcher = TestChildProcess::spawn();
    let sibling = TestChildProcess::spawn();

    let session_id = "sess-runtime-sibling";
    let persona_id = "persona-runtime-sibling";
    let socket_path = "/tmp/test-session-runtime-sibling.sock";
    write_open_session_meta_with_launcher_pid(
        &sessions_dir,
        session_id,
        persona_id,
        launcher.pid_u32(),
    );
    seed_socket_enrollment_for_test(&store, socket_path, persona_id, 501);

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        session_runtime_socket_ctx(&sessions_dir, socket_path, 501, sibling.pid_i32()),
        "broker_exec",
        &json!({
            "caller_persona": persona_id,
            "session_id": session_id,
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32001);
    assert!(
        err.1.contains("missing"),
        "same-uid sibling replay must fail closed at the authority gate: {err:?}"
    );
}

#[tokio::test]
async fn dispatch_broker_exec_accepts_valid_attachment_endpoint_from_non_descendant_without_presence_token()
 {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();

    let root = tempfile::TempDir::new().unwrap();
    let sessions_dir = root.path().join("sessions");
    std::fs::create_dir_all(&sessions_dir).unwrap();

    let launcher = TestChildProcess::spawn();
    let sibling = TestChildProcess::spawn();

    let session_id = "sess-runtime-attachment";
    let persona_id = "persona-runtime-attachment";
    let socket_path = "/tmp/test-session-runtime-attachment.sock";
    let session_store = core_state::SessionStore::new(sessions_dir.clone());
    session_store
        .create(&core_state::sessions::SessionMeta {
            session_id: session_id.to_string(),
            persona: persona_id.to_string(),
            durable_persona: Some("persona-durable-attachment".to_string()),
            grant_id: "grant-session-runtime".to_string(),
            caller_binding_id: Some("binding-runtime-attachment".to_string()),
            started_at: chrono::Utc::now(),
            launcher_pid: launcher.pid_u32(),
            authority_strict: false,
            delegation_id: None,
            delegation_template: None,
        })
        .unwrap();
    session_store
        .write_attachment_endpoint(
            session_id,
            &core_state::sessions::AttachmentEndpoint::active(
                "att-runtime-attachment".to_string(),
                "token-runtime-attachment".to_string(),
            ),
        )
        .unwrap();
    seed_socket_enrollment_for_test(&store, socket_path, persona_id, 501);

    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        session_runtime_socket_ctx(&sessions_dir, socket_path, 501, sibling.pid_i32()),
        "broker_exec",
        &json!({
            "caller_persona": persona_id,
            "session_id": session_id,
            "attachment_id": "att-runtime-attachment",
            "attachment_endpoint_token": "token-runtime-attachment",
        }),
    )
    .await;

    match result {
        Ok(_) => {}
        Err((code, msg)) => {
            assert_ne!(
                code, -32001,
                "valid attachment endpoint must satisfy session-runtime authority even when the caller is not a launcher descendant; got {msg}"
            );
        }
    }
}

#[tokio::test]
async fn presence_token_mint_refuses_generic_cli_use() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let ctx = RequestContext {
        source: DispatchSource::Socket,
        peer: Some(PeerCred {
            uid: 777,
            pid: Some(4242),
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
        ctx,
        "presence_token_mint",
        &json!({}),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32601);
    assert!(
        err.1
            .contains("not a shipped generic CLI authority surface"),
        "error must explain the disabled posture: {}",
        err.1
    );
}

#[tokio::test]
async fn ping_returns_pong() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let result = dispatch_method(&store, &vault, &policy, &rl, "ping", &json!(null))
        .await
        .unwrap();
    assert_eq!(result["pong"], json!(true));
}

#[tokio::test]
async fn unknown_method_returns_32601() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let err = dispatch_method(&store, &vault, &policy, &rl, "no_such_method", &json!(null))
        .await
        .unwrap_err();
    assert_eq!(err.0, -32601);
}

#[tokio::test]
async fn grant_revocation_logged_to_audit() {
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
        &json!({"name": "audit-revocation"}),
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
        &json!({
            "persona_id": persona_id,
            "credential_name": "revoke-cred",
            "scope": "read",
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();

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

    let entries = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("grant.revoked".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert!(
        !entries.is_empty(),
        "expected at least one grant.revoked audit row"
    );
    let entry = entries.iter().find(|e| {
        e.details
            .as_ref()
            .map(|d| d.contains(grant_id))
            .unwrap_or(false)
    });
    assert!(
        entry.is_some(),
        "audit row should reference the revoked grant_id"
    );
    let entry = entry.unwrap();
    assert_eq!(entry.action, "grant.revoked");
    assert_eq!(entry.outcome, "allowed");
    assert_eq!(entry.agent_id.as_deref(), Some(persona_id));
    assert_eq!(entry.credential.as_deref(), Some("revoke-cred"));
}

#[tokio::test]
async fn team0_poll_notifications_defaults_to_trusted_principal_and_refuses_mismatch() {
    let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let actor_a_id = "persona-team0-notif-a".to_string();
    let actor_b_id = "persona-team0-notif-b".to_string();
    store
        .push_notification(
            &actor_a_id,
            "grant.revoked",
            &json!({"grant_id": "grant-a"}),
        )
        .unwrap();
    store
        .push_notification(
            &actor_b_id,
            "grant.revoked",
            &json!({"grant_id": "grant-b"}),
        )
        .unwrap();

    let ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 1000,
            pid: Some(91_011),
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
        "poll_notifications",
        &json!({}),
    )
    .await
    .unwrap();
    let arr = rows.as_array().expect("notification rows");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["payload"]["grant_id"], json!("grant-a"));

    // Queue was drained only for actor_a; actor_b's row is still there.
    let actor_b_rows = store.poll_notifications(&actor_b_id).unwrap();
    assert_eq!(actor_b_rows.len(), 1);

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "poll_notifications",
        &json!({"persona_id": actor_b_id}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32004);
}

#[tokio::test]
async fn list_all_grants_returns_empty_store_projection() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // list_all_grants is OperatorPresence-class for the same reason
    // as list_operator_grants: it is read-only, but cross-persona.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let all = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Socket,
        "list_all_grants",
        &json!({}),
    )
    .await
    .unwrap();
    assert!(all.as_array().unwrap().is_empty());

    let active_only = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Socket,
        "list_all_grants",
        &json!({"active_only": true}),
    )
    .await
    .unwrap();
    assert!(active_only.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn list_all_grants_returns_cross_persona_view_and_active_filter() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let p1 = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "list-all-p1"}),
    )
    .await
    .unwrap();
    let p2 = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "list-all-p2"}),
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
        &json!({"persona_id": p1_id, "credential_name": "all-k1", "scope": "r", "force": true}),
    )
    .await
    .unwrap();
    let g2 = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({"persona_id": p2_id, "credential_name": "all-k2", "scope": "r", "force": true}),
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
        "list_all_grants",
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
        "list_all_grants",
        &json!({}),
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

// --- Shared receipt identity helper -----------------------------------

/// Init a process-singleton identity keyed off a temp dir so the test
/// has real receipts to exercise. Called by each receipt test — the
/// OnceCell silently no-ops on the second call, which is fine because
/// the key file is stable.
fn setup_receipt_identity() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let _ = crate::infra::receipt::init_identity(dir.path());
    dir
}

#[tokio::test]
async fn resolve_approval_dispatches_and_returns_resolved_row() {
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
        &json!({"name": "approval-rpc"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();
    let req = store
        .submit_approval(
            persona_id,
            "api-key",
            "read",
            None,
            "credential.access",
            "high",
        )
        .unwrap();

    let resolved = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "resolve_approval",
        &json!({"id": req.id, "decision": "approve"}),
    )
    .await
    .unwrap();
    assert_eq!(resolved["id"], json!(req.id));
    assert_eq!(resolved["status"], json!("approved"));
}

#[tokio::test]
async fn approval_resolve_alias_accepts_approval_id_and_defaults_approve() {
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
        &json!({"name": "approval-resolve-alias"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();
    let req = store
        .submit_approval(
            persona_id,
            "api-key",
            "read",
            None,
            "credential.access",
            "high",
        )
        .unwrap();

    let resolved = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "approval.resolve",
        &json!({"approval_id": req.id}),
    )
    .await
    .unwrap();
    assert_eq!(resolved["id"], json!(req.id));
    assert_eq!(resolved["status"], json!("approved"));
}

#[tokio::test]
async fn approval_narrow_alias_mints_narrowed_grant() {
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
        &json!({"name": "approval-narrow-alias"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();
    let req = store
        .submit_approval(
            persona_id,
            "api-key",
            "*",
            None,
            "credential.access",
            "high",
        )
        .unwrap();

    let resolved = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "approval.narrow",
        &json!({"approval_id": req.id, "new_scope": "read"}),
    )
    .await
    .unwrap();
    assert_eq!(resolved["id"], json!(req.id));
    assert_eq!(resolved["status"], json!("narrowed"));
    assert_eq!(resolved["scope"], json!("read"));
    let grants = store.list_grants().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].scope, "read");
}

/// approval_socket_arm_operator_presence_required — adversarial-review
/// 2026-05-19 CRIT-1 regression guard. An agent that submitted an
/// approval MUST NOT be able to approve its own request via the socket
/// dispatch path, regardless of whether the daemon is in the dev-mode
/// presence short-circuit.
#[tokio::test]
async fn resolve_approval_socket_refuses_self_approve() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // Create a persona, then have THAT persona submit an approval.
    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "self-approve-attacker"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap().to_string();
    let req = store
        .submit_approval(
            &persona_id,
            "api-key",
            "read",
            None,
            "credential.access",
            "high",
        )
        .unwrap();

    ensure_test_authority_bridge_env();
    // resolve_approval is OperatorPresence-class — satisfy both the
    // presence-token and unlocked-session gates so we reach the
    // two-party invariant under test.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    // Now route the resolve_approval call through a Socket context
    // whose principal == the submitter. The two-party invariant must
    // refuse.
    let ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 501,
            pid: Some(std::process::id() as i32),
        }),
        persona_id.clone(),
    )
    .with_presence_token(Some(test_presence_token(501)));
    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "resolve_approval",
        &json!({"id": req.id, "decision": "approve"}),
    )
    .await
    .expect_err("self-approve via Socket must be refused");
    assert_eq!(err.0, -32003, "expected unauthorized: {err:?}");
    assert!(
        err.1.contains("caller cannot approve own request"),
        "error must name the two-party invariant: {}",
        err.1
    );

    // Sanity: the approval row is still pending (the refusal was
    // before any state mutation).
    let row = store.get_approval(&req.id).unwrap();
    assert_eq!(row.status, "pending");
}

#[tokio::test]
async fn approval_resolve_alias_socket_refuses_self_approve() {
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
        &json!({"name": "self-approve-alias-attacker"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap().to_string();
    let req = store
        .submit_approval(
            &persona_id,
            "api-key",
            "read",
            None,
            "credential.access",
            "high",
        )
        .unwrap();

    ensure_test_authority_bridge_env();
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 501,
            pid: Some(std::process::id() as i32),
        }),
        persona_id.clone(),
    )
    .with_presence_token(Some(test_presence_token(501)));
    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "approval.resolve",
        &json!({"approval_id": req.id}),
    )
    .await
    .expect_err("self-approve via approval.resolve must be refused");
    assert_eq!(err.0, -32003, "expected unauthorized: {err:?}");
    assert!(
        err.1.contains("caller cannot approve own request"),
        "error must name the two-party invariant: {}",
        err.1
    );

    let row = store.get_approval(&req.id).unwrap();
    assert_eq!(row.status, "pending");
}

/// approval_socket_arm_operator_presence_required — adversarial-review
/// 2026-05-19 CRIT-1 sibling guard. A different principal CAN resolve
/// the approval (the dashboard / second-party flow is unaffected).
#[tokio::test]
async fn resolve_approval_socket_allows_second_party_approve() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let agent = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "agent-requester"}),
    )
    .await
    .unwrap();
    let agent_id = agent["id"].as_str().unwrap().to_string();
    let operator = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "operator-approver"}),
    )
    .await
    .unwrap();
    let operator_id = operator["id"].as_str().unwrap().to_string();
    let req = store
        .submit_approval(
            &agent_id,
            "api-key",
            "read",
            None,
            "credential.access",
            "high",
        )
        .unwrap();

    ensure_test_authority_bridge_env();
    // resolve_approval is OperatorPresence-class — satisfy the
    // presence-token and unlocked-session gates so the second-party
    // happy path under test is reachable.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 501,
            pid: Some(std::process::id() as i32),
        }),
        operator_id,
    )
    .with_presence_token(Some(test_presence_token(501)));
    let resolved = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "resolve_approval",
        &json!({"id": req.id, "decision": "approve"}),
    )
    .await
    .unwrap();
    assert_eq!(resolved["status"], json!("approved"));
}

#[tokio::test]
async fn status_aggregated_rpc_landed_empty_store_returns_summary_shape() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let status = dispatch_method(&store, &vault, &policy, &rl, "status", &json!({}))
        .await
        .unwrap();
    assert_eq!(status["personas"].as_array().unwrap().len(), 0);
    assert_eq!(status["grants"].as_array().unwrap().len(), 0);
    assert_eq!(status["grant_live_leases"].as_array().unwrap().len(), 0);
    assert_eq!(status["sandboxes"].as_array().unwrap().len(), 0);
    assert_eq!(status["approvals"].as_array().unwrap().len(), 0);
    assert_eq!(status["recent_activity"].as_array().unwrap().len(), 0);
    assert_eq!(status["standing_grants"], json!(0));
    assert_eq!(status["audit_events_total"], json!(0));
    assert_eq!(status["quarantined"], json!(false));
    assert_eq!(status["quarantine_authority"], json!(null));
}

#[tokio::test]
async fn status_dispatch_returns_aggregated_rows() {
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
        &json!({"name": "status-alpha"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap().to_string();
    let _grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "api-key", "scope": "read", "force": true}),
        )
        .await
        .unwrap();
    store
        .log_event(
            Some("persona-test"),
            "grant.issued",
            Some("api-key"),
            "allowed",
            None,
        )
        .unwrap();

    let status = dispatch_method(&store, &vault, &policy, &rl, "status", &json!({}))
        .await
        .unwrap();
    assert_eq!(status["personas"].as_array().unwrap().len(), 1);
    assert_eq!(status["grants"].as_array().unwrap().len(), 1);
    assert_eq!(status["approvals"].as_array().unwrap().len(), 0);
    assert_eq!(status["standing_grants"], json!(0));
    assert_eq!(status["quarantined"], json!(false));
    assert_eq!(status["quarantine_authority"], json!(null));
    assert!(
        status["audit_events_total"].as_u64().unwrap() >= 1,
        "status must report at least the emitted audit row"
    );
    assert!(
        !status["recent_activity"].as_array().unwrap().is_empty(),
        "status must surface recent audit activity"
    );
}

#[tokio::test]
async fn team0_status_scopes_rows_to_trusted_principal() {
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
        &json!({"name": "status-team0-a"}),
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
        &json!({"name": "status-team0-b"}),
    )
    .await
    .unwrap();
    let persona_b_id = persona_b["id"].as_str().unwrap().to_string();

    for persona_id in [&persona_a_id, &persona_b_id] {
        dispatch_method(
                &store,
                &vault,
                &policy,
                &rl,
                "create_grant",
                &json!({"persona_id": persona_id, "credential_name": "api-key", "scope": "read", "force": true}),
            )
            .await
            .unwrap();
        store
            .submit_approval(
                persona_id,
                "api-key",
                "read",
                None,
                "credential.access",
                "high",
            )
            .unwrap();
        store
            .create_standing_grant(
                persona_id,
                &core_event_types::ActionSelector::named("tool.call"),
                "*",
                None,
            )
            .unwrap();
        store
            .log_event(
                Some(persona_id),
                "grant.issued",
                Some("api-key"),
                "allowed",
                None,
            )
            .unwrap();
    }

    let ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 1000,
            pid: Some(91_004),
        }),
        persona_a_id.clone(),
    );
    let status = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "status",
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(status["personas"].as_array().unwrap().len(), 1);
    assert_eq!(status["personas"][0]["id"], json!(persona_a_id));
    assert_eq!(status["grants"].as_array().unwrap().len(), 1);
    assert_eq!(status["approvals"].as_array().unwrap().len(), 1);
    assert_eq!(status["standing_grants"], json!(1));
    assert_eq!(status["quarantined"], json!(false));
    assert_eq!(status["quarantine_authority"], json!(null));
    assert!(
        status["audit_events_total"].as_u64().unwrap() >= 1,
        "status should report at least one audit row for the scoped persona"
    );
    let recent = status["recent_activity"]
        .as_array()
        .expect("recent_activity array");
    assert!(
        !recent.is_empty(),
        "status should include scoped recent activity"
    );
    assert!(
        recent
            .iter()
            .all(|row| row["agent_id"] == json!(persona_a_id))
    );
}

#[tokio::test]
async fn daemon_persona_method_returns_pubkey_when_initialised() {
    let _guard = setup_receipt_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let result = dispatch_method(&store, &vault, &policy, &rl, "daemon_persona", &json!({}))
        .await
        .unwrap();
    // Either a pubkey object or null (init raced on separate process) — but
    // since _guard held a tempdir that init_identity used for the OnceCell,
    // we expect a pubkey here.
    assert!(
        result.is_object(),
        "identity should be initialised in this test"
    );
    let pubkey = result["pubkey"].as_str().unwrap();
    assert_eq!(pubkey.len(), 64);
}

// --- C39-HANDLER-C2 regression tests ---------------------------------
// These tests verify that the `force: true` policy-bypass flag on
// `create_grant` is NOT honored when the request arrives via the socket
// entry point (`DispatchSource::Socket`). Previously an unauthenticated
// socket client could pass `force: true` and skip every policy gate.

#[tokio::test]
async fn create_grant_socket_rejects_force_true() {
    // A socket client sends `create_grant` with `force: true`. The
    // handler must reject with -32602 rather than minting the grant.
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
        &json!({"name": "c2-victim"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    // create_grant is OperatorPresence-class; the socket-source
    // shim synthesizes a presence_token, but the unlocked-session
    // gate still applies. Move presence to Unlocked so the test
    // reaches the force-refusal it asserts on (-32602).
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    // The default policy's `credential.access` rule is
    // `RequireApproval` — without `force`, a socket caller gets a
    // pending approval rather than a grant. With `force: true` the
    // handler MUST reject instead of bypassing policy.
    let err = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Socket,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "prod-stripe-key",
            "scope": "*",
            "force": true,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.0, -32602,
        "socket force must return -32602, got {err:?}"
    );
    assert!(
        err.1.to_lowercase().contains("force"),
        "error should mention force, got: {}",
        err.1
    );
}

#[tokio::test]
async fn create_grant_socket_without_force_runs_policy() {
    // Same request shape minus `force` — must be treated as an ordinary
    // policy-gated call. With default policy (RequireApproval for
    // credential.access), the response is a pending_approval envelope,
    // NOT a freshly minted grant.
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
        &json!({"name": "c2-policy"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    // Satisfy the OperatorPresence unlocked-session gate (see
    // create_grant_socket_rejects_force_true for the same setup).
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let result = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Socket,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "prod-stripe-key",
            "scope": "*",
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        result["status"],
        json!("pending_approval"),
        "default policy requires approval for credential.access"
    );
    assert!(result["approval_id"].is_string());
    // Crucially: no grant id was issued.
    assert!(result.get("id").is_none());
}

#[tokio::test]
async fn create_grant_socket_slash_credential_name_runs_policy() {
    // Credential names are vault resource identifiers, not policy action
    // names. Slash-containing names such as anthropic/oauth-token must
    // still route through the generic credential.access policy gate.
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
        &json!({"name": "slash-credential-policy"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let result = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Socket,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "anthropic/oauth-token",
            "scope": "llm:generate",
        }),
    )
    .await
    .unwrap();
    assert_eq!(result["status"], json!("pending_approval"));
    assert!(result["approval_id"].is_string());
    assert!(result.get("id").is_none());
}

#[tokio::test]
async fn create_grant_socket_with_force_false_is_allowed() {
    // Explicit `force: false` is indistinguishable from omitting it —
    // the socket path runs policy either way.
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
        &json!({"name": "c2-force-false"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    // Satisfy the OperatorPresence unlocked-session gate (see
    // create_grant_socket_rejects_force_true for the same setup).
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let result = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Socket,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "prod-stripe-key",
            "scope": "*",
            "force": false,
        }),
    )
    .await
    .unwrap();
    assert_eq!(result["status"], json!("pending_approval"));
}

#[tokio::test]
async fn create_grant_internal_honors_force() {
    // Internal callers (test harness / admin CLI path) retain the
    // ability to skip policy with `force: true`. This keeps the
    // legitimate bypass path working.
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
        &json!({"name": "c2-internal"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let result = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Internal {
            reason: "test harness — create_grant force bypass",
        },
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "prod-stripe-key",
            "scope": "read",
            "force": true,
        }),
    )
    .await
    .unwrap();
    assert!(
        result["id"].as_str().unwrap_or("").starts_with("grant-"),
        "internal force should mint a grant, got: {result}"
    );
}

// --- C39-HANDLER-C3 regression tests ---------------------------------
// A socket caller must assert `caller_persona_id` and it must match the
// parent grant's owner (`persona_id`). Otherwise any socket process
// could pick any leaked `parent_grant_id` and mint a child grant
// pinned to an attacker-controlled persona, forging the audit trail
// under the legitimate owner's name.

/// Helper: create two personas (A, B) and a grant owned by A with
/// delegation depth so it can be further attenuated. Returns the
/// tuple (a_id, b_id, parent_grant_id). Uses the `Internal` dispatch
/// path to set up — the `force: true` on `create_grant` requires it.
async fn c3_setup_two_personas_and_grant(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rl: &RefCell<RateLimiter>,
) -> (String, String, String) {
    let persona_a = dispatch_method(
        store,
        vault,
        policy,
        rl,
        "create_persona",
        &json!({"name": "c3-persona-a"}),
    )
    .await
    .unwrap();
    let a_id = persona_a["id"].as_str().unwrap().to_string();

    let persona_b = dispatch_method(
        store,
        vault,
        policy,
        rl,
        "create_persona",
        &json!({"name": "c3-persona-b"}),
    )
    .await
    .unwrap();
    let b_id = persona_b["id"].as_str().unwrap().to_string();

    let parent_grant = dispatch_method(
        store,
        vault,
        policy,
        rl,
        "create_grant",
        &json!({
            "persona_id": a_id,
            "credential_name": "c3-key",
            "scope": "*",
            "max_delegation_depth": 2,
            "force": true,
        }),
    )
    .await
    .unwrap();
    let parent_grant_id = parent_grant["id"].as_str().unwrap().to_string();

    (a_id, b_id, parent_grant_id)
}

#[tokio::test]
async fn test_delegate_grant_socket_rejects_non_owner() {
    // Parent grant is issued to persona A. Persona B tries to delegate
    // it via the socket path. The handler MUST reject before any state
    // mutation — no child grant may be minted, no `grant.delegated`
    // audit row may be written.
    //
    // PR #3828 hard-lock: delegate_grant is OperatorPresence-class and
    // requires an unlocked presence session. Pin to unlocked so the
    // refusal we assert on is the non-owner refusal, not the lock gate.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let (_a_id, b_id, parent_grant_id) =
        c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

    // Enroll caller PID with b_id so the Socket-source PID-enrollment
    // gate passes and the test exercises the authority-check path
    // (caller does not own parent) it was written to validate.
    enroll_pid_persona(std::process::id() as i32, &b_id);

    // Snapshot grant count before the attack to prove nothing was
    // minted. `list_active_grants` returns every active grant in the
    // store; we expect the count to be identical after rejection.
    let before = store.list_active_grants().unwrap().len();

    let err = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Socket,
        "delegate_grant",
        &json!({
            "parent_grant_id": parent_grant_id,
            "child_persona_id": b_id,
            "scope": "read",
            // Attacker asserts they are B, not A. B does not own
            // `parent_grant_id`.
            "caller_persona_id": b_id,
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32002, "expected -32002, got {err:?}");
    assert!(
        err.1.to_lowercase().contains("does not own"),
        "error should say caller does not own parent, got: {}",
        err.1
    );

    let after = store.list_active_grants().unwrap().len();
    assert_eq!(
        before, after,
        "no child grant must be minted when socket caller isn't parent owner"
    );
}

#[tokio::test]
async fn test_delegate_grant_socket_accepts_owner() {
    // Same setup but the socket caller correctly asserts persona A
    // (the parent owner). Delegation must succeed.
    //
    // PR #3828 hard-lock: see test_delegate_grant_socket_rejects_non_owner.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let (a_id, b_id, parent_grant_id) =
        c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

    // Enroll caller PID with a_id (parent owner) so the Socket-source
    // PID-enrollment gate passes and the test exercises the happy
    // owner-delegation path.
    enroll_pid_persona(std::process::id() as i32, &a_id);

    let result = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Socket,
        "delegate_grant",
        &json!({
            "parent_grant_id": parent_grant_id,
            "child_persona_id": b_id,
            "scope": "read",
            "caller_persona_id": a_id,
        }),
    )
    .await
    .unwrap();

    assert!(
        result["id"].as_str().unwrap_or("").starts_with("grant-"),
        "socket owner-delegation must mint a grant, got: {result}"
    );
    assert_eq!(result["parent"], json!(parent_grant_id));
}

// delegate_grant_socket_principal_not_enrolled — checkpoint for
// META-AP-DAEMON-SOCKET-MISSING-CALLER-PERSONA-ID-TEST-REWRITE.
//
// Original contract (pre-PR #3608): a Socket-source dispatch
// with missing `caller_persona_id` returned -32602 (invalid params).
// PR #3608 superseded that contract with the per-connection PID
// enrollment model: identity now flows from the PID registry,
// and the wire-claimed `caller_persona_id` is implicit when the
// calling PID is enrolled. The fail-closed property moved with
// the contract — it's now expressed as -32401
// (`PrincipalNotEnrolled`) when the calling PID has no enrollment
// AND no override caller_persona_id is on the wire.
//
// This rewritten test preserves the original test's intent
// ("Socket path must refuse to proceed when the caller's identity
// cannot be resolved") under the new identity model.
#[tokio::test]
async fn test_delegate_grant_socket_rejects_missing_caller_persona_id() {
    // Synthetic peer's PID is intentionally NOT enrolled —
    // dispatch_method_with_source synthesizes a peer (process PID),
    // but no prior call has registered it with a persona. With no
    // `caller_persona_id` on the wire either, principal resolution
    // fails closed via PrincipalNotEnrolled (-32401).
    //
    // PR #3828 hard-lock: see test_delegate_grant_socket_rejects_non_owner.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let (_a_id, b_id, parent_grant_id) =
        c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

    // Defense against test-order pollution: ensure the synthetic
    // test-process PID is NOT enrolled (other tests in this module
    // call enroll_pid_persona; without this clear the registry
    // could carry an entry from a prior test on the same thread).
    clear_pid_persona_registry();

    let err = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Socket,
        "delegate_grant",
        &json!({
            "parent_grant_id": parent_grant_id,
            "child_persona_id": b_id,
            "scope": "read",
            // no caller_persona_id, no PID enrollment
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(
        err.0, -32602,
        "missing param must return -32602, got {err:?}"
    );
    assert!(
        err.1.to_lowercase().contains("caller_persona_id"),
        "missing explicit fallback should mention caller_persona_id, got: {}",
        err.1
    );
}

#[tokio::test]
async fn test_delegate_grant_internal_bypass() {
    // Internal callers (admin CLI / test harness) bypass the
    // ownership gate. Parent is owned by A; an `Internal` dispatch
    // without any `caller_persona_id` MUST still succeed — mirrors
    // the C2 `force` bypass semantics for Internal.
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let (_a_id, b_id, parent_grant_id) =
        c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

    let result = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Internal {
            reason: "test harness — delegate_grant ownership bypass",
        },
        "delegate_grant",
        &json!({
            "parent_grant_id": parent_grant_id,
            "child_persona_id": b_id,
            "scope": "read",
            // Deliberately omit caller_persona_id — Internal bypasses.
        }),
    )
    .await
    .unwrap();

    assert!(
        result["id"].as_str().unwrap_or("").starts_with("grant-"),
        "internal bypass must mint a grant, got: {result}"
    );
}

// --- C39-HANDLER-C3-FULL regression tests ----------------------------
//
// Full principal binding via `SO_PEERCRED` / `LOCAL_PEERCRED` derived
// peer credential. The new layer:
//   1. Enrolls (peer.pid -> persona_id) in `create_persona` from a
//      Socket caller carrying a real PeerCred.
//   2. On `delegate_grant`, derives the kernel principal from the
//      peer's PID and rejects any params.caller_persona_id that
//      doesn't match the kernel principal (`PrincipalMismatch`).
//   3. On macOS where pid is None, fails closed with
//      `PrincipalUnavailable` rather than silently allowing.
//
// These tests exercise the handler dispatch surface directly with
// synthetic `RequestContext` so we don't need a real Unix socket
// pair or a second OS user — both impossible in CI.

#[tokio::test]
async fn forged_caller_persona_id_in_delegate_params_rejected() {
    // The threat model that motivated C39-HANDLER-C3-FULL: an
    // attacker process running under the daemon's UID enumerates
    // personas, learns the victim's persona_id, and asserts it as
    // `caller_persona_id`.  Under C39-HANDLER-C3 alone the request
    // would succeed.  Under C39-HANDLER-C3-FULL the kernel-derived
    // principal does not match, so the handler MUST reject with
    // `PrincipalMismatch`.
    clear_pid_persona_registry();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let (a_id, b_id, parent_grant_id) =
        c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

    // Attacker connection: the kernel says the peer is persona B
    // (the attacker's enrolled identity).  Attacker forges params
    // claiming to be A (the parent grant's owner).  The mismatch
    // between asserted A and kernel-derived B must trip the gate
    // BEFORE we even reach the ownership check.
    let attacker_pid: i32 = 70_001;
    enroll_pid_persona(attacker_pid, &b_id);

    ensure_test_authority_bridge_env();
    // delegate_grant is OperatorPresence-class. The test attaches a
    // valid presence_token below, but the unlocked-session gate
    // still applies — move presence to Unlocked so we reach the
    // PrincipalMismatch check under test.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();
    let ctx = RequestContext {
        source: DispatchSource::Socket,
        peer: Some(PeerCred {
            uid: 1000,
            pid: Some(attacker_pid),
        }),
        principal: None,
        sessions_dir: None,
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: None,
        // META-AP-DAEMON-PER-METHOD-AUTHORITY-D-4-HANDLER-VALIDATE
        // — attach a valid presence_token so the Phase D-4 gate
        // passes; the test asserts a deeper authorization check.
        presence_token: Some(test_presence_token(1000)),
        bypass_binary_pin_gate_for_test: false,
    };

    let before = store.list_active_grants().unwrap().len();

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "delegate_grant",
        &json!({
            "parent_grant_id": parent_grant_id,
            "child_persona_id": b_id,
            "scope": "read",
            // Attacker forges A as caller — but the kernel knows
            // they are running under PID enrolled to B.
            "caller_persona_id": a_id,
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(
        err.0, -32401,
        "expected -32401 PrincipalMismatch, got {err:?}"
    );
    assert!(
        err.1.to_lowercase().contains("principal") || err.1.to_lowercase().contains("mismatch"),
        "error should reference principal mismatch, got: {}",
        err.1
    );

    let after = store.list_active_grants().unwrap().len();
    assert_eq!(
        before, after,
        "no child grant must be minted when params forge a different caller"
    );
}

#[tokio::test]
async fn create_persona_can_skip_peer_pid_enrollment_for_launcher_onboarding() {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();
    clear_pid_persona_registry();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let operator = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "root"}),
    )
    .await
    .unwrap();
    let operator_id = operator["id"].as_str().unwrap().to_string();

    let peer = PeerCred {
        uid: 1000,
        pid: Some(80_104),
    };
    ensure_test_authority_bridge_env();
    let create_ctx = RequestContext {
        source: DispatchSource::Socket,
        peer: Some(peer),
        principal: None,
        sessions_dir: None,
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: None,
        presence_token: Some(test_presence_token(peer.uid)),
        bypass_binary_pin_gate_for_test: false,
    };
    let agent = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        create_ctx,
        "create_persona",
        &json!({"name": "claude-code-default", "enroll_peer_pid": false}),
    )
    .await
    .unwrap();
    let agent_id = agent["id"].as_str().unwrap().to_string();

    assert_eq!(
        peercred_principal(&peer),
        Err(HandlerError::PrincipalNotEnrolled),
        "launcher onboarding creates an agent persona but must not bind the operator CLI PID to it"
    );

    let req = store
        .submit_approval(
            &agent_id,
            "claude-code-default-v1",
            "claude-code-default-v1",
            None,
            "credential.access",
            "high",
        )
        .unwrap();
    let resolve_ctx = RequestContext {
        source: DispatchSource::Socket,
        peer: Some(peer),
        principal: None,
        sessions_dir: None,
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: None,
        presence_token: Some(test_presence_token(peer.uid)),
        bypass_binary_pin_gate_for_test: false,
    };
    let resolved = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        resolve_ctx,
        "resolve_approval",
        &json!({
            "id": req.id,
            "decision": "approve",
            "caller_persona_id": operator_id,
        }),
    )
    .await
    .unwrap();
    assert_eq!(resolved["status"], json!("approved"));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_peercred_resolves_persona_via_pid_lookup() {
    // Happy path on Linux: a Socket caller creates a persona and the
    // daemon enrolls (peer.pid -> persona_id).  A subsequent
    // `delegate_grant` from the same PID is bound to that persona
    // without the caller having to assert `caller_persona_id`.
    //
    // Partial of META-AP-EMBER-DAEMON-BROKEN-TEST-CLUSTER (#4372):
    // `dispatch_method_with_context` enforces a presence-unlocked
    // gate at the entry of every method dispatch (line ~2618).
    // Tests that exercise the dispatch path must hold a
    // `test_state_guard()` and call `mark_unlocked()` first or the
    // gate fires before the test reaches its assertions. The
    // surrounding tests in this module (see e.g. handler.rs:7785,
    // 7837, 9793) follow the same pattern.
    // Anchor: `ember_daemon_broken_test_cluster_resolved`.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();
    clear_pid_persona_registry();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // Use a synthetic PID — never reused by a real process during
    // the test because the registry is thread-local and reset.
    let caller_pid: i32 = 80_002;
    let peer = PeerCred {
        uid: 1000,
        pid: Some(caller_pid),
    };

    // Step 1: create_persona via Socket with the peer credential.
    // Handler enrolls the (pid -> persona_id) pair.
    ensure_test_authority_bridge_env();
    let create_ctx = RequestContext {
        source: DispatchSource::Socket,
        peer: Some(peer),
        principal: None,
        sessions_dir: None,
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: None,
        // META-AP-DAEMON-PER-METHOD-AUTHORITY-D-4-HANDLER-VALIDATE
        // — attach a valid presence_token so the Phase D-4 gate
        // passes; the test exercises the enrollment/peercred
        // resolution path, not the auth gate.
        presence_token: Some(test_presence_token(peer.uid)),
        bypass_binary_pin_gate_for_test: false,
    };
    let persona = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        create_ctx,
        "create_persona",
        &json!({"name": "c3full-linux-caller"}),
    )
    .await
    .unwrap();
    let caller_persona_id = persona["id"].as_str().unwrap().to_string();

    // Verify the enrollment landed.
    let resolved =
        peercred_principal(&peer).expect("PID must resolve to enrolled persona on Linux");
    assert_eq!(
        resolved, caller_persona_id,
        "peercred_principal must return the enrolled persona id"
    );

    // Step 2: build a parent grant owned by the enrolled persona
    // via Internal (force=true requires Internal).  Then delegate
    // via Socket from the same PID — must succeed without any
    // caller_persona_id forgery.
    let parent_grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": caller_persona_id,
            "credential_name": "c3full-linux-key",
            "scope": "*",
            "max_delegation_depth": 2,
            "force": true,
        }),
    )
    .await
    .unwrap();
    let parent_grant_id = parent_grant["id"].as_str().unwrap().to_string();

    // child persona for the delegation target.
    let child = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "c3full-linux-child"}),
    )
    .await
    .unwrap();
    let child_id = child["id"].as_str().unwrap().to_string();

    let delegate_ctx = RequestContext {
        source: DispatchSource::Socket,
        peer: Some(peer),
        principal: None,
        sessions_dir: None,
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: None,
        // META-AP-DAEMON-PER-METHOD-AUTHORITY-D-4-HANDLER-VALIDATE
        // — attach a valid presence_token so the Phase D-4 gate
        // passes; the test asserts the delegation succeeds via the
        // enrolled persona, not the auth gate.
        presence_token: Some(test_presence_token(peer.uid)),
        bypass_binary_pin_gate_for_test: false,
    };
    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        delegate_ctx,
        "delegate_grant",
        &json!({
            "parent_grant_id": parent_grant_id,
            "child_persona_id": child_id,
            "scope": "read",
            // Caller may also assert caller_persona_id; if so, it
            // must match the kernel principal.  Here we assert the
            // correct value to exercise the matching branch.
            "caller_persona_id": caller_persona_id,
        }),
    )
    .await
    .unwrap();

    assert!(
        result["id"].as_str().unwrap_or("").starts_with("grant-"),
        "Linux peercred-resolved owner must mint a grant, got: {result}"
    );
    assert_eq!(result["parent"], json!(parent_grant_id));
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn macos_peercred_pid_none_fails_closed() {
    // macOS LOCAL_PEERCRED does not always surface the peer PID.
    // When pid is `None` we cannot derive a principal — the only
    // safe move is to fail-closed with `PrincipalUnavailable`.
    // Falling back to UID-only binding would let any same-UID
    // process claim any persona, defeating the gate.
    clear_pid_persona_registry();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let (a_id, b_id, parent_grant_id) =
        c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;
    // Suppress unused warning when the kernel-principal path runs
    // before the ownership check would have been hit.
    let _ = a_id;

    ensure_test_authority_bridge_env();
    // The OperatorPresence gate enforces both a presence-token AND
    // an unlocked session before any handler runs. The test asserts
    // the PrincipalUnavailable path for pid=None, which fires after
    // both gates — so move presence to Unlocked here.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();
    // Peer credential with no PID — the macOS edge case.
    let ctx = RequestContext {
        source: DispatchSource::Socket,
        peer: Some(PeerCred {
            uid: 1000,
            pid: None,
        }),
        principal: None,
        sessions_dir: None,
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: None,
        // META-AP-DAEMON-PER-METHOD-AUTHORITY-D-4-HANDLER-VALIDATE
        // — attach a valid presence_token so the Phase D-4 gate
        // passes; the test asserts the PrincipalUnavailable path
        // for pid=None, not the auth gate.
        presence_token: Some(test_presence_token(1000)),
        bypass_binary_pin_gate_for_test: false,
    };

    let before = store.list_active_grants().unwrap().len();

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "delegate_grant",
        &json!({
            "parent_grant_id": parent_grant_id,
            "child_persona_id": b_id,
            "scope": "read",
            // Even with a "correct" caller_persona_id assertion,
            // the daemon must still reject — pid=None means the
            // principal is unverifiable, so we cannot trust ANY
            // attacker-supplied caller_persona_id.
            "caller_persona_id": b_id,
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(
        err.0, -32401,
        "expected -32401 PrincipalUnavailable, got {err:?}"
    );
    assert!(
        err.1.to_lowercase().contains("unavailable") || err.1.to_lowercase().contains("principal"),
        "error should mention principal unavailable, got: {}",
        err.1
    );

    let after = store.list_active_grants().unwrap().len();
    assert_eq!(
        before, after,
        "no child grant must be minted on macOS when pid is None"
    );
}

#[test]
fn peercred_principal_returns_unavailable_when_pid_is_none() {
    // Direct unit test of the peercred_principal helper — no
    // dispatch overhead.  This is the single-source-of-truth for
    // the macOS fail-closed semantics.
    let peer = PeerCred {
        uid: 1000,
        pid: None,
    };
    match peercred_principal(&peer) {
        Err(HandlerError::PrincipalUnavailable) => {}
        other => panic!("expected PrincipalUnavailable for pid=None, got: {other:?}"),
    }
}

#[test]
fn peercred_principal_returns_not_enrolled_for_unknown_pid() {
    // Direct unit test: a PID with no enrollment yields
    // `PrincipalNotEnrolled` — the caller has not yet established
    // an identity in this daemon.
    clear_pid_persona_registry();
    let peer = PeerCred {
        uid: 1000,
        pid: Some(99_999),
    };
    match peercred_principal(&peer) {
        Err(HandlerError::PrincipalNotEnrolled) => {}
        other => panic!("expected PrincipalNotEnrolled for un-enrolled PID, got: {other:?}"),
    }
}

// -----------------------------------------------------------------
// TZ-SOPS-1B-IMPL Phase 2: sops_unwrap_dek RPC tests
// -----------------------------------------------------------------

/// Build an age-encrypted DEK ciphertext for the given recipient
/// public key. Used by the sops_unwrap_dek tests below.
#[cfg(feature = "age")]
fn encrypt_dek_for(public_key: &str, plaintext: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let recipient: age::x25519::Recipient = public_key.parse().unwrap();
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .unwrap();
    let mut ciphertext = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    ciphertext
}

/// Happy path: a valid grant + a vault-stored age key + a
/// well-formed ciphertext returns the plaintext DEK as hex.
#[tokio::test]
#[cfg(feature = "age")]
async fn sops_unwrap_dek_happy_path_returns_plaintext() {
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
        &json!({"name": "sops-happy"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    // Generate an age keypair, stash the private key in the vault
    // at the canonical path, and prepare a ciphertext recipient.
    let keypair = crate::age::generate_age_keypair().unwrap();
    let vault_path = crate::age::vault_path_for_persona(persona_id);
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": vault_path, "value": keypair.private_key}),
    )
    .await
    .unwrap();

    let plaintext_dek = b"deadbeef-this-is-the-data-encryption-key";
    let ciphertext = encrypt_dek_for(&keypair.public_key, plaintext_dek);
    let blob_hex = hex::encode(&ciphertext);

    // The brief defines the receipted credential as the SOPS DEK
    // unwrap, not a vault credential — but the grant gating still
    // requires a credential_name. Use the canonical vault_path so a
    // single grant covers both "read the age key" and "unwrap a
    // DEK" semantics from the operator's POV.
    let grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": vault_path,
            "scope": "sops:unwrap",
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "sops_unwrap_dek",
        &json!({
            "persona_id": persona_id,
            "grant_id": grant_id,
            "encrypted_dek_blob": blob_hex,
        }),
    )
    .await
    .unwrap();

    let dek_hex = result["dek_hex"].as_str().unwrap();
    let unwrapped = hex::decode(dek_hex).unwrap();
    assert_eq!(unwrapped.as_slice(), plaintext_dek.as_slice());

    let fp = result["dek_fingerprint"].as_str().unwrap();
    assert_eq!(
        fp.len(),
        32,
        "fingerprint should be 16 bytes -> 32 hex chars"
    );
    assert_eq!(result["grant_id"], json!(grant_id));
    assert_eq!(result["persona_id"], json!(persona_id));

    // Audit: a sops_dek_unwrapped row should be present.
    assert!(store.is_dek_grant_consumed(grant_id));
}

/// Rate-limit: a second call with the same grant_id is rejected.
#[tokio::test]
#[cfg(feature = "age")]
async fn sops_unwrap_dek_rejects_duplicate_grant_id() {
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
        &json!({"name": "sops-dup"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let keypair = crate::age::generate_age_keypair().unwrap();
    let vault_path = crate::age::vault_path_for_persona(persona_id);
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": vault_path, "value": keypair.private_key}),
    )
    .await
    .unwrap();

    let ciphertext = encrypt_dek_for(&keypair.public_key, b"payload");
    let blob_hex = hex::encode(&ciphertext);

    let grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": vault_path,
            "scope": "sops:unwrap",
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();

    // First call: success.
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "sops_unwrap_dek",
        &json!({
            "persona_id": persona_id,
            "grant_id": grant_id,
            "encrypted_dek_blob": blob_hex,
        }),
    )
    .await
    .unwrap();

    // Second call with the SAME grant_id: rejected with -32005
    // (the same code we use for revoked / inactive grants).
    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "sops_unwrap_dek",
        &json!({
            "persona_id": persona_id,
            "grant_id": grant_id,
            "encrypted_dek_blob": blob_hex,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32005);
    assert!(
        err.1.contains("already been used") || err.1.contains("already-consumed"),
        "expected duplicate-rejection message, got: {}",
        err.1
    );
}

/// Cross-persona attack: caller supplies a valid grant_id whose
/// persona doesn't match the asserted persona_id. Rejected.
#[tokio::test]
#[cfg(feature = "age")]
async fn sops_unwrap_dek_rejects_cross_persona_grant() {
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
        &json!({"name": "sops-owner"}),
    )
    .await
    .unwrap();
    let owner_id = owner["id"].as_str().unwrap();

    let keypair = crate::age::generate_age_keypair().unwrap();
    let vault_path = crate::age::vault_path_for_persona(owner_id);
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": vault_path, "value": keypair.private_key}),
    )
    .await
    .unwrap();

    let ciphertext = encrypt_dek_for(&keypair.public_key, b"payload");
    let blob_hex = hex::encode(&ciphertext);

    let grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": owner_id,
            "credential_name": vault_path,
            "scope": "sops:unwrap",
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "sops_unwrap_dek",
        &json!({
            "persona_id": "persona-other",
            "grant_id": grant_id,
            "encrypted_dek_blob": blob_hex,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32002);
    // Slot must NOT be consumed when the caller is rejected.
    assert!(!store.is_dek_grant_consumed(grant_id));
}

/// Inactive grant: a revoked grant cannot unwrap a DEK.
#[tokio::test]
#[cfg(feature = "age")]
async fn sops_unwrap_dek_rejects_revoked_grant() {
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
        &json!({"name": "sops-revoked"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let keypair = crate::age::generate_age_keypair().unwrap();
    let vault_path = crate::age::vault_path_for_persona(persona_id);
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": vault_path, "value": keypair.private_key}),
    )
    .await
    .unwrap();

    let ciphertext = encrypt_dek_for(&keypair.public_key, b"payload");
    let blob_hex = hex::encode(&ciphertext);

    let grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": vault_path,
            "scope": "sops:unwrap",
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();

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

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "sops_unwrap_dek",
        &json!({
            "persona_id": persona_id,
            "grant_id": grant_id,
            "encrypted_dek_blob": blob_hex,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32005);
}

/// Missing persona age key: vault has no entry at the canonical
/// path, so the unwrap fails with a clear -32000 error.
#[tokio::test]
#[cfg(feature = "age")]
async fn sops_unwrap_dek_errors_when_age_key_missing() {
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
        &json!({"name": "sops-no-key"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let vault_path = crate::age::vault_path_for_persona(persona_id);
    let grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": vault_path,
            "scope": "sops:unwrap",
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();

    // Build a synthetic ciphertext (won't be reached — vault lookup fails).
    let dummy_keypair = crate::age::generate_age_keypair().unwrap();
    let ciphertext = encrypt_dek_for(&dummy_keypair.public_key, b"x");
    let blob_hex = hex::encode(&ciphertext);

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "sops_unwrap_dek",
        &json!({
            "persona_id": persona_id,
            "grant_id": grant_id,
            "encrypted_dek_blob": blob_hex,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32000);
    assert!(err.1.contains("no age private key"), "got: {}", err.1);
    // Slot must NOT be consumed when the vault lookup fails — we
    // reject before claiming it.
    assert!(!store.is_dek_grant_consumed(grant_id));
}

/// ADR 211: an active grant with no live grant-scoped lease key is inert and
/// cannot perform the authority-to-act DEK unwrap.
#[tokio::test]
#[cfg(feature = "age")]
async fn sops_unwrap_dek_rejects_active_grant_without_live_lease() {
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
        &json!({"name": "sops-no-live-lease"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let keypair = crate::age::generate_age_keypair().unwrap();
    let vault_path = crate::age::vault_path_for_persona(persona_id);
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": vault_path, "value": keypair.private_key}),
    )
    .await
    .unwrap();

    let ciphertext = encrypt_dek_for(&keypair.public_key, b"payload");
    let blob_hex = hex::encode(&ciphertext);

    let grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": vault_path,
            "scope": "sops:unwrap",
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();
    assert!(
        store.leases().drop_lease(grant_id),
        "test setup must remove the live lease while leaving the grant active"
    );

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "sops_unwrap_dek",
        &json!({
            "persona_id": persona_id,
            "grant_id": grant_id,
            "encrypted_dek_blob": blob_hex,
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32005);
    assert!(
        err.1.contains("no live leased authority") || err.1.contains("inert"),
        "expected live-lease rejection message, got: {}",
        err.1
    );
    assert!(
        !store.is_dek_grant_consumed(grant_id),
        "missing leased authority must not consume the one-shot unwrap slot"
    );
}

/// Malformed hex blob: caller passes an unparseable hex string.
/// Rejected with -32602 (invalid params).
#[tokio::test]
#[cfg(feature = "age")]
async fn sops_unwrap_dek_rejects_malformed_hex() {
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
        &json!({"name": "sops-bad-hex"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();
    let vault_path = crate::age::vault_path_for_persona(persona_id);
    let grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": vault_path,
            "scope": "sops:unwrap",
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "sops_unwrap_dek",
        &json!({
            "persona_id": persona_id,
            "grant_id": grant_id,
            "encrypted_dek_blob": "not-hex!@#",
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32602);
}
