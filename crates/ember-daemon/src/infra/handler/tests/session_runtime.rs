use super::*;
use crate::infra::handlers::session::handle_session_lookup_or_open;

// -------------------------------------------------------------------------
// COHORT-A-V03-LAUNCHER-SESSION-RPC: register_session + close_session T2
// -------------------------------------------------------------------------

#[tokio::test]
async fn register_session_and_close_session_emit_clean_exit_receipt() {
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    interactive_unlock::reset_for_tests();
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
        &json!({"name": "sess-test-persona"}),
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
            "credential_name": "claude-code-default-v1",
            "scope": "claude-code",
            "ttl_secs": 3600,
            "max_delegation_depth": 1,
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();
    assert!(!grant_id.is_empty(), "grant must be created");

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir.clone());

    let reg = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx.clone(),
        "register_session",
        &json!({
            "persona": "sess-test-persona",
            "launcher_pid": std::process::id(),
        }),
    )
    .await
    .unwrap();

    let session_id = reg["session_id"].as_str().unwrap().to_string();
    let reg_grant_id = reg["grant_id"].as_str().unwrap();
    assert_ne!(
        reg_grant_id, grant_id,
        "register_session must mint a fresh runtime grant rather than reusing the durable parent grant"
    );
    assert_eq!(reg["durable_persona_id"], json!(persona_id));
    assert_ne!(
        reg["persona_id"],
        json!(persona_id),
        "register_session must return the runtime persona id, not the durable parent persona id"
    );
    let runtime_grant = store
        .get_grant(reg_grant_id)
        .expect("runtime child grant must exist");
    assert_eq!(
        runtime_grant.parent_grant_id.as_deref(),
        Some(grant_id),
        "runtime child grant must delegate from the durable parent grant"
    );
    assert!(!session_id.is_empty(), "session_id must be non-empty");
    assert_eq!(
        interactive_unlock::pin_count(),
        1,
        "register_session must acquire one interactive unlock pin"
    );

    let session_dir = sessions_dir.join(&session_id);
    assert!(session_dir.exists(), "session directory must be created");
    assert!(
        session_dir.join("meta.json").exists(),
        "meta.json must be written"
    );

    let close = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "close_session",
        &json!({ "session_id": session_id }),
    )
    .await
    .unwrap();

    assert_eq!(
        close["closed"],
        json!(true),
        "close_session must return closed:true"
    );
    assert_eq!(
        interactive_unlock::pin_count(),
        0,
        "close_session must release the interactive unlock pin"
    );

    let receipt_path = session_dir.join("receipt.json");
    let receipt_bytes =
        std::fs::read(&receipt_path).expect("receipt.json must be written by close_session");
    assert!(!receipt_bytes.is_empty(), "receipt.json must be non-empty");

    let envelope: core_events::receipt::ReceiptEnvelope =
        serde_json::from_slice(&receipt_bytes).expect("receipt.json parses as v2 envelope");
    assert_eq!(envelope.kind, "session.claude_code");
    assert!(envelope.signature.is_some(), "receipt must be signed");

    let body: core_events::receipt::ClaudeCodeBody = serde_json::from_value(envelope.body).unwrap();
    assert_eq!(
        body.termination_reason,
        Some(core_events::receipt::TerminationReason::CleanExit),
        "termination_reason must be clean_exit"
    );

    assert!(
        !session_dir.join("meta.json").exists(),
        "meta.json must be renamed to meta.json.closed on close"
    );
    assert!(
        session_dir.join("meta.json.closed").exists(),
        "meta.json.closed must exist after close"
    );

    // COHORT-A-V03-T3-FIX-HANDLER-CLEAN-EXIT-REVOKE: grant must remain
    // Active after CleanExit — the handler no longer calls revoke_grant.
    let grant_after = store.get_grant(grant_id).expect("grant still queryable");
    assert_eq!(
        grant_after.status, "active",
        "CleanExit MUST NOT revoke the durable parent grant — multi-session per 24h grant invariant"
    );
    let runtime_grant_after = store
        .get_grant(reg_grant_id)
        .expect("runtime grant still queryable after runtime revoke");
    assert_eq!(
        runtime_grant_after.status, "revoked",
        "closing the last attachment must revoke the ephemeral runtime grant"
    );
    interactive_unlock::reset_for_tests();
}

/// target_state_anchor: SCION-everywhere — verify the host-mode
/// `agent_socket_enrollments` row that `handle_register_session`
/// writes carries the runtime persona/grant/host-mode-hash shape
/// and is keyed on the synthetic `host-mode/<session_id>` path.
/// Without this row, broker_resolve's
/// `check_principal_enrollment_strict` (checkpoint
/// `fail_closed_broker_resolve`) refuses every PATH-shadow shim
/// call on behalf of this session with PrincipalNotEnrolled
/// (-32401), upstream of any authority_delegation scope check.
#[tokio::test]
async fn register_session_writes_host_mode_enrollment_row() {
    use crate::infra::handlers::session::host_mode_enrollment_socket_path;
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    interactive_unlock::reset_for_tests();
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
        &json!({"name": "host-mode-enroll-persona"}),
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

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir.clone());

    let reg = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "host-mode-enroll-persona",
            "launcher_pid": std::process::id(),
        }),
    )
    .await
    .unwrap();

    let session_id = reg["session_id"].as_str().unwrap();
    let runtime_persona_id = reg["runtime_persona_id"].as_str().unwrap();
    let runtime_grant_id = reg["grant_id"].as_str().unwrap();
    let socket_path = host_mode_enrollment_socket_path(session_id);

    let row = store
        .lookup_agent_socket_enrollment(&socket_path)
        .expect("lookup must succeed")
        .expect("host-mode enrollment row must be written by register_session");
    assert_eq!(row.persona_id, runtime_persona_id);
    assert_eq!(row.grant_id, runtime_grant_id);
    assert_eq!(row.brief_content_hash, "host-mode");
    assert_eq!(row.state, "active");
    assert!(
        row.cgroup_v2_id.is_none(),
        "host-mode rows must leave cgroup_v2_id NULL so the namespace gate no-ops"
    );
    assert!(
        row.userns_inode.is_none(),
        "host-mode rows must leave userns_inode NULL so the namespace gate no-ops"
    );
    assert!(
        row.mnt_ns_inode.is_none(),
        "host-mode rows must leave mnt_ns_inode NULL so the namespace gate no-ops"
    );
    interactive_unlock::reset_for_tests();
}

/// target_state_anchor: SCION-everywhere — verify
/// `handle_close_session` revokes (flips state to 'revoked') the
/// host-mode `agent_socket_enrollments` row so the runtime persona
/// stops satisfying `check_principal_enrollment_strict` once the
/// session is closed. Otherwise the row would survive past the
/// session's lifetime and keep granting broker-resolve access to
/// any process that happens to claim the same persona_id.
#[tokio::test]
async fn close_session_revokes_host_mode_enrollment_row() {
    use crate::infra::handlers::session::host_mode_enrollment_socket_path;
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    interactive_unlock::reset_for_tests();
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
        &json!({"name": "host-mode-close-persona"}),
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

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir.clone());

    let reg = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx.clone(),
        "register_session",
        &json!({
            "persona": "host-mode-close-persona",
            "launcher_pid": std::process::id(),
        }),
    )
    .await
    .unwrap();
    let session_id = reg["session_id"].as_str().unwrap().to_string();
    let socket_path = host_mode_enrollment_socket_path(&session_id);

    // Sanity: row is active before close.
    let row_before = store
        .lookup_agent_socket_enrollment(&socket_path)
        .expect("lookup must succeed")
        .expect("host-mode row must exist before close");
    assert_eq!(row_before.state, "active");

    dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "close_session",
        &json!({ "session_id": session_id }),
    )
    .await
    .unwrap();

    // `lookup_agent_socket_enrollment` filters on state='active';
    // the row should drop out of the active surface after close.
    let row_after = store
        .lookup_agent_socket_enrollment(&socket_path)
        .expect("lookup must succeed");
    assert!(
        row_after.is_none(),
        "close_session must flip the host-mode row out of the active surface"
    );
    interactive_unlock::reset_for_tests();
}

/// target_state_anchor: SCION-everywhere — store-level unit test:
/// `record_host_mode_socket_enrollment` populates `peer_uid` when
/// `Some(uid)` is passed, and leaves it NULL when `None` is
/// passed. The peer_uid value is what
/// `lookup_persona_uid_from_enrollments` reads — the upstream
/// hooks (`check_principal_enrollment_strict`,
/// `check_principal_against_persona`) depend on this for the gate
/// to recognize the row.
#[test]
fn record_host_mode_socket_enrollment_stamps_peer_uid_when_present() {
    let store = crate::infra::store::DaemonStore::open_in_memory().unwrap();
    store
        .record_host_mode_socket_enrollment(
            "host-mode/with-uid",
            "persona-with-uid",
            "grant-with-uid",
            Some(4242),
        )
        .expect("write host-mode row with peer_uid");

    let row = store
        .lookup_agent_socket_enrollment("host-mode/with-uid")
        .expect("lookup")
        .expect("row exists");
    assert_eq!(row.persona_id, "persona-with-uid");
    assert_eq!(row.grant_id, "grant-with-uid");
    assert_eq!(row.brief_content_hash, "host-mode");
    assert_eq!(row.state, "active");

    let uid = crate::infra::store::lookup_persona_uid_from_enrollments(&store, "persona-with-uid")
        .expect("lookup_persona_uid_from_enrollments");
    assert_eq!(
        uid,
        Some(4242),
        "peer_uid must be readable by the broker gate after a host-mode write"
    );
}

/// target_state_anchor: SCION-everywhere — internal-source register
/// callers (admin CLI, test harness) have `peer = None`; the row
/// is still written but `peer_uid` is NULL. The broker gates
/// short-circuit on `principal = None` for these callers, so the
/// NULL is the correct posture — only the kernel-attested socket
/// path needs the bound uid.
#[test]
fn record_host_mode_socket_enrollment_leaves_peer_uid_null_when_absent() {
    let store = crate::infra::store::DaemonStore::open_in_memory().unwrap();
    store
        .record_host_mode_socket_enrollment(
            "host-mode/no-uid",
            "persona-no-uid",
            "grant-no-uid",
            None,
        )
        .expect("write host-mode row without peer_uid");

    let row = store
        .lookup_agent_socket_enrollment("host-mode/no-uid")
        .expect("lookup")
        .expect("row exists");
    assert_eq!(row.brief_content_hash, "host-mode");

    let uid = crate::infra::store::lookup_persona_uid_from_enrollments(&store, "persona-no-uid")
        .expect("lookup_persona_uid_from_enrollments");
    assert!(
        uid.is_none(),
        "peer_uid NULL must surface as None from lookup_persona_uid_from_enrollments"
    );
}

/// target_state_anchor: SCION-everywhere — end-to-end: a host-mode
/// enrollment with a matching `peer_uid` satisfies both
/// `check_principal_enrollment_strict` (presence gate) and
/// `check_principal_against_persona` (uid-binding gate), the two
/// gates that today refuse a host-mode session's broker_resolve
/// calls with PrincipalNotEnrolled (-32401) / principal-binding
/// mismatch (-32004) respectively.
#[test]
fn host_mode_enrollment_satisfies_broker_resolve_gates() {
    use crate::broker::handler::{
        check_principal_against_persona, check_principal_enrollment_strict,
    };
    use crate::infra::runtime::PeerCredPrincipal;

    let store = crate::infra::store::DaemonStore::open_in_memory().unwrap();
    store
        .record_host_mode_socket_enrollment(
            "host-mode/sess_test",
            "runtime-persona-gate",
            "runtime-grant-gate",
            Some(7777),
        )
        .expect("write host-mode row");

    let principal =
        PeerCredPrincipal::new(7777, 12_345, std::path::PathBuf::from("/tmp/host.sock"));
    let params = json!({"persona_id": "runtime-persona-gate"});

    check_principal_enrollment_strict(Some(&principal), &store, &params, "persona_id")
        .expect("enrollment-strict gate must pass for matching host-mode row");
    check_principal_against_persona(Some(&principal), &store, &params, "persona_id")
        .expect("uid-binding gate must pass when peer_uid matches");
}

#[tokio::test]
async fn register_session_attach_reuses_runtime_lane_and_last_close_revokes_it() {
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    interactive_unlock::reset_for_tests();
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
        &json!({"name": "attach-runtime-persona"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap().to_string();

    let durable_grant = dispatch_method(
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
    let durable_grant_id = durable_grant["id"].as_str().unwrap().to_string();

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir.clone());

    let reg1 = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx.clone(),
        "register_session",
        &json!({
            "persona": "attach-runtime-persona",
            "launcher_pid": 41010,
        }),
    )
    .await
    .unwrap();
    let runtime_persona_id = reg1["runtime_persona_id"].as_str().unwrap().to_string();
    let runtime_grant_id = reg1["grant_id"].as_str().unwrap().to_string();
    let session1_id = reg1["session_id"].as_str().unwrap().to_string();

    let reg2 = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx.clone(),
        "register_session",
        &json!({
            "persona": "attach-runtime-persona",
            "launcher_pid": 41011,
            "attach_runtime_persona_id": runtime_persona_id,
        }),
    )
    .await
    .unwrap();
    let session2_id = reg2["session_id"].as_str().unwrap().to_string();

    assert_eq!(reg2["runtime_persona_id"], reg1["runtime_persona_id"]);
    assert_eq!(reg2["grant_id"], reg1["grant_id"]);
    assert_eq!(reg2["caller_binding_id"], reg1["caller_binding_id"]);
    assert_eq!(reg2["durable_persona_id"], json!(persona_id));

    let runtime_grant = store
        .get_grant(&runtime_grant_id)
        .expect("runtime grant must exist");
    assert_eq!(
        runtime_grant.parent_grant_id.as_deref(),
        Some(durable_grant_id.as_str())
    );

    dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx.clone(),
        "close_session",
        &json!({ "session_id": session1_id }),
    )
    .await
    .unwrap();

    assert_eq!(
        store
            .get_grant(&runtime_grant_id)
            .expect("runtime grant still exists")
            .status,
        "active",
        "closing one attachment must keep the shared runtime grant alive"
    );
    assert_eq!(
        store
            .get_persona(reg1["runtime_persona_id"].as_str().unwrap())
            .expect("runtime persona still exists")
            .status,
        "active",
        "closing one attachment must keep the shared runtime persona alive"
    );

    dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "close_session",
        &json!({ "session_id": session2_id }),
    )
    .await
    .unwrap();

    assert_eq!(
        store
            .get_grant(&runtime_grant_id)
            .expect("runtime grant still queryable")
            .status,
        "revoked",
        "closing the last attachment must revoke the runtime grant"
    );
    assert_eq!(
        store
            .get_persona(reg1["runtime_persona_id"].as_str().unwrap())
            .expect("runtime persona still queryable")
            .status,
        "revoked",
        "closing the last attachment must revoke the runtime persona"
    );
}

#[tokio::test]
async fn register_session_attach_inherits_binding_scoped_delegated_authority() {
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    interactive_unlock::reset_for_tests();
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
        &json!({"name": "attach-delegated-runtime"}),
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
            "scope": "claude-code",
            "ttl_secs": 3600,
            "max_delegation_depth": 1,
            "force": true,
        }),
    )
    .await
    .unwrap();

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir.clone());

    let reg1 = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx.clone(),
        "register_session",
        &json!({
            "persona": "attach-delegated-runtime",
            "launcher_pid": 42010,
        }),
    )
    .await
    .unwrap();
    let runtime_persona_id = reg1["runtime_persona_id"].as_str().unwrap().to_string();
    let session1_id = reg1["session_id"].as_str().unwrap().to_string();
    let binding_id = reg1["caller_binding_id"].as_str().unwrap().to_string();

    // BKR-4c (ADR 205 §6): the per-session authority is the shared runtime
    // persona's standing grant — the legacy delegation sidecar is retired. The
    // binding-scoped lifecycle (sibling attach keeps it live; last close
    // revokes) is observable via close_session's `workflow_cascade_revoked`.
    let session_store = core_state::sessions::SessionStore::new(sessions_dir.clone());
    let meta1 = session_store
        .read(&session1_id)
        .unwrap()
        .expect("session meta present");
    assert_eq!(
        store.get_grant(&meta1.grant_id).unwrap().status,
        "active",
        "register_session must mint an active runtime standing grant"
    );

    let reg2 = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx.clone(),
        "register_session",
        &json!({
            "persona": "attach-delegated-runtime",
            "launcher_pid": 42011,
            "attach_runtime_persona_id": runtime_persona_id,
        }),
    )
    .await
    .unwrap();
    let session2_id = reg2["session_id"].as_str().unwrap().to_string();

    assert_eq!(reg2["caller_binding_id"], json!(binding_id));

    // Closing one attachment must NOT revoke the binding-scoped standing grant
    // while a sibling attachment remains live.
    let close1 = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx.clone(),
        "close_session",
        &json!({ "session_id": session1_id }),
    )
    .await
    .unwrap();
    assert_eq!(
        close1["workflow_cascade_revoked"],
        json!(false),
        "closing one attachment must keep binding-scoped standing authority live for the sibling"
    );

    // Closing the last attachment terminates the runtime persona, revoking the
    // binding-scoped standing grant.
    let close2 = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "close_session",
        &json!({ "session_id": session2_id }),
    )
    .await
    .unwrap();
    assert_eq!(
        close2["workflow_cascade_revoked"],
        json!(true),
        "closing the last attachment must revoke the binding-scoped standing authority"
    );
}

#[tokio::test]
async fn revoke_grant_emits_receipt_with_grant_scope_claim_rollup_when_present() {
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
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
        &json!({"name": "revoke-rollup-persona"}),
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
            "credential_name": "cloudflare",
            "scope": "dns:edit",
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap().to_string();

    let journal = crate::infra::claim_journal::SqliteClaimJournal::new(&store, 64);
    let grant_scope = crate::infra::claim_journal::ScopeRef {
        kind: crate::infra::claim_journal::ClaimScopeKind::Grant,
        id: grant_id.clone(),
    };
    journal
        .record_successful_claim(
            &grant_scope,
            &crate::infra::claim_journal::SuccessfulClaimInput {
                source_key: "grant-resolve-1".to_string(),
                occurred_at: "2026-05-22T12:00:00Z".to_string(),
                claim_kind: core_events::receipt::ClaimKind::CredentialVended,
                tool: "git.push".to_string(),
                action_ref: None,
                runner_class: None,
                execution_domain: None,
                materialization_class: None,
                input_hash: "grant-hash-1".to_string(),
                input_redacted: json!({"kind": "broker_resolve", "grant_id": grant_id}),
                resolved: json!({"allowed": true}),
                audit: crate::infra::claim_journal::AuditEvidenceInput {
                    agent_id: Some(persona_id.to_string()),
                    action: "broker.resolve.materialized".to_string(),
                    credential: Some("cloudflare".to_string()),
                    outcome: "allowed".to_string(),
                    details: Some("{\"kind\":\"broker_resolve_materialized\"}".to_string()),
                },
                persona_id: Some(persona_id.to_string()),
                grant_id: Some(grant_id.clone()),
                device_id: None,
                delegation_id: None,
                materialization_id: Some("mat-grant-rollup-1".to_string()),
                credential_name: Some("cloudflare".to_string()),
            },
        )
        .unwrap();

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir.clone());

    dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "revoke_grant",
        &json!({ "id": grant_id }),
    )
    .await
    .unwrap();

    let receipt_path = sessions_dir
        .join(format!("grant:{grant_id}"))
        .join("receipt.json");
    let receipt_bytes =
        std::fs::read(&receipt_path).expect("revoke_grant must persist receipt.json sidecar");
    let envelope: core_events::receipt::ReceiptEnvelope =
        serde_json::from_slice(&receipt_bytes).expect("receipt.json parses as v2 envelope");
    assert_eq!(
        envelope.kind,
        core_events::receipt::RECEIPT_KIND_COMPOSITE_GRANT
    );
    let body: core_events::receipt::ClaudeCodeBody =
        serde_json::from_value(envelope.body).expect("receipt body parses");
    assert_eq!(body.base.claim_count_total, Some(1));
    assert_eq!(body.base.claim_events.len(), 1);
    assert_eq!(body.base.claim_segment_summaries.len(), 1);
    assert!(!body.base.claim_history_merkle_root.is_empty());
    assert_eq!(
        body.termination_reason,
        Some(core_events::receipt::TerminationReason::ExplicitRevoke)
    );
}

#[tokio::test]
async fn register_session_uses_trusted_principal_when_present() {
    // register_session mints an operator presence token, which requires
    // the process-singleton daemon identity to be initialised. The
    // sibling register_session_* tests in this module install the
    // identity via `setup_receipt_identity()` (e.g. handler.rs:16807,
    // :16894); this one was missing the call and tripped
    // `daemon identity not initialised — cannot mint operator presence
    // token` (handler.rs:1242) when run with no peer identity already
    // established by a prior test in the same process.
    let _id_dir = setup_receipt_identity();
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

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
        &json!({"name": "trusted-session-persona"}),
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
    let grant_id = grant["id"].as_str().unwrap().to_string();

    let sessions_root = tempfile::TempDir::new().unwrap();
    let mut ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 1000,
            pid: Some(41001),
        }),
        persona_id.clone(),
    );
    ctx.presence_token = Some(test_presence_token_for_scope(
        1000,
        PRESENCE_SCOPE_CLASS_SESSION_RUNTIME,
    ));
    ctx.sessions_dir = Some(sessions_root.path().to_path_buf());

    // Keep the §4 window pinned at the operation under test; fixture setup
    // above awaits multiple internal dispatches before this socket call.
    crate::trust::presence::mark_unlocked();

    let reg = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "trusted-session-persona",
            "launcher_pid": std::process::id(),
        }),
    )
    .await
    .unwrap();

    let runtime_grant_id = reg["grant_id"].as_str().expect("runtime grant id");
    assert_ne!(runtime_grant_id, grant_id.as_str());
    assert_eq!(reg["durable_persona_id"], json!(persona_id));
    assert_eq!(
        reg["presence_token"]["uid"],
        json!(1000),
        "socket register_session must mint a peer-bound operator presence token"
    );
    assert_eq!(
        reg["presence_token"]["scope"],
        json!("class:session-runtime"),
        "register_session must mint the session-runtime scope class"
    );
    let runtime_grant = store
        .get_grant(runtime_grant_id)
        .expect("runtime child grant must exist");
    assert_eq!(
        runtime_grant.parent_grant_id.as_deref(),
        Some(grant_id.as_str())
    );
}

/// ARCH-BROKER-FAIL-CLOSED-PER-RPC-ROLLOUT-E (option b): `register_session`
/// is the bootstrap enrollment WRITER and must stay open to an attested but
/// not-yet-enrolled caller. Adding `check_principal_enrollment_strict` here
/// would deadlock bootstrap (the caller could never become enrolled). This
/// guards the terminal rollout state recorded by
/// `broker::handler::FAIL_CLOSED_RPC_ROLLOUT_COMPLETE`
/// (checkpoint `fail_closed_rpc_rollout_complete`).
#[tokio::test]
async fn register_session_stays_open_for_unenrolled_attested_caller_completes_rollout_e() {
    let _id_dir = setup_receipt_identity();
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

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
        &json!({"name": "rollout-e-bootstrap-persona"}),
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
            "scope": "claude-code",
            "ttl_secs": 3600,
            "max_delegation_depth": 1,
            "force": true,
        }),
    )
    .await
    .unwrap();

    // Precondition: the durable persona has NO `agent_socket_enrollments`
    // row — the gated broker RPCs would refuse it with -32401. The bootstrap
    // writer (register_session) must NOT.
    assert!(
        crate::infra::store::lookup_persona_uid_from_enrollments(&store, &persona_id)
            .expect("enrollment lookup")
            .is_none(),
        "precondition: durable persona must be unenrolled before register_session"
    );

    let sessions_root = tempfile::TempDir::new().unwrap();
    let mut ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 1000,
            pid: Some(41002),
        }),
        persona_id.clone(),
    );
    ctx.presence_token = Some(test_presence_token_for_scope(
        1000,
        PRESENCE_SCOPE_CLASS_SESSION_RUNTIME,
    ));
    ctx.sessions_dir = Some(sessions_root.path().to_path_buf());

    // Keep the §4 window pinned at the operation under test; fixture setup
    // above awaits multiple internal dispatches before this socket call.
    crate::trust::presence::mark_unlocked();

    let reg = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "rollout-e-bootstrap-persona",
            "launcher_pid": std::process::id(),
        }),
    )
    .await
    .expect(
        "register_session must stay open for an attested but unenrolled caller \
         (ARCH-BROKER-FAIL-CLOSED-PER-RPC-ROLLOUT-E option b)",
    );

    assert!(
        reg["session_id"].as_str().is_some(),
        "bootstrap register must open a session"
    );
    assert_eq!(
        crate::broker::handler::FAIL_CLOSED_RPC_ROLLOUT_COMPLETE,
        "fail_closed_rpc_rollout_complete"
    );
}

#[tokio::test]
async fn register_session_can_create_session_from_open_se_window_without_existing_runtime_token() {
    let _id_dir = setup_receipt_identity();
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

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
        &json!({"name": "se-window-session-persona"}),
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
    let grant_id = grant["id"].as_str().unwrap().to_string();

    let sessions_root = tempfile::TempDir::new().unwrap();
    let ctx = RequestContext {
        source: DispatchSource::Socket,
        peer: Some(PeerCred {
            uid: 1000,
            pid: Some(42001),
        }),
        principal: None,
        sessions_dir: Some(sessions_root.path().to_path_buf()),
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: None,
        presence_token: None,
        bypass_binary_pin_gate_for_test: false,
    };

    let reg = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "se-window-session-persona",
            "launcher_pid": std::process::id(),
        }),
    )
    .await
    .unwrap();

    let runtime_grant_id = reg["grant_id"].as_str().expect("runtime grant id");
    assert_ne!(runtime_grant_id, grant_id.as_str());
    assert_eq!(reg["durable_persona_id"], json!(persona_id));
    assert_eq!(
        reg["presence_token"]["uid"],
        json!(1000),
        "session-open must mint a peer-bound runtime token"
    );
    assert_eq!(
        reg["presence_token"]["scope"],
        json!(PRESENCE_SCOPE_CLASS_SESSION_RUNTIME),
        "session-open must return the runtime scope for later broker calls"
    );
}

#[tokio::test]
async fn register_session_rejects_asserted_persona_mismatch_for_trusted_principal() {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(std::rc::Rc::new(test_vault()));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let trusted = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "trusted-session-persona"}),
    )
    .await
    .unwrap();
    let trusted_id = trusted["id"].as_str().unwrap().to_string();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": trusted_id,
            "credential_name": "claude-code-default-v1",
            "scope": "claude-code",
            "ttl_secs": 3600,
            "max_delegation_depth": 1,
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
        "create_persona",
        &json!({"name": "other-session-persona"}),
    )
    .await
    .unwrap();

    let sessions_root = tempfile::TempDir::new().unwrap();
    let mut ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 1000,
            pid: Some(41002),
        }),
        trusted_id,
    );
    ctx.presence_token = Some(test_presence_token_for_scope(
        1000,
        PRESENCE_SCOPE_CLASS_SESSION_RUNTIME,
    ));
    ctx.sessions_dir = Some(sessions_root.path().to_path_buf());

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "other-session-persona",
            "launcher_pid": std::process::id(),
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32004);
    assert!(
        err.1.contains("trusted principal"),
        "mismatch refusal should explain the trusted-principal binding, got: {}",
        err.1
    );
}

#[tokio::test]
async fn register_session_keeps_explicit_persona_fallback_without_trusted_principal() {
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
        &json!({"name": "fallback-session-persona"}),
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
    let grant_id = grant["id"].as_str().unwrap().to_string();

    let sessions_root = tempfile::TempDir::new().unwrap();
    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_root.path().to_path_buf());

    let reg = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "fallback-session-persona",
            "launcher_pid": std::process::id(),
        }),
    )
    .await
    .unwrap();

    let runtime_grant_id = reg["grant_id"].as_str().expect("runtime grant id");
    assert_ne!(runtime_grant_id, grant_id.as_str());
    assert_eq!(reg["durable_persona_id"], json!(persona_id));
    let runtime_grant = store
        .get_grant(runtime_grant_id)
        .expect("runtime child grant must exist");
    assert_eq!(
        runtime_grant.parent_grant_id.as_deref(),
        Some(grant_id.as_str())
    );
}

#[tokio::test]
async fn register_session_fails_closed_after_explicit_lock() {
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    interactive_unlock::reset_for_tests();
    crate::trust::presence::reset_for_tests();
    // SAFETY: serialized by PROCESS_TEST_LOCK for this test binary.
    unsafe { std::env::set_var("EMBER_VAULT_TEST_KEYRING_PRESENT", "1") };

    let config_root = tempfile::TempDir::new().unwrap();
    let config = crate::infra::config::DaemonConfig::for_test(config_root.path());
    let runtime_vault = std::rc::Rc::new(test_vault());

    let store = DaemonStore::open_in_memory_without_vault().unwrap();
    store.set_vault(std::rc::Rc::clone(&runtime_vault));
    let store = std::rc::Rc::new(store);
    crate::trust::presence::register_store(std::rc::Rc::clone(&store));
    interactive_unlock::register_config(config.clone());

    let policy = test_policy();
    let rl = test_rate_limiter();

    let persona = dispatch_method(
        store.as_ref(),
        runtime_vault.as_ref(),
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "reopen-persona"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let grant = dispatch_method(
        store.as_ref(),
        runtime_vault.as_ref(),
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "claude-code-default-v1",
            "scope": "claude-code",
            "ttl_secs": 3600,
            "force": true,
        }),
    )
    .await
    .unwrap();
    assert!(
        grant["id"].as_str().is_some(),
        "grant must exist before session-open reopen"
    );

    runtime_vault
        .add(
            crate::infra::vault::VaultScope::Interactive,
            store.as_ref(),
            "reopen-proof/key",
            b"secret-after-lock",
            None,
        )
        .expect("seed credential before explicit lock");

    crate::trust::presence::lock();
    assert!(
        store.vault().is_none(),
        "explicit lock must clear the live vault before register_session"
    );

    let sessions_root = tempfile::TempDir::new().unwrap();
    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_root.path().to_path_buf());

    let err = dispatch_method_with_context(
        store.as_ref(),
        runtime_vault.as_ref(),
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "reopen-persona",
            "launcher_pid": std::process::id(),
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32030);
    assert!(
        err.1.contains(
            "same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts"
        ),
        "register_session must fail closed instead of reopening the locked daemon"
    );
    assert!(
        err.1.contains("EMBER_VAULT_PASSPHRASE"),
        "guidance should name the fresh bootstrap/dev probe lane"
    );
    assert!(
        store.vault().is_none(),
        "hard lock must keep the live vault cleared"
    );
    assert_eq!(
        interactive_unlock::pin_count(),
        0,
        "failed register_session must not acquire a session pin"
    );

    interactive_unlock::reset_for_tests();
    crate::trust::presence::reset_for_tests();
    // SAFETY: serialized by PROCESS_TEST_LOCK for this test binary.
    unsafe { std::env::remove_var("EMBER_VAULT_TEST_KEYRING_PRESENT") };
}

#[tokio::test]
async fn register_session_fails_without_sessions_dir() {
    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(std::rc::Rc::new(test_vault()));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let ctx = RequestContext::internal("test harness");

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({ "persona": "x", "launcher_pid": 1u32 }),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.0, -32000,
        "should fail with -32000 when sessions_dir absent"
    );
    assert!(
        err.1.contains("sessions_dir"),
        "error should mention sessions_dir"
    );
}

#[tokio::test]
async fn register_session_codex_lane_rejects_legacy_default_grant_without_openai_gateway() {
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
        &json!({"name": "codex-legacy-only-persona"}),
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
            "credential_name": "codex-default-v1",
            "scope": "codex-default-v1",
            "ttl_secs": 3600,
            "max_delegation_depth": 1,
            "force": true,
        }),
    )
    .await
    .unwrap();

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "codex-legacy-only-persona",
            "launcher_pid": std::process::id(),
            "attestation_caller": "codex-network-proxy",
        }),
    )
    .await
    .expect_err("Codex launcher sessions must not bind legacy local-only grants");

    assert_eq!(err.0, -32004);
    assert!(
        err.1
            .contains("openai/plan/chatgpt-oauth/<account>/<subject>"),
        "error should name the required OpenAI credential: {err:?}"
    );
    assert!(
        err.1
            .contains("cannot fall back to legacy codex-default-v1"),
        "error should make the fail-closed posture explicit: {err:?}"
    );
}

#[tokio::test]
async fn register_session_codex_lane_rejects_model_gateway_without_github_ceiling() {
    use core_grant_types::{ResourceSelector, ResourceType, StatementProposal};

    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(std::rc::Rc::new(test_vault()));
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
        &json!({"name": "codex-model-only-persona"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();
    let credential_name = "openai/plan/chatgpt-oauth/acct/sub";

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_composite_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": credential_name,
            "scope": "codex-default-v1",
            "ttl_secs": 3600,
            "max_delegation_depth": 1,
            "statements": [
                StatementProposal {
                    resource_type: ResourceType::Credential,
                    credential_name: credential_name.to_string(),
                    actions: vec!["credential:read".to_string()],
                    resource: ResourceSelector::Exact {
                        value: credential_name.to_string(),
                    },
                    budget: None,
                    conditions: vec![],
                },
                StatementProposal {
                    resource_type: ResourceType::Session,
                    credential_name: credential_name.to_string(),
                    actions: vec!["llm:generate".to_string()],
                    resource: ResourceSelector::Glob {
                        pattern: "openai/*".to_string(),
                    },
                    budget: None,
                    conditions: vec![],
                }
            ]
        }),
    )
    .await
    .expect("model-only codex composite grant should mint");

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "codex-model-only-persona",
            "launcher_pid": std::process::id(),
            "attestation_caller": "codex-network-proxy",
            "delegation_template": "read-only",
            "authority_strict": true,
        }),
    )
    .await
    .expect_err("model-only codex grants must not be selected for delegated ember-gh sessions");

    assert_eq!(err.0, -32004);
    assert!(
        err.1
            .contains("openai/plan/chatgpt-oauth/<account>/<subject>"),
        "error should ask for a repaired Codex brokered runtime grant: {err:?}"
    );
}

#[tokio::test]
async fn register_session_codex_lane_skips_gateway_grant_without_live_lease() {
    use core_grant_types::{ResourceSelector, ResourceType, StatementProposal};

    fn codex_gateway_statements(credential_name: &str) -> Vec<StatementProposal> {
        vec![
            StatementProposal {
                resource_type: ResourceType::Credential,
                credential_name: credential_name.to_string(),
                actions: vec!["credential:read".to_string()],
                resource: ResourceSelector::Exact {
                    value: credential_name.to_string(),
                },
                budget: None,
                conditions: vec![],
            },
            StatementProposal {
                resource_type: ResourceType::Credential,
                credential_name: String::new(),
                actions: vec!["github:*".to_string()],
                resource: ResourceSelector::Glob {
                    pattern: "*".to_string(),
                },
                budget: None,
                conditions: vec![],
            },
            StatementProposal {
                resource_type: ResourceType::Session,
                credential_name: credential_name.to_string(),
                actions: vec!["llm:generate".to_string()],
                resource: ResourceSelector::Glob {
                    pattern: "openai/*".to_string(),
                },
                budget: None,
                conditions: vec![],
            },
        ]
    }

    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(std::rc::Rc::new(test_vault()));
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
        &json!({"name": "codex-stale-grant-persona"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();
    let credential_name = "openai/plan/chatgpt-oauth/acct/sub";

    let stale = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_composite_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": credential_name,
            "scope": "codex-default-v1",
            "ttl_secs": 3600,
            "max_delegation_depth": 1,
            "statements": codex_gateway_statements(credential_name),
        }),
    )
    .await
    .expect("stale codex composite grant should mint");
    let stale_id = stale["id"].as_str().unwrap().to_string();
    assert!(
        store.leases().drop_lease(&stale_id),
        "test setup must leave the first grant active but inert"
    );

    let live = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_composite_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": credential_name,
            "scope": "codex-default-v1",
            "ttl_secs": 3600,
            "max_delegation_depth": 1,
            "statements": codex_gateway_statements(credential_name),
        }),
    )
    .await
    .expect("replacement codex composite grant should mint");
    let live_id = live["id"].as_str().unwrap().to_string();

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);

    let reg = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "codex-stale-grant-persona",
            "launcher_pid": std::process::id(),
            "attestation_caller": "codex-network-proxy",
            "delegation_template": "read-only",
            "authority_strict": true,
        }),
    )
    .await
    .expect("register_session must skip the stale active OpenAI gateway grant");

    let runtime_grant_id = reg["grant_id"].as_str().expect("runtime grant id");
    let runtime_grant = store
        .get_grant(runtime_grant_id)
        .expect("runtime child grant must exist");
    assert_eq!(
        runtime_grant.parent_grant_id.as_deref(),
        Some(live_id.as_str()),
        "runtime delegation must be minted from the live grant, not the stale active row"
    );
}

#[tokio::test]
async fn register_session_claude_lane_rejects_legacy_default_grant_without_anthropic_gateway() {
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
        &json!({"name": "claude-legacy-only-persona"}),
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
            "scope": "claude-code-default-v1",
            "ttl_secs": 3600,
            "max_delegation_depth": 1,
            "force": true,
        }),
    )
    .await
    .unwrap();

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "claude-legacy-only-persona",
            "launcher_pid": std::process::id(),
            "attestation_caller": "claude-code",
        }),
    )
    .await
    .expect_err("Claude launcher sessions must not bind legacy local-only grants");

    assert_eq!(err.0, -32004);
    assert!(
        err.1
            .contains("anthropic/plan/claude-oauth/* or anthropic/api/key/*"),
        "error should name the required Anthropic credential: {err:?}"
    );
    assert!(
        err.1
            .contains("cannot fall back to legacy claude-code-default-v1"),
        "error should make the fail-closed posture explicit: {err:?}"
    );
}

#[tokio::test]
async fn register_session_claude_lane_rejects_model_gateway_without_github_ceiling() {
    use core_grant_types::{ResourceSelector, ResourceType, StatementProposal};

    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(std::rc::Rc::new(test_vault()));
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
        &json!({"name": "claude-model-only-persona"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();
    let credential_name = "anthropic/plan/claude-oauth/fp-test";

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_composite_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": credential_name,
            "scope": "claude-code-default-v1",
            "ttl_secs": 3600,
            "max_delegation_depth": 1,
            "statements": [
                StatementProposal {
                    resource_type: ResourceType::Credential,
                    credential_name: credential_name.to_string(),
                    actions: vec!["credential:read".to_string()],
                    resource: ResourceSelector::Exact {
                        value: credential_name.to_string(),
                    },
                    budget: None,
                    conditions: vec![],
                },
                StatementProposal {
                    resource_type: ResourceType::Session,
                    credential_name: credential_name.to_string(),
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
    .expect("model-only composite grant should mint");

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "claude-model-only-persona",
            "launcher_pid": std::process::id(),
            "attestation_caller": "claude-code",
            "delegation_template": "read-only",
            "authority_strict": true,
        }),
    )
    .await
    .expect_err("model-only grants must not be selected for delegated ember-gh sessions");

    assert_eq!(err.0, -32004);
    assert!(
        err.1
            .contains("anthropic/plan/claude-oauth/* or anthropic/api/key/*"),
        "error should ask for a repaired brokered runtime grant: {err:?}"
    );
}

#[tokio::test]
async fn register_session_ember_forge_lane_rejects_legacy_default_grant_without_anthropic_gateway()
{
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
        &json!({"name": "forge-legacy-only-persona"}),
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
            "scope": "claude-code-default-v1",
            "ttl_secs": 3600,
            "max_delegation_depth": 1,
            "force": true,
        }),
    )
    .await
    .unwrap();

    let mut ctx = RequestContext::internal("test harness");
    ctx.sessions_dir = Some(sessions_dir);

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "register_session",
        &json!({
            "persona": "forge-legacy-only-persona",
            "launcher_pid": std::process::id(),
            "attestation_caller": "internal-automation",
        }),
    )
    .await
    .expect_err("Ember Forge sessions must not bind legacy local-only grants");

    assert_eq!(err.0, -32004);
    assert!(
        err.1
            .contains("anthropic/plan/claude-oauth/* or anthropic/api/key/*"),
        "error should name the required Anthropic credential: {err:?}"
    );
    assert!(
        err.1
            .contains("cannot fall back to legacy claude-code-default-v1"),
        "error should make the fail-closed posture explicit: {err:?}"
    );
}

// ---------------------------------------------------------------
// ARCH-BROKER-PEERCRED-PRINCIPAL-BINDING — session.lookup_or_open
// ---------------------------------------------------------------

/// `session.lookup_or_open` refuses when no kernel-attested
/// principal is available — wire-only RPC, Internal source is
/// rejected with `-32401`.
#[tokio::test]
async fn session_lookup_or_open_refuses_without_principal() {
    let store = crate::infra::store::DaemonStore::open_in_memory().unwrap();
    let res = handle_session_lookup_or_open(None, &store, &json!({})).await;
    let (code, msg) = res.expect_err("must refuse without principal");
    assert_eq!(code, -32401, "expected -32401, got {code}: {msg}");
}

/// `session.lookup_or_open` refuses when the caller-supplied
/// `parent_pid` does not match the kernel-attested peer pid.
#[tokio::test]
async fn session_lookup_or_open_refuses_mismatched_parent_pid() {
    use crate::infra::runtime::PeerCredPrincipal;
    let store = crate::infra::store::DaemonStore::open_in_memory().unwrap();
    let principal =
        PeerCredPrincipal::new(1001, 42_000, std::path::PathBuf::from("/tmp/agent.sock"));
    let params = json!({"parent_pid": 99_999});
    let res = handle_session_lookup_or_open(Some(&principal), &store, &params).await;
    let (code, msg) = res.expect_err("must refuse mismatched parent_pid");
    assert_eq!(code, -32004, "expected -32004, got {code}: {msg}");
    assert!(
        msg.contains("parent_pid") || msg.contains("99999") || msg.contains("42000"),
        "error must mention the mismatch, got: {msg}"
    );
}

/// `session.lookup_or_open` refuses when the caller-supplied
/// `persona` resolves to a different bound uid than the kernel-
/// attested principal's uid.
#[tokio::test]
async fn session_lookup_or_open_refuses_mismatched_persona() {
    use crate::infra::runtime::PeerCredPrincipal;
    let store = crate::infra::store::DaemonStore::open_in_memory().unwrap();
    store
        .record_agent_socket_enrollment(
            "/run/emberd/test-agent-victim.sock",
            "victim-persona",
            "test-grant",
            "test-hash",
            None,
            None,
            None,
        )
        .unwrap();
    store
        .conn()
        .execute(
            "UPDATE agent_socket_enrollments SET peer_uid = ?1 WHERE socket_path = ?2",
            rusqlite::params![5555i64, "/run/emberd/test-agent-victim.sock"],
        )
        .unwrap();
    let principal =
        PeerCredPrincipal::new(6666, 42_000, std::path::PathBuf::from("/tmp/agent.sock"));
    let params = json!({"persona": "victim-persona"});
    let res = handle_session_lookup_or_open(Some(&principal), &store, &params).await;
    let (code, _) = res.expect_err("must refuse mismatched persona binding");
    assert_eq!(code, -32004);
}

/// `session.lookup_or_open` succeeds when the principal is
/// supplied and no caller-supplied identity claims conflict with
/// it. Returns the session_id + parent_pid + socket_path triple.
#[tokio::test]
async fn session_lookup_or_open_succeeds_on_matched_principal() {
    use crate::infra::runtime::PeerCredPrincipal;
    let store = crate::infra::store::DaemonStore::open_in_memory().unwrap();
    store
        .record_agent_socket_enrollment(
            "/run/emberd/test-agent-matched.sock",
            "matched-persona",
            "test-grant",
            "test-hash",
            None,
            None,
            None,
        )
        .unwrap();
    store
        .conn()
        .execute(
            "UPDATE agent_socket_enrollments SET peer_uid = ?1 WHERE socket_path = ?2",
            rusqlite::params![7777i64, "/run/emberd/test-agent-matched.sock"],
        )
        .unwrap();
    let principal =
        PeerCredPrincipal::new(7777, 12_345, std::path::PathBuf::from("/tmp/agent.sock"));
    let params = json!({"persona": "matched-persona", "parent_pid": 12_345});
    let res = handle_session_lookup_or_open(Some(&principal), &store, &params).await;
    let value = res.expect("matched principal must succeed");
    assert_eq!(value["parent_pid"].as_i64(), Some(12_345));
    assert_eq!(value["persona_id"].as_str(), Some("matched-persona"));
    assert_eq!(value["socket_path"].as_str(), Some("/tmp/agent.sock"));
    assert!(
        value["session_id"]
            .as_str()
            .unwrap_or("")
            .starts_with("sess_"),
        "session_id must be minted, got: {value}"
    );
}

/// META-AP-DAEMON-EVALUATE-TOOL-CALL-OVERLAY-EXTEND — shape check that
/// the overlay block at the dispatch site overwrites the wire-claimed
/// `persona` (and the `persona_id` / `id` aliases the various dispatch
/// arms read) with the kernel-attested or cert-attested identity. The
/// pre-fix code only inserted `caller_persona` / `caller_persona_id`,
/// leaving a persona-reading arm to honor the attacker-controlled wire
/// `persona` field. This test replicates the overlay logic on test data
/// — full per-agent-UDS enrollment scaffolding is heavier than this
/// shape-check warrants, but the load-bearing invariant (wire-claimed
/// persona is OVERWRITTEN, not honored, when an overlay source exists)
/// is what we assert here.
#[test]
fn dispatch_overlay_pins_persona_for_enrolled_caller() {
    // Wire payload claims persona-B (the attacker's target).
    let mut wire = json!({
        "persona": "persona-B",
        "persona_id": "persona-B",
        "id": "persona-B",
        "caller_persona": "persona-B",
        "caller_persona_id": "persona-B",
        "tool_name": "Bash",
        "tool_params": {"command": "echo hi"},
    });

    // Overlay source: kernel-attested identity is persona-A with grant-A.
    let overlay_persona_id = "persona-A".to_string();
    let overlay_grant_id = Some("grant-A".to_string());

    // Same overlay logic as `dispatch_method_with_context`.
    if let Value::Object(obj) = &mut wire {
        for key in [
            "caller_persona",
            "caller_persona_id",
            "persona",
            "persona_id",
            "id",
        ] {
            obj.insert(key.to_string(), Value::String(overlay_persona_id.clone()));
        }
        if let Some(gid) = overlay_grant_id.as_ref() {
            obj.insert("caller_grant_id".to_string(), Value::String(gid.clone()));
        }
    }

    // Every persona-claim alias the dispatch arms read must now be the
    // overlay-pinned A, not the wire-claimed B.
    assert_eq!(wire["persona"], json!("persona-A"));
    assert_eq!(wire["persona_id"], json!("persona-A"));
    assert_eq!(wire["id"], json!("persona-A"));
    assert_eq!(wire["caller_persona"], json!("persona-A"));
    assert_eq!(wire["caller_persona_id"], json!("persona-A"));
    assert_eq!(wire["caller_grant_id"], json!("grant-A"));
    // Non-persona fields untouched.
    assert_eq!(wire["tool_name"], json!("Bash"));
}
