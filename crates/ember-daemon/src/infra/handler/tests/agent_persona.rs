use super::*;
use crate::infra::audit::AuditFilter;

// ------------------------------------------------------------------
// SCION-FOUNDATION-AGENT-PERSONA-RPC end-to-end tests.
// ------------------------------------------------------------------

/// Helper: mint a parent grant suitable for delegation tests.
/// Returns `(parent_persona_id, parent_grant_id)`.
async fn setup_parent_grant_for_agent_persona(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rl: &RefCell<RateLimiter>,
    parent_name: &str,
) -> (String, String) {
    let parent_persona = dispatch_method(
        store,
        vault,
        policy,
        rl,
        "create_persona",
        &json!({"name": parent_name}),
    )
    .await
    .unwrap();
    let parent_persona_id = parent_persona["id"].as_str().unwrap().to_string();

    let parent_grant = dispatch_method(
        store,
        vault,
        policy,
        rl,
        "create_grant",
        &json!({
            "persona_id": parent_persona_id,
            "credential_name": "delegate-key",
            "scope": "*",
            "max_delegation_depth": 2,
            "ttl_secs": 3_600,
            "force": true,
        }),
    )
    .await
    .unwrap();
    let parent_grant_id = parent_grant["id"].as_str().unwrap().to_string();
    (parent_persona_id, parent_grant_id)
}

#[tokio::test]
async fn create_agent_persona_atomic_mints_active_persona_and_attenuated_grant() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let (_parent_persona_id, parent_grant_id) =
        setup_parent_grant_for_agent_persona(&store, &vault, &policy, &rl, "agent-parent-atomic")
            .await;

    let resp = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_agent_persona",
        &json!({
            "name": "scion-worker-1",
            "container_id": "ctr-atomic-001",
            "parent_grant_id": parent_grant_id,
            "child_scope": "read",
            "ttl_secs": 1_800,
            "binding_request_id": "br-scion-001",
            "agent_id": "scion-agent-aaa",
        }),
    )
    .await
    .unwrap();

    // Caller sees an `active` persona (the `enrolling` intermediate
    // state is internal to the two-phase commit).
    assert_eq!(resp["status"], json!("active"));
    let new_persona_id = resp["persona_id"].as_str().unwrap().to_string();
    assert!(new_persona_id.starts_with("persona-"));
    let attenuated_grant_id = resp["attenuated_grant_id"].as_str().unwrap();
    assert!(attenuated_grant_id.starts_with("grant-"));
    assert_eq!(resp["container_id"], json!("ctr-atomic-001"));
    assert_eq!(resp["parent_grant_id"], json!(parent_grant_id));

    // Persona row matches: status=active, container binding persisted.
    let row = store.get_persona(&new_persona_id).unwrap();
    assert_eq!(row.status, "active");
    assert_eq!(row.container_id.as_deref(), Some("ctr-atomic-001"));
    assert_eq!(
        row.parent_grant_id.as_deref(),
        Some(parent_grant_id.as_str())
    );

    // Audit log carries the canonical binding event.
    let entries = store
        .query_audit(&AuditFilter {
            persona_id: Some(new_persona_id.clone()),
            ..Default::default()
        })
        .unwrap();
    let row = entries
        .iter()
        .find(|e| e.action == "agent_persona.created")
        .unwrap_or_else(|| panic!("expected agent_persona.created audit row, got {entries:?}"));
    let details: serde_json::Value =
        serde_json::from_str(row.details.as_deref().expect("details JSON populated"))
            .expect("details parses as JSON");
    assert_eq!(details["container_id"], json!("ctr-atomic-001"));
    assert_eq!(details["parent_grant_id"], json!(parent_grant_id));
    assert_eq!(details["child_grant_id"], json!(attenuated_grant_id));
    assert_eq!(details["binding_request_id"], json!("br-scion-001"));
    assert_eq!(details["agent_id"], json!("scion-agent-aaa"));
}

/// SCION-209 #2 — requesting `bridge_client_bundle: true` is FAIL-SOFT: when the
/// daemon bridge listener is unconfigured (as in this in-memory test daemon) the
/// persona + attenuated grant are still minted active and the bundle is simply
/// omitted, so the spawn never fails on a bridge-mint error. (When a bridge
/// listener IS configured the daemon mints + returns the real ADR 154 bundle —
/// SAN content is pinned by `sign_client_cert_emits_persona_and_container_spiffe_sans`,
/// and end-to-end delivery is a runtime check.) The orchestrator never mints
/// the cert locally.
#[tokio::test]
async fn create_agent_persona_bridge_bundle_request_is_fail_soft() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let (_parent_persona_id, parent_grant_id) =
        setup_parent_grant_for_agent_persona(&store, &vault, &policy, &rl, "agent-parent-bundle")
            .await;

    let resp = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_agent_persona",
        &json!({
            "name": "scion-worker-bundle",
            "container_id": "ctr-bundle-001",
            "parent_grant_id": parent_grant_id,
            "child_scope": "read",
            "ttl_secs": 1_800,
            "bridge_client_bundle": true,
        }),
    )
    .await
    .unwrap();

    // Spawn succeeds: persona active, grant minted ...
    assert_eq!(resp["status"], json!("active"));
    assert!(resp["persona_id"].as_str().unwrap().starts_with("persona-"));
    assert!(
        resp["attenuated_grant_id"]
            .as_str()
            .unwrap()
            .starts_with("grant-")
    );
    // ... and the bundle is omitted (fail-soft: no bridge listener in tests),
    // rather than the spawn failing on a bridge-mint error.
    assert!(
        resp.get("bridge_client_bundle").is_none(),
        "bridge bundle must be fail-soft omitted when the bridge is unconfigured, got {resp}"
    );
}

/// SCION-209 #2 / ADR 154 ESC-3 — a bridge RPC carrying an mTLS principal whose
/// container SAN does NOT match the persona's `agent_personas.container_id`
/// binding is refused at dispatch (-32004). This is the cross-check the
/// `MtlsPrincipal` contract promises; before this change the container SAN was
/// emitted but never enforced on the non-session bridge lane. A matching
/// container SAN is NOT rejected on the container axis.
#[tokio::test]
async fn bridge_rpc_rejects_container_san_mismatch_against_persona_binding() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let sessions = tempfile::tempdir().expect("sessions tempdir");

    let (_parent_persona_id, parent_grant_id) =
        setup_parent_grant_for_agent_persona(&store, &vault, &policy, &rl, "agent-parent-esc3")
            .await;

    // Spawn a container-bound worker persona (binding container_id = ctr-esc3-bind).
    let spawn = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_agent_persona",
        &json!({
            "name": "scion-worker-esc3",
            "container_id": "ctr-esc3-bind",
            "parent_grant_id": parent_grant_id,
            "child_scope": "read",
            "ttl_secs": 1_800,
        }),
    )
    .await
    .unwrap();
    let worker_persona = spawn["persona_id"].as_str().unwrap().to_string();

    // Build a bridge ctx whose cert container SAN MISMATCHES the binding.
    let mismatch_ctx = RequestContext {
        source: DispatchSource::Bridge(MtlsPrincipal {
            persona_id: worker_persona.clone(),
            container_id: "ctr-esc3-WRONG".to_owned(),
            cert_fingerprint: [7u8; 32],
        }),
        peer: Some(PeerCred {
            uid: 1000,
            pid: Some(std::process::id() as i32),
        }),
        principal: None,
        sessions_dir: Some(sessions.path().to_path_buf()),
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: None,
        presence_token: None,
        bypass_binary_pin_gate_for_test: true,
    };
    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        mismatch_ctx,
        "list_grants",
        &json!({ "persona_id": worker_persona }),
    )
    .await
    .expect_err("container SAN mismatch must be refused");
    assert_eq!(
        err.0, -32004,
        "must be a principal-binding violation: {err:?}"
    );
    assert!(
        err.1.contains("container"),
        "error must name the container binding: {}",
        err.1
    );

    // A MATCHING container SAN is not rejected on the container axis.
    let match_ctx = RequestContext {
        source: DispatchSource::Bridge(MtlsPrincipal {
            persona_id: worker_persona.clone(),
            container_id: "ctr-esc3-bind".to_owned(),
            cert_fingerprint: [7u8; 32],
        }),
        peer: Some(PeerCred {
            uid: 1000,
            pid: Some(std::process::id() as i32),
        }),
        principal: None,
        sessions_dir: Some(sessions.path().to_path_buf()),
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: None,
        presence_token: None,
        bypass_binary_pin_gate_for_test: true,
    };
    let res = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        match_ctx,
        "list_grants",
        &json!({ "persona_id": worker_persona }),
    )
    .await;
    if let Err(e) = res {
        assert!(
            !(e.0 == -32004 && e.1.contains("container")),
            "matching container SAN must NOT trip the container-binding violation: {e:?}"
        );
    }
}

/// ADR 155 priv-sep §1c (SLICE 1) — a credential-plaintext-bearing method
/// (`PLAINTEXT_BEARING_METHODS`) is refused DAEMON-SIDE on the `Bridge` lane,
/// defense-in-depth over the untrusted sibling's own `gate_method`. Even if a
/// compromised sibling forwarded one, emberd refuses it before dispatch with
/// the policy-denied error code.
#[tokio::test]
async fn bridge_lane_refuses_plaintext_bearing_method_daemon_side() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // Seed a host-mode persona (container_id NULL) so the F6 persona-existence
    // gate passes and the request reaches the daemon-side denylist.
    store
        .conn()
        .execute(
            "INSERT INTO personas (id, name, public_key, created_at, status) \
             VALUES (?1, ?2, 'pk', ?3, 'active')",
            rusqlite::params![
                "persona-bridge-denylist",
                "bridge-denylist",
                chrono::Utc::now().to_rfc3339()
            ],
        )
        .unwrap();

    let ctx = RequestContext::bridge(
        Some(PeerCred {
            uid: 501,
            pid: Some(std::process::id() as i32),
        }),
        MtlsPrincipal {
            persona_id: "persona-bridge-denylist".to_owned(),
            container_id: "ctr-bridge-denylist".to_owned(),
            cert_fingerprint: [0xAB; 32],
        },
    );

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "vault_unseal",
        &json!({}),
    )
    .await
    .expect_err("plaintext-bearing method must be refused on the bridge lane");

    assert_eq!(
        err.0,
        ember_rpc::POLICY_DENIED_ERROR_CODE as i32,
        "must be the policy-denied code: {err:?}"
    );
    assert!(
        err.1.contains("bridge lane"),
        "error must name the bridge lane: {}",
        err.1
    );
}

/// ADR 154 audit-equivalence (SLICE 1) — every `Bridge` dispatch writes one
/// hash-chained `bridge.dispatch` audit row carrying the client cert
/// fingerprint + the resolved persona/container/method, so a later-revoked
/// cert can be correlated to its bridge-lane traffic.
#[tokio::test]
async fn bridge_dispatch_writes_cert_fingerprint_audit_row() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // Seed a host-mode persona (container_id NULL) so F6 + the container
    // cross-check both pass and dispatch reaches the audit-chain write.
    store
        .conn()
        .execute(
            "INSERT INTO personas (id, name, public_key, created_at, status) \
             VALUES (?1, ?2, 'pk', ?3, 'active')",
            rusqlite::params![
                "persona-bridge-audit",
                "bridge-audit",
                chrono::Utc::now().to_rfc3339()
            ],
        )
        .unwrap();

    let fingerprint = [0xCDu8; 32];
    let ctx = RequestContext::bridge(
        Some(PeerCred {
            uid: 501,
            pid: Some(std::process::id() as i32),
        }),
        MtlsPrincipal {
            persona_id: "persona-bridge-audit".to_owned(),
            container_id: "ctr-bridge-audit".to_owned(),
            cert_fingerprint: fingerprint,
        },
    );

    // `list_grants` is NOT plaintext-bearing, so it passes the denylist; the
    // audit row is written before any downstream authorization outcome.
    let _ = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "list_grants",
        &json!({ "persona_id": "persona-bridge-audit" }),
    )
    .await;

    let entries = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("bridge.dispatch".to_string()),
            ..Default::default()
        })
        .unwrap();
    let row = entries
        .iter()
        .find(|e| {
            e.details
                .as_ref()
                .map(|d| d.contains(&hex::encode(fingerprint)))
                .unwrap_or(false)
        })
        .expect("a bridge.dispatch audit row carrying the cert fingerprint");
    assert_eq!(row.action, "bridge.dispatch");
    assert_eq!(row.outcome, "bridge_call");
    assert_eq!(row.agent_id.as_deref(), Some("persona-bridge-audit"));
    let details = row.details.as_deref().unwrap_or("");
    assert!(details.contains("list_grants"), "details: {details}");
    assert!(details.contains("ctr-bridge-audit"), "details: {details}");
}

/// F6 (ADR 155 priv-sep SLICE 2a) — a Bridge cert claiming a persona that does
/// NOT exist is refused fail-closed (-32004), not silently passed. Before F6 the
/// (persona,container) cross-check short-circuited (PASSED) on `get_persona`
/// NotFound, which — once a production Bridge context is stamped — would let a
/// cert minted for a non-existent persona be honored as the caller.
#[tokio::test]
async fn bridge_refuses_nonexistent_persona_fail_closed() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // No persona seeded → get_persona returns NotFound.
    let ctx = RequestContext::bridge(
        Some(PeerCred {
            uid: 501,
            pid: Some(std::process::id() as i32),
        }),
        MtlsPrincipal {
            persona_id: "persona-does-not-exist".to_owned(),
            container_id: "ctr-x".to_owned(),
            cert_fingerprint: [0u8; 32],
        },
    );
    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "list_grants",
        &json!({}),
    )
    .await
    .expect_err("a Bridge cert for a non-existent persona must be refused");
    assert_eq!(
        err.0, -32004,
        "must be a principal-binding violation: {err:?}"
    );
    assert!(
        err.1.contains("persona"),
        "error must name the persona SAN: {}",
        err.1
    );
}

/// F7 (ADR 155 priv-sep) — the Bridge lane must NEVER ride the operator's §4
/// presence window to obtain operator-direct (`*`) authority. Even with the
/// window OPEN (operator se-unlocked), a Bridge-sourced operator-direct
/// OperatorPresence method (here `local_state_key_get`) is denied -32001
/// instead of being granted the `*` scope. Legitimate bridge calls use the
/// session-runtime scope, exercised by the `dispatch_broker_*_from_bridge_lane`
/// tests; this pins that the operator-authority escalation is closed.
#[tokio::test]
async fn bridge_lane_denied_operator_section4_window() {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked(); // §4 window OPEN
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();

    // Seed the persona so F6 + the container cross-check pass and dispatch
    // reaches the operator-presence authority gate.
    store
        .conn()
        .execute(
            "INSERT INTO personas (id, name, public_key, created_at, status) \
             VALUES (?1, ?2, 'pk', ?3, 'active')",
            rusqlite::params![
                "persona-bridge-f7",
                "bridge-f7",
                chrono::Utc::now().to_rfc3339()
            ],
        )
        .unwrap();

    let ctx = RequestContext::bridge(
        Some(PeerCred {
            uid: 501,
            pid: Some(std::process::id() as i32),
        }),
        MtlsPrincipal {
            persona_id: "persona-bridge-f7".to_owned(),
            container_id: "ctr-f7".to_owned(),
            cert_fingerprint: [0u8; 32],
        },
    );

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "local_state_key_get",
        &json!({ "caller": "claude", "key": "k" }),
    )
    .await
    .expect_err("Bridge must not obtain operator-direct authority via the §4 window");
    assert_eq!(
        err.0, -32001,
        "must be an authority denial, not an operator-direct grant: {err:?}"
    );
}

#[tokio::test]
async fn create_agent_persona_rejects_unknown_parent_grant() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_agent_persona",
        &json!({
            "name": "scion-worker-orphan",
            "container_id": "ctr-orphan",
            "parent_grant_id": "grant-does-not-exist",
            "child_scope": "read",
        }),
    )
    .await
    .unwrap_err();

    // Bad parent grant must surface BEFORE any persona row is
    // inserted — leaves no poisoned enrolling slot.
    assert_eq!(err.0, -32004, "got: {err:?}");
    let by_container = store.enrolling_persona_for_container("ctr-orphan").unwrap();
    assert!(
        by_container.is_none(),
        "failed-validation create_agent_persona must NOT leave an enrolling row behind"
    );
}

#[tokio::test]
async fn create_agent_persona_rejects_duplicate_container_spawn() {
    // CRIT-4: a second create_agent_persona for the same
    // container_id must be refused even after the first has
    // successfully activated.
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let (_pp, parent_grant_id) =
        setup_parent_grant_for_agent_persona(&store, &vault, &policy, &rl, "agent-parent-dup")
            .await;

    let _first = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_agent_persona",
        &json!({
            "name": "scion-dup-1",
            "container_id": "ctr-dup",
            "parent_grant_id": parent_grant_id,
            "child_scope": "read",
            "ttl_secs": 1_800,
        }),
    )
    .await
    .unwrap();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_agent_persona",
        &json!({
            "name": "scion-dup-2",
            "container_id": "ctr-dup",
            "parent_grant_id": parent_grant_id,
            "child_scope": "read",
            "ttl_secs": 1_800,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32005, "got: {err:?}");
    assert!(
        err.1.contains("ctr-dup") || err.1.contains("already bound"),
        "expected container-already-bound message, got: {}",
        err.1
    );
}

/// SCION-FOUNDATION-AGENT-PERSONA-RPC acceptance criterion:
/// "emberd restart mid-spawn → reconciler refuses to spawn into
/// enrolling slot."
///
/// Simulated by directly inserting a persona row in `enrolling`
/// state (representing phase 1 having committed before the daemon
/// crashed); the reconciler's
/// `enrolling_persona_for_container` lookup MUST surface the
/// poisoned slot, and a subsequent `create_agent_persona` for the
/// same container_id MUST be refused.
#[tokio::test]
async fn create_agent_persona_emberd_restart_mid_spawn_blocks_reconciler() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let (_pp, parent_grant_id) =
        setup_parent_grant_for_agent_persona(&store, &vault, &policy, &rl, "agent-parent-restart")
            .await;

    // Simulate "emberd crashed after phase 1 (insert enrolling
    // row) but before phase 3 (activate)" by inserting the
    // enrolling row directly through the store API — bypassing
    // the RPC's atomic phase-2 + phase-3 path.
    let enrolling = store
        .create_agent_persona_enrolling("scion-crashed", "ctr-mid-spawn", &parent_grant_id)
        .unwrap();
    // Note: we never call activate_persona — the row stays in
    // `enrolling` forever, mimicking the daemon-crash window.

    // The reconciler's lookup MUST see the poisoned slot.
    let poisoned = store
        .enrolling_persona_for_container("ctr-mid-spawn")
        .unwrap()
        .expect("reconciler must see enrolling row after simulated crash");
    assert_eq!(poisoned.id, enrolling.id);
    assert_eq!(poisoned.status, "enrolling");

    // A second create_agent_persona RPC for the same
    // container_id MUST be refused — the reconciler will see the
    // -32005 error and treat the slot as poisoned until an
    // operator cleans it up out-of-band.
    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_agent_persona",
        &json!({
            "name": "scion-restart-attempt",
            "container_id": "ctr-mid-spawn",
            "parent_grant_id": parent_grant_id,
            "child_scope": "read",
            "ttl_secs": 1_800,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32005, "got: {err:?}");
    assert!(
        err.1.contains("ctr-mid-spawn") || err.1.contains("already bound"),
        "expected reconciler-refusal message, got: {}",
        err.1
    );

    // The poisoned row must NOT have been overwritten by the
    // refused spawn attempt — it is still in `enrolling` state.
    let after_attempt = store.get_persona(&enrolling.id).unwrap();
    assert_eq!(after_attempt.status, "enrolling");
}
