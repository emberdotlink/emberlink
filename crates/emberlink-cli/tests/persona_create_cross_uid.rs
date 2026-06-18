//! CLASSIFICATION: PUBLIC
//! T2 integration test: `ember persona create` round-trips through daemon RPC.
//!
//! META-AP-EMBER-PERSONA-CREATE-CROSS-UID-REGRESSION — under ADR 131
//! separate-uid posture (daemon uid ≠ operator uid) the CLI can no longer
//! open the daemon's SQLite DB directly. All persona verbs must go through
//! the JSON-RPC socket. This test exercises the create → list → revoke path
//! via `call_daemon_method` against a real `SocketListener` backed by an
//! in-memory store, which is the same code path the CLI uses after the
//! migration in `crates/emberlink-cli/src/bin/ember.rs`.
//!
//! Specifically verified:
//!   - `create_persona` RPC returns an `id` starting with "persona-".
//!   - `list_personas` RPC returns the newly-created persona.
//!   - `revoke_persona` RPC marks the persona revoked (visible in list).
//!   - All three RPC calls succeed without touching any file-system DB path,
//!     simulating the cross-uid restriction where the operator cannot open
//!     the daemon's DB file.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use ember_daemon::infra::rate_limit::RateLimiter;
use ember_daemon::infra::socket::{SocketListener, new_shared_policy_engine};
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use ember_daemon::trust::policy::{
    ActionSelector, ApprovalRequirement, PolicyConfig, PolicyEngine, PolicyRule, RiskLevel,
};
use tempfile::TempDir;
use tokio::sync::watch;

fn permissive_policy() -> PolicyEngine {
    PolicyEngine::new(PolicyConfig {
        rules: vec![PolicyRule {
            action: ActionSelector::named("credential.access.*"),
            risk: RiskLevel::Low,
            requirement: ApprovalRequirement::Auto,
            tier: None,
        }],
        default_requirement: ApprovalRequirement::Auto,
        default_risk: RiskLevel::Low,
    })
}

/// Spawn a `SocketListener` backed by an in-memory store and return the
/// socket path plus a shutdown handle. The listener's store is never persisted
/// to disk — simulating the access restriction a cross-uid operator would face
/// against a daemon-owned DB file.
fn spawn_listener(tmp: &TempDir, name: &str) -> (PathBuf, watch::Sender<bool>) {
    // Flip the process-global presence manager to Unlocked. The dispatch
    // gate added in PR #3828 (hard-lock after session grace window)
    // refuses non-exempt RPC methods when the session is `Locked`; tests
    // that bypass `register_session` must satisfy the gate explicitly.
    ember_daemon::trust::presence::mark_unlocked();
    let socket_path = tmp.path().join(format!("{name}.sock"));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let path_for_thread = socket_path.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            let store = Rc::new(DaemonStore::open_in_memory().unwrap());
            let vault = Rc::new(Vault::new([42u8; 32]));
            store.set_vault(Rc::clone(&vault));
            let policy = new_shared_policy_engine(permissive_policy());
            let rate_limiter = Rc::new(RefCell::new(RateLimiter::default()));
            let _vault = vault; // hold until end of scope: set_vault is the wire now
            let listener =
                SocketListener::new(path_for_thread, shutdown_rx, store, policy, rate_limiter)
                    .with_test_mode_synthetic_presence_token(true);
            let _ = listener.run().await;
        });
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !socket_path.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        socket_path.exists(),
        "socket {} never appeared within 2s",
        socket_path.display()
    );

    (socket_path, shutdown_tx)
}

#[test]
fn persona_create_via_rpc_returns_id() {
    let tmp = TempDir::new().unwrap();
    let (socket_path, _shutdown) = spawn_listener(&tmp, "persona-create");

    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "create_persona",
        &serde_json::json!({"name": "test-agent"}),
    )
    .expect("create_persona RPC must succeed");

    let id = result.get("id").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        id.starts_with("persona-"),
        "persona id must start with 'persona-', got: {id}"
    );
    let name = result.get("name").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(name, "test-agent", "name must round-trip through create");
}

#[test]
fn persona_create_then_list_via_rpc() {
    let tmp = TempDir::new().unwrap();
    let (socket_path, _shutdown) = spawn_listener(&tmp, "persona-list");

    // Create a persona via RPC (the cross-uid path — no direct DB access).
    let created = emberlink_cli::call_daemon_method(
        &socket_path,
        "create_persona",
        &serde_json::json!({"name": "rpc-persona"}),
    )
    .expect("create_persona RPC must succeed");

    let created_id = created.get("id").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        !created_id.is_empty(),
        "create_persona must return a non-empty id"
    );

    // List personas via RPC.
    let list_result =
        emberlink_cli::call_daemon_method(&socket_path, "list_personas", &serde_json::Value::Null)
            .expect("list_personas RPC must succeed");

    let personas = list_result
        .as_array()
        .expect("list_personas must return a JSON array");
    assert!(
        !personas.is_empty(),
        "list_personas must return at least one persona after create"
    );

    let found = personas
        .iter()
        .find(|p| p.get("id").and_then(|v| v.as_str()) == Some(created_id));
    assert!(
        found.is_some(),
        "created persona id {created_id} must appear in list_personas result"
    );
    let found_name = found
        .unwrap()
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(
        found_name, "rpc-persona",
        "listed persona must have the correct name"
    );
}

#[test]
fn persona_revoke_via_rpc() {
    let tmp = TempDir::new().unwrap();
    let (socket_path, _shutdown) = spawn_listener(&tmp, "persona-revoke");

    // Create a persona.
    let created = emberlink_cli::call_daemon_method(
        &socket_path,
        "create_persona",
        &serde_json::json!({"name": "to-be-revoked"}),
    )
    .expect("create_persona RPC must succeed");
    let persona_id = created
        .get("id")
        .and_then(|v| v.as_str())
        .expect("create must return id")
        .to_string();

    // Revoke it via RPC.
    let revoke_result = emberlink_cli::call_daemon_method(
        &socket_path,
        "revoke_persona",
        &serde_json::json!({"id": persona_id}),
    )
    .expect("revoke_persona RPC must succeed");

    let revoked = revoke_result
        .get("revoked")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(revoked, "revoke_persona must return {{\"revoked\": true}}");

    // List and confirm the persona is now revoked.
    let list_result =
        emberlink_cli::call_daemon_method(&socket_path, "list_personas", &serde_json::Value::Null)
            .expect("list_personas RPC must succeed after revoke");

    let personas = list_result
        .as_array()
        .expect("list_personas must return array");
    let persona = personas
        .iter()
        .find(|p| p.get("id").and_then(|v| v.as_str()) == Some(persona_id.as_str()))
        .expect("revoked persona must still appear in list");

    let status = persona.get("status").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(
        status, "revoked",
        "persona status must be 'revoked' after revoke_persona RPC"
    );
}

#[test]
fn persona_create_cross_uid_no_direct_db_access() {
    // This test explicitly verifies the cross-uid contract: the CLI can
    // create a persona by talking to the daemon socket even when there is
    // no DB file on disk (as would be the case for an operator who cannot
    // read the daemon's DB because it is owned by a different uid).
    //
    // The SocketListener uses an in-memory store — there is no file path to
    // open. The call_daemon_method function only needs a socket path, not a
    // DB path. This is the exact API the migrated CLI code uses.

    let tmp = TempDir::new().unwrap();
    let (socket_path, _shutdown) = spawn_listener(&tmp, "persona-cross-uid");

    // No DB file exists at any path the operator would try to open.
    // Verify the DB file is NOT on disk (proving the store is in-memory).
    assert!(
        !tmp.path().join("daemon.db").exists(),
        "no daemon.db must exist for cross-uid simulation"
    );

    // Despite no DB file, the RPC create must succeed.
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "create_persona",
        &serde_json::json!({"name": "cross-uid-agent"}),
    )
    .expect("create_persona via RPC must succeed without a DB file (cross-uid contract)");

    let id = result.get("id").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        id.starts_with("persona-"),
        "cross-uid create must return valid persona id, got: {id}"
    );
}
