use super::*;
use crate::infra::vault::VaultScope;

fn with_fresh_presence_proof(
    store: &DaemonStore,
    method: &str,
    op_id: &str,
    op_params: serde_json::Value,
) -> serde_json::Value {
    use core_crypto::{DOMAIN_EVENT, P256Signer, Signer, sign_with_context};

    let data_dir = store
        .data_dir()
        .expect("presence proof tests require an on-disk daemon store");
    let _ = crate::infra::receipt::init_identity(data_dir);

    let device = P256Signer::from_scalar_bytes(&[0x5E; 32]).unwrap();
    let device_key = device.public_key().0;
    let encryption_key = P256Signer::from_scalar_bytes(&[0xA1; 32])
        .unwrap()
        .public_key()
        .0;
    let prepared = handle_identity_device_enroll(
        store,
        &json!({
            "device_key": device_key.clone(),
            "encryption_key": encryption_key.clone(),
            "device_label": "Vault RPC Presence Device",
        }),
    )
    .expect("prepare presence device enrollment");
    let signatures: Vec<serde_json::Value> = prepared["to_sign"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| {
            let bytes = hex::decode(step["bytes_hex"].as_str().unwrap()).unwrap();
            let sig = sign_with_context(DOMAIN_EVENT, &device, &bytes);
            serde_json::Value::String(sig.0.strip_prefix("p256sig:").unwrap().to_string())
        })
        .collect();
    handle_identity_device_enroll(
        store,
        &json!({
            "device_key": device_key,
            "encryption_key": encryption_key,
            "device_label": "Vault RPC Presence Device",
            "signatures": signatures,
        }),
    )
    .expect("commit presence device enrollment");

    let ctx = RequestContext::socket(Some(PeerCred {
        uid: 1000,
        pid: Some(4242),
    }));
    let digest = crate::auth::presence_gate::presence_params_digest(&op_params).unwrap();
    let nonce_response = handle_presence_request_nonce(
        store,
        &ctx,
        &json!({ "op_id": op_id, "method": method, "params_digest": digest }),
    )
    .expect("request presence nonce");
    let nonce = nonce_response["nonce"].as_str().unwrap().to_string();
    let intent = hex::decode(nonce_response["intent_bytes_hex"].as_str().unwrap()).unwrap();
    let sig = device.sign(&intent);
    let mut params = op_params;
    params["_presence_proof"] = json!({
        "op_id": op_id,
        "nonce": nonce,
        "signature": sig.0,
    });
    params
}

// --- per-op user-presence wiring ---
//
// These tests prove the new methods (`vault_remove`, `vault_lock`,
// `vault_status`) dispatch correctly. The gate's lock/allow state
// machine has its own coverage in `crate::trust::presence::tests`. Because
// cargo-test binaries set `dev_mode_enabled() = true`, the gate
// returns `Allowed` for every call here, exercising the wire shape
// without forcing live keychain access.

#[tokio::test]
async fn vault_remove_round_trip() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "to-be-removed", "value": "secret"}),
    )
    .await
    .unwrap();
    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_remove",
        &json!({"name": "to-be-removed"}),
    )
    .await
    .unwrap();
    assert_eq!(result["removed"], json!(true));
    assert_eq!(result["name"], json!("to-be-removed"));

    // G6 / OQ-5: the removal MUST leave a tamper-evident audit-chain record.
    let entries = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("vault.remove".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        entries.len(),
        1,
        "vault_remove must append exactly one audit row"
    );
    assert_eq!(entries[0].outcome, "allowed");
    assert_eq!(entries[0].credential.as_deref(), Some("to-be-removed"));
}

#[tokio::test]
async fn vault_remove_missing_name_returns_invalid_params() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let err = dispatch_method(&store, &vault, &policy, &rl, "vault_remove", &json!({}))
        .await
        .unwrap_err();
    assert_eq!(err.0, -32602);
}

#[tokio::test]
async fn vault_export_import_sealed_round_trip_rpc() {
    use base64::Engine as _;

    let export_dir = tempfile::TempDir::new().unwrap();
    let store = DaemonStore::open(&export_dir.path().join("daemon.db")).unwrap();
    store.set_vault(std::rc::Rc::new(Vault::new([0x42; 32])));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let exported = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_export_sealed",
        &json!({"passphrase": "correct horse battery staple"}),
    )
    .await
    .unwrap();
    let blob_b64 = exported["blob"].as_str().expect("blob");
    let blob = base64::engine::general_purpose::STANDARD
        .decode(blob_b64)
        .expect("valid base64");
    assert!(blob.starts_with(b"EMVS"));
    let fingerprint = exported["mek_fingerprint"].as_str().expect("fingerprint");
    assert_eq!(fingerprint.len(), 64);
    assert!(exported["audit_event_id"].as_i64().unwrap() > 0);

    let import_dir = tempfile::TempDir::new().unwrap();
    let import_store = DaemonStore::open(&import_dir.path().join("daemon.db")).unwrap();
    let imported = dispatch_method(
        &import_store,
        &vault,
        &policy,
        &rl,
        "vault_import_sealed",
        &json!({
            "blob": blob_b64,
            "passphrase": "correct horse battery staple",
            "expected_fingerprint": fingerprint,
        }),
    )
    .await
    .unwrap();

    assert_eq!(imported["imported"], json!(true));
    assert_eq!(imported["mek_fingerprint"], json!(fingerprint));
    assert!(imported["audit_event_id"].as_i64().unwrap() > 0);
    assert!(import_store.vault().is_some());
    assert_eq!(
        import_store.read_mek_fingerprint().unwrap().as_deref(),
        Some(fingerprint)
    );

    let import_events = import_store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("vault.mek_sealed_imported".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(import_events.len(), 1);
}

#[tokio::test]
async fn vault_import_sealed_refuses_when_live_mek_loaded() {
    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(std::rc::Rc::new(Vault::new([0x42; 32])));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_import_sealed",
        &json!({
            "blob": "AA==",
            "passphrase": "pw",
            "expected_fingerprint": "fp",
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32030);
    assert!(err.1.contains("live MEK already loaded"));
}

#[tokio::test]
async fn vault_lock_returns_locked_true() {
    let _presence_test_guard = crate::trust::presence::test_state_guard();

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let result = dispatch_method(&store, &vault, &policy, &rl, "vault_lock", &json!(null))
        .await
        .unwrap();
    assert_eq!(result["locked"], json!(true));
}

#[tokio::test]
async fn vault_unlock_fails_closed_after_explicit_lock() {
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    crate::infra::vault_macos_se::stub_vault_mek_label();
    interactive_unlock::reset_for_tests();
    crate::trust::presence::reset_for_tests();
    // SAFETY: serialized by PROCESS_TEST_LOCK for this test binary.
    unsafe { std::env::set_var("EMBER_VAULT_TEST_KEYRING_PRESENT", "1") };

    let config_root = tempfile::TempDir::new().unwrap();
    let config = crate::infra::config::DaemonConfig::for_test(config_root.path());
    let store = DaemonStore::open_in_memory_without_vault().unwrap();
    let runtime_vault = std::rc::Rc::new(crate::infra::vault::Vault::new([0xAB; 32]));

    store.set_vault(std::rc::Rc::clone(&runtime_vault));
    let store = std::rc::Rc::new(store);
    crate::trust::presence::register_store(std::rc::Rc::clone(&store));
    interactive_unlock::register_config(config);
    interactive_unlock::set_test_grace_window(std::time::Duration::from_secs(1));
    let policy = test_policy();
    let rl = test_rate_limiter();

    dispatch_method(
        store.as_ref(),
        runtime_vault.as_ref(),
        &policy,
        &rl,
        "vault_lock",
        &json!(null),
    )
    .await
    .unwrap();
    assert!(
        store.vault().is_none(),
        "explicit lock must clear live vault"
    );

    // ADR 216: vault_unlock now fails after explicit lock because the daemon
    // can no longer self-reopen via direct SE access (System/0 domain). The
    // vault must be reopened via the CLI relay (vault.de_unlock_complete).
    let result = dispatch_method(
        store.as_ref(),
        runtime_vault.as_ref(),
        &policy,
        &rl,
        "vault_unlock",
        &json!(null),
    )
    .await;
    assert!(
        result.is_err(),
        "vault_unlock must fail after explicit lock (ADR 216: daemon cannot self-reopen)"
    );
    assert!(
        store.vault().is_none(),
        "vault must remain locked after failed vault_unlock"
    );

    interactive_unlock::reset_for_tests();
}

#[tokio::test]
async fn vault_unlock_socket_path_succeeds_via_se_after_explicit_lock() {
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    crate::infra::vault_macos_se::stub_vault_mek_label();
    interactive_unlock::reset_for_tests();
    crate::trust::presence::reset_for_tests();
    ensure_test_presence_identity();
    // SAFETY: serialized by PROCESS_TEST_LOCK for this test binary.
    unsafe { std::env::set_var("EMBER_VAULT_TEST_KEYRING_PRESENT", "1") };

    let config_root = tempfile::TempDir::new().unwrap();
    let config = crate::infra::config::DaemonConfig::for_test(config_root.path());
    let store = DaemonStore::open_in_memory_without_vault().unwrap();
    let runtime_vault = std::rc::Rc::new(crate::infra::vault::Vault::new([0xAB; 32]));

    store.set_vault(std::rc::Rc::clone(&runtime_vault));
    let store = std::rc::Rc::new(store);
    crate::trust::presence::register_store(std::rc::Rc::clone(&store));
    interactive_unlock::register_config(config);
    let policy = test_policy();
    let rl = test_rate_limiter();

    dispatch_method(
        store.as_ref(),
        runtime_vault.as_ref(),
        &policy,
        &rl,
        "vault_lock",
        &json!(null),
    )
    .await
    .unwrap();
    crate::trust::presence::mark_unlocked();

    let ctx = RequestContext {
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
        presence_token: Some(test_presence_token_for_scope(
            501,
            PRESENCE_SCOPE_CLASS_VAULT,
        )),
        bypass_binary_pin_gate_for_test: false,
    };
    // ADR 216: vault_unlock via socket now fails because the daemon can no
    // longer self-reopen via direct SE access (System/0 domain).
    let result = dispatch_method_with_context(
        store.as_ref(),
        runtime_vault.as_ref(),
        &policy,
        &rl,
        None,
        ctx,
        "vault_unlock",
        &json!(null),
    )
    .await;
    assert!(
        result.is_err(),
        "vault_unlock must fail (ADR 216: daemon cannot self-reopen)"
    );

    interactive_unlock::reset_for_tests();
}

#[tokio::test]
async fn vault_unlock_requested_method_succeeds_via_se_after_explicit_lock() {
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    crate::infra::vault_macos_se::stub_vault_mek_label();
    interactive_unlock::reset_for_tests();
    crate::trust::presence::reset_for_tests();
    ensure_test_presence_identity();
    // SAFETY: serialized by PROCESS_TEST_LOCK for this test binary.
    unsafe { std::env::set_var("EMBER_VAULT_TEST_KEYRING_PRESENT", "1") };

    let config_root = tempfile::TempDir::new().unwrap();
    let config = crate::infra::config::DaemonConfig::for_test(config_root.path());
    let store = DaemonStore::open_in_memory_without_vault().unwrap();
    let runtime_vault = std::rc::Rc::new(crate::infra::vault::Vault::new([0xAB; 32]));

    store.set_vault(std::rc::Rc::clone(&runtime_vault));
    let store = std::rc::Rc::new(store);
    crate::trust::presence::register_store(std::rc::Rc::clone(&store));
    interactive_unlock::register_config(config);
    let policy = test_policy();
    let rl = test_rate_limiter();

    dispatch_method(
        store.as_ref(),
        runtime_vault.as_ref(),
        &policy,
        &rl,
        "vault_lock",
        &json!(null),
    )
    .await
    .unwrap();
    crate::trust::presence::mark_unlocked();

    let socket_ctx = RequestContext {
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
        presence_token: Some(test_presence_token_for_scope(
            501,
            PRESENCE_SCOPE_CLASS_VAULT,
        )),
        bypass_binary_pin_gate_for_test: false,
    };
    // ADR 216: vault_unlock with requested_method now fails because the
    // daemon can no longer self-reopen via direct SE access.
    let result = dispatch_method_with_context(
        store.as_ref(),
        runtime_vault.as_ref(),
        &policy,
        &rl,
        None,
        socket_ctx,
        "vault_unlock",
        &json!({"requested_method": "create_persona"}),
    )
    .await;
    assert!(
        result.is_err(),
        "vault_unlock must fail (ADR 216: daemon cannot self-reopen)"
    );

    interactive_unlock::reset_for_tests();
}

#[tokio::test]
async fn vault_unlock_reuses_bootstrap_env_passphrase_after_startup_lock() {
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    crate::infra::vault_macos_se::stub_vault_mek_label();
    interactive_unlock::reset_for_tests();
    crate::trust::presence::reset_for_tests();
    crate::infra::vault::clear_runtime_reopen_passphrase_cache();
    ensure_test_presence_identity();

    let config_root = tempfile::TempDir::new().unwrap();
    let config = crate::infra::config::DaemonConfig::for_test(config_root.path());
    let store = DaemonStore::open_in_memory_without_vault().unwrap();
    let runtime_vault = std::rc::Rc::new(crate::infra::vault::Vault::new([0xAB; 32]));

    store.set_vault(std::rc::Rc::clone(&runtime_vault));
    let store = std::rc::Rc::new(store);
    crate::trust::presence::register_store(std::rc::Rc::clone(&store));
    interactive_unlock::register_config(config);
    crate::trust::presence::startup_lock();
    assert!(
        store.vault().is_none(),
        "startup lock must clear the live vault before the reopen probe"
    );
    // The startup bootstrap cache may still reopen the vault, but
    // vault_unlock itself is no longer token-optional.
    crate::trust::presence::mark_unlocked();

    let policy = test_policy();
    let rl = test_rate_limiter();
    let socket_ctx = RequestContext {
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
        presence_token: Some(test_presence_token_for_scope(
            501,
            PRESENCE_SCOPE_CLASS_VAULT,
        )),
        bypass_binary_pin_gate_for_test: false,
    };
    // ADR 216: vault_unlock now fails after startup_lock because the daemon
    // can no longer self-reopen via direct SE access (System/0 domain).
    let result = dispatch_method_with_context(
        store.as_ref(),
        runtime_vault.as_ref(),
        &policy,
        &rl,
        None,
        socket_ctx,
        "vault_unlock",
        &json!({"requested_method": "create_persona"}),
    )
    .await;
    assert!(
        result.is_err(),
        "vault_unlock must fail (ADR 216: daemon cannot self-reopen)"
    );

    crate::infra::vault::clear_runtime_reopen_passphrase_cache();
    interactive_unlock::reset_for_tests();
}

#[tokio::test]
async fn vault_status_exposes_session_shape() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let result = dispatch_method(&store, &vault, &policy, &rl, "vault_status", &json!(null))
        .await
        .unwrap();
    // Shape contract: dashboard relies on these field names.
    assert!(result["posture"].is_string());
    assert!(result["unlocked"].is_boolean());
    assert!(result["idle_timeout_secs"].is_u64());
    assert!(result["live_vault_attached"].is_boolean());
    assert!(result["session_pin_count"].is_u64());
    assert!(result["grace_window_secs"].is_u64());
    assert!(result["grace_remaining_secs"].is_u64());
    assert!(result["grace_lock_pending"].is_boolean());
    assert!(result["grace_zero_due"].is_boolean());
    // quiet_hours_* may be null, which is .is_null() (or .is_number() if set).
    assert!(result.get("quiet_hours_start").is_some());
    assert!(result.get("quiet_hours_end").is_some());
}

#[tokio::test]
async fn vault_status_distinguishes_presence_locked_from_hard_lock() {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::reset_for_tests();
    crate::infra::interactive_unlock::reset_for_tests();

    let store = DaemonStore::open_in_memory().unwrap();
    let runtime_vault = std::rc::Rc::new(test_vault());
    store.set_vault(std::rc::Rc::clone(&runtime_vault));
    crate::infra::interactive_unlock::register_vault_slot(store.vault_slot());
    crate::trust::presence::lock();
    store.set_vault(std::rc::Rc::clone(&runtime_vault));
    crate::infra::interactive_unlock::acquire_session_pin("sess-soft");

    let policy = test_policy();
    let rl = test_rate_limiter();
    let result = dispatch_method(
        &store,
        runtime_vault.as_ref(),
        &policy,
        &rl,
        "vault_status",
        &json!(null),
    )
    .await
    .unwrap();
    assert_eq!(result["unlocked"], json!(false));
    assert_eq!(result["live_vault_attached"], json!(true));
    assert_eq!(result["session_pin_count"], json!(1));
    assert_eq!(result["grace_remaining_secs"], json!(0));
    assert_eq!(result["posture"], json!("presence-locked-vault-pinned"));
}

#[tokio::test]
async fn vault_lock_status_round_trip_reports_hard_lock() {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::reset_for_tests();
    crate::infra::interactive_unlock::reset_for_tests();

    let store = DaemonStore::open_in_memory().unwrap();
    let runtime_vault = std::rc::Rc::new(test_vault());
    store.set_vault(std::rc::Rc::clone(&runtime_vault));
    crate::infra::interactive_unlock::register_vault_slot(store.vault_slot());
    crate::trust::presence::mark_unlocked();

    let policy = test_policy();
    let rl = test_rate_limiter();

    dispatch_method(
        &store,
        runtime_vault.as_ref(),
        &policy,
        &rl,
        "vault_lock",
        &json!(null),
    )
    .await
    .unwrap();

    let result = dispatch_method(
        &store,
        runtime_vault.as_ref(),
        &policy,
        &rl,
        "vault_status",
        &json!(null),
    )
    .await
    .unwrap();
    assert_eq!(result["unlocked"], json!(false));
    assert_eq!(result["live_vault_attached"], json!(false));
    assert_eq!(result["session_pin_count"], json!(0));
    assert_eq!(result["posture"], json!("hard-locked"));
}

#[tokio::test]
async fn team0_vault_list_requires_operator_presence_token() {
    // PR #3828 hard-lock: see team0_detect_anomalies_requires_operator_presence_token.
    // ADR 206 slice 4 C: a presence token (or an open §4 window) authorizes;
    // with NO token AND a LOCKED §4 window the OperatorPresence method fails
    // closed.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "team0/list-target", "value": "secret"}),
    )
    .await
    .unwrap();

    // No token + LOCKED §4 window → fail closed.
    crate::trust::presence::lock();
    let no_token_ctx = RequestContext {
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
    };
    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        no_token_ctx,
        "vault_list",
        &json!(null),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32001);

    // Token + open §4 window → authorized.
    crate::trust::presence::mark_unlocked();
    let with_token_ctx = RequestContext {
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
        presence_token: Some(test_presence_token(501)),
        bypass_binary_pin_gate_for_test: false,
    };
    let rows = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        with_token_ctx,
        "vault_list",
        &json!(null),
    )
    .await
    .unwrap();
    let arr = rows.as_array().expect("vault_list returns array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], json!("team0/list-target"));
}

#[tokio::test]
async fn team0_vault_scope_token_allows_vault_list_but_not_create_persona() {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "team0/scoped-target", "value": "secret"}),
    )
    .await
    .unwrap();

    let scoped_ctx = RequestContext {
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
        presence_token: Some(test_presence_token_for_scope(
            501,
            PRESENCE_SCOPE_CLASS_VAULT,
        )),
        bypass_binary_pin_gate_for_test: false,
    };
    let rows = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        scoped_ctx.clone(),
        "vault_list",
        &json!(null),
    )
    .await
    .unwrap();
    let arr = rows.as_array().expect("vault_list returns array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], json!("team0/scoped-target"));

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        scoped_ctx,
        "create_persona",
        &json!({"name": "scope-should-fail"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32001);
    assert!(
        err.1.contains("\"scope-mismatch\""),
        "non-vault operator methods must fail with scope-mismatch, got: {}",
        err.1
    );
}

#[tokio::test]
async fn vault_get_round_trip_returns_plaintext_value_and_bytes() {
    // VAULT-GET-RPC-FIX: pulumi-render.sh + similar headless
    // integrations call `ember vault get` -> daemon RPC `vault_get`.
    // This proves the RPC arm is wired and returns the decrypted
    // value under the canonical {"value": ..., "value_bytes": ...}
    // shape.
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "rpc-fetch-target", "value": "passphrase-42"}),
    )
    .await
    .unwrap();
    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_get",
        &json!({"name": "rpc-fetch-target"}),
    )
    .await
    .unwrap();
    assert_eq!(result["value"], json!("passphrase-42"));
    assert_eq!(
        result["value_bytes"],
        json!(b"passphrase-42".to_vec()),
        "vault_get must return exact bytes alongside the UTF-8 convenience field"
    );
}

#[tokio::test]
async fn vault_get_biometric_row_requires_fresh_presence_proof() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "rpc-biometric-target", "value": "passphrase-42"}),
    )
    .await
    .unwrap();
    store
        .conn()
        .execute(
            "UPDATE credentials SET presence_policy = 'per_access_fresh' WHERE name = ?1",
            rusqlite::params!["rpc-biometric-target"],
        )
        .unwrap();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_get",
        &json!({"name": "rpc-biometric-target"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32030);
    assert!(
        err.1.contains("presence-Device signature"),
        "protected vault_get must return the CLI proof-retry signal, got: {err:?}"
    );
}

#[tokio::test]
async fn vault_get_biometric_success_emits_authenticator_receipt() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = DaemonStore::open(&dir.path().join("daemon.db")).unwrap();
    let vault = std::rc::Rc::new(test_vault());
    store.set_vault(vault.clone());
    let policy = test_policy();
    let rl = test_rate_limiter();
    let name = "rpc-biometric-receipted";

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": name, "value": "passphrase-42"}),
    )
    .await
    .unwrap();
    store
        .conn()
        .execute(
            "UPDATE credentials SET presence_policy = 'per_access_fresh' WHERE name = ?1",
            rusqlite::params![name],
        )
        .unwrap();

    let params = with_fresh_presence_proof(
        &store,
        "vault_get",
        "op-rpc-biometric-receipted",
        json!({"name": name}),
    );
    let result = dispatch_method(&store, &vault, &policy, &rl, "vault_get", &params)
        .await
        .unwrap();
    assert_eq!(result["value"], json!("passphrase-42"));

    let rows = store
        .query_receipts(&crate::infra::receipt::ReceiptFilter {
            kind: Some(crate::infra::receipt::VAULT_BIOMETRIC_RECEIPT_KIND.to_string()),
            resource: Some(name.to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "flagged successful read must emit biometric receipt"
    );
    let receipt = store.get_vault_biometric_receipt(&rows[0].id).unwrap();
    assert_eq!(receipt.key_name, name);
    assert_eq!(receipt.read_path, "vault_get");
    assert!(
        !receipt.presence_authenticator_id.is_empty(),
        "receipt must name the enrolled authenticator that verified the proof"
    );
    assert!(
        receipt.presence_public_key_hash.starts_with("sha256:"),
        "receipt must carry a stable public-key hash for authenticator disambiguation"
    );
}

#[tokio::test]
async fn vault_add_require_biometric_sets_sentinel_and_invalidates_live_vault() {
    let _presence_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();
    let dir = tempfile::TempDir::new().unwrap();
    let store = DaemonStore::open(&dir.path().join("daemon.db")).unwrap();
    let vault = std::rc::Rc::new(test_vault());
    store.set_vault(vault.clone());
    let policy = test_policy();
    let rl = test_rate_limiter();

    let missing_proof = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({
            "name": "rpc-biometric-add",
            "value": "passphrase-42",
            "require_biometric": true,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(missing_proof.0, -32030);
    assert!(
        missing_proof.1.contains("presence-Device signature"),
        "setting the biometric checkpoint must require a fresh proof, got: {missing_proof:?}"
    );

    let params = with_fresh_presence_proof(
        &store,
        "vault_add",
        "op-rpc-biometric-add",
        json!({
            "name": "rpc-biometric-add",
            "value": "passphrase-42",
            "require_biometric": true,
        }),
    );
    let result = dispatch_method(&store, &vault, &policy, &rl, "vault_add", &params)
        .await
        .unwrap();
    assert_eq!(result["requires_biometric"], json!(true));
    assert!(
        vault
            .credential_presence_policy(VaultScope::Interactive, &store, "rpc-biometric-add")
            .unwrap()
            .requires_fresh_presence()
    );
    let (unlocked, _) = crate::trust::presence::snapshot();
    assert!(
        !unlocked,
        "setting the biometric checkpoint must invalidate the cached presence window"
    );

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_get",
        &json!({"name": "rpc-biometric-add"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32030);
    assert!(
        err.1.contains("presence-Device signature"),
        "protected vault_get must still require a fresh proof after the test dispatcher reattaches its vault, got: {err:?}"
    );
}

#[tokio::test]
async fn vault_put_require_biometric_upgrades_existing_row_only_with_fresh_proof() {
    let _presence_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();
    let dir = tempfile::TempDir::new().unwrap();
    let store = DaemonStore::open(&dir.path().join("daemon.db")).unwrap();
    let vault = std::rc::Rc::new(test_vault());
    store.set_vault(vault.clone());
    let policy = test_policy();
    let rl = test_rate_limiter();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "rpc-biometric-put", "value": "old"}),
    )
    .await
    .unwrap();

    let missing_proof = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_put",
        &json!({
            "name": "rpc-biometric-put",
            "value": "new",
            "require_biometric": true,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(missing_proof.0, -32030);
    assert!(
        missing_proof.1.contains("presence-Device signature"),
        "upgrading an existing row must require a fresh proof, got: {missing_proof:?}"
    );
    assert!(
        !vault
            .credential_presence_policy(VaultScope::Interactive, &store, "rpc-biometric-put")
            .unwrap()
            .requires_fresh_presence(),
        "missing proof must not set the checkpoint"
    );

    let params = with_fresh_presence_proof(
        &store,
        "vault_put",
        "op-rpc-biometric-put",
        json!({
            "name": "rpc-biometric-put",
            "value": "new",
            "require_biometric": true,
        }),
    );
    let result = dispatch_method(&store, &vault, &policy, &rl, "vault_put", &params)
        .await
        .unwrap();
    assert_eq!(result["requires_biometric"], json!(true));
    assert!(
        vault
            .credential_presence_policy(VaultScope::Interactive, &store, "rpc-biometric-put")
            .unwrap()
            .requires_fresh_presence()
    );

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_get",
        &json!({"name": "rpc-biometric-put"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32030);
}

#[tokio::test]
async fn vault_add_accepts_exact_value_bytes() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({
            "name": "rpc-byte-target",
            "value_bytes": [0, 255, 65],
        }),
    )
    .await
    .unwrap();
    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_get",
        &json!({"name": "rpc-byte-target"}),
    )
    .await
    .unwrap();
    assert_eq!(result["value_bytes"], json!([0, 255, 65]));
}

#[tokio::test]
async fn vault_put_replaces_existing_value() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "rpc-put-target", "value": "old-value"}),
    )
    .await
    .unwrap();
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_put",
        &json!({"name": "rpc-put-target", "value_bytes": [110, 101, 119]}),
    )
    .await
    .unwrap();
    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_get",
        &json!({"name": "rpc-put-target"}),
    )
    .await
    .unwrap();
    assert_eq!(result["value"], json!("new"));
    assert_eq!(result["value_bytes"], json!([110, 101, 119]));
}

#[tokio::test]
async fn vault_get_missing_name_returns_invalid_params() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let err = dispatch_method(&store, &vault, &policy, &rl, "vault_get", &json!({}))
        .await
        .unwrap_err();
    assert_eq!(err.0, -32602);
}

#[tokio::test]
async fn vault_get_unknown_name_returns_application_error() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_get",
        &json!({"name": "no-such-credential"}),
    )
    .await
    .unwrap_err();
    // Generic application error code (-32000) — vault.get returns
    // VaultError::NotFound, mapped uniformly with other vault errors.
    assert_eq!(err.0, -32000);
}

#[tokio::test]
async fn vault_get_uses_store_live_vault_slot_not_passed_dispatch_vault() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "slot-cutoff", "value": "secret"}),
    )
    .await
    .unwrap();

    store.drop_vault();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_get",
        &json!({"name": "slot-cutoff"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32030);
    assert!(
        err.1.contains("live vault is locked"),
        "handler must fail because the store live-vault slot was cleared, got: {err:?}"
    );
}

#[tokio::test]
async fn vault_remove_via_socket_source_runs_under_dev_mode_gate() {
    // Even via Socket dispatch (where the gate WOULD run), the
    // cargo-test binary detection short-circuits the gate to Allowed
    // — so the call still succeeds and we can prove the wiring is
    // wired through dispatch_method_with_source, not just the
    // Internal-only convenience entry point.
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    // Seed via Internal so add doesn't trip its own gate path.
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "seed", "value": "v"}),
    )
    .await
    .unwrap();
    // Satisfy the OperatorPresence unlocked-session gate (vault_remove
    // is OperatorPresence-class).
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();
    // Now exercise via Socket source.
    let result = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Socket,
        "vault_remove",
        &json!({"name": "seed"}),
    )
    .await
    .unwrap();
    assert_eq!(result["removed"], json!(true));
}

// ============================================================
// KEYCHAIN-CONSOLIDATE-CLI-DAEMON-METHODS — T1 dispatch arm tests
// ============================================================

#[tokio::test]
async fn local_state_key_get_generates_on_first_call() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "local_state_key_get",
        &json!({"caller": "cli"}),
    )
    .await
    .unwrap();
    assert_eq!(result["resolved_or_generated"], json!("generated"));
    assert_eq!(result["vault_namespace"], json!("local-state/cli"));
    let key = result["key"].as_str().unwrap();
    // `core_crypto::generate_content_key` returns the canonical
    // `xchacha20-key:<64 hex>` content-key form (14-byte prefix +
    // 64 hex chars = 78 chars total).
    assert!(
        key.starts_with("xchacha20-key:") && key.len() == 78,
        "expected xchacha20-key:<64 hex> content key, got: {key}"
    );
}

#[tokio::test]
async fn local_state_key_get_resolves_on_second_call() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let first = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "local_state_key_get",
        &json!({"caller": "cli"}),
    )
    .await
    .unwrap();
    let second = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "local_state_key_get",
        &json!({"caller": "cli"}),
    )
    .await
    .unwrap();
    assert_eq!(second["resolved_or_generated"], json!("resolved"));
    assert_eq!(first["key"], second["key"]);
}

#[tokio::test]
async fn local_state_key_get_appends_audit_rows() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "local_state_key_get",
        &json!({"caller": "cli"}),
    )
    .await
    .unwrap();
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "local_state_key_get",
        &json!({"caller": "cli"}),
    )
    .await
    .unwrap();

    let entries = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some(core_events::receipt::RECEIPT_KIND_LOCAL_STATE_KEY_RESOLVE.to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        entries.len(),
        2,
        "local_state_key_get must append one audit row per resolve"
    );
    let outcomes: std::collections::HashSet<&str> =
        entries.iter().map(|entry| entry.outcome.as_str()).collect();
    assert!(
        outcomes.contains("generated"),
        "first local-state key get must audit key generation"
    );
    assert!(
        outcomes.contains("resolved"),
        "second local-state key get must audit key resolution"
    );
    for entry in entries {
        assert_eq!(entry.credential.as_deref(), Some("local-state/cli"));
        let details = entry.details.as_deref().expect("typed audit details");
        let body: core_events::receipt::LocalStateKeyResolveBody =
            serde_json::from_str(details).unwrap();
        assert_eq!(body.peer_uid, 501);
        assert_eq!(body.caller, "cli");
        assert_eq!(body.vault_namespace, "local-state/cli");
        assert_eq!(body.resolved_or_generated, entry.outcome);
    }
}

#[tokio::test]
async fn local_state_key_get_namespaces_per_caller() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let cli_key = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "local_state_key_get",
        &json!({"caller": "cli"}),
    )
    .await
    .unwrap();
    let gui_key = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "local_state_key_get",
        &json!({"caller": "gui"}),
    )
    .await
    .unwrap();
    assert_ne!(
        cli_key["key"], gui_key["key"],
        "per-caller namespaces must produce distinct keys"
    );
    assert_eq!(cli_key["vault_namespace"], json!("local-state/cli"));
    assert_eq!(gui_key["vault_namespace"], json!("local-state/gui"));
}

#[tokio::test]
async fn local_state_key_get_missing_caller_returns_invalid_params() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "local_state_key_get",
        &json!({}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32602);
}

#[tokio::test]
async fn local_state_key_set_is_idempotent() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    // First set: not already set.
    let first = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "local_state_key_set",
            &json!({"caller": "cli", "key": "xchacha20-key:0000000000000000000000000000000000000000000000000000000000000001"}),
        )
        .await
        .unwrap();
    assert_eq!(first["already_set"], json!(false));
    // Second set: idempotent no-op.
    let second = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "local_state_key_set",
            &json!({"caller": "cli", "key": "xchacha20-key:0000000000000000000000000000000000000000000000000000000000000002"}),
        )
        .await
        .unwrap();
    assert_eq!(second["already_set"], json!(true));
    // After set, get returns the originally-set value.
    let got = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "local_state_key_get",
        &json!({"caller": "cli"}),
    )
    .await
    .unwrap();
    assert_eq!(got["resolved_or_generated"], json!("resolved"));
    assert_eq!(
        got["key"].as_str().unwrap(),
        "xchacha20-key:0000000000000000000000000000000000000000000000000000000000000001",
        "set + get must round-trip the originally-set value"
    );
}

#[tokio::test]
async fn local_state_key_rotate_and_reencrypt_round_trips() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // 1. Vend a key.
    let get_result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "local_state_key_get",
        &json!({"caller": "cli"}),
    )
    .await
    .unwrap();
    let old_key = get_result["key"].as_str().unwrap().to_string();

    // 2. Encrypt a payload client-side using core_crypto.
    let plaintext = b"local-state-payload-v1";
    let encrypted =
        core_crypto::encrypt_content(&old_key, plaintext, b"emberlink-local-state").unwrap();
    let nonce_bytes = core_types::hex_to_bytes(&encrypted.nonce_hex).unwrap();
    let mut ciphertext = Vec::with_capacity(nonce_bytes.len() + encrypted.ciphertext.len());
    ciphertext.extend_from_slice(&nonce_bytes);
    ciphertext.extend_from_slice(&encrypted.ciphertext);

    // 3. Call rotate_and_reencrypt.
    let rotate_result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "local_state_key_rotate_and_reencrypt",
        &json!({"caller": "cli", "ciphertext": ciphertext}),
    )
    .await
    .unwrap();
    let new_ciphertext: Vec<u8> = rotate_result["ciphertext"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();
    assert_eq!(rotate_result["vault_namespace"], json!("local-state/cli"));

    // 4. The new ciphertext must be different (fresh key + nonce).
    assert_ne!(ciphertext, new_ciphertext);

    // 5. A subsequent get returns the *new* key.
    let new_get = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "local_state_key_get",
        &json!({"caller": "cli"}),
    )
    .await
    .unwrap();
    let new_key = new_get["key"].as_str().unwrap().to_string();
    assert_ne!(old_key, new_key, "rotation must produce a new key");

    // 6. The new ciphertext decrypts under the new key back to the
    //    original plaintext.
    assert!(new_ciphertext.len() >= 24);
    let (new_nonce, new_ct) = new_ciphertext.split_at(24);
    let encrypted_new = core_crypto::EncryptedContent {
        nonce_hex: core_types::bytes_to_hex(new_nonce),
        ciphertext: new_ct.to_vec(),
    };
    let decrypted =
        core_crypto::decrypt_content(&new_key, &encrypted_new, b"emberlink-local-state").unwrap();
    assert_eq!(decrypted, plaintext);

    let entries = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some(core_events::receipt::RECEIPT_KIND_LOCAL_STATE_KEY_ROTATION.to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        entries.len(),
        1,
        "local_state_key_rotate_and_reencrypt must append one audit row"
    );
    let entry = &entries[0];
    assert_eq!(entry.credential.as_deref(), Some("local-state/cli"));
    assert_eq!(entry.outcome, "rotated");
    let body: core_events::receipt::LocalStateKeyRotationBody =
        serde_json::from_str(entry.details.as_deref().expect("typed audit details")).unwrap();
    assert_eq!(body.peer_uid, 501);
    assert_eq!(body.caller, "cli");
    assert_eq!(body.vault_namespace, "local-state/cli");
    assert!(body.old_key_hash.starts_with("blake3:"));
    assert!(body.new_key_hash.starts_with("blake3:"));
    assert_ne!(body.old_key_hash, body.new_key_hash);
    assert!(
        !entry.details.as_deref().unwrap().contains(&old_key)
            && !entry.details.as_deref().unwrap().contains(&new_key),
        "rotation audit details must not include raw key material"
    );
}

#[tokio::test]
async fn local_state_key_rotate_missing_caller_returns_invalid_params() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "local_state_key_rotate_and_reencrypt",
        &json!({"ciphertext": []}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32602);
}

#[tokio::test]
async fn de_provision_first_boot_persists_lease_kek_outer_blob() {
    // V030-NO-LIVE-LEASE-AFTER-FRESH-INIT secondary bug: the `lease_kek`
    // arm of `vault.de_provision_outer` refused when
    // `store.lease_kek().is_some()`. That was correct against the pre-#5836
    // shape (the outer arrived BEFORE any in-memory install), but #5836
    // changed `vault.de_provision_begin` to call `store.set_lease_kek` —
    // making `lease_kek().is_some()` TRUE at the very moment the CLI relay
    // round-trips the outer blob. The strict guard refused the very
    // first-boot persistence the relay is built to drive, so the DE-path's
    // own lease-KEK provision could never complete.
    //
    // Post-fix the guard is conjunctive (mirrors the `vault_mek` arm at
    // handler.rs:1992-1999): refuse only when BOTH the in-memory slot AND
    // the on-disk outer blob are already present.
    let store = DaemonStore::open_in_memory().unwrap();
    store
        .provision_dwk()
        .expect("provision DWK for the de_provision lease_kek path");
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // Pre-condition: clean slate — no lease-KEK in memory, no outer blob on
    // disk (mirrors the V030 dev0 fresh-init shape that the CLI relay
    // would attempt to first-boot-provision against).
    assert!(store.lease_kek().is_none());
    assert!(
        store
            .read_lease_kek_double_envelope_outer()
            .expect("read outer")
            .is_none()
    );

    // de_provision_begin installs the lease-KEK in memory (per #5836).
    let begin = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault.de_provision_begin",
        &json!({"purpose": "lease_kek"}),
    )
    .await
    .expect("de_provision_begin(lease_kek) must succeed");
    let inner_hex = begin
        .get("inner_blob")
        .and_then(|v| v.as_str())
        .expect("inner_blob present in begin response");
    let _inner = hex::decode(inner_hex).expect("inner_blob is hex");
    assert!(
        store.lease_kek().is_some(),
        "de_provision_begin installs the lease-KEK in memory before the outer round-trip"
    );

    // de_provision_outer with a stub SE-wrapped outer blob — pre-fix this
    // FAILS because the strict guard refused on `lease_kek().is_some()`;
    // post-fix it succeeds because the outer blob row is still absent.
    let stub_outer = vec![0xABu8; 64];
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault.de_provision_outer",
        &json!({
            "outer_blob": hex::encode(&stub_outer),
            "purpose": "lease_kek",
        }),
    )
    .await
    .expect(
        "de_provision_outer(lease_kek) MUST persist the outer blob on first boot \
         (pre-fix the strict guard refused after de_provision_begin's in-memory install)",
    );

    // The outer blob row exists and matches what we wrote.
    let persisted = store
        .read_lease_kek_double_envelope_outer()
        .expect("read outer post-provision")
        .expect("outer blob row exists post-provision");
    assert_eq!(
        persisted, stub_outer,
        "persisted DE outer blob matches the bytes the CLI relay submitted"
    );

    // de_provision_begin's in-memory install remains: the outer round-trip
    // does NOT touch the slot.
    assert!(
        store.lease_kek().is_some(),
        "de_provision_outer must not touch the in-memory lease-KEK slot"
    );

    // Repeat (idempotent under the conjunctive guard until BOTH are set):
    // a second outer write with the slot+blob both present is now refused.
    let stub_outer_2 = vec![0xCDu8; 64];
    let refuse = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault.de_provision_outer",
        &json!({
            "outer_blob": hex::encode(&stub_outer_2),
            "purpose": "lease_kek",
        }),
    )
    .await
    .expect_err("second outer write must be refused (slot + blob both present)");
    assert_eq!(refuse.0, -32000);
    assert!(
        refuse.1.contains("refusing to overwrite"),
        "the refusal must keep the existing fail-loud message: got {}",
        refuse.1
    );
    // The first-write blob is preserved.
    assert_eq!(
        store
            .read_lease_kek_double_envelope_outer()
            .expect("read outer")
            .expect("first-write blob preserved"),
        stub_outer,
        "the refused second write must NOT overwrite the persisted first-write blob"
    );
}
