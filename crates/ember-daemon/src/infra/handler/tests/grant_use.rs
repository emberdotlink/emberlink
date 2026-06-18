use super::*;

#[tokio::test]
async fn use_credential_with_valid_grant_returns_value() {
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
        &json!({"name": "agent-gamma"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "my-token", "value": "supersecret"}),
    )
    .await
    .unwrap();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "my-token",
            "scope": "read",
            "force": true,
        }),
    )
    .await
    .unwrap();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "use_credential",
        &json!({"persona_id": persona_id, "credential_name": "my-token"}),
    )
    .await
    .unwrap();
    assert_eq!(result["credential"], json!("supersecret"));
}

#[tokio::test]
async fn use_credential_biometric_row_requires_fresh_presence_proof() {
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
        &json!({"name": "agent-biometric-use"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "biometric-use-token", "value": "supersecret"}),
    )
    .await
    .unwrap();
    store
        .conn()
        .execute(
            "UPDATE credentials SET presence_policy = 'per_access_fresh' WHERE name = ?1",
            rusqlite::params!["biometric-use-token"],
        )
        .unwrap();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "biometric-use-token",
            "scope": "read",
            "force": true,
        }),
    )
    .await
    .unwrap();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "use_credential",
        &json!({"persona_id": persona_id, "credential_name": "biometric-use-token"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32030);
    assert!(
        err.1.contains("presence-Device signature"),
        "protected use_credential must return the fresh-proof retry signal, got: {err:?}"
    );
}

#[tokio::test]
async fn revoke_statement_blocks_use_credential() {
    // DEMO-MAY3-COMPOSITE-PER-STMT-REVOKE: per-statement revoke MVP.
    // Revoking the Credential Statement's sid blocks use_credential
    // while the grant is otherwise still active.
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
        &json!({"name": "agent-stmtrev"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "stmtrev-token", "value": "supersecret"}),
    )
    .await
    .unwrap();

    let grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "stmtrev-token",
            "scope": "read",
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap().to_string();

    // Baseline: works.
    let ok = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "use_credential",
        &json!({"persona_id": persona_id, "credential_name": "stmtrev-token"}),
    )
    .await
    .unwrap();
    assert_eq!(ok["credential"], json!("supersecret"));

    // Revoke S0 (the credential statement built by create_grant).
    let resp = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "revoke_statement",
        &json!({"grant_id": grant_id, "statement_sid": "S0"}),
    )
    .await
    .unwrap();
    assert_eq!(resp["status"], json!("revoked"));

    // Now use_credential is blocked with -32006.
    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "use_credential",
        &json!({"persona_id": persona_id, "credential_name": "stmtrev-token"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32006);

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
    let revoked = status["revoked_sids"]
        .as_array()
        .expect("revoked_sids array");
    assert!(revoked.iter().any(|v| v.as_str() == Some("S0")));
}

#[tokio::test]
async fn use_credential_without_grant_returns_error() {
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
        &json!({"name": "agent-delta"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "my-token", "value": "supersecret"}),
    )
    .await
    .unwrap();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "use_credential",
        &json!({"persona_id": persona_id, "credential_name": "my-token"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32000);
    assert!(err.1.contains("no active grant"));
}

#[tokio::test]
async fn use_credential_records_usage_and_enforces_rate_limit() {
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
        &json!({"name": "agent-usage"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "usage-token", "value": "secret"}),
    )
    .await
    .unwrap();

    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "usage-token",
            "scope": "read",
            "max_uses_per_hour": 2,
            "force": true,
        }),
    )
    .await
    .unwrap();

    let r1 = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "use_credential",
        &json!({"persona_id": persona_id, "credential_name": "usage-token"}),
    )
    .await;
    assert!(r1.is_ok());

    let r2 = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "use_credential",
        &json!({"persona_id": persona_id, "credential_name": "usage-token"}),
    )
    .await;
    assert!(r2.is_ok());

    let r3 = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "use_credential",
        &json!({"persona_id": persona_id, "credential_name": "usage-token"}),
    )
    .await;
    assert!(r3.is_err());
    assert_eq!(r3.unwrap_err().0, -32000);
}

#[tokio::test]
async fn use_credential_by_grant_id_succeeds() {
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
        &json!({"name": "uc-grant"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "gk", "value": "secret-by-grant-id"}),
    )
    .await
    .unwrap();
    let grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({"persona_id": persona_id, "credential_name": "gk", "scope": "r", "force": true}),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "use_credential",
        &json!({"grant_id": grant_id, "persona_id": persona_id}),
    )
    .await
    .unwrap();
    assert_eq!(result["credential"], "secret-by-grant-id");
    assert_eq!(result["grant_id"], json!(grant_id));
    assert_eq!(result["credential_name"], "gk");
}

#[tokio::test]
async fn use_credential_by_grant_id_rejects_cross_persona() {
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
        &json!({"name": "owner"}),
    )
    .await
    .unwrap();
    let owner_id = owner["id"].as_str().unwrap();
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "ok", "value": "v"}),
    )
    .await
    .unwrap();
    let grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({"persona_id": owner_id, "credential_name": "ok", "scope": "r", "force": true}),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();

    // A caller supplying the owner's grant_id but a foreign persona
    // MUST be rejected: leaked id cannot be used to redeem.
    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "use_credential",
        &json!({"grant_id": grant_id, "persona_id": "persona-other"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32002);
}

#[tokio::test]
async fn use_credential_by_grant_id_rejects_inactive_grant() {
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
        &json!({"name": "inact"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();
    dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "vault_add",
        &json!({"name": "ik", "value": "v"}),
    )
    .await
    .unwrap();
    let grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({"persona_id": persona_id, "credential_name": "ik", "scope": "r", "force": true}),
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
        "use_credential",
        &json!({"grant_id": grant_id, "persona_id": persona_id}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32005);
}
