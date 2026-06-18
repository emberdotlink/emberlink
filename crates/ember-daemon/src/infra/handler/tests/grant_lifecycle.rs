use super::*;

#[tokio::test]
async fn create_persona_then_list_shows_it() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "agent-alpha"}),
    )
    .await
    .unwrap();
    assert!(result["id"].as_str().unwrap().starts_with("persona-"));
    assert_eq!(result["name"], json!("agent-alpha"));

    let list = dispatch_method(&store, &vault, &policy, &rl, "list_personas", &json!(null))
        .await
        .unwrap();
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], json!("agent-alpha"));
    assert_eq!(arr[0]["status"], json!("active"));
}

#[tokio::test]
async fn team0_list_personas_scopes_to_trusted_principal() {
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
        &json!({"name": "team0-persona-a"}),
    )
    .await
    .unwrap();
    let persona_b = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "team0-persona-b"}),
    )
    .await
    .unwrap();

    let ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 1000,
            pid: Some(91_001),
        }),
        persona_a["id"].as_str().unwrap().to_string(),
    );
    let list = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "list_personas",
        &json!(null),
    )
    .await
    .unwrap();
    let arr = list.as_array().expect("persona list array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], persona_a["id"]);
    assert_ne!(arr[0]["id"], persona_b["id"]);
}

#[tokio::test]
async fn team0_list_personas_refuses_without_trusted_principal() {
    let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
    clear_pid_persona_registry();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        RequestContext::socket(Some(PeerCred {
            uid: 1000,
            pid: Some(91_002),
        })),
        "list_personas",
        &json!(null),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32004);
    assert!(
        err.1.contains("trusted enrolled principal"),
        "team0 refusal should name the missing trusted principal: {}",
        err.1
    );
}

#[tokio::test]
async fn build_init_first_grant_receipt_returns_signed_file() {
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
        &json!({"name": "root"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let result = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "build_init_first_grant_receipt",
        &json!({"persona_id": persona_id}),
    )
    .await
    .unwrap();

    let file: crate::infra::init_first_grant::FirstGrantReceiptFile =
        serde_json::from_value(result).expect("parse first-grant receipt file");
    assert_eq!(file.issuer.persona, persona_id);
    assert!(file.evidence.signed);
    assert!(file.evidence.hash.starts_with("sha256:"));
    assert!(!file.receipt.receipt_id.is_empty());
    assert!(file.receipt.signature.is_some());
}

#[tokio::test]
async fn create_persona_missing_name_returns_32602() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let err = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({}))
        .await
        .unwrap_err();
    assert_eq!(err.0, -32602);
}

#[tokio::test]
async fn create_grant_then_evaluate_finds_it() {
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
        &json!({"name": "agent-beta"}),
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
            "credential_name": "api-key",
            "scope": "read",
            "force": true,
        }),
    )
    .await
    .unwrap();
    assert!(grant["id"].as_str().unwrap().starts_with("grant-"));

    let eval = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "evaluate_grant",
        &json!({"persona_id": persona_id, "credential_name": "api-key"}),
    )
    .await
    .unwrap();
    assert_eq!(eval["scope"], json!("read"));
}

#[tokio::test]
async fn create_composite_grant_with_presence_emits_authority_receipt() {
    use base64::Engine as _;
    use core_crypto::{P256Signer, Signer as _};
    use core_event_types::{AttestationTier, CustodyClass, DeviceEnrolledEvent, PresenceFactor};
    use core_grant_types::{ResourceSelector, ResourceType, StatementProposal};
    use core_principals::{KeyAlgorithm, PublicKeyMaterial};

    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();
    let _chokepoint_guard = PresenceChokepointEnforceGuard::on();
    let dir = tempfile::TempDir::new().unwrap();
    let _ = crate::infra::receipt::init_identity(dir.path());
    let store = DaemonStore::open(&dir.path().join("daemon.db")).unwrap();
    store.set_vault(std::rc::Rc::new(test_vault()));
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let mut identity_store =
        crate::infra::identity_substrate::open_identity_store(store.data_dir().unwrap()).unwrap();
    let founding = P256Signer::from_scalar_bytes(&[0x51; 32]).unwrap();
    let founding_material = founding.public_key_material("key-authority-receipt-founding");
    let ids = crate::infra::operator_identity::ensure_operator_identity(
        &mut identity_store,
        &founding_material,
        &founding,
    )
    .unwrap();
    let device = P256Signer::from_scalar_bytes(&[0x52; 32]).unwrap();
    let encryption = P256Signer::from_scalar_bytes(&[0x53; 32]).unwrap();
    let device_id = "device-authority-receipt-dispatch".to_string();
    crate::infra::operator_identity::enroll_presence_device(
        &mut identity_store,
        &ids.root_id,
        DeviceEnrolledEvent {
            root_id: ids.root_id.clone(),
            device_id: device_id.clone(),
            label: "Authority Receipt Dispatch".to_string(),
            device_key: device.public_key_material("key-authority-receipt-dispatch"),
            encryption_key: PublicKeyMaterial {
                key_id: "key-authority-receipt-dispatch-ecies".to_string(),
                algorithm: KeyAlgorithm::EcdsaP256,
                public_key: encryption.public_key().0,
            },
            custody_class: CustodyClass::Presence,
            attestation_statement: None,
            attestation_tier: AttestationTier::None,
            presence_factor: PresenceFactor::UserPresence,
        },
        &founding,
        &ids.key_id,
        1_800_000_000,
    )
    .unwrap();
    drop(identity_store);

    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "authority-receipt-runtime"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();
    let op_params = json!({
        "persona_id": persona_id,
        "credential_name": "github",
        "scope": "github:pr:list",
        "ttl_secs": 3_600,
        "statements": [
            StatementProposal {
                resource_type: ResourceType::Credential,
                credential_name: "github".to_string(),
                actions: vec!["credential:read".to_string()],
                resource: ResourceSelector::Exact {
                    value: "github".to_string(),
                },
                budget: None,
                conditions: vec![],
            }
        ]
    });
    let params_digest = crate::auth::presence_gate::presence_params_digest(&op_params).unwrap();
    let ctx = RequestContext::socket(Some(PeerCred {
        uid: 501,
        pid: Some(std::process::id() as i32),
    }));
    let nonce = handle_presence_request_nonce(
        &store,
        &ctx,
        &json!({
            "op_id": "op-authority-receipt-dispatch",
            "method": "create_composite_grant",
            "params_digest": params_digest,
        }),
    )
    .unwrap();
    let intent = hex::decode(nonce["intent_bytes_hex"].as_str().unwrap()).unwrap();
    let signature = device.sign(&intent).0;
    let mut params = op_params.clone();
    params["_presence_proof"] = json!({
        "op_id": "op-authority-receipt-dispatch",
        "nonce": nonce["nonce"],
        "signature": signature,
    });

    let created = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "create_composite_grant",
        &params,
    )
    .await
    .unwrap();
    let receipt_id = created["authority_receipt_id"]
        .as_str()
        .expect("authority receipt id");
    assert!(!receipt_id.is_empty());

    let raw = store.get_receipt_v2_envelope_json(receipt_id).unwrap();
    let explained = crate::trust::introspect::handle_trust_explain_with_store(
        Some(&store),
        &json!({
            "artifact_kind": "receipt",
            "artifact_bytes_b64": base64::engine::general_purpose::STANDARD.encode(raw.as_bytes()),
            "sidecar_bytes_b64": "",
        }),
    )
    .unwrap();
    assert_eq!(explained["verdict"], json!("verified"), "{explained:#}");
    assert_eq!(explained["receipt_class"], json!("authority_decision"));
    assert_eq!(
        explained["receipt_kind"],
        json!(core_events::receipt::RECEIPT_KIND_AUTHORITY_GRANT_ISSUED)
    );
    assert_eq!(
        explained["chain_contains_trusted_operator_principal"],
        json!(true)
    );
    assert_eq!(explained["chain_contains_signing_device"], json!(true));
    assert_eq!(explained["chain_contains_presence_proof"], json!(true));
}

#[tokio::test]
async fn grant_expire_stale_rpc_expires_due_grants() {
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
        &json!({"name": "expire-stale-agent"}),
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
            "credential_name": "expiring-token",
            "scope": "read",
            "ttl_secs": 3_600,
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();
    store
        .conn()
        .execute(
            "UPDATE grants SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?1",
            rusqlite::params![grant_id],
        )
        .unwrap();

    let expired = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "grant.expire_stale",
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(expired["expired_count"], json!(1));

    let stored_status: String = store
        .conn()
        .query_row(
            "SELECT status FROM grants WHERE id = ?1",
            rusqlite::params![grant_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_status, "expired");
}

#[tokio::test]
async fn team0_evaluate_grant_scopes_persona_to_trusted_principal() {
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
        &json!({"name": "team0-evaluate-a"}),
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
        &json!({"name": "team0-evaluate-b"}),
    )
    .await
    .unwrap();
    let persona_b_id = persona_b["id"].as_str().unwrap().to_string();
    store
        .create_grant(&persona_a_id, "cred-a", "read", None)
        .unwrap();
    store
        .create_grant(&persona_b_id, "cred-b", "read", None)
        .unwrap();

    let ctx = RequestContext::socket_with_principal(
        Some(PeerCred {
            uid: 1000,
            pid: Some(91_004),
        }),
        persona_a_id.clone(),
    );
    let eval = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx.clone(),
        "evaluate_grant",
        &json!({"credential_name": "cred-a"}),
    )
    .await
    .unwrap();
    assert_eq!(eval["scope"], json!("read"));

    let err = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "evaluate_grant",
        &json!({"persona_id": persona_b_id, "credential_name": "cred-b"}),
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
async fn propose_grant_rpc_persists_n_statements() {
    // DEMO-MAY3-COMPOSITE-RPC — N-statement persistence + retrieval.
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
        &json!({"name": "composite-rpc-agent"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    // 3-Statement composite envelope (credential + session + time).
    // Composite statement actions remain generic grant verbs here; they
    // are not forced through the old flat DID-prefixed action-key model.
    let statements = json!([
        {
            "sid": "S0",
            "resource_type": "credential",
            "actions": ["github.push", "github.read"],
            "resource": {"kind": "any"},
            "budget": null,
            "usage": {},
            "conditions": [],
        },
        {
            "sid": "S1",
            "resource_type": "session",
            "actions": ["generic.write"],
            "resource": {"kind": "any"},
            "budget": {"tokens": 10000},
            "usage": {},
            "conditions": [],
        },
        {
            "sid": "S2",
            "resource_type": "time",
            "actions": ["generic.write"],
            "resource": {"kind": "any"},
            "budget": {"wall_clock_secs": 300},
            "usage": {},
            "conditions": [],
        },
    ]);

    let resp = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "propose_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "gh-token",
            "scope": "*",
            "action": "github.push",
            "risk_level": "high",
            "statements": statements,
        }),
    )
    .await
    .unwrap();

    let approval_id = resp["approval_id"].as_str().expect("approval_id present");
    assert!(approval_id.starts_with("approval-"));
    assert_eq!(resp["status"], json!("pending"));
    assert_eq!(resp["statement_count"], json!(3));

    // Retrieval round-trip via the store directly: the row should carry
    // all three statements exactly.
    let info = store
        .get_approval(approval_id)
        .expect("approval row present");
    let stmts = info
        .composite_statements
        .expect("composite_statements present");
    assert_eq!(stmts.len(), 3);
    assert_eq!(stmts[0].sid, "S0");
    assert_eq!(stmts[1].sid, "S1");
    assert_eq!(stmts[2].sid, "S2");
}

#[tokio::test]
async fn propose_grant_rpc_rejects_empty_statements() {
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
        &json!({"name": "composite-rpc-empty"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "propose_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "gh-token",
            "scope": "*",
            "action": "x",
            "risk_level": "high",
            "statements": [],
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32602);
    assert!(err.1.contains("statements"));
}

#[tokio::test]
async fn propose_grant_rpc_accepts_generic_action_strings() {
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
        &json!({"name": "composite-rpc-bare-key"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let resp = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "propose_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "gh-token",
            "scope": "*",
            "action": "credential.access",
            "risk_level": "high",
            "statements": [
                {
                    "sid": "S0",
                    "resource_type": "credential",
                    "actions": ["gh.pr_create"],
                    "resource": {"kind": "any"},
                    "budget": null,
                    "usage": {},
                    "conditions": [],
                }
            ],
        }),
    )
    .await
    .expect("generic action strings must pass the propose_grant parse gate");

    assert!(
        resp["approval_id"]
            .as_str()
            .unwrap_or("")
            .starts_with("approval-")
    );
}

#[tokio::test]
async fn propose_grant_rpc_accepts_structured_action_ref_strings() {
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
        &json!({"name": "composite-rpc-fwd-compat"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let resp = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "propose_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "tf-token",
            "scope": "*",
            "action": "credential.access",
            "risk_level": "high",
            "statements": [
                {
                    "sid": "S0",
                    "resource_type": "credential",
                    "actions": ["registry.ember.systems/ember-systems/ember-gh/pr_create@v1"],
                    "resource": {"kind": "any"},
                    "budget": null,
                    "usage": {},
                    "conditions": [],
                }
            ],
        }),
    )
    .await
    .expect("structured action-ref strings must pass the propose_grant parse gate");

    assert!(
        resp["approval_id"]
            .as_str()
            .unwrap_or("")
            .starts_with("approval-")
    );
}

#[tokio::test]
async fn create_and_list_standing_grant_rpc_round_trips_structured_selector() {
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
        &json!({"name": "standing-selector-rpc"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    let created = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_standing_grant",
        &json!({
            "persona_id": persona_id,
            "action_selector": {
                "kind": "action_ref",
                "plugin_address": "registry.ember.systems/ember-systems/ember-gh",
                "action_key": "pr_merge",
                "action_version": "v1"
            },
            "scope": "*",
        }),
    )
    .await
    .unwrap();

    assert_eq!(created["created"], json!(true));
    assert_eq!(created["action_selector"]["kind"], json!("action_ref"));
    assert_eq!(created["action_selector"]["action_key"], json!("pr_merge"));

    let listed = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "list_standing_grants",
        &json!({}),
    )
    .await
    .unwrap();
    let grants = listed.as_array().expect("standing grant list");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0]["persona_id"], json!(persona_id));
    assert_eq!(grants[0]["action_selector"]["kind"], json!("action_ref"));
    assert_eq!(
        grants[0]["action_selector"]["plugin_address"],
        json!("registry.ember.systems/ember-systems/ember-gh")
    );
    assert_eq!(
        grants[0]["action_selector"]["action_key"],
        json!("pr_merge")
    );
    assert_eq!(grants[0]["action_selector"]["action_version"], json!("v1"));
}

#[tokio::test]
async fn create_grant_with_rate_limit_stores_condition() {
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
        &json!({"name": "agent-ratelimit"}),
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
            "credential_name": "rate-key",
            "scope": "read",
            "max_uses_per_hour": 5,
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();
    assert!(grant_id.starts_with("grant-"));
    assert_eq!(grant["conditions"]["max_uses_per_hour"], json!(5));

    // Verify it was stored in the DB.
    let stored: Option<i64> = store
        .conn()
        .query_row(
            "SELECT max_uses_per_hour FROM grants WHERE id = ?1",
            rusqlite::params![grant_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, Some(5));
}

#[tokio::test]
async fn create_grant_with_budget_and_standing_shapes_grant() {
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
        &json!({"name": "agent-shaped"}),
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
            "credential_name": "shape-key",
            "scope": "github:push:acme/widgets",
            "budget": {"tokens": 42, "wall_clock_secs": 900},
            "max_delegation_depth": 2,
            "max_children_per_day": 7,
            "auto_delegate_scope_template": "github:push:acme/*",
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();
    assert_eq!(grant["budget"]["tokens"], json!(42));
    assert_eq!(grant["standing"]["max_children_per_day"], json!(7));

    let stored = store.get_grant(grant_id).expect("grant row");
    assert_eq!(stored.budget.as_ref().and_then(|b| b.tokens), Some(42));
    assert!(stored.is_standing);
    assert_eq!(stored.max_children_per_day, Some(7));
    assert_eq!(
        stored.auto_delegate_scope_template.as_deref(),
        Some("github:push:acme/*")
    );
}

#[tokio::test]
async fn create_grant_socket_pending_approval_preserves_grant_shape() {
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
        &json!({"name": "agent-approval-shaped"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap();

    // create_grant is OperatorPresence-class. The socket-source
    // shim synthesizes a peer + presence_token under #[cfg(test)],
    // but the unlocked-session gate still applies — move presence
    // to Unlocked so the test reaches the pending-approval shape
    // it asserts on.
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
            "budget": {"tokens": 99},
            "max_delegation_depth": 2,
            "max_children_per_day": 3,
            "auto_delegate_scope_template": "stripe:*",
        }),
    )
    .await
    .unwrap();
    assert_eq!(result["status"], json!("pending_approval"));
    let approval_id = result["approval_id"].as_str().unwrap();

    let pending = store.get_approval(approval_id).expect("approval row");
    assert_eq!(pending.max_delegation_depth, Some(2));
    assert_eq!(pending.budget.as_ref().and_then(|b| b.tokens), Some(99));
    assert_eq!(pending.max_children_per_day, Some(3));
    assert_eq!(
        pending.auto_delegate_scope_template.as_deref(),
        Some("stripe:*")
    );
}

#[tokio::test]
async fn delegate_grant_creates_child_grant() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let parent_persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "agent-parent"}),
    )
    .await
    .unwrap();
    let parent_persona_id = parent_persona["id"].as_str().unwrap();

    let child_persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "agent-child"}),
    )
    .await
    .unwrap();
    let child_persona_id = child_persona["id"].as_str().unwrap();

    let parent_grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": parent_persona_id,
            "credential_name": "delegate-key",
            "scope": "*",
            "max_delegation_depth": 2,
            "force": true,
        }),
    )
    .await
    .unwrap();
    let parent_grant_id = parent_grant["id"].as_str().unwrap();

    let child_grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "delegate_grant",
        &json!({
            "parent_grant_id": parent_grant_id,
            "child_persona_id": child_persona_id,
            "scope": "read",
        }),
    )
    .await
    .unwrap();

    assert!(child_grant["id"].as_str().unwrap().starts_with("grant-"));
    assert_eq!(child_grant["scope"], json!("read"));
    assert_eq!(child_grant["parent"], json!(parent_grant_id));
}

/// ADR 207 seam 8B — a delegated child grant does NOT inherit (and so
/// cannot widen) the parent's `allowed_targets` host clamp. The delegation
/// INSERT omits the column, so the child's `allowed_targets` is NULL; for
/// the generic credential lane that means the child fails closed
/// (`DenyGenericNoAllowlist`) rather than reaching the parent's hosts —
/// the host clamp cannot be confused-deputy'd wider through delegation.
#[tokio::test]
async fn delegated_child_does_not_inherit_allowed_targets() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let parent_persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "agent-parent"}),
    )
    .await
    .unwrap();
    let parent_persona_id = parent_persona["id"].as_str().unwrap();
    let child_persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "agent-child"}),
    )
    .await
    .unwrap();
    let child_persona_id = child_persona["id"].as_str().unwrap();

    // Parent carries an explicit allowed_targets host allowlist.
    let parent_grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": parent_persona_id,
            "credential_name": "delegate-key",
            "scope": "*",
            "allowed_targets": ["api.acme.com"],
            "max_delegation_depth": 2,
            "force": true,
        }),
    )
    .await
    .unwrap();
    let parent_grant_id = parent_grant["id"].as_str().unwrap();
    // Sanity: the parent really has the allowlist set.
    assert_eq!(
        store.get_grant(parent_grant_id).unwrap().allowed_targets,
        Some("[\"api.acme.com\"]".to_string())
    );

    let child_grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "delegate_grant",
        &json!({
            "parent_grant_id": parent_grant_id,
            "child_persona_id": child_persona_id,
            "scope": "read",
        }),
    )
    .await
    .unwrap();
    let child_grant_id = child_grant["id"].as_str().unwrap();

    // The child does NOT inherit the parent's allowed_targets.
    assert_eq!(
        store.get_grant(child_grant_id).unwrap().allowed_targets,
        None,
        "delegated child must not inherit/widen the host allowlist"
    );
}

/// Exercise the socket-level `delegate_grant` method with an
/// explicit child `budget` param. Parent carries a tokens budget,
/// child asks for a strict subset — attenuation must accept and the
/// response envelope must surface the child budget + expiry.
#[tokio::test]
async fn delegate_grant_via_socket_accepts_child_budget() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let parent_persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "agent-parent-budget"}),
    )
    .await
    .unwrap();
    let parent_persona_id = parent_persona["id"].as_str().unwrap();

    let child_persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "agent-child-budget"}),
    )
    .await
    .unwrap();
    let child_persona_id = child_persona["id"].as_str().unwrap();

    let parent_grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": parent_persona_id,
            "credential_name": "delegate-key",
            "scope": "github:push:acme/*",
            "budget": {"tokens": 10000},
            "max_delegation_depth": 2,
            "ttl_secs": 3_600,
            "force": true,
        }),
    )
    .await
    .unwrap();
    let parent_grant_id = parent_grant["id"].as_str().unwrap().to_string();

    let child_grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "delegate_grant",
        &json!({
            "parent_grant_id": parent_grant_id,
            "child_persona_id": child_persona_id,
            "scope": "github:push:acme/widgets",
            "ttl_secs": 900,
            "budget": {"tokens": 2000},
        }),
    )
    .await
    .unwrap();

    assert!(child_grant["id"].as_str().unwrap().starts_with("grant-"));
    assert_eq!(child_grant["scope"], json!("github:push:acme/widgets"));
    assert_eq!(child_grant["parent"], json!(parent_grant_id));
    assert_eq!(
        child_grant["budget"]["tokens"].as_u64(),
        Some(2000),
        "child budget echoed in response"
    );
    assert!(
        child_grant["expires_at"].is_string(),
        "expires_at present on delegated grant"
    );
}

// --- ADR 207 SEAM-8B follow-up: per-entry allowed_targets validation -----
//
// `create_grant` refuses entries flagged by the SEAM-8B adversarial review
// before the JSON-array is persisted. Anchor:
// `allowed_targets_storage_and_parse_one_encoding`.

async fn persona_id_for_validation_tests(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rl: &std::cell::RefCell<crate::infra::rate_limit::RateLimiter>,
) -> String {
    let persona = dispatch_method(
        store,
        vault,
        policy,
        rl,
        "create_persona",
        &json!({"name": "agent-allowed-targets-validation"}),
    )
    .await
    .unwrap();
    persona["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn create_grant_rejects_empty_allowed_targets_entry() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let persona_id = persona_id_for_validation_tests(&store, &vault, &policy, &rl).await;

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "delegate-key",
            "scope": "*",
            "allowed_targets": ["api.acme.com", ""],
            "force": true,
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32602);
    assert!(
        err.1.contains("invalid_allowed_targets_entry"),
        "refusal must be labelled invalid_allowed_targets_entry: {}",
        err.1
    );
    assert!(
        err.1.contains("empty"),
        "refusal must name the empty-entry reason: {}",
        err.1
    );
}

#[tokio::test]
async fn create_grant_rejects_bare_star_allowed_targets_entry() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let persona_id = persona_id_for_validation_tests(&store, &vault, &policy, &rl).await;

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "delegate-key",
            "scope": "*",
            "allowed_targets": ["*"],
            "force": true,
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32602);
    assert!(
        err.1.contains("invalid_allowed_targets_entry"),
        "refusal must be labelled invalid_allowed_targets_entry: {}",
        err.1
    );
    assert!(
        err.1.contains("bare '*'"),
        "refusal must name the bare-star reason: {}",
        err.1
    );
}

#[tokio::test]
async fn create_grant_rejects_star_dot_empty_domain_allowed_targets_entry() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let persona_id = persona_id_for_validation_tests(&store, &vault, &policy, &rl).await;

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "delegate-key",
            "scope": "*",
            "allowed_targets": ["*."],
            "force": true,
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.0, -32602);
    assert!(
        err.1.contains("invalid_allowed_targets_entry"),
        "refusal must be labelled invalid_allowed_targets_entry: {}",
        err.1
    );
    assert!(
        err.1.contains("empty domain"),
        "refusal must name the empty-domain reason: {}",
        err.1
    );
}

// grant_extend_rpc_landed: T1 coverage for the dotted `grant.extend`
// RPC. Happy path goes through the Internal source bypass (mirrors the
// existing dispatch_method shim used across the file); auth-fail path
// asserts that a socket caller cannot pass `force: true` — the same
// gate `handle_create` enforces, applied symmetrically here so an
// attacker can never silently bypass the policy/presence checks via
// extend.
#[tokio::test]
async fn grant_extend_rpc_landed_dotted_spelling_extends_budget_and_ttl() {
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
        &json!({"name": "agent-extend-happy"}),
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
            "credential_name": "extendable-key",
            "scope": "read",
            "ttl_secs": 3_600,
            "budget": {"tokens": 100},
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();
    let initial_expires_at = grant["expires_at"].as_str().map(str::to_owned);

    // Dispatch the dotted spelling — proves dispatch_method::"grant.extend"
    // routes to handle_extend.
    let extended = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "grant.extend",
        &json!({
            "grant_id": grant_id,
            "add_tokens": 50,
            "add_ttl_secs": 1_800,
            "force": true,
        }),
    )
    .await
    .unwrap();

    assert_eq!(extended["grant_id"], json!(grant_id));
    let new_expires_at = extended["expires_at"].as_str().map(str::to_owned);
    assert!(
        new_expires_at.is_some() && new_expires_at != initial_expires_at,
        "extend must advance expires_at (was {:?}, now {:?})",
        initial_expires_at,
        new_expires_at,
    );
    let budget = &extended["budget"];
    assert!(
        budget.is_object(),
        "extend response must carry the updated budget: {budget}"
    );
}

#[tokio::test]
async fn grant_extend_rpc_landed_legacy_extend_grant_spelling_still_works() {
    // Compatibility check: the legacy `extend_grant` arm continues to
    // route through `handle_extend` (kept as an alias for current CLI
    // releases, same pattern as `grant.expire_stale` | `expire_grants`).
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
        &json!({"name": "agent-extend-legacy"}),
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
            "credential_name": "legacy-key",
            "scope": "read",
            "ttl_secs": 3_600,
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();

    let extended = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "extend_grant",
        &json!({
            "grant_id": grant_id,
            "add_ttl_secs": 600,
            "force": true,
        }),
    )
    .await
    .unwrap();
    assert_eq!(extended["grant_id"], json!(grant_id));
}

#[tokio::test]
async fn grant_extend_rpc_landed_socket_force_rejected() {
    // Auth-fail (escalation-attempt) path: a socket caller cannot pass
    // `force: true` — the symmetric guard with `handle_create` that
    // blocks silent policy/presence bypass via the extend arm. This
    // proves the "authority gates match create_grant" acceptance.
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
        &json!({"name": "agent-extend-socket-force"}),
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
            "credential_name": "socket-force-target",
            "scope": "read",
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"].as_str().unwrap();

    // `grant.extend` is OperatorPresence-class. Satisfy the outer
    // chokepoint so this test reaches the handler-local force-on-socket
    // rejection instead of stopping at the generic presence gate.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let err = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Socket,
        "grant.extend",
        &json!({
            "grant_id": grant_id,
            "add_ttl_secs": 600,
            "force": true,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32602);
    assert!(
        err.1.contains("'force' parameter is not permitted on the socket API"),
        "refusal must name the force-on-socket rule: {}",
        err.1
    );
}
