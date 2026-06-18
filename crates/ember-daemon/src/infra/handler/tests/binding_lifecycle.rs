use super::*;
use crate::infra::audit::AuditFilter;

// TZ-EMBERD-BINDING-RPC-DELETE — graceful binding delete (ADR 119).
#[tokio::test]
async fn binding_delete_revokes_persona_and_cascades_grants() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // Provision a workload Persona + a grant. The binding cascade
    // is the assertion target — after delete, the persona is
    // revoked AND the grant is drained (status=revoked).
    let persona = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "ml-eval-worker"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap().to_string();

    // `force: true` honored on Internal dispatch (test harness) — bypasses
    // the policy approval gate so the test exercises the cascade path,
    // not the approval queue.
    let grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "anthropic-key",
            "scope": "llm:generate",
            "ttl_secs": 3600,
            "force": true,
        }),
    )
    .await
    .unwrap();
    let grant_id = grant["id"]
        .as_str()
        .unwrap_or_else(|| panic!("create_grant response missing id: {grant:?}"))
        .to_string();

    let resp = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding.delete",
        &json!({
            "persona_id": persona_id,
            "binding_request_id": "br-test-001",
        }),
    )
    .await
    .unwrap();
    assert_eq!(resp["deleted"], json!(true));
    assert_eq!(resp["persona_id"], json!(persona_id));

    // Grant should now be drained — i.e. evaluate_grant fails because
    // the cascade flipped its status to `revoked`.
    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "evaluate_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "anthropic-key",
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32000);

    // Audit log must contain a `binding.deleted` row tied to the persona.
    let audit = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "audit_query",
        &json!({"persona_id": persona_id}),
    )
    .await
    .unwrap();
    let entries = audit.as_array().expect("audit_query returns array");
    assert!(
        entries
            .iter()
            .any(|e| e["action"] == json!("binding.deleted")),
        "expected binding.deleted audit row, got {entries:?}"
    );
    // The grant id is unused beyond the cascade assertion above; bind
    // it once so the compiler doesn't warn about an unused let.
    let _ = grant_id;
}

#[tokio::test]
async fn binding_delete_missing_persona_id_returns_32602() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(&store, &vault, &policy, &rl, "binding.delete", &json!({}))
        .await
        .unwrap_err();
    assert_eq!(err.0, -32602);
}

#[tokio::test]
async fn binding_delete_unknown_persona_returns_32004() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding.delete",
        &json!({"persona_id": "persona-does-not-exist"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32004);
}

#[tokio::test]
async fn binding_delete_underscore_alias_dispatches_too() {
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
        &json!({"name": "alias-worker"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap().to_string();

    let resp = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding_delete",
        &json!({"persona_id": persona_id}),
    )
    .await
    .unwrap();
    assert_eq!(resp["deleted"], json!(true));
}

// TZ-EMBERD-BINDING-RPC-REVOKE-URGENT — compromise-response revocation
// (ADR 119 §"binding.revoke_urgent").
#[tokio::test]
async fn binding_revoke_urgent_cascades_grants_and_emits_urgent_audit() {
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
        &json!({"name": "compromised-worker"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap().to_string();

    // Provision a grant under the persona — it must be cascaded
    // to `revoked` by the urgent path, same as `binding.delete`.
    let _grant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "anthropic-key",
            "scope": "llm:generate",
            "ttl_secs": 3600,
            "force": true,
        }),
    )
    .await
    .unwrap();

    let resp = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding.revoke_urgent",
        &json!({
            "persona_id": persona_id,
            "binding_request_id": "br-urgent-001",
            "reason": "credential leaked in public repo",
        }),
    )
    .await
    .unwrap();
    assert_eq!(resp["revoked_urgent"], json!(true));
    assert_eq!(resp["persona_id"], json!(persona_id));

    // Cascade assertion: evaluate_grant fails because the urgent
    // path flipped the grant to `revoked` (same SQL as delete).
    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "evaluate_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "anthropic-key",
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32000);

    // Audit assertion: action MUST be `binding.revoke_urgent` (NOT
    // `binding.deleted` — operators distinguish urgent revocations
    // from graceful deletes for compliance + alerting).
    let audit = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "audit_query",
        &json!({"persona_id": persona_id}),
    )
    .await
    .unwrap();
    let entries = audit.as_array().expect("audit_query returns array");
    assert!(
        entries.iter().any(|e| {
            e["action"] == json!("binding.revoke_urgent") && e["outcome"] == json!("urgent")
        }),
        "expected binding.revoke_urgent + outcome=urgent audit row, got {entries:?}"
    );
}

#[tokio::test]
async fn binding_revoke_urgent_missing_persona_id_returns_32602() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding.revoke_urgent",
        &json!({}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32602);
}

#[tokio::test]
async fn binding_revoke_urgent_unknown_persona_returns_32004() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding.revoke_urgent",
        &json!({"persona_id": "persona-does-not-exist"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32004);
}

#[tokio::test]
async fn binding_revoke_urgent_underscore_alias_dispatches_too() {
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
        &json!({"name": "alias-urgent-worker"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap().to_string();

    let resp = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding_revoke_urgent",
        &json!({"persona_id": persona_id}),
    )
    .await
    .unwrap();
    assert_eq!(resp["revoked_urgent"], json!(true));
}

// TZ-EMBERD-BINDING-RPC-UPDATE — mutate binding metadata
// (ADR 119 §"binding.update").
#[tokio::test]
async fn binding_update_mutates_name_and_emits_before_after_audit() {
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
        &json!({"name": "old-name"}),
    )
    .await
    .unwrap();
    let binding_id = persona["id"].as_str().unwrap().to_string();

    let resp = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding.update",
        &json!({
            "binding_id": binding_id,
            "binding_request_id": "br-update-001",
            "name": "new-name",
            "cred_class_allowlist": ["llm:generate", "fs:read"],
            "lease_duration_cap": 3600,
        }),
    )
    .await
    .unwrap();
    assert_eq!(resp["updated"], json!(true));
    assert_eq!(resp["binding_id"], json!(binding_id));
    assert_eq!(resp["name"], json!("new-name"));

    // Persona row in SQL must reflect the new name.
    let fetched = store.get_persona(&binding_id).unwrap();
    assert_eq!(fetched.name, "new-name");

    // Audit row carries the before/after snapshot AND the
    // audit-only metadata fields the caller passed. The
    // `audit_query` JSON-RPC response strips `details` (operator
    // dashboards don't paginate details JSON), so read directly
    // via `query_audit` to assert the full payload landed.
    let entries = store
        .query_audit(&AuditFilter {
            persona_id: Some(binding_id.clone()),
            ..Default::default()
        })
        .unwrap();
    let row = entries
        .iter()
        .find(|e| e.action == "binding.updated")
        .unwrap_or_else(|| panic!("expected binding.updated audit row, got {entries:?}"));
    let details: serde_json::Value =
        serde_json::from_str(row.details.as_deref().expect("details JSON populated"))
            .expect("details parses as JSON");
    assert_eq!(details["before"]["name"], json!("old-name"));
    assert_eq!(details["after"]["name"], json!("new-name"));
    assert_eq!(
        details["requested"]["cred_class_allowlist"],
        json!(["llm:generate", "fs:read"])
    );
    assert_eq!(details["requested"]["lease_duration_cap"], json!(3600));
    assert_eq!(details["binding_request_id"], json!("br-update-001"));
}

#[tokio::test]
async fn binding_update_missing_binding_id_returns_32602() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding.update",
        &json!({"name": "irrelevant"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32602);
}

#[tokio::test]
async fn binding_update_unknown_binding_returns_32004() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding.update",
        &json!({
            "binding_id": "persona-does-not-exist",
            "name": "ghost",
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32004);
}

#[tokio::test]
async fn binding_update_duplicate_name_returns_32005() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    // Create two personas — renaming one to the other's name must
    // hit the UNIQUE constraint and surface as -32005.
    let _occupant = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "occupied"}),
    )
    .await
    .unwrap();
    let other = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "free"}),
    )
    .await
    .unwrap();
    let other_id = other["id"].as_str().unwrap().to_string();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding.update",
        &json!({
            "binding_id": other_id,
            "name": "occupied",
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32005);
}

#[tokio::test]
async fn binding_update_underscore_alias_and_persona_id_synonym_dispatch() {
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
        &json!({"name": "alias-update-worker"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap().to_string();

    // Underscore alias + `persona_id` synonym for `binding_id`.
    let resp = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding_update",
        &json!({
            "persona_id": persona_id,
            "name": "alias-update-renamed",
        }),
    )
    .await
    .unwrap();
    assert_eq!(resp["updated"], json!(true));
    assert_eq!(resp["name"], json!("alias-update-renamed"));
}

#[tokio::test]
async fn binding_update_no_mutation_still_emits_audit() {
    // Sanity: a no-op update (no `name` change requested) is
    // still a valid call — it serves as a "touch" for the
    // reconciler to record a binding-update receipt.
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
        &json!({"name": "touch-target"}),
    )
    .await
    .unwrap();
    let binding_id = persona["id"].as_str().unwrap().to_string();

    let resp = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding.update",
        &json!({
            "binding_id": binding_id,
            "binding_request_id": "br-touch-001",
            "metadata": {"reconciler_pass": "ts-2026-05-07"},
        }),
    )
    .await
    .unwrap();
    assert_eq!(resp["updated"], json!(true));
    assert_eq!(resp["name"], json!("touch-target"));

    let audit = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "audit_query",
        &json!({"persona_id": binding_id}),
    )
    .await
    .unwrap();
    let entries = audit.as_array().expect("audit_query returns array");
    assert!(
        entries
            .iter()
            .any(|e| e["action"] == json!("binding.updated")),
        "expected binding.updated audit row, got {entries:?}"
    );
}

// TZ-EMBERD-BINDING-RPC-UPSERT — idempotent insert-or-update
// (ADR 119 §"binding.upsert").

#[tokio::test]
async fn binding_upsert_creates_when_persona_absent() {
    // First-pass reconcile: no persona row exists yet. The verb
    // creates one and emits a `binding.upserted` audit row with
    // `before: null` and a populated `after` snapshot.
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let resp = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding.upsert",
        &json!({
            "namespace": "ns-prod",
            "name": "ml-eval-worker",
            "binding_request_id": "br-upsert-001",
            "cred_class_allowlist": ["llm:generate", "fs:read"],
            "lease_duration_cap": 3600,
            "metadata": {"sa_uid": "uid-abc"},
        }),
    )
    .await
    .unwrap();

    assert_eq!(resp["created"], json!(true));
    assert_eq!(resp["updated"], json!(false));
    assert_eq!(resp["name"], json!("ml-eval-worker"));
    let canonical_id = resp["persona_id"]
        .as_str()
        .expect("response carries persona_id");

    // Persona row exists in SQL with `active` status and the
    // requested name.
    let row = store.get_persona(canonical_id).unwrap();
    assert_eq!(row.name, "ml-eval-worker");
    assert_eq!(row.status, "active");

    // Audit row carries the create snapshot AND the audit-only
    // metadata fields the caller passed.
    let entries = store
        .query_audit(&AuditFilter {
            persona_id: Some(canonical_id.to_string()),
            ..Default::default()
        })
        .unwrap();
    let row = entries
        .iter()
        .find(|e| e.action == "binding.upserted")
        .unwrap_or_else(|| panic!("expected binding.upserted audit row, got {entries:?}"));
    let details: serde_json::Value =
        serde_json::from_str(row.details.as_deref().expect("details JSON populated"))
            .expect("details parses as JSON");
    assert_eq!(details["created"], json!(true));
    assert_eq!(details["before"], serde_json::Value::Null);
    assert_eq!(details["after"]["name"], json!("ml-eval-worker"));
    assert_eq!(details["after"]["status"], json!("active"));
    assert_eq!(
        details["requested"]["cred_class_allowlist"],
        json!(["llm:generate", "fs:read"])
    );
    assert_eq!(details["requested"]["lease_duration_cap"], json!(3600));
    assert_eq!(details["requested"]["namespace"], json!("ns-prod"));
    assert_eq!(
        details["requested"]["metadata"],
        json!({"sa_uid": "uid-abc"})
    );
    assert_eq!(details["binding_request_id"], json!("br-upsert-001"));
}

#[tokio::test]
async fn binding_upsert_updates_when_persona_present() {
    // Steady-state reconcile: persona row already exists. The
    // verb reuses its id, mutates `name` if the request asks for
    // a rename, and emits an audit row with a populated
    // before/after diff.
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
        &json!({"name": "old-name"}),
    )
    .await
    .unwrap();
    let persona_id = persona["id"].as_str().unwrap().to_string();

    let resp = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding.upsert",
        &json!({
            "persona_id": persona_id,
            "name": "new-name",
            "binding_request_id": "br-upsert-002",
            "cred_class_allowlist": ["llm:generate"],
            "lease_duration_cap": 7200,
            "metadata": {"reconciler_pass": "ts-2026-05-07"},
        }),
    )
    .await
    .unwrap();

    assert_eq!(resp["created"], json!(false));
    assert_eq!(resp["updated"], json!(true));
    assert_eq!(resp["persona_id"], json!(persona_id));
    assert_eq!(resp["name"], json!("new-name"));

    // Persona row name updated in SQL.
    let row = store.get_persona(&persona_id).unwrap();
    assert_eq!(row.name, "new-name");

    // Audit row carries before/after diff.
    let entries = store
        .query_audit(&AuditFilter {
            persona_id: Some(persona_id.clone()),
            ..Default::default()
        })
        .unwrap();
    let row = entries
        .iter()
        .find(|e| e.action == "binding.upserted")
        .unwrap_or_else(|| panic!("expected binding.upserted audit row, got {entries:?}"));
    let details: serde_json::Value =
        serde_json::from_str(row.details.as_deref().expect("details JSON populated"))
            .expect("details parses as JSON");
    assert_eq!(details["created"], json!(false));
    assert_eq!(details["before"]["name"], json!("old-name"));
    assert_eq!(details["after"]["name"], json!("new-name"));
    assert_eq!(
        details["requested"]["cred_class_allowlist"],
        json!(["llm:generate"])
    );
    assert_eq!(details["requested"]["lease_duration_cap"], json!(7200));
    assert_eq!(details["binding_request_id"], json!("br-upsert-002"));
}

#[tokio::test]
async fn binding_upsert_idempotent_no_mutation_still_emits_audit() {
    // Replay-safety: calling upsert twice with the same params
    // updates nothing on the second call but still emits a
    // fresh `binding.upserted` audit row (the reconciler relies
    // on per-call receipts for retry idempotency).
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let first = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding.upsert",
        &json!({
            "name": "stable-worker",
            "binding_request_id": "br-replay-001",
        }),
    )
    .await
    .unwrap();
    let persona_id = first["persona_id"].as_str().unwrap().to_string();

    let second = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding.upsert",
        &json!({
            "persona_id": persona_id,
            "name": "stable-worker",
            "binding_request_id": "br-replay-001",
        }),
    )
    .await
    .unwrap();
    assert_eq!(second["created"], json!(false));
    assert_eq!(second["updated"], json!(true));
    assert_eq!(second["persona_id"], json!(persona_id));

    let entries = store
        .query_audit(&AuditFilter {
            persona_id: Some(persona_id.clone()),
            ..Default::default()
        })
        .unwrap();
    let upsert_count = entries
        .iter()
        .filter(|e| e.action == "binding.upserted")
        .count();
    assert_eq!(
        upsert_count, 2,
        "expected two binding.upserted audit rows, got {entries:?}"
    );
}

#[tokio::test]
async fn binding_upsert_missing_both_id_and_name_returns_32602() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let err = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding.upsert",
        &json!({"binding_request_id": "br-noop"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, -32602);
}

#[tokio::test]
async fn binding_upsert_unknown_persona_id_with_name_creates_fresh() {
    // Snapshot-drift path: caller supplies a `persona_id` that
    // does not exist on this daemon (e.g. cluster restored from
    // an older etcd snapshot pointing at a rotated id). With a
    // `name` available, the verb falls through to the create
    // path and returns the daemon's freshly-minted canonical id.
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let resp = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding.upsert",
        &json!({
            "persona_id": "persona-stale-id",
            "name": "drift-recovered-worker",
        }),
    )
    .await
    .unwrap();
    assert_eq!(resp["created"], json!(true));
    let canonical_id = resp["persona_id"].as_str().unwrap();
    assert_ne!(canonical_id, "persona-stale-id");
}

#[tokio::test]
async fn binding_upsert_underscore_alias_dispatches_too() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();

    let resp = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "binding_upsert",
        &json!({"name": "alias-upsert-worker"}),
    )
    .await
    .unwrap();
    assert_eq!(resp["created"], json!(true));
    assert_eq!(resp["name"], json!("alias-upsert-worker"));
}

// --- META-AP-DAEMON-REVOKE-PERSONA-AUTHORITY tests --------------------

#[tokio::test]
async fn revoke_persona_rejects_non_operator_non_self() {
    // T1: non-operator non-self revocation must be rejected with -32003.
    // Persona B (attacker) asserts caller_persona_id = B and tries to
    // revoke persona A. The authority check must fire before any mutation.
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
        &json!({"name": "revoke-test-a"}),
    )
    .await
    .unwrap();
    let a_id = persona_a["id"].as_str().unwrap().to_string();

    let persona_b = dispatch_method(
        &store,
        &vault,
        &policy,
        &rl,
        "create_persona",
        &json!({"name": "revoke-test-b"}),
    )
    .await
    .unwrap();
    let b_id = persona_b["id"].as_str().unwrap().to_string();

    // Enroll caller PID with b_id (the claimed attacker) so the
    // Socket-source PID-enrollment gate passes; the test then
    // exercises the authority-check path it was written to validate.
    enroll_pid_persona(std::process::id() as i32, &b_id);

    // revoke_persona is OperatorPresence-class; the socket-source
    // shim synthesizes a presence_token, but the unlocked-session
    // gate still applies — move presence to Unlocked so the
    // authority check under test (cross-persona refusal) fires.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    // Persona B attempts to revoke persona A — must be denied.
    let err = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Socket,
        "revoke_persona",
        &json!({
            "id": a_id,
            "caller_persona_id": b_id,
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(
        err.0, -32003,
        "non-self socket revoke must return -32003, got {err:?}"
    );
    assert!(
        err.1.to_lowercase().contains("not authorized")
            || err.1.to_lowercase().contains("revocation target"),
        "error must describe the authority failure, got: {}",
        err.1
    );

    // Verify persona A is still active (no mutation occurred).
    let personas = store.list_personas().unwrap();
    let a_status = personas.iter().find(|p| p.id == a_id).map(|p| &p.status);
    assert!(
        a_status.is_some(),
        "persona A must still exist after rejected revoke"
    );
    assert!(
        a_status.map(|s| s != "revoked").unwrap_or(false),
        "persona A must NOT be revoked after rejected cross-persona attempt"
    );
}

#[tokio::test]
async fn revoke_persona_allows_self_revoke() {
    // T2: self-revoke (caller_persona_id == id) must succeed on Socket.
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
        &json!({"name": "revoke-self-test-a"}),
    )
    .await
    .unwrap();
    let a_id = persona_a["id"].as_str().unwrap().to_string();

    // Enroll PID with a_id so the Socket-source PID-enrollment gate
    // passes; the test then exercises the self-revoke success path.
    enroll_pid_persona(std::process::id() as i32, &a_id);

    // Satisfy the OperatorPresence unlocked-session gate.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::mark_unlocked();

    let result = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Socket,
        "revoke_persona",
        &json!({
            "id": a_id,
            "caller_persona_id": a_id,
        }),
    )
    .await
    .unwrap();

    assert_eq!(
        result["revoked"],
        json!(true),
        "self-revoke must succeed, got: {result}"
    );
}

#[tokio::test]
async fn revoke_persona_internal_bypasses_authority_check() {
    // T3: Internal callers (admin CLI / test harness) bypass the authority
    // check and can revoke any persona without asserting caller_persona_id.
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
        &json!({"name": "revoke-internal-test-a"}),
    )
    .await
    .unwrap();
    let a_id = persona_a["id"].as_str().unwrap().to_string();

    let result = dispatch_method_with_source(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        DispatchSource::Internal {
            reason: "test harness — revoke_persona internal bypass",
        },
        "revoke_persona",
        &json!({"id": a_id}),
    )
    .await
    .unwrap();

    assert_eq!(
        result["revoked"],
        json!(true),
        "internal bypass must succeed, got: {result}"
    );
}
