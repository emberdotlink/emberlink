// COMPOSITE-PR6-DONE
//
// T2 property tests for the propose_grant flow.
//
// These tests exercise the propose_grant → approval-store → dashboard render
// pipeline to validate the following invariants:
//
//   P1. skill_ref round-trips through propose_grant_typed: a GrantProposal with
//       skill_ref Some("my-skill") persists the value and get_approval returns it.
//
//   P2. propose_grant_typed rejects malformed skill_refs (> 256 chars or
//       containing null bytes) with StoreError::InvalidInput before any DB write.
//
//   P3. Dashboard approval-card HTML includes skill_ref iff Some(_):
//       - When Some("deploy-tool") the rendered HTML contains the skill_ref text.
//       - When None the rendered HTML does not contain the skill-ref-row element.
//
//   P4. skill_ref is None (and not present in HTML) for approvals submitted via
//       the legacy submit_approval path that predates GrantProposal.
//
//   P5. list_pending_approvals returns skill_ref from the DB for typed proposals.

use ember_daemon::infra::dashboard::render_approval_page;
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::trust::approval::ApprovalRequestInfo;

use core_grant_types::{GrantProposal, ResourceSelector, ResourceType, StatementProposal};

use std::rc::Rc;

fn make_store() -> DaemonStore {
    DaemonStore::open_in_memory().expect("in-memory store")
}

fn make_persona(store: &DaemonStore) -> String {
    let vault = Rc::new(ember_daemon::infra::vault::Vault::new([1u8; 32]));
    store.set_vault(Rc::clone(&vault));
    store
        .create_persona("test-agent")
        .expect("create persona")
        .id
}

fn minimal_statement(credential_name: &str) -> StatementProposal {
    StatementProposal {
        resource_type: ResourceType::Credential,
        credential_name: credential_name.to_string(),
        actions: vec!["read".to_string()],
        resource: ResourceSelector::Any,
        budget: None,
        conditions: vec![],
    }
}

fn fake_approval_with_skill_ref(skill_ref: Option<&str>) -> ApprovalRequestInfo {
    ApprovalRequestInfo {
        id: "approval-test-00000000-0000-0000-0000-000000000001".to_string(),
        persona_id: "persona-test".to_string(),
        credential_name: "test-key".to_string(),
        scope: "composite".to_string(),
        ttl_secs: None,
        action: "credential.access".to_string(),
        risk_level: "low".to_string(),
        status: "pending".to_string(),
        reason: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        tool_name: None,
        target_host: None,
        target_summary: None,
        target_url: None,
        agent_framework: None,
        composite_statements: None,
        result_grant_id: None,
        skill_ref: skill_ref.map(str::to_owned),
        // META-AP-DAEMON-APPROVAL-FLOW-DROPS-DELEGATION-FIELDS-FIXED — the
        // five grant-shaping fields default to None for legacy fixtures
        // that don't exercise the delegation-cap path.
        max_delegation_depth: None,
        max_uses_per_hour: None,
        allowed_hours_start: None,
        allowed_hours_end: None,
        allowed_targets: None,
        budget: None,
        max_children_per_day: None,
        auto_delegate_scope_template: None,
    }
}

// --- P1: skill_ref round-trips through propose_grant_typed ---

#[test]
fn skill_ref_round_trips_through_propose_grant_typed() {
    let store = make_store();
    let pid = make_persona(&store);

    let proposal = GrantProposal {
        persona_id: pid.clone(),
        statements: vec![minimal_statement("api-key")],
        expires_at: None,
        label: None,
        skill_ref: Some("my-construct/deploy-v1".to_string()),
        note: None,
    };

    let info = store
        .propose_grant_typed(&proposal, "credential.access", "low")
        .expect("propose_grant_typed must succeed");

    assert_eq!(
        info.skill_ref.as_deref(),
        Some("my-construct/deploy-v1"),
        "returned ApprovalRequestInfo must carry the skill_ref"
    );

    let fetched = store
        .get_approval(&info.id)
        .expect("get_approval must find the row");

    assert_eq!(
        fetched.skill_ref.as_deref(),
        Some("my-construct/deploy-v1"),
        "skill_ref must survive the DB round-trip via get_approval"
    );
}

// --- P2a: propose_grant_typed rejects excessively long skill_ref ---

#[test]
fn propose_grant_typed_rejects_skill_ref_longer_than_256_chars() {
    let store = make_store();
    let pid = make_persona(&store);

    let long_skill_ref = "x".repeat(257);

    let proposal = GrantProposal {
        persona_id: pid.clone(),
        statements: vec![minimal_statement("api-key")],
        expires_at: None,
        label: None,
        skill_ref: Some(long_skill_ref),
        note: None,
    };

    let result = store.propose_grant_typed(&proposal, "credential.access", "low");
    match result {
        Ok(_) => panic!("propose_grant_typed must reject skill_ref longer than 256 chars"),
        Err(e) => {
            let err_str = e.to_string();
            assert!(
                err_str.contains("256") || err_str.to_lowercase().contains("skill_ref"),
                "error message must mention skill_ref or the 256 limit; got: {err_str}"
            );
        }
    }
}

// --- P2b: propose_grant_typed rejects skill_ref with null bytes ---

#[test]
fn propose_grant_typed_rejects_skill_ref_with_null_bytes() {
    let store = make_store();
    let pid = make_persona(&store);

    let null_skill_ref = "skill\0ref-with-nul".to_string();

    let proposal = GrantProposal {
        persona_id: pid.clone(),
        statements: vec![minimal_statement("api-key")],
        expires_at: None,
        label: None,
        skill_ref: Some(null_skill_ref),
        note: None,
    };

    let result = store.propose_grant_typed(&proposal, "credential.access", "low");
    assert!(
        result.is_err(),
        "propose_grant_typed must reject skill_ref containing null bytes"
    );
}

// --- P3a: dashboard renders skill_ref when Some ---

#[test]
fn dashboard_render_includes_skill_ref_when_some() {
    let approval = fake_approval_with_skill_ref(Some("deploy-tool"));
    let html = render_approval_page("test-csrf-token", &approval, None);

    assert!(
        html.contains("deploy-tool"),
        "rendered HTML must contain the skill_ref value 'deploy-tool'"
    );
    assert!(
        html.contains("skill-ref-row"),
        "rendered HTML must contain the skill-ref-row element when skill_ref is Some"
    );
}

// --- P3b: dashboard omits skill_ref row when None ---

#[test]
fn dashboard_render_omits_skill_ref_row_when_none() {
    let approval = fake_approval_with_skill_ref(None);
    let html = render_approval_page("test-csrf-token", &approval, None);

    assert!(
        !html.contains("skill-ref-row"),
        "rendered HTML must NOT contain the skill-ref-row element when skill_ref is None"
    );
    assert!(
        !html.contains("Skill</span>"),
        "rendered HTML must NOT contain a Skill field label when skill_ref is None"
    );
}

// --- P4: legacy submit_approval has skill_ref == None ---

#[test]
fn legacy_submit_approval_has_no_skill_ref() {
    let store = make_store();
    let pid = make_persona(&store);

    let info = store
        .submit_approval(&pid, "api-key", "read", None, "credential.access", "low")
        .expect("submit_approval must succeed");

    assert!(
        info.skill_ref.is_none(),
        "legacy submit_approval must return skill_ref == None"
    );

    let fetched = store.get_approval(&info.id).expect("get_approval");
    assert!(
        fetched.skill_ref.is_none(),
        "legacy approval row must have skill_ref == None in DB"
    );

    let html = render_approval_page("test-csrf", &fetched, None);
    assert!(
        !html.contains("skill-ref-row"),
        "legacy approval card must not render skill-ref-row"
    );
}

// --- P5: list_pending_approvals returns skill_ref from DB ---

#[test]
fn list_pending_approvals_returns_skill_ref() {
    let store = make_store();
    let pid = make_persona(&store);

    let proposal = GrantProposal {
        persona_id: pid.clone(),
        statements: vec![minimal_statement("storage-key")],
        expires_at: None,
        label: None,
        skill_ref: Some("storage-construct/v2".to_string()),
        note: None,
    };

    store
        .propose_grant_typed(&proposal, "credential.access", "low")
        .expect("propose_grant_typed must succeed");

    let pending = store
        .list_pending_approvals()
        .expect("list_pending_approvals");
    assert_eq!(pending.len(), 1, "should have exactly one pending approval");

    let p = &pending[0];
    assert_eq!(
        p.skill_ref.as_deref(),
        Some("storage-construct/v2"),
        "list_pending_approvals must return skill_ref from the DB"
    );
}

// --- P6: skill_ref of exactly 256 chars is accepted (boundary) ---

#[test]
fn propose_grant_typed_accepts_skill_ref_at_256_char_boundary() {
    let store = make_store();
    let pid = make_persona(&store);

    let boundary_skill_ref = "a".repeat(256);

    let proposal = GrantProposal {
        persona_id: pid.clone(),
        statements: vec![minimal_statement("api-key")],
        expires_at: None,
        label: None,
        skill_ref: Some(boundary_skill_ref.clone()),
        note: None,
    };

    let info = store
        .propose_grant_typed(&proposal, "credential.access", "low")
        .expect("256-char skill_ref must be accepted");

    assert_eq!(
        info.skill_ref.as_deref(),
        Some(boundary_skill_ref.as_str()),
        "256-char skill_ref must round-trip"
    );
}
