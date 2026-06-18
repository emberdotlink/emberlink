use std::rc::Rc;
use std::thread;
use std::time::Duration as StdDuration;

use super::*;
use crate::infra::claim_journal::{
    AuditEvidenceInput, ClaimJournal, ClaimScopeKind, ScopeRef, SqliteClaimJournal,
    SuccessfulClaimInput,
};
use crate::infra::receipt::{current_identity, init_identity};
use crate::infra::store::DaemonStore;
use crate::infra::vault::Vault;
use core_broker::{
    MockRailAdapter, MockRailFailureMode, RailAdapter, RailOutcomeReport, RailSettlementState,
    RailSpendAttempt,
};
use core_events::receipt::{
    ClaudeCodeBody, PaymentEvaluatedBody, PaymentEvaluatedState, PaymentSettledBody,
    PaymentSettledState, RECEIPT_KIND_COMPOSITE_GRANT, RECEIPT_KIND_PAYMENT_EVALUATED,
    RECEIPT_KIND_PAYMENT_SETTLED, TerminationReason,
};
use core_grant_types::grant_chain::{Condition, ResourceSelector, ResourceType};
use once_cell::sync::OnceCell as SyncOnceCell;

fn setup() -> DaemonStore {
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    store.set_vault(Rc::new(Vault::new([0xAB; 32])));
    store
}

fn ensure_test_identity() {
    static INIT_DIR: SyncOnceCell<tempfile::TempDir> = SyncOnceCell::new();
    let dir = INIT_DIR.get_or_init(|| tempfile::tempdir().expect("tempdir"));
    let _ = init_identity(dir.path());
    current_identity().expect("identity must be initialised for receipt tests");
}

fn seed_grant_claim_journal(
    store: &DaemonStore,
    grant_id: &str,
    persona_id: &str,
    credential_name: &str,
    source_key: &str,
) {
    let journal = SqliteClaimJournal::new(store, 64);
    journal
        .record_successful_claim(
            &ScopeRef {
                kind: ClaimScopeKind::Grant,
                id: grant_id.to_string(),
            },
            &SuccessfulClaimInput {
                source_key: source_key.to_string(),
                occurred_at: "2026-05-22T12:00:00Z".to_string(),
                claim_kind: core_events::receipt::ClaimKind::CredentialVended,
                tool: "gh.pr_create".to_string(),
                action_ref: None,
                runner_class: None,
                execution_domain: None,
                materialization_class: None,
                input_hash: format!("hash-{source_key}"),
                input_redacted: serde_json::json!({
                    "kind": "broker_resolve",
                    "grant_id": grant_id,
                }),
                resolved: serde_json::json!({"allowed": true}),
                audit: AuditEvidenceInput {
                    agent_id: Some(persona_id.to_string()),
                    action: "broker.resolve.materialized".to_string(),
                    credential: Some(credential_name.to_string()),
                    outcome: "allowed".to_string(),
                    details: Some("{\"kind\":\"broker_resolve_materialized\"}".to_string()),
                },
                persona_id: Some(persona_id.to_string()),
                grant_id: Some(grant_id.to_string()),
                device_id: None,
                delegation_id: None,
                materialization_id: Some(format!("mat-{source_key}")),
                credential_name: Some(credential_name.to_string()),
            },
        )
        .unwrap();
}

fn assert_composite_grant_v2_receipt(
    store: &DaemonStore,
    grant_id: &str,
    expected_reason: TerminationReason,
) {
    let rows = store
        .list_receipts_v2_envelopes(&[grant_id.to_string()])
        .expect("list v2 receipts");
    let matching: Vec<_> = rows
        .into_iter()
        .filter(|(_, kind, _, _)| kind == RECEIPT_KIND_COMPOSITE_GRANT)
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "expected exactly one session.composite_grant receipt for {grant_id}"
    );
    let (_, kind, stored_grant_id, envelope) = matching
        .into_iter()
        .next()
        .expect("session.composite_grant receipt must exist");
    assert_eq!(kind, RECEIPT_KIND_COMPOSITE_GRANT);
    assert_eq!(stored_grant_id, grant_id);
    let body: ClaudeCodeBody =
        serde_json::from_value(envelope.body).expect("composite receipt body parses");
    assert_eq!(body.base.claim_count_total, Some(1));
    assert_eq!(body.base.claim_segment_summaries.len(), 1);
    assert_eq!(body.termination_reason, Some(expected_reason));
}

#[test]
fn create_grant_list_shows_active() {
    let store = setup();
    let persona = store.create_persona("agent-alpha").unwrap();
    let grant = store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();
    assert_eq!(grant.status, "active");
    assert!(grant.expires_at.is_none());

    let grants = store.list_grants().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].id, grant.id);
    assert_eq!(grants[0].status, "active");
}

#[test]
fn create_grant_with_ttl_expires_at_set() {
    let store = setup();
    let persona = store.create_persona("agent-beta").unwrap();
    let grant = store
        .create_grant(&persona.id, "api-key", "write", Some(3600))
        .unwrap();
    assert!(grant.expires_at.is_some());

    // Parse and verify it's in the future.
    let expires: DateTime<Utc> = DateTime::parse_from_rfc3339(grant.expires_at.as_ref().unwrap())
        .unwrap()
        .into();
    assert!(expires > Utc::now());
}

#[test]
fn create_grant_with_ttl_at_cap_succeeds() {
    // grant_ttl_capped_at_max — boundary case: exactly the cap value
    // is accepted (the check is strict `>`). Tracks adversarial-review
    // 2026-05-19 HIGH-7 closure.
    let store = setup();
    let persona = store.create_persona("agent-cap-edge").unwrap();
    store
        .create_grant_with_budget(
            &persona.id,
            "api-key",
            "read",
            Some(MAX_GRANT_TTL_SECS),
            None,
        )
        .expect("exact-cap TTL must be accepted");
}

#[test]
fn create_grant_with_ttl_past_cap_refused() {
    // grant_ttl_capped_at_max — adversarial-review 2026-05-19 HIGH-7
    // regression guard. A 1-year TTL must be refused even when policy
    // would otherwise allow it. The cap is enforced inside
    // `create_grant_with_budget_inner`, which sits below every public
    // create_grant entry point, so callers (including Internal admin
    // paths) cannot bypass.
    let store = setup();
    let persona = store.create_persona("agent-too-long").unwrap();
    let too_long = MAX_GRANT_TTL_SECS + 1;
    let err = store
        .create_grant_with_budget(&persona.id, "api-key", "read", Some(too_long), None)
        .expect_err("over-cap TTL must be refused");
    match err {
        StoreError::InvalidInput(msg) => {
            assert!(
                msg.contains("MAX_GRANT_TTL_SECS"),
                "error must name the cap: {msg}"
            );
            assert!(
                msg.contains(&too_long.to_string()),
                "error must echo the rejected value: {msg}"
            );
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[test]
fn evaluate_grant_returns_active_grant() {
    let store = setup();
    let persona = store.create_persona("agent-gamma").unwrap();
    store
        .create_grant(&persona.id, "secret", "read", None)
        .unwrap();

    let found = store.evaluate_grant(&persona.id, "secret").unwrap();
    assert_eq!(found.persona_id, persona.id);
    assert_eq!(found.credential_name, "secret");
    assert_eq!(found.status, "active");
}

#[test]
fn evaluate_grant_after_ttl_expires_returns_not_found() {
    let store = setup();
    let persona = store.create_persona("agent-delta").unwrap();

    // Insert a grant with expires_at in the past directly.
    let id = format!("grant-{}", Uuid::new_v4());
    let now = Utc::now();
    let past = now - Duration::seconds(10);
    store
            .conn()
            .execute(
                "INSERT INTO grants (id, persona_id, credential_name, scope, ttl_secs, created_at, expires_at, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active')",
                rusqlite::params![
                    id,
                    persona.id,
                    "expired-key",
                    "read",
                    1_i64,
                    now.to_rfc3339(),
                    past.to_rfc3339(),
                ],
            )
            .unwrap();

    let result = store.evaluate_grant(&persona.id, "expired-key");
    assert!(matches!(result, Err(StoreError::NotFound)));
}

#[test]
fn revoke_grant_evaluate_returns_not_found() {
    let store = setup();
    let persona = store.create_persona("agent-epsilon").unwrap();
    let grant = store
        .create_grant(&persona.id, "token", "full", None)
        .unwrap();

    store.revoke_grant(&grant.id).unwrap();

    let result = store.evaluate_grant(&persona.id, "token");
    assert!(matches!(result, Err(StoreError::NotFound)));
}

#[test]
fn abandon_grant_marks_terminal_and_drops_lease() {
    ensure_test_identity();
    let store = setup();
    let persona = store.create_persona("agent-abandon").unwrap();
    let grant = store
        .create_grant(&persona.id, "token", "read", Some(3600))
        .unwrap();
    let now = Utc::now();
    assert!(store.leases().has_live_lease(&grant.id, now));

    store
        .abandon_grant(&grant.id, "missing embed-canonical chain evidence")
        .unwrap();

    let abandoned = store.get_grant(&grant.id).unwrap();
    assert_eq!(abandoned.status, "abandoned");
    assert!(
        abandoned.receipt_id.is_some(),
        "abandoned grant must have a terminal receipt id"
    );
    assert!(
        !store.leases().has_live_lease(&grant.id, now),
        "abandoned grants must not retain authority-to-act leases"
    );
    let result = store.evaluate_grant(&persona.id, "token");
    assert!(matches!(result, Err(StoreError::NotFound)));
}

// ADR 211 §1 — leased-authority lifecycle through the grant store: a grant's
// authority-to-act is a lease minted at issuance and dropped on revoke.
#[test]
fn lease_minted_on_create_and_dropped_on_revoke() {
    let store = setup();
    let persona = store.create_persona("agent-lease").unwrap();
    let grant = store
        .create_grant(&persona.id, "token", "read", Some(3600))
        .unwrap();

    // Mint hook: issuance creates a live lease bound to the grant.
    let now = Utc::now();
    assert!(
        store.leases().has_live_lease(&grant.id, now),
        "create_grant must mint a lease for the grant"
    );

    // Drop hook: revocation ends authority-to-act.
    store.revoke_grant(&grant.id).unwrap();
    assert!(
        !store.leases().has_live_lease(&grant.id, now),
        "revoke_grant must drop the grant's lease"
    );
}

#[test]
fn grant_persona_secret_is_persisted_at_mint_and_deleted_on_revoke() {
    let store = setup();
    let persona = store.create_persona("agent-lease-secret").unwrap();
    let grant = store
        .create_grant(&persona.id, "token", "read", Some(3600))
        .unwrap();

    assert!(
        store
            .read_grant_persona_secret_for_test(&grant.id)
            .is_some(),
        "create_grant must persist the persona root re-sealed under the grant lease"
    );

    store.revoke_grant(&grant.id).unwrap();
    assert!(
        store
            .read_grant_persona_secret_for_test(&grant.id)
            .is_none(),
        "revoke must delete the grant-scoped persona root blob with the lease"
    );
}

#[test]
fn resigning_refuses_when_grant_persona_secret_missing_even_with_live_lease() {
    let store = setup();
    let persona = store.create_persona("agent-lease-secret-missing").unwrap();
    let grant = store
        .create_grant(&persona.id, "token", "read", Some(3600))
        .unwrap();
    assert!(store.leases().has_live_lease(&grant.id, Utc::now()));
    store.delete_grant_persona_secret(&grant.id).unwrap();

    let err = store
        .extend_grant(&grant.id, None, None, Some(60))
        .expect_err("re-signing must refuse without the lease-wrapped persona root");
    match err {
        StoreError::InvalidInput(reason) => assert!(
            reason.contains("no lease-wrapped persona root"),
            "expected missing grant persona blob error, got: {reason}"
        ),
        other => panic!("expected InvalidInput missing grant persona blob, got {other:?}"),
    }
}

#[test]
fn create_grant_zero_ttl_refuses_persona_root_persistence_without_live_lease() {
    let store = setup();
    let persona = store.create_persona("agent-zero-ttl-inert").unwrap();

    let err = store
        .create_grant(&persona.id, "token", "read", Some(0))
        .expect_err("zero-ttl grant must be inert before persona-root persistence");
    match err {
        StoreError::InvalidInput(reason) => assert!(
            reason.contains("live leased authority")
                && reason.contains("grant-scoped persona root")
                && reason.contains(&persona.id),
            "expected grant-scoped persona-root live-lease rejection, got: {reason}"
        ),
        other => panic!("expected InvalidInput live-lease reject, got {other:?}"),
    }

    let grants = store.list_grants().unwrap();
    assert!(
        grants.is_empty(),
        "failed zero-ttl creation must not insert a grant row"
    );
    assert!(
        store.leases().is_empty(),
        "failed zero-ttl creation must not retain a lease"
    );
}

/// ADR 211 PR-A — the lease-wrapped persona-root blob is bound to its grant by
/// (a) the per-grant lease key it is sealed under and (b) the grant_id+persona_id
/// AAD (re-checked inside the authenticated plaintext). A swapped, tampered, or
/// truncated blob must fail closed at re-sign time and never yield a persona key.
#[test]
fn grant_persona_secret_rejects_splice_tamper_and_truncation() {
    let store = setup();
    let persona = store.create_persona("agent-splice").unwrap();
    let grant_a = store
        .create_grant(&persona.id, "token", "read", Some(3600))
        .unwrap();
    let grant_b = store
        .create_grant(&persona.id, "token", "read", Some(3600))
        .unwrap();

    let blob_a = store
        .read_grant_persona_secret_for_test(&grant_a.id)
        .expect("grant A has a lease-wrapped persona root");

    let expect_resign_refused =
        |grant_id: &str, case: &str| match store.extend_grant(grant_id, None, None, Some(60)) {
            Err(StoreError::InvalidInput(_)) => {}
            other => panic!("{case}: expected InvalidInput re-sign refusal, got {other:?}"),
        };

    // (1) Cross-grant splice: grant A's blob written under grant B. B's distinct
    // lease key cannot decrypt it (and the AAD binds grant_id), so re-signing B
    // fails closed.
    store
        .write_grant_persona_secret(&grant_b.id, &blob_a)
        .unwrap();
    expect_resign_refused(&grant_b.id, "cross-grant splice");

    // (2) Tamper: flip a ciphertext byte in grant A's blob. The XChaCha20Poly1305
    // tag check fails, so re-signing A fails closed.
    let mut tampered = blob_a.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    store
        .write_grant_persona_secret(&grant_a.id, &tampered)
        .unwrap();
    expect_resign_refused(&grant_a.id, "tampered ciphertext");

    // (3) Truncation: a blob shorter than nonce(24)+tag(16) is rejected by the
    // length guard before any decrypt is attempted.
    store
        .write_grant_persona_secret(&grant_a.id, b"too-short")
        .unwrap();
    expect_resign_refused(&grant_a.id, "truncated blob");
}

// Per-statement revoke unit tests.

#[test]
fn revoke_grant_statement_appends_sid() {
    let store = setup();
    let persona = store.create_persona("agent-stmtrev").unwrap();
    let grant = store
        .create_grant(&persona.id, "token", "read", None)
        .unwrap();

    // Initially empty.
    let before = store.get_revoked_sids(&grant.id).unwrap();
    assert!(before.is_empty());

    store.revoke_grant_statement(&grant.id, "S0").unwrap();
    let after = store.get_revoked_sids(&grant.id).unwrap();
    assert_eq!(after, vec!["S0".to_string()]);
}

#[test]
fn revoke_grant_statement_is_idempotent() {
    let store = setup();
    let persona = store.create_persona("agent-stmtrev2").unwrap();
    let grant = store
        .create_grant(&persona.id, "token", "read", None)
        .unwrap();
    store.revoke_grant_statement(&grant.id, "S0").unwrap();
    store.revoke_grant_statement(&grant.id, "S0").unwrap();
    let sids = store.get_revoked_sids(&grant.id).unwrap();
    assert_eq!(sids, vec!["S0".to_string()]);
}

#[test]
fn revoke_grant_statement_independent_sids() {
    let store = setup();
    let persona = store.create_persona("agent-stmtrev3").unwrap();
    let grant = store
        .create_grant(&persona.id, "token", "read", None)
        .unwrap();
    store.revoke_grant_statement(&grant.id, "S0").unwrap();
    store.revoke_grant_statement(&grant.id, "S1").unwrap();
    let sids = store.get_revoked_sids(&grant.id).unwrap();
    assert!(sids.contains(&"S0".to_string()));
    assert!(sids.contains(&"S1".to_string()));
    assert_eq!(sids.len(), 2);
}

#[test]
fn revoke_grant_statement_unknown_grant_returns_not_found() {
    let store = setup();
    let result = store.revoke_grant_statement("grant-does-not-exist", "S0");
    assert!(matches!(result, Err(StoreError::NotFound)));
}

// Revocation parent-walk cascade test. Revoking a
// statement on an ancestor persona's grant must surface as a revoked
// sid when reading the descendant grant's revoked set, so the proxy's
// per-call check (`get_revoked_sids(&grant.id).contains(&resolved_sid)`)
// denies workers spawned under a revoked orchestrator without any
// change to the per-grant `revoked_sids_json` on the descendant row.
#[test]
fn revocation_cascades_through_parent_chain() {
    let store = setup();

    // Build three-generation chain: A (root) → B → C.
    let root = store.create_persona("root-orch").unwrap();
    let g_a = store.create_grant(&root.id, "cred-a", "*", None).unwrap();

    let child = store
        .create_agent_persona_enrolling("child-worker", "ctr-child", &g_a.id)
        .unwrap();
    store.activate_persona(&child.id).unwrap();
    let g_b = store.create_grant(&child.id, "cred-b", "*", None).unwrap();

    let grand = store
        .create_agent_persona_enrolling("grand-worker", "ctr-grand", &g_b.id)
        .unwrap();
    store.activate_persona(&grand.id).unwrap();
    let g1 = store.create_grant(&grand.id, "cred-1", "*", None).unwrap();

    // Pre-cascade: every grant's revoked set is empty.
    assert!(store.get_revoked_sids(&g1.id).unwrap().is_empty());

    // Revoke a statement on the ROOT's grant (the orchestrator).
    store.revoke_grant_statement(&g_a.id, "S0").unwrap();

    // The grandchild's grant must now report S0 as revoked even
    // though g1.revoked_sids_json is still empty.
    let cascaded = store.get_revoked_sids(&g1.id).unwrap();
    assert!(
        cascaded.contains(&"S0".to_string()),
        "ancestor revocation did not cascade: {cascaded:?}"
    );

    // Per-grant read (no ancestry walk) confirms the column itself
    // is untouched — cascade lives in the union, not on the row.
    let own = store.get_revoked_sids_for_grant(&g1.id).unwrap();
    assert!(
        own.is_empty(),
        "per-grant row should be untouched, got {own:?}"
    );
}

// Revocation parent-walk: middle-of-chain revocation
// also cascades to descendants but NOT to ancestors. Sibling grants
// owned by the same intermediate persona share the revocation
// (BTreeSet union over all grants owned by every ancestor).
#[test]
fn revocation_cascade_propagates_down_not_up() {
    let store = setup();

    let root = store.create_persona("root-orch-2").unwrap();
    let g_a = store.create_grant(&root.id, "cred-a", "*", None).unwrap();

    let child = store
        .create_agent_persona_enrolling("child-worker-2", "ctr-child-2", &g_a.id)
        .unwrap();
    store.activate_persona(&child.id).unwrap();
    let g_b = store.create_grant(&child.id, "cred-b", "*", None).unwrap();

    let grand = store
        .create_agent_persona_enrolling("grand-worker-2", "ctr-grand-2", &g_b.id)
        .unwrap();
    store.activate_persona(&grand.id).unwrap();
    let g1 = store.create_grant(&grand.id, "cred-1", "*", None).unwrap();

    // Revoke on the MIDDLE persona's grant.
    store.revoke_grant_statement(&g_b.id, "S7").unwrap();

    // Descendant sees the revocation.
    let descendant = store.get_revoked_sids(&g1.id).unwrap();
    assert!(descendant.contains(&"S7".to_string()));

    // Ancestor (root's grant) does NOT — revocations don't propagate
    // up the chain.
    let ancestor = store.get_revoked_sids(&g_a.id).unwrap();
    assert!(
        !ancestor.contains(&"S7".to_string()),
        "revocation leaked upward: {ancestor:?}"
    );
}

#[test]
fn create_grant_nonexistent_persona_returns_error() {
    let store = setup();
    let result = store.create_grant("persona-does-not-exist", "key", "read", None);
    assert!(matches!(result, Err(StoreError::NotFound)));
}

#[test]
fn create_grant_revoked_persona_returns_error() {
    let store = setup();
    let persona = store.create_persona("agent-zeta").unwrap();
    store.revoke_persona(&persona.id).unwrap();

    let result = store.create_grant(&persona.id, "key", "read", None);
    assert!(matches!(result, Err(StoreError::InvalidInput(_))));
}

#[test]
fn list_active_grants_excludes_expired_and_revoked() {
    let store = setup();
    let persona = store.create_persona("agent-eta").unwrap();

    // Active grant (no TTL).
    let active = store
        .create_grant(&persona.id, "active-key", "read", None)
        .unwrap();

    // Revoked grant.
    let revoked = store
        .create_grant(&persona.id, "revoked-key", "read", None)
        .unwrap();
    store.revoke_grant(&revoked.id).unwrap();

    // Expired grant: insert directly with past expires_at.
    let exp_id = format!("grant-{}", Uuid::new_v4());
    let now = Utc::now();
    let past = now - Duration::seconds(10);
    store
            .conn()
            .execute(
                "INSERT INTO grants (id, persona_id, credential_name, scope, ttl_secs, created_at, expires_at, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active')",
                rusqlite::params![
                    exp_id,
                    persona.id,
                    "expired-key2",
                    "read",
                    1_i64,
                    now.to_rfc3339(),
                    past.to_rfc3339(),
                ],
            )
            .unwrap();

    let active_grants = store.list_active_grants().unwrap();
    assert_eq!(active_grants.len(), 1);
    assert_eq!(active_grants[0].id, active.id);
}

// Keep the import used only in the sleep-based variant (unused without it).
#[allow(dead_code)]
fn _uses_thread_sleep() {
    thread::sleep(StdDuration::from_millis(0));
}

// --- Offline attenuation integration tests (ADR 072 § 69K.6) ---

/// Attach a budget + max_delegation_depth to a newly-created parent grant
/// by patching the row directly. create_grant doesn't accept these yet
/// (that's a separate task); the attenuation path does its own reads.
///
/// Post-composite-port: also patch the composite `blocks_json` so that
/// `get_grant` hydrates the parent with the attached budget. Without
/// this, `row_to_grant` prefers `blocks_json` (which has no budget from
/// `create_grant`) and attenuation sees `budget = None`.
fn attach_parent_constraints(
    store: &DaemonStore,
    grant_id: &str,
    budget: Option<Budget>,
    max_depth: u32,
) {
    let budget_json: Option<String> = budget
        .as_ref()
        .filter(|b| !b.is_none_set())
        .map(|b| serde_json::to_string(b).unwrap());

    // Patch the composite chain's first-statement budget to match.
    // Prefer the stored `blocks_json` so we preserve the signed block
    // written by `create_grant` (real Ed25519, not a placeholder).
    let existing = store.get_grant(grant_id).expect("grant exists");
    let mut new_chain = store
        .project_access_grant(&existing)
        .expect("projection succeeds in tests");
    let raw: Option<String> = store
        .conn()
        .query_row(
            "SELECT blocks_json FROM grants WHERE id = ?1",
            rusqlite::params![grant_id],
            |row| row.get(0),
        )
        .ok()
        .flatten();
    if let Some(s) = raw
        && let Ok(blocks) = serde_json::from_str::<Vec<SignedBlock>>(&s)
        && !blocks.is_empty()
    {
        new_chain.blocks = blocks;
    }
    if let Some(first_block) = new_chain.blocks.first_mut()
        && let Some(first_stmt) = first_block.block.statements.first_mut()
    {
        first_stmt.budget = budget.clone().filter(|b| !b.is_none_set());
    }
    // Re-sign block 0 after mutating its payload so the stored chain
    // stays verifiable. Tests that don't care about verification still
    // benefit from the invariant.
    //
    // H3 fix — go through the lease-aware persisting helper so the
    // newly-rotated `pubkey_next` is sealed and persisted to
    // `grant_chain_secrets`. Without this re-persist, the daemon's
    // delegation path would open a stale secret whose public-half no
    // longer matches `blocks[0].pubkey_next` and the resulting appended
    // block would fail chain verification at block 1. (This mirrors
    // what the production extend / increment-statement-usage paths now
    // do — see `sign_block_zero_with_live_lease_persisting_chain_secret`
    // call sites in grant.rs.)
    if let Some(first_block) = new_chain.blocks.first_mut() {
        let resigned = store
            .sign_block_zero_with_live_lease_persisting_chain_secret(
                grant_id,
                &existing.persona_id,
                &first_block.block,
                chrono::Utc::now(),
                "test attach_parent_constraints",
            )
            .expect("re-sign + persist chain secret");
        *first_block = resigned;
    }
    let blocks_json = access_grant_blocks_to_json(&new_chain).unwrap();

    store
            .conn()
            .execute(
                "UPDATE grants SET budget_json = ?1, max_delegation_depth = ?2, blocks_json = ?3 WHERE id = ?4",
                rusqlite::params![budget_json, max_depth as i64, blocks_json, grant_id],
            )
            .unwrap();
}

fn setup_parent_with_budget(store: &DaemonStore, tokens: u64, ttl_secs: u64) -> (String, String) {
    let parent_persona = store.create_persona("agent-parent").unwrap();
    let child_persona = store.create_persona("agent-child").unwrap();
    let parent_grant = store
        .create_grant(
            &parent_persona.id,
            "delegate-key",
            "github:push:acme/*",
            Some(ttl_secs),
        )
        .unwrap();
    attach_parent_constraints(
        store,
        &parent_grant.id,
        Some(Budget {
            tokens: Some(tokens),
            ..Default::default()
        }),
        3,
    );
    (parent_grant.id, child_persona.id)
}

#[test]
fn delegate_different_target_rejected() {
    let store = setup();
    let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

    let err = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            // `other/*` is outside `acme/*`.
            "github:push:other/widgets",
            Some(600),
            Some(Budget {
                tokens: Some(3_000),
                ..Default::default()
            }),
        )
        .unwrap_err();
    match err {
        StoreError::DelegationViolation { reason } => {
            // Post-H3 the rejection comes from `check_statement_attenuation`,
            // which names the failing axis as "selector/actions" rather
            // than the legacy "scope" string. Accept either wording so
            // the assertion stays meaningful across the migration.
            assert!(
                reason.contains("scope")
                    || reason.contains("selector")
                    || reason.contains("actions"),
                "reason: {reason}"
            );
        }
        other => panic!("expected DelegationViolation, got {other:?}"),
    }
}

#[test]
fn delegate_child_budget_exceeds_parent_rejected() {
    let store = setup();
    let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

    let err = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(600),
            Some(Budget {
                tokens: Some(15_000),
                ..Default::default()
            }),
        )
        .unwrap_err();
    match err {
        StoreError::DelegationViolation { reason } => {
            assert!(reason.contains("tokens"), "reason: {reason}");
        }
        other => panic!("expected DelegationViolation, got {other:?}"),
    }
}

#[test]
fn delegate_attenuated_child_approved() {
    let store = setup();
    let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

    let child = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(600),
            Some(Budget {
                tokens: Some(3_000),
                ..Default::default()
            }),
        )
        .expect("attenuated delegate approved");
    assert_eq!(child.scope, "github:push:acme/widgets");
    assert_eq!(child.parent_grant_id.as_deref(), Some(parent_id.as_str()));
    assert_eq!(child.budget.and_then(|b| b.tokens), Some(3_000));
}

#[test]
fn delegate_rejects_active_parent_without_live_lease() {
    let store = setup();
    let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

    assert!(
        store.leases().drop_lease(&parent_id),
        "test setup must start with a live parent lease"
    );
    assert!(
        !store.leases().has_live_lease(&parent_id, Utc::now()),
        "parent grant should remain active in SQL but inert for authority-to-act"
    );

    let err = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(600),
            Some(Budget {
                tokens: Some(3_000),
                ..Default::default()
            }),
        )
        .expect_err("delegation must fail without the parent lease");
    match err {
        StoreError::InvalidInput(reason) => {
            assert!(
                reason.contains("live leased authority") && reason.contains("grant-scoped lease"),
                "expected live-lease error, got: {reason}"
            );
        }
        other => panic!("expected InvalidInput live-lease reject, got {other:?}"),
    }

    let child_count: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM grants WHERE parent_grant_id = ?1",
            rusqlite::params![&parent_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        child_count, 0,
        "failed delegation must not insert a child grant"
    );
    assert!(
        store.leases().is_empty(),
        "failed delegation must not mint a child lease"
    );
    let witnesses = store
        .list_spawn_witnesses_for_grants(std::slice::from_ref(&parent_id))
        .expect("list_spawn_witnesses_for_grants succeeds");
    assert!(
        witnesses.is_empty(),
        "failed delegation must not emit a spawn witness"
    );
}

#[test]
fn delegate_zero_ttl_child_refuses_persona_root_persistence_without_live_lease() {
    let store = setup();
    let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

    let err = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(0),
            Some(Budget {
                tokens: Some(3_000),
                ..Default::default()
            }),
        )
        .expect_err("zero-ttl child lease must be inert before persona-root persistence");
    match err {
        StoreError::InvalidInput(reason) => assert!(
            reason.contains("live leased authority")
                && reason.contains("grant-scoped persona root")
                && reason.contains(&child_persona_id),
            "expected delegated grant-scoped persona-root live-lease rejection, got: {reason}"
        ),
        other => panic!("expected InvalidInput live-lease reject, got {other:?}"),
    }

    let child_count: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM grants WHERE parent_grant_id = ?1",
            rusqlite::params![&parent_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        child_count, 0,
        "failed child signing must not insert a child grant"
    );
    assert!(
        store.leases().has_live_lease(&parent_id, Utc::now()),
        "failed child signing must not drop the still-live parent lease"
    );
    let witnesses = store
        .list_spawn_witnesses_for_grants(std::slice::from_ref(&parent_id))
        .expect("list_spawn_witnesses_for_grants succeeds");
    assert!(
        witnesses.is_empty(),
        "failed child signing must not emit a spawn witness"
    );
}

#[test]
fn delegate_chained_grandchild_approved() {
    let store = setup();
    let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

    let child = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(600),
            Some(Budget {
                tokens: Some(3_000),
                ..Default::default()
            }),
        )
        .expect("first delegate approved");

    // Grandchild further narrows budget.
    let grandchild_persona = store.create_persona("agent-grandchild").unwrap();
    let grandchild = store
        .delegate_grant_full(
            &child.id,
            &grandchild_persona.id,
            "github:push:acme/widgets",
            Some(60),
            Some(Budget {
                tokens: Some(1_000),
                ..Default::default()
            }),
        )
        .expect("grandchild delegate approved");
    assert_eq!(
        grandchild.parent_grant_id.as_deref(),
        Some(child.id.as_str())
    );
    assert_eq!(grandchild.budget.and_then(|b| b.tokens), Some(1_000));
}

#[test]
fn delegate_parent_budget_child_no_budget_rejected() {
    let store = setup();
    let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

    // No child budget — parent has one, so this must fail.
    let err = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(600),
            None,
        )
        .unwrap_err();
    match err {
        StoreError::DelegationViolation { reason } => {
            assert!(reason.contains("budget"), "reason: {reason}");
        }
        other => panic!("expected DelegationViolation, got {other:?}"),
    }
}

// --- wall-clock budget sweep (P69K-A2) ---

/// Seed a grant whose created_at is in the past and whose composite
/// chain carries a single Statement with `wall_clock_secs: budget`.
fn seed_wall_clock_grant(
    store: &DaemonStore,
    persona_id: &str,
    credential_name: &str,
    wall_clock_secs: u64,
    age_secs: i64,
) -> String {
    let id = format!("grant-{}", Uuid::new_v4());
    let now = Utc::now();
    let created = now - Duration::seconds(age_secs);

    let stmt = Statement {
        sid: "S0".into(),
        resource_type: ResourceType::Session,
        actions: vec!["llm:generate".into()],
        resource: ResourceSelector::Any,
        budget: Some(Budget {
            wall_clock_secs: Some(wall_clock_secs),
            ..Default::default()
        }),
        usage: Usage::default(),
        conditions: Vec::new(),
        can_delegate: None,
    };
    let created_epoch = created.timestamp().max(0) as u64;
    let root = store
        .persona_root_keypair(persona_id)
        .expect("persona root key present");
    let block = Block {
        statements: vec![stmt],
        nbf: None,
        expires_at: None,
        issued_by: persona_id.to_string(),
        issued_at: created_epoch,
        approval: None,
        note: None,
    };
    let signed = sign_block_zero_with(&root, &block).expect("sign block 0");
    let grant = access_grant_envelope(
        &id,
        persona_id,
        credential_name,
        "active",
        signed,
        created_epoch,
    );
    let blocks_json = access_grant_blocks_to_json(&grant).unwrap();

    store
            .conn()
            .execute(
                "INSERT INTO grants (id, persona_id, credential_name, scope, created_at, status, blocks_json)
                 VALUES (?1, ?2, ?3, 'llm:generate', ?4, 'active', ?5)",
                rusqlite::params![id, persona_id, credential_name, created.to_rfc3339(), blocks_json],
            )
            .unwrap();
    id
}

#[test]
fn wall_clock_sweep_exhausts_grant_past_limit() {
    ensure_test_identity();
    let store = setup();
    let persona = store.create_persona("agent-wc").unwrap();
    // 10s limit, 11s elapsed — must exhaust.
    let gid = seed_wall_clock_grant(&store, &persona.id, "llm-key", 10, 11);
    seed_grant_claim_journal(&store, &gid, &persona.id, "llm-key", "wall-clock-1");

    let (exhausted, _warned) = store.expire_grants_by_wall_clock().unwrap();
    assert!(exhausted >= 1, "expected exhaustion, got {exhausted}");

    let grant = store.get_grant(&gid).unwrap();
    assert_eq!(grant.status, "exhausted_by_budget");
    assert_composite_grant_v2_receipt(&store, &gid, TerminationReason::ExhaustedByBudget);
}

#[test]
fn expire_grant_if_terminal_now_emits_composite_receipt_for_ttl() {
    ensure_test_identity();
    let store = setup();
    let persona = store.create_persona("agent-sync-ttl").unwrap();
    let grant = store
        .create_grant(&persona.id, "github-token", "repo:read", Some(1))
        .unwrap();
    seed_grant_claim_journal(&store, &grant.id, &persona.id, "github-token", "sync-ttl-1");
    store
        .conn()
        .execute(
            "UPDATE grants SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?1",
            rusqlite::params![grant.id],
        )
        .unwrap();

    assert!(store.expire_grant_if_terminal_now(&grant.id).unwrap());
    assert_eq!(store.get_grant(&grant.id).unwrap().status, "expired");
    assert_composite_grant_v2_receipt(&store, &grant.id, TerminationReason::TtlExpired);
    assert!(!store.expire_grant_if_terminal_now(&grant.id).unwrap());
}

#[test]
fn expire_grant_if_terminal_now_emits_composite_receipt_for_budget() {
    ensure_test_identity();
    let store = setup();
    let persona = store.create_persona("agent-sync-budget").unwrap();
    let gid = seed_wall_clock_grant(&store, &persona.id, "llm-key", 10, 11);
    seed_grant_claim_journal(&store, &gid, &persona.id, "llm-key", "sync-budget-1");

    assert!(store.expire_grant_if_terminal_now(&gid).unwrap());
    assert_eq!(store.get_grant(&gid).unwrap().status, "exhausted_by_budget");
    assert_composite_grant_v2_receipt(&store, &gid, TerminationReason::ExhaustedByBudget);
    assert!(!store.expire_grant_if_terminal_now(&gid).unwrap());
}

#[test]
fn wall_clock_sweep_warns_at_80pct() {
    let store = setup();
    let persona = store.create_persona("agent-wc-warn").unwrap();
    // 10s limit, 8s elapsed — 80% crossed, must warn, NOT exhaust.
    let _gid = seed_wall_clock_grant(&store, &persona.id, "llm-key", 10, 8);

    let (exhausted, warned) = store.expire_grants_by_wall_clock().unwrap();
    assert_eq!(exhausted, 0, "should not exhaust at 80%");
    assert!(warned >= 1, "expected warn, got {warned}");

    let entries = store
        .query_audit(&crate::infra::audit::AuditFilter::default())
        .unwrap();
    assert!(entries.iter().any(|e| e.action == "budget.warning"));
}

#[test]
fn wall_clock_sweep_skips_grants_under_threshold() {
    let store = setup();
    let persona = store.create_persona("agent-wc-skip").unwrap();
    // 100s limit, 10s elapsed — no warn, no exhaust.
    let _gid = seed_wall_clock_grant(&store, &persona.id, "llm-key", 100, 10);

    let (exhausted, warned) = store.expire_grants_by_wall_clock().unwrap();
    assert_eq!(exhausted, 0);
    assert_eq!(warned, 0);
}

#[test]
fn delegate_child_expiry_later_rejected() {
    let store = setup();
    let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 600);

    // Parent TTL is 600s; child asks for 3600s.
    let err = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(3600),
            Some(Budget {
                tokens: Some(1_000),
                ..Default::default()
            }),
        )
        .unwrap_err();
    match err {
        StoreError::DelegationViolation { reason } => {
            assert!(reason.contains("expiry"), "reason: {reason}");
        }
        other => panic!("expected DelegationViolation, got {other:?}"),
    }
}

#[test]
fn delegate_grant_with_ttl_at_cap_succeeds_under_unbounded_parent() {
    let store = setup();
    let parent_persona = store.create_persona("agent-ttl-parent").unwrap();
    let child_persona = store.create_persona("agent-ttl-child").unwrap();
    let parent = store
        .create_grant(
            &parent_persona.id,
            "delegate-key",
            "github:push:acme/*",
            None,
        )
        .unwrap();
    attach_parent_constraints(&store, &parent.id, None, 3);

    let child = store
        .delegate_grant_full(
            &parent.id,
            &child_persona.id,
            "github:push:acme/widgets",
            Some(MAX_GRANT_TTL_SECS),
            None,
        )
        .expect("exact-cap delegated TTL must be accepted");

    assert_eq!(child.parent_grant_id.as_deref(), Some(parent.id.as_str()));
    assert!(child.expires_at.is_some());
}

#[test]
fn delegate_grant_with_ttl_past_cap_refused_under_unbounded_parent() {
    let store = setup();
    let parent_persona = store.create_persona("agent-ttl-too-long-parent").unwrap();
    let child_persona = store.create_persona("agent-ttl-too-long-child").unwrap();
    let parent = store
        .create_grant(
            &parent_persona.id,
            "delegate-key",
            "github:push:acme/*",
            None,
        )
        .unwrap();
    attach_parent_constraints(&store, &parent.id, None, 3);

    let too_long = MAX_GRANT_TTL_SECS + 1;
    let err = store
        .delegate_grant_full(
            &parent.id,
            &child_persona.id,
            "github:push:acme/widgets",
            Some(too_long),
            None,
        )
        .expect_err("over-cap delegated TTL must be refused");
    match err {
        StoreError::InvalidInput(msg) => {
            assert!(
                msg.contains("MAX_GRANT_TTL_SECS"),
                "error must name the cap: {msg}"
            );
            assert!(
                msg.contains(&too_long.to_string()),
                "error must echo the rejected value: {msg}"
            );
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

// --- W1: Ed25519 signing integration tests (ADR 074 rev) ---

/// Verify a daemon-created grant's block chain against the issuing
/// persona's declared root public key. This is the acceptance invariant
/// for removing the `"unsigned-phase1"` placeholder: block 0 must
/// carry a real Ed25519 signature that `verify_chain` accepts under
/// the persona's stored root key.
#[test]
fn create_grant_produces_verifiable_block_zero() {
    let store = setup();
    let persona = store.create_persona("agent-sign-create").unwrap();
    let grant = store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();

    let chain = store.get_access_grant(&grant.id).unwrap();
    assert_eq!(chain.blocks.len(), 1);

    let root = store.persona_root_keypair(&persona.id).unwrap();
    let root_pubkey_bytes = hex::decode(root.public_hex()).unwrap();
    grant_chain::verify_chain(&chain.blocks, &root_pubkey_bytes)
        .expect("block 0 signature verifies under persona root key");

    // Smoke-check: no residual placeholder strings.
    assert_ne!(
        chain.blocks[0].signature,
        core_crypto::grant_chain::UNSIGNED_PHASE1_PLACEHOLDER
    );
    assert_ne!(
        chain.blocks[0].pubkey_next,
        core_crypto::grant_chain::UNSIGNED_PHASE1_PLACEHOLDER
    );
}

/// `access_grant_from_statements` produces a real signature under the
/// caller-supplied root keypair. Mirrors the `ember sandbox run` path
/// that composes a multi-Statement envelope.
#[test]
fn access_grant_from_statements_produces_verifiable_chain() {
    let store = setup();
    let persona = store.create_persona("agent-sign-compose").unwrap();
    let stmts = vec![
        Statement {
            sid: "S0".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["credential:read".into()],
            resource: ResourceSelector::Exact {
                value: "api-key".into(),
            },
            budget: None,
            usage: Usage::default(),
            conditions: Vec::new(),
            can_delegate: None,
        },
        Statement {
            sid: "S1".into(),
            resource_type: ResourceType::Session,
            actions: vec!["llm:generate".into()],
            resource: ResourceSelector::Glob {
                pattern: "anthropic/*".into(),
            },
            budget: Some(Budget {
                tokens: Some(5_000),
                ..Default::default()
            }),
            usage: Usage::default(),
            conditions: Vec::new(),
            can_delegate: None,
        },
    ];
    let root = store.persona_root_keypair(&persona.id).unwrap();
    let grant = access_grant_from_statements(
        "grant-fixture-compose",
        &persona.id,
        "api-key",
        stmts,
        42,
        None,
        &root,
    )
    .unwrap();
    let root_pubkey_bytes = hex::decode(root.public_hex()).unwrap();
    grant_chain::verify_chain(&grant.blocks, &root_pubkey_bytes).unwrap();

    assert_ne!(
        grant.blocks[0].signature,
        core_crypto::grant_chain::UNSIGNED_PHASE1_PLACEHOLDER
    );
}

/// `access_grant_from_statements_for_persona` returns the same `AccessGrant`
/// as the explicit-root form when both use the same persona.
#[test]
fn access_grant_from_statements_for_persona_matches_explicit_root() {
    let store = setup();
    let persona = store.create_persona("agent-for-persona-lookup").unwrap();
    let stmts = || {
        vec![Statement {
            sid: "S0".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["credential:read".into()],
            resource: ResourceSelector::Exact {
                value: "api-key".into(),
            },
            budget: None,
            usage: Usage::default(),
            conditions: Vec::new(),
            can_delegate: None,
        }]
    };
    let created_at = 100u64;

    let root = store.persona_root_keypair(&persona.id).unwrap();
    let explicit = access_grant_from_statements(
        "grant-explicit",
        &persona.id,
        "svc",
        stmts(),
        created_at,
        None,
        &root,
    )
    .unwrap();

    let via_persona = access_grant_from_statements_for_persona(
        &store,
        "grant-via-persona",
        &persona.id,
        "svc",
        stmts(),
        created_at,
        None,
    )
    .unwrap();

    // Both grants carry the same persona, recipient, and block structure.
    assert_eq!(explicit.issuing_persona_id, via_persona.issuing_persona_id);
    assert_eq!(explicit.recipient_id, via_persona.recipient_id);
    assert_eq!(explicit.blocks.len(), via_persona.blocks.len());
    assert_eq!(
        explicit.blocks[0].block.statements,
        via_persona.blocks[0].block.statements
    );

    // Both signatures verify under the same root public key.
    let root_pubkey_bytes = hex::decode(root.public_hex()).unwrap();
    grant_chain::verify_chain(&explicit.blocks, &root_pubkey_bytes).unwrap();
    grant_chain::verify_chain(&via_persona.blocks, &root_pubkey_bytes).unwrap();

    // Signatures are real (not the placeholder).
    assert_ne!(
        via_persona.blocks[0].signature,
        core_crypto::grant_chain::UNSIGNED_PHASE1_PLACEHOLDER
    );
}

// --- W4: M-2 read-path verify_chain tests ---

/// Seed a persona row with a caller-supplied public_key (ed25519: prefix)
/// and return the persona id. Used by verify_chain tests that need a
/// persona with a known key so we can construct matching signed chains.
///
/// V0 schema: the secret is sealed under the store's attached vault and
/// written into the `private_key_nonce` + `private_key_ciphertext`
/// columns. `open_in_memory()` attaches a deterministic test vault so
/// this helper works for every test setup.
fn seed_persona_with_key(store: &DaemonStore, public_key: &str, private_key: &str) -> String {
    let id = format!("persona-{}", Uuid::new_v4());
    let now = Utc::now().to_rfc3339();
    let vault = store
        .vault()
        .expect("test store must have a vault attached");
    // ADR 198 Part B — seal under the MEK→DEK envelope with the same
    // persona-bound AAD id the production path uses
    // (`b"persona-secret:" || persona_id`), so `persona_root_keypair` /
    // `persona_signer` can open it back.
    let mut aad_id = b"persona-secret:".to_vec();
    aad_id.extend_from_slice(id.as_bytes());
    let env = vault
        .seal(
            crate::infra::vault::ValueClass::AuthorityBearing,
            &aad_id,
            private_key.as_bytes(),
        )
        .expect("seal secret under test vault");
    store
        .conn()
        .execute(
            "INSERT INTO personas (id, name, public_key, private_key_nonce, \
                                       private_key_ciphertext, private_key_dek_nonce, \
                                       private_key_wrapped_dek, created_at, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active')",
            rusqlite::params![
                id,
                id,
                public_key,
                env.payload_nonce,
                env.ciphertext,
                env.dek_nonce,
                env.wrapped_dek,
                now
            ],
        )
        .unwrap();
    id
}

/// Seed a grant row with caller-supplied blocks_json for a given persona.
fn seed_grant_with_blocks(store: &DaemonStore, persona_id: &str, blocks_json: &str) -> String {
    let id = format!("grant-{}", Uuid::new_v4());
    let now = Utc::now().to_rfc3339();
    store
            .conn()
            .execute(
                "INSERT INTO grants (id, persona_id, credential_name, scope, created_at, status, blocks_json)
                 VALUES (?1, ?2, 'test-cred', 'read', ?3, 'active', ?4)",
                rusqlite::params![id, persona_id, now, blocks_json],
            )
            .unwrap();
    id
}

#[test]
fn get_access_grant_valid_ed25519_chain_returns_ok() {
    use core_crypto::grant_chain::{RootKeyPair, sign_block_zero};
    use core_grant_types::{Block, ResourceSelector, ResourceType, Statement, Usage};

    let store = setup();

    // Generate a root keypair and seed a persona with its public key.
    let kp = core_crypto::generate_local_key_pair("persona", "test");
    let persona_id = seed_persona_with_key(&store, &kp.public_key, &kp.private_key);

    // Build and sign a single-block chain.
    let root_kp = RootKeyPair::from_hex(
        kp.public_key.trim_start_matches("ed25519:"),
        kp.private_key.trim_start_matches("ed25519-secret:"),
    )
    .unwrap();
    let block = Block {
        statements: vec![Statement {
            sid: "S0".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["read".into()],
            resource: ResourceSelector::Any,
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        }],
        nbf: None,
        expires_at: None,
        issued_by: persona_id.clone(),
        issued_at: 1_000_000,
        approval: None,
        note: None,
    };
    let out = sign_block_zero(&root_kp, &block).unwrap();
    let blocks_json = serde_json::to_string(&[out.signed]).unwrap();
    let grant_id = seed_grant_with_blocks(&store, &persona_id, &blocks_json);

    // Should succeed — valid chain.
    let grant = store
        .get_access_grant(&grant_id)
        .expect("valid chain must succeed");
    assert_eq!(grant.id, grant_id);
    assert_eq!(grant.issuing_persona_id, persona_id);
}

#[test]
fn get_access_grant_create_then_read_round_trip() {
    // create_grant now signs block 0 under the issuing persona's root
    // key (W1). get_access_grant verifies on the way out (W4). This
    // test covers the happy-path round-trip after both land.
    let store = setup();
    let persona = store.create_persona("agent-verify-roundtrip").unwrap();
    let grant_info = store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();
    let grant = store
        .get_access_grant(&grant_info.id)
        .expect("create_grant → get_access_grant must succeed after W1+W4");
    assert_eq!(grant.id, grant_info.id);
}

#[test]
fn get_access_grant_tampered_signature_returns_err() {
    use core_crypto::grant_chain::{RootKeyPair, sign_block_zero};
    use core_grant_types::{Block, ResourceSelector, ResourceType, Statement, Usage};

    let store = setup();

    let kp = core_crypto::generate_local_key_pair("persona", "test-tamper");
    let persona_id = seed_persona_with_key(&store, &kp.public_key, &kp.private_key);

    let root_kp = RootKeyPair::from_hex(
        kp.public_key.trim_start_matches("ed25519:"),
        kp.private_key.trim_start_matches("ed25519-secret:"),
    )
    .unwrap();
    let block = Block {
        statements: vec![Statement {
            sid: "S0".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["read".into()],
            resource: ResourceSelector::Any,
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        }],
        nbf: None,
        expires_at: None,
        issued_by: persona_id.clone(),
        issued_at: 2_000_000,
        approval: None,
        note: None,
    };
    let mut out = sign_block_zero(&root_kp, &block).unwrap();

    // Tamper: flip the last two hex chars of the signature.
    let sig = out.signed.signature.clone();
    let tampered = format!(
        "{}{}",
        &sig[..sig.len() - 2],
        if sig.ends_with("00") { "ff" } else { "00" }
    );
    out.signed.signature = tampered;

    let blocks_json = serde_json::to_string(&[out.signed]).unwrap();
    let grant_id = seed_grant_with_blocks(&store, &persona_id, &blocks_json);

    let err = store.get_access_grant(&grant_id).unwrap_err();
    assert!(
        matches!(err, StoreError::InvalidInput(ref s) if s.contains("chain verification failed")),
        "expected chain verification error, got: {err:?}"
    );
}

// --- P69K-F07 regression tests: verify_and_return None-persona tightening ---

/// Build a placeholder `SignedBlock` with `issued_by = persona_id`.
fn placeholder_block_for(persona_id: &str, sid: &str) -> SignedBlock {
    use core_grant_types::{Block, ResourceSelector, ResourceType, Statement, Usage};
    SignedBlock {
        block: Block {
            statements: vec![Statement {
                sid: sid.into(),
                resource_type: ResourceType::Credential,
                actions: vec!["read".into()],
                resource: ResourceSelector::Any,
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
                can_delegate: None,
            }],
            nbf: None,
            expires_at: None,
            issued_by: persona_id.into(),
            issued_at: 0,
            approval: None,
            note: None,
        },
        pubkey_next: grant_chain::UNSIGNED_PHASE1_PLACEHOLDER.into(),
        signature: grant_chain::UNSIGNED_PHASE1_PLACEHOLDER.into(),
    }
}

/// Seed a grant row whose persona_id has no matching personas row.
/// Disables FK enforcement for the insert, then re-enables it.
fn seed_orphan_grant(store: &DaemonStore, persona_id: &str, blocks_json: &str) -> String {
    store
        .conn()
        .execute_batch("PRAGMA foreign_keys = OFF")
        .unwrap();
    let grant_id = seed_grant_with_blocks(store, persona_id, blocks_json);
    store
        .conn()
        .execute_batch("PRAGMA foreign_keys = ON")
        .unwrap();
    grant_id
}

/// An orphaned grant whose single block carries the unsigned-phase1
/// placeholder is the only valid pass-through. verify_and_return must
/// return it as-is (no persona row, but the placeholder signals the grant
/// was minted before the signing path landed).
#[test]
fn verify_and_return_allows_single_block_phase1_placeholder_orphan() {
    let store = setup();
    let persona_id = format!("orphan-ph1-{}", Uuid::new_v4());
    let blocks_json = serde_json::to_string(&[placeholder_block_for(&persona_id, "S0")]).unwrap();
    let grant_id = seed_orphan_grant(&store, &persona_id, &blocks_json);

    // Must succeed — single block + phase-1 placeholder passes through.
    let grant = store
        .get_access_grant(&grant_id)
        .expect("single-block phase-1 placeholder orphan must pass verify_and_return");
    assert_eq!(grant.id, grant_id);
}

/// An orphaned grant with two blocks must be rejected by verify_and_return
/// — multi-block orphans had a real persona at mint time and the missing
/// row is suspicious (deleted persona or tampered grant).
#[test]
fn verify_and_return_rejects_multi_block_orphan_grant() {
    let store = setup();
    let persona_id = format!("orphan-multi-{}", Uuid::new_v4());
    let blocks_json = serde_json::to_string(&[
        placeholder_block_for(&persona_id, "S0"),
        placeholder_block_for(&persona_id, "S1"),
    ])
    .unwrap();
    let grant_id = seed_orphan_grant(&store, &persona_id, &blocks_json);

    let err = store
        .get_access_grant(&grant_id)
        .expect_err("multi-block orphan must be rejected by verify_and_return");
    assert!(
        matches!(err, StoreError::InvalidInput(ref s) if s.contains("chain verification failed")),
        "expected chain verification error for multi-block orphan, got: {err:?}"
    );
}

/// H3 post-fix shape: the delegated grant's chain is `parent.blocks
/// ++ [appended]`, signed end-to-end under the CHAIN-ROOT (parent's
/// apex) persona's root key — NOT the child persona's root. Pre-fix
/// the test expected the child chain to verify under the child's own
/// root because delegation minted a fresh single-block chain; that
/// shape is gone (it left attenuation cryptographically un-enforced
/// — the H3 security finding).
#[test]
fn delegate_grant_produces_verifiable_appended_chain_under_chain_root() {
    let store = setup();
    let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

    let parent_chain_before = store.get_access_grant(&parent_id).unwrap();
    let chain_root_persona_id = parent_chain_before.blocks[0].block.issued_by.clone();

    let child = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(600),
            Some(Budget {
                tokens: Some(3_000),
                ..Default::default()
            }),
        )
        .unwrap();
    let chain = store.get_access_grant(&child.id).unwrap();
    assert_eq!(
        chain.blocks.len(),
        parent_chain_before.blocks.len() + 1,
        "delegated grant is parent.blocks ++ [appended]"
    );
    assert_eq!(
        chain.blocks.last().unwrap().block.issued_by,
        child_persona_id,
        "appended tail block issued by the new authority holder"
    );
    let chain_root = store.persona_root_keypair(&chain_root_persona_id).unwrap();
    let chain_root_bytes = hex::decode(chain_root.public_hex()).unwrap();
    grant_chain::verify_chain(&chain.blocks, &chain_root_bytes)
        .expect("delegated chain verifies end-to-end under the chain-root persona key");
}

/// **H3 regression** — production `delegate_grant_full_sql` now mints
/// a real append-chain: the child's appended block is signed by the
/// parent's persisted tail `pubkey_next_secret` (sealed under the
/// parent's lease, persisted in `grant_chain_secrets`), and the full
/// child chain `parent.blocks ++ [child_appended]` verifies under the
/// CHAIN-ROOT persona key.
///
/// Pre-fix delegation minted a fresh single-block chain signed by the
/// child persona's own root and linked to the parent only by the
/// mutable `parent_grant_id` SQL column — `sign_appended_block` had
/// zero production callers, so the C1 fix's "tail-key bound into
/// signature" property protected nothing in the real delegation path.
#[test]
fn delegation_mints_appended_block_verifiable_end_to_end() {
    let store = setup();
    let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1_800);

    // Snapshot the parent's chain pre-delegation. For an apex parent
    // this is a single-block chain; the child's chain must extend it
    // by exactly one block.
    let parent_chain_before = store.get_access_grant(&parent_id).unwrap();
    assert_eq!(
        parent_chain_before.blocks.len(),
        1,
        "apex parent should have a single-block chain"
    );
    let parent_tail_pubkey_next_pre = parent_chain_before
        .blocks
        .last()
        .unwrap()
        .pubkey_next
        .clone();
    let chain_root_persona_id = parent_chain_before.blocks[0].block.issued_by.clone();

    // Mint the delegation.
    let child = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(600),
            Some(Budget {
                tokens: Some(3_000),
                ..Default::default()
            }),
        )
        .expect("delegation succeeds within parent bounds");

    let child_chain = store.get_access_grant(&child.id).unwrap();

    // Structural shape: [P0, C1] (parent's apex block + child's
    // appended block).
    assert_eq!(
        child_chain.blocks.len(),
        2,
        "delegated chain = parent.blocks ++ [appended]"
    );
    assert_eq!(
        child_chain.blocks[0].block.issued_by, chain_root_persona_id,
        "block 0 carries the chain-root persona's apex authority"
    );
    assert_eq!(
        child_chain.blocks[1].block.issued_by, child_persona_id,
        "appended block 1 issued by the delegated child persona"
    );

    // Issuer identity: the envelope's `issuing_persona_id` is the
    // chain-root persona (so use-time verification looks up the right
    // root key), even though the row's `persona_id` SQL column tracks
    // the child persona for operational purposes.
    assert_eq!(
        child_chain.issuing_persona_id, chain_root_persona_id,
        "envelope issuing_persona_id binds to the chain root"
    );

    // Cryptographic linkage: block 1's signature is verified by block
    // 0's `pubkey_next` (the C1-fix binding). Verifying the full chain
    // under the chain-root persona key must succeed.
    let chain_root = store.persona_root_keypair(&chain_root_persona_id).unwrap();
    let chain_root_bytes = hex::decode(chain_root.public_hex()).unwrap();
    grant_chain::verify_chain(&child_chain.blocks, &chain_root_bytes)
        .expect("appended chain verifies end-to-end under chain-root persona key");

    // The child block's pubkey_next is a fresh secret (different from
    // the parent's persisted secret) — the child can be delegated FROM
    // in turn. This is the persisted-tail invariant H3 protects: the
    // appended block carries its own freshly-minted pubkey_next, and
    // its private half is sealed under the CHILD'S lease (so a future
    // grandchild delegation can extend the chain again).
    let child_tail_pubkey_next = child_chain.blocks.last().unwrap().pubkey_next.clone();
    assert_ne!(
        child_tail_pubkey_next, parent_tail_pubkey_next_pre,
        "child's new tail pubkey_next is freshly minted (rotates from parent's)"
    );
}
///   1. Create parent grant with a tokens budget + delegation depth.
///   2. Delegate a narrower scope + smaller budget to a child persona.
///   3. Verify the child chain is `parent.blocks ++ [appended]` (an
///      append-chain rooted at the chain-root persona, the H3
///      post-fix shape — pre-fix it was an independent single-block
///      chain signed by the child persona's root, which left
///      attenuation unenforced).
///   4. Verify parent usage is unchanged (delegation must not
///      consume parent budget at issue time).
///   5. Verify the `parent_grant_id` link + depth decrement.
#[test]
fn delegate_grant_end_to_end_integration() {
    let store = setup();
    let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 3_600);

    // Snapshot parent usage and chain pre-delegation.
    let parent_before = store.get_grant(&parent_id).unwrap();
    let usage_before = parent_before.usage.clone();
    let parent_chain_before = store.get_access_grant(&parent_id).unwrap();
    let chain_root_persona_id = parent_chain_before.blocks[0].block.issued_by.clone();

    // Delegate: subset scope (`acme/widgets` ⊆ `acme/*`), smaller
    // budget (2_000 ≤ 10_000 − 0 remaining), shorter TTL.
    let child = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(900),
            Some(Budget {
                tokens: Some(2_000),
                ..Default::default()
            }),
        )
        .expect("delegation succeeds within parent bounds");

    // (3) H3 post-fix: chain = parent.blocks ++ [child_appended],
    // verifies end-to-end under the CHAIN-ROOT persona key.
    let chain = store.get_access_grant(&child.id).unwrap();
    assert_eq!(
        chain.blocks.len(),
        parent_chain_before.blocks.len() + 1,
        "delegated grant is parent.blocks ++ [appended]"
    );
    assert_eq!(
        chain.blocks.last().unwrap().block.issued_by,
        child_persona_id,
        "appended tail block issued by the new authority holder"
    );
    let chain_root = store.persona_root_keypair(&chain_root_persona_id).unwrap();
    let chain_root_bytes = hex::decode(chain_root.public_hex()).unwrap();
    grant_chain::verify_chain(&chain.blocks, &chain_root_bytes)
        .expect("delegated chain verifies end-to-end under the chain-root persona key");

    // (4) Parent usage must be unchanged — delegation issues a new
    // grant; it does not debit the parent at creation time.
    let parent_after = store.get_grant(&parent_id).unwrap();
    assert_eq!(parent_after.usage, usage_before, "parent usage unchanged");

    // (5) Parent link + depth attenuation preserved.
    assert_eq!(child.parent_grant_id, Some(parent_id.clone()));
    assert_eq!(
        child.max_delegation_depth,
        parent_before
            .max_delegation_depth
            .map(|d| d.saturating_sub(1)),
        "child depth = parent depth − 1",
    );
    assert_eq!(
        child.budget.as_ref().and_then(|b| b.tokens),
        Some(2_000),
        "child budget plumbed through"
    );
}

/// Attenuation violation surfaces as `DelegationViolation` with a
/// reason the CLI prints verbatim. Budget-exceeds case.
#[test]
fn delegate_grant_budget_exceeds_parent_surfaces_reason() {
    let store = setup();
    let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 3_600);

    let err = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(600),
            Some(Budget {
                tokens: Some(20_000), // exceeds parent's 10_000
                ..Default::default()
            }),
        )
        .unwrap_err();

    match err {
        StoreError::DelegationViolation { reason } => {
            assert!(
                reason.contains("budget") || reason.contains("tokens"),
                "reason should name the violating axis, got: {reason}"
            );
        }
        other => panic!("expected DelegationViolation, got {other:?}"),
    }
}

#[test]
fn extend_grant_re_signs_block_zero() {
    let store = setup();
    let persona = store.create_persona("agent-sign-extend").unwrap();
    let grant = store
        .create_grant(&persona.id, "api-key", "read", Some(3600))
        .unwrap();

    // Extend — block 0's payload changes, so the signature must be
    // refreshed; otherwise verify_chain would fail after the update.
    store
        .extend_grant(&grant.id, Some(5_000), None, Some(600))
        .unwrap();

    let chain = store.get_access_grant(&grant.id).unwrap();
    let root = store.persona_root_keypair(&persona.id).unwrap();
    let root_pubkey_bytes = hex::decode(root.public_hex()).unwrap();
    grant_chain::verify_chain(&chain.blocks, &root_pubkey_bytes)
        .expect("re-signed block 0 verifies after extend_grant");
}

#[test]
fn extend_grant_rejects_active_grant_without_live_lease() {
    let store = setup();
    let persona = store.create_persona("agent-sign-extend-inert").unwrap();
    let grant = store
        .create_grant(&persona.id, "api-key", "read", Some(3600))
        .unwrap();
    let before: (Option<String>, Option<String>) = store
        .conn()
        .query_row(
            "SELECT expires_at, blocks_json FROM grants WHERE id = ?1",
            rusqlite::params![&grant.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();

    assert!(
        store.leases().drop_lease(&grant.id),
        "test setup must remove the live lease while leaving the grant active"
    );
    assert!(
        !store.leases().has_live_lease(&grant.id, Utc::now()),
        "active SQL grant should be inert without a live grant-scoped lease"
    );
    assert_eq!(
        store.get_grant(&grant.id).unwrap().status,
        "active",
        "dropping the in-memory lease must not revoke the SQL row"
    );

    let err = store
        .extend_grant(&grant.id, Some(5_000), None, Some(600))
        .expect_err("grant extension must fail without the live lease");
    match err {
        StoreError::InvalidInput(reason) => {
            assert!(
                reason.contains("live leased authority") && reason.contains("inert"),
                "expected live-lease rejection, got: {reason}"
            );
        }
        other => panic!("expected InvalidInput live-lease reject, got {other:?}"),
    }

    let after: (Option<String>, Option<String>) = store
        .conn()
        .query_row(
            "SELECT expires_at, blocks_json FROM grants WHERE id = ?1",
            rusqlite::params![&grant.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        after, before,
        "failed extension must not update expiry or re-sign blocks_json"
    );
    assert!(
        store.leases().is_empty(),
        "failed extension must not mint a replacement lease"
    );
}

#[test]
fn get_access_grant_missing_persona_signed_chain_returns_err() {
    // F-07: a signed-chain orphan (persona row deleted after mint) must
    // now be rejected by verify_and_return. Only unsigned-phase1
    // placeholder grants pass through without a persona row.
    use core_crypto::grant_chain::{RootKeyPair, sign_block_zero};
    use core_grant_types::{Block, ResourceSelector, ResourceType, Statement, Usage};

    let store = setup();

    let kp = core_crypto::generate_local_key_pair("persona", "ghost");
    let persona_id = seed_persona_with_key(&store, &kp.public_key, &kp.private_key);

    let root_kp = RootKeyPair::from_hex(
        kp.public_key.trim_start_matches("ed25519:"),
        kp.private_key.trim_start_matches("ed25519-secret:"),
    )
    .unwrap();
    let block = Block {
        statements: vec![Statement {
            sid: "S0".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["read".into()],
            resource: ResourceSelector::Any,
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        }],
        nbf: None,
        expires_at: None,
        issued_by: persona_id.clone(),
        issued_at: 3_000_000,
        approval: None,
        note: None,
    };
    let out = sign_block_zero(&root_kp, &block).unwrap();
    let blocks_json = serde_json::to_string(&[out.signed]).unwrap();
    let grant_id = seed_grant_with_blocks(&store, &persona_id, &blocks_json);

    // Delete persona to create the orphan scenario.
    store
        .conn()
        .execute_batch("PRAGMA foreign_keys = OFF")
        .unwrap();
    store
        .conn()
        .execute(
            "DELETE FROM personas WHERE id = ?1",
            rusqlite::params![persona_id],
        )
        .unwrap();
    store
        .conn()
        .execute_batch("PRAGMA foreign_keys = ON")
        .unwrap();

    // F-07: signed-chain orphan is rejected, not silently passed through.
    let err = store
        .get_access_grant(&grant_id)
        .expect_err("signed orphan grant must be rejected after F-07");
    assert!(
        matches!(err, StoreError::InvalidInput(ref s) if s.contains("chain verification failed")),
        "expected chain verification error for signed orphan, got: {err:?}"
    );
}

// --- W2: Stream C per-Statement usage increment (P69K-C) ---

/// Seed a multi-statement grant with custom statements and return its id.
fn seed_multi_stmt_grant(
    store: &DaemonStore,
    persona_id: &str,
    credential_name: &str,
    statements: Vec<Statement>,
) -> String {
    let grant = store
        .create_grant(persona_id, credential_name, "*", None)
        .unwrap();
    let root = store.persona_root_keypair(persona_id).unwrap();
    let ag = access_grant_from_statements(
        &grant.id,
        persona_id,
        credential_name,
        statements,
        0,
        None,
        &root,
    )
    .unwrap();
    store.overwrite_grant_blocks(&grant.id, &ag).unwrap();
    grant.id
}

fn session_stmt(sid: &str, tokens: u64, cents: u64) -> Statement {
    Statement {
        sid: sid.into(),
        resource_type: ResourceType::Session,
        actions: vec!["*".into()],
        resource: ResourceSelector::Any,
        budget: Some(Budget {
            tokens: Some(tokens),
            cents: Some(cents),
            ..Default::default()
        }),
        usage: Usage::default(),
        conditions: Vec::new(),
        can_delegate: None,
    }
}

fn payment_stmt(sid: &str, vendor: &str, budget_cents: u64, threshold_cents: u64) -> Statement {
    Statement {
        sid: sid.into(),
        resource_type: ResourceType::Payment,
        actions: vec!["payment:charge".into()],
        resource: ResourceSelector::Exact {
            value: vendor.into(),
        },
        budget: Some(Budget {
            cents: Some(budget_cents),
            ..Default::default()
        }),
        usage: Usage::default(),
        conditions: vec![
            Condition::MerchantAllowlist {
                merchants: vec![vendor.into()],
            },
            Condition::Range {
                field: "amount_cents".into(),
                min: Some(0),
                max: Some(threshold_cents as i64),
            },
        ],
        can_delegate: None,
    }
}

fn payment_evaluated_receipts(store: &DaemonStore, grant_id: &str) -> Vec<PaymentEvaluatedBody> {
    store
        .list_receipts_v2_envelopes(&[grant_id.to_string()])
        .unwrap()
        .into_iter()
        .filter_map(|(_, kind, _, envelope)| {
            if kind == RECEIPT_KIND_PAYMENT_EVALUATED {
                serde_json::from_value::<PaymentEvaluatedBody>(envelope.body).ok()
            } else {
                None
            }
        })
        .collect()
}

fn payment_settled_receipts(store: &DaemonStore, grant_id: &str) -> Vec<PaymentSettledBody> {
    store
        .list_receipts_v2_envelopes(&[grant_id.to_string()])
        .unwrap()
        .into_iter()
        .filter_map(|(_, kind, _, envelope)| {
            if kind == RECEIPT_KIND_PAYMENT_SETTLED {
                serde_json::from_value::<PaymentSettledBody>(envelope.body).ok()
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn increment_statement_usage_updates_single_statement() {
    let store = setup();
    let persona = store.create_persona("inc-1").unwrap();
    let gid = seed_multi_stmt_grant(
        &store,
        &persona.id,
        "cred",
        vec![session_stmt("S1", 10_000, 1_000)],
    );
    let delta = store
        .increment_statement_usage(
            &gid,
            "S1",
            Usage {
                tokens: 100,
                cents: 5,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(delta.prior.tokens, 0);
    assert_eq!(delta.current.tokens, 100);
    assert_eq!(delta.current.cents, 5);
    // Re-read round-trip.
    let ag = store.get_access_grant(&gid).unwrap();
    let s = ag.statements().find(|(_, s)| s.sid == "S1").unwrap().1;
    assert_eq!(s.usage.tokens, 100);
    assert_eq!(s.usage.cents, 5);
}

#[test]
fn increment_statement_usage_rejects_active_grant_without_live_lease() {
    let store = setup();
    let persona = store.create_persona("inc-inert").unwrap();
    let gid = seed_multi_stmt_grant(
        &store,
        &persona.id,
        "cred",
        vec![session_stmt("S1", 10_000, 1_000)],
    );
    let before: Option<String> = store
        .conn()
        .query_row(
            "SELECT blocks_json FROM grants WHERE id = ?1",
            rusqlite::params![&gid],
            |row| row.get(0),
        )
        .unwrap();

    assert!(
        store.leases().drop_lease(&gid),
        "test setup must remove the live lease while leaving the grant active"
    );
    assert!(
        !store.leases().has_live_lease(&gid, Utc::now()),
        "active SQL grant should be inert without a live grant-scoped lease"
    );
    assert_eq!(
        store.get_grant(&gid).unwrap().status,
        "active",
        "dropping the in-memory lease must not revoke the SQL row"
    );
    let err = store
        .increment_statement_usage(
            &gid,
            "S1",
            Usage {
                tokens: 100,
                cents: 5,
                ..Default::default()
            },
        )
        .expect_err("metering must fail without the live lease");
    match err {
        StoreError::InvalidInput(reason) => assert!(
            reason.contains("live leased authority")
                && reason.contains("block-0 signing refused")
                && reason.contains("statement usage metering"),
            "expected metering live-lease rejection, got: {reason}"
        ),
        other => panic!("expected InvalidInput live-lease reject, got {other:?}"),
    }

    let after: Option<String> = store
        .conn()
        .query_row(
            "SELECT blocks_json FROM grants WHERE id = ?1",
            rusqlite::params![&gid],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        after, before,
        "failed usage metering must not persist mutated blocks_json"
    );
    assert!(
        store.leases().is_empty(),
        "failed usage metering must not mint a replacement lease"
    );
}

#[test]
fn increment_statement_usage_unknown_sid_returns_not_found() {
    let store = setup();
    let persona = store.create_persona("inc-miss").unwrap();
    let gid = seed_multi_stmt_grant(
        &store,
        &persona.id,
        "cred",
        vec![session_stmt("S1", 10_000, 1_000)],
    );
    let err = store
        .increment_statement_usage(&gid, "S99", Usage::default())
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

#[test]
fn increment_is_cumulative_across_calls() {
    let store = setup();
    let persona = store.create_persona("inc-cum").unwrap();
    let gid = seed_multi_stmt_grant(
        &store,
        &persona.id,
        "cred",
        vec![session_stmt("S1", 10_000, 1_000)],
    );
    store
        .increment_statement_usage(
            &gid,
            "S1",
            Usage {
                tokens: 200,
                ..Default::default()
            },
        )
        .unwrap();
    let delta = store
        .increment_statement_usage(
            &gid,
            "S1",
            Usage {
                tokens: 300,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(delta.prior.tokens, 200);
    assert_eq!(delta.current.tokens, 500);
}

#[test]
fn mark_exhausted_flips_grant_when_all_budgets_spent() {
    let store = setup();
    let persona = store.create_persona("mark-1").unwrap();
    let gid = seed_multi_stmt_grant(
        &store,
        &persona.id,
        "cred",
        vec![session_stmt("S1", 100, 50)],
    );
    // Exhaust tokens axis.
    store
        .increment_statement_usage(
            &gid,
            "S1",
            Usage {
                tokens: 100,
                ..Default::default()
            },
        )
        .unwrap();
    let flipped = store
        .mark_grant_exhausted_by_budget_if_terminal(&gid)
        .unwrap();
    assert!(flipped);
    assert_eq!(store.get_grant(&gid).unwrap().status, "exhausted_by_budget");
}

#[test]
fn mark_exhausted_noop_when_no_budget_bearing_statements() {
    let store = setup();
    let persona = store.create_persona("mark-nobudget").unwrap();
    // Stmt without any budget.
    let stmt = Statement {
        sid: "S0".into(),
        resource_type: ResourceType::Credential,
        actions: vec!["*".into()],
        resource: ResourceSelector::Any,
        budget: None,
        usage: Usage::default(),
        conditions: Vec::new(),
        can_delegate: None,
    };
    let gid = seed_multi_stmt_grant(&store, &persona.id, "cred", vec![stmt]);
    let flipped = store
        .mark_grant_exhausted_by_budget_if_terminal(&gid)
        .unwrap();
    assert!(!flipped);
    assert_eq!(store.get_grant(&gid).unwrap().status, "active");
}

#[test]
fn mark_exhausted_noop_when_already_revoked() {
    let store = setup();
    let persona = store.create_persona("mark-revoked").unwrap();
    let gid = seed_multi_stmt_grant(
        &store,
        &persona.id,
        "cred",
        vec![session_stmt("S1", 100, 50)],
    );
    store.revoke_grant(&gid).unwrap();
    // Even if we crank usage past limit, a revoked grant must NOT
    // silently flip to exhausted_by_budget.
    let flipped = store
        .mark_grant_exhausted_by_budget_if_terminal(&gid)
        .unwrap();
    assert!(!flipped);
    assert_eq!(store.get_grant(&gid).unwrap().status, "revoked");
}

// --- Hard-pause tests (69K.7) ---

#[test]
fn pause_active_grant_blocks_proxy() {
    let store = setup();
    let persona = store.create_persona("pause-proxy-agent").unwrap();
    let grant = store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();

    // Grant is active; evaluate_grant should succeed.
    assert!(store.evaluate_grant(&persona.id, "api-key").is_ok());

    // Pause the grant.
    store.pause_grant(&grant.id).unwrap();
    let g = store.get_grant(&grant.id).unwrap();
    assert_eq!(g.status, "paused");
    assert!(g.paused);

    // evaluate_grant (used by proxy) should now return NotFound — grant is no longer 'active'.
    let result = store.evaluate_grant(&persona.id, "api-key");
    assert!(
        matches!(result, Err(StoreError::NotFound)),
        "paused grant must be invisible to evaluate_grant (proxy enforcement)"
    );
}

#[test]
fn resume_paused_grant_allows_proxy() {
    let store = setup();
    let persona = store.create_persona("resume-proxy-agent").unwrap();
    let grant = store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();

    store.pause_grant(&grant.id).unwrap();
    // Confirm blocked.
    assert!(store.evaluate_grant(&persona.id, "api-key").is_err());

    // Resume.
    store.resume_grant(&grant.id).unwrap();
    let g = store.get_grant(&grant.id).unwrap();
    assert_eq!(g.status, "active");
    assert!(!g.paused);

    // evaluate_grant should succeed again.
    assert!(store.evaluate_grant(&persona.id, "api-key").is_ok());
}

#[test]
fn pause_nonexistent_grant_returns_notfound() {
    let store = setup();
    // Well-formed but unknown grant id — must reach the DB lookup and
    // return NotFound rather than failing the upstream UUID parse.
    let unknown_id = format!("grant-{}", uuid::Uuid::new_v4());
    let result = store.pause_grant(&unknown_id);
    assert!(
        matches!(result, Err(StoreError::NotFound)),
        "pause on unknown id must return NotFound, got: {result:?}"
    );
}

#[test]
fn cannot_pause_revoked_grant() {
    let store = setup();
    let persona = store.create_persona("no-pause-revoked").unwrap();
    let grant = store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();
    store.revoke_grant(&grant.id).unwrap();

    let result = store.pause_grant(&grant.id);
    assert!(
        matches!(result, Err(StoreError::InvalidInput(_))),
        "pausing a revoked grant must return InvalidInput"
    );
    // Status must remain 'revoked'.
    assert_eq!(store.get_grant(&grant.id).unwrap().status, "revoked");
}

#[test]
fn pause_grant_is_idempotent() {
    let store = setup();
    let persona = store.create_persona("idem-pause").unwrap();
    let grant = store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();

    store.pause_grant(&grant.id).unwrap();
    // Second pause should not error — idempotent.
    store.pause_grant(&grant.id).unwrap();
    assert_eq!(store.get_grant(&grant.id).unwrap().status, "paused");
}

#[test]
fn resume_grant_is_idempotent() {
    let store = setup();
    let persona = store.create_persona("idem-resume").unwrap();
    let grant = store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();

    // Resume on an already-active grant should not error.
    store.resume_grant(&grant.id).unwrap();
    assert_eq!(store.get_grant(&grant.id).unwrap().status, "active");
}

#[test]
fn list_active_grants_includes_paused() {
    // Paused grants are reversible; the operator
    // who pauses a grant must still see it on the Active list to be
    // able to resume it. Terminal states (revoked / expired /
    // exhausted_by_budget) belong behind the "show terminated"
    // toggle, but paused is not terminal.
    let store = setup();
    let persona = store.create_persona("excl-paused").unwrap();
    let g1 = store
        .create_grant(&persona.id, "key-a", "read", None)
        .unwrap();
    let g2 = store
        .create_grant(&persona.id, "key-b", "read", None)
        .unwrap();

    store.pause_grant(&g1.id).unwrap();

    let active = store.list_active_grants().unwrap();
    assert_eq!(
        active.len(),
        2,
        "paused grants must remain visible on the Active list — they are reversible, not terminal",
    );
    let mut ids: Vec<&str> = active.iter().map(|g| g.id.as_str()).collect();
    ids.sort();
    let mut expected = vec![g1.id.as_str(), g2.id.as_str()];
    expected.sort();
    assert_eq!(ids, expected);

    // Sanity: terminal states still excluded so the toggle remains useful.
    store.revoke_grant(&g2.id).unwrap();
    let after_revoke = store.list_active_grants().unwrap();
    assert_eq!(
        after_revoke.len(),
        1,
        "terminal states (revoked) still belong off the active list",
    );
    assert_eq!(after_revoke[0].id, g1.id);
}

#[test]
fn list_grants_shows_effective_status_for_time_expired_grant() {
    let store = setup();
    let persona = store.create_persona("agent-eff-status").unwrap();
    // Create a grant with a 1-second TTL.
    let grant = store
        .create_grant(&persona.id, "api-key", "read", Some(1))
        .unwrap();
    assert_eq!(grant.status, "active");

    // Backdate expires_at to a timestamp clearly in the past so
    // row_to_grant derives "expired" without waiting.
    store
        .conn()
        .execute(
            "UPDATE grants SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?1",
            rusqlite::params![grant.id],
        )
        .expect("backdate expires_at");

    let grants = store.list_grants().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(
        grants[0].status, "expired",
        "list_grants must surface effective status for a time-expired grant"
    );
}

// --- P69K-BUDGET-WRITE: create_grant_with_budget encodes budget into
//     block-zero statement ---

#[test]
fn create_grant_encodes_budget_into_block_zero_statement() {
    let store = setup();
    let persona = store.create_persona("agent-budget-write").unwrap();
    let grant = store
        .create_grant_with_budget(
            &persona.id,
            "llm-key",
            "llm:generate",
            Some(3600),
            Some(Budget {
                tokens: Some(20_000),
                ..Default::default()
            }),
        )
        .unwrap();

    // (1) GrantInfo projection carries the budget.
    assert_eq!(
        grant.budget.as_ref().and_then(|b| b.tokens),
        Some(20_000),
        "GrantInfo.budget.tokens must reflect the caller's budget"
    );

    // (2) Authoritative composite read path sees the budget in the
    //     first statement.
    let ag = store.get_access_grant(&grant.id).unwrap();
    assert_eq!(ag.blocks.len(), 1);
    let stmt = &ag.blocks[0].block.statements[0];
    assert_eq!(
        stmt.budget.as_ref().and_then(|b| b.tokens),
        Some(20_000),
        "block[0].statements[0].budget.tokens must carry the caller's budget"
    );
}

#[test]
fn create_grant_without_budget_leaves_statement_budget_none() {
    let store = setup();
    let persona = store.create_persona("agent-budget-none").unwrap();
    // Both the legacy `create_grant` (no budget param) and the new
    // `create_grant_with_budget(..., None)` must produce a statement
    // with `budget = None`.
    let g1 = store.create_grant(&persona.id, "k1", "read", None).unwrap();
    let g2 = store
        .create_grant_with_budget(&persona.id, "k2", "read", None, None)
        .unwrap();

    for gid in [&g1.id, &g2.id] {
        let ag = store.get_access_grant(gid).unwrap();
        assert!(
            ag.blocks[0].block.statements[0].budget.is_none(),
            "statement.budget must be None when no budget is supplied (grant {gid})"
        );
    }
}

#[test]
fn create_grant_with_empty_budget_is_normalized_to_none() {
    // An operator-supplied `Budget::default()` (all axes unset) is
    // indistinguishable from "no budget" — `create_grant_with_budget`
    // normalizes it to `None` so downstream code doesn't have to
    // branch on "is this empty?".
    let store = setup();
    let persona = store.create_persona("agent-budget-empty").unwrap();
    let grant = store
        .create_grant_with_budget(&persona.id, "k", "read", None, Some(Budget::default()))
        .unwrap();
    assert!(grant.budget.is_none());
    let ag = store.get_access_grant(&grant.id).unwrap();
    assert!(ag.blocks[0].block.statements[0].budget.is_none());
}

// --- P69K-A2 L3: size caps on blocks_json write paths ---

/// Build an [`AccessGrant`] with the caller-supplied block list.
/// Skips chain signing — these tests are about the size-cap check
/// which runs **before** chain verification in the write paths.
fn make_grant_with_blocks(id: &str, persona_id: &str, blocks: Vec<SignedBlock>) -> AccessGrant {
    AccessGrant {
        id: id.into(),
        version: 1,
        issuing_persona_id: persona_id.into(),
        recipient_kind: PresentationAudienceKind::Service,
        recipient_id: "cred".into(),
        recipient_profile: RecipientProfile::Agent,
        status: GrantStatus::Active,
        mode: GrantMode::OneShot,
        blocks,
        attestation: AttestationBinding::default(),
        created_at: 0,
        updated_at: 0,
        revoked_at: None,
        revoked_reason: None,
        last_used_at: None,
        label: None,
    }
}

fn dummy_signed_block(persona_id: &str, n_statements: usize) -> SignedBlock {
    let statements: Vec<Statement> = (0..n_statements)
        .map(|i| Statement {
            sid: format!("S{i}"),
            resource_type: ResourceType::Credential,
            actions: vec!["read".into()],
            resource: ResourceSelector::Any,
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        })
        .collect();
    let block = Block {
        statements,
        nbf: None,
        expires_at: None,
        issued_by: persona_id.to_string(),
        issued_at: 0,
        approval: None,
        note: None,
    };
    // Sign with a fresh ephemeral keypair so this block carries a real
    // Ed25519 signature. Cap-check tests only inspect block/statement
    // counts and JSON byte size — the signer identity is irrelevant to
    // them. Using a real signature removes the unsigned-phase1 placeholder
    // from all test emission paths (P69K-B).
    let ephemeral = core_crypto::grant_chain::PubkeyNextKeyPair::generate();
    let root = RootKeyPair::from_hex(&ephemeral.public_hex, &ephemeral.secret_hex)
        .expect("ephemeral key is valid RootKeyPair material");
    sign_block_zero_with(&root, &block).expect("dummy block signing must not fail")
}

#[test]
fn blocks_json_write_rejects_too_many_blocks() {
    let store = setup();
    let persona = store.create_persona("agent-cap-blocks").unwrap();
    // Seed a grant so `overwrite_grant_blocks` finds the row.
    let seeded = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();

    // Build a 33-block chain — one over the cap.
    let blocks: Vec<SignedBlock> = (0..MAX_BLOCKS + 1)
        .map(|_| dummy_signed_block(&persona.id, 1))
        .collect();
    let grant = make_grant_with_blocks(&seeded.id, &persona.id, blocks);

    let err = store
        .overwrite_grant_blocks(&seeded.id, &grant)
        .unwrap_err();
    match err {
        StoreError::InvalidInput(s) => {
            assert!(
                s.contains("blocks"),
                "message must name the violated cap, got: {s}"
            );
            assert!(
                s.contains(&format!("{}", MAX_BLOCKS)),
                "message should cite the cap: {s}"
            );
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[test]
fn blocks_json_write_rejects_too_many_statements_per_block() {
    let store = setup();
    let persona = store.create_persona("agent-cap-stmts").unwrap();
    let seeded = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();

    // Single block, 17 statements — one over the per-block cap.
    let blocks = vec![dummy_signed_block(
        &persona.id,
        MAX_STATEMENTS_PER_BLOCK + 1,
    )];
    let grant = make_grant_with_blocks(&seeded.id, &persona.id, blocks);

    let err = store
        .overwrite_grant_blocks(&seeded.id, &grant)
        .unwrap_err();
    match err {
        StoreError::InvalidInput(s) => {
            assert!(
                s.contains("statements"),
                "message must name the violated cap, got: {s}"
            );
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[test]
fn blocks_json_write_rejects_oversized_payload() {
    let store = setup();
    let persona = store.create_persona("agent-cap-size").unwrap();
    let seeded = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();

    // Single block, single statement — but the statement's resource
    // selector is a giant glob pattern that pushes the serialized
    // JSON over MAX_BLOCKS_JSON_BYTES.
    let giant = "x".repeat(MAX_BLOCKS_JSON_BYTES + 1024);
    let mut sb = dummy_signed_block(&persona.id, 1);
    sb.block.statements[0].resource = ResourceSelector::Glob { pattern: giant };
    let grant = make_grant_with_blocks(&seeded.id, &persona.id, vec![sb]);

    let err = store
        .overwrite_grant_blocks(&seeded.id, &grant)
        .unwrap_err();
    match err {
        StoreError::InvalidInput(s) => {
            assert!(
                s.contains("bytes") || s.contains(&format!("{}", MAX_BLOCKS_JSON_BYTES)),
                "message must name the payload cap, got: {s}"
            );
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[test]
fn blocks_json_write_accepts_well_sized_chain() {
    // Nominal case: 5 blocks × 3 statements each. Well under every
    // cap — the check must pass and the envelope/chain guards
    // (persona mismatch, signature) take over. Those later guards
    // will reject because `dummy_signed_block` uses a placeholder
    // signature, but that's a *different* error; the size check
    // itself must NOT fire.
    let store = setup();
    let persona = store.create_persona("agent-cap-ok").unwrap();
    let seeded = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();

    let blocks: Vec<SignedBlock> = (0..5).map(|_| dummy_signed_block(&persona.id, 3)).collect();
    let grant = make_grant_with_blocks(&seeded.id, &persona.id, blocks);

    // `validate_blocks_json_caps` must pass — assert by calling it
    // directly (bypasses the downstream chain-verify rejection so
    // we can assert the cap check in isolation).
    let json = access_grant_blocks_to_json(&grant).unwrap();
    assert!(
        validate_blocks_json_caps(&grant, &json).is_ok(),
        "5 blocks x 3 stmts is nominal; size caps must not fire"
    );
}

#[test]
fn validate_blocks_json_caps_accepts_exact_max_blocks() {
    // Cap is inclusive at MAX_BLOCKS. Exactly 32 blocks, one
    // minimal statement each, must pass. Guards against an
    // off-by-one that would silently reject a maxed-out legitimate
    // chain.
    let persona_id = "agent-boundary-blocks";
    let blocks: Vec<SignedBlock> = (0..MAX_BLOCKS)
        .map(|_| dummy_signed_block(persona_id, 1))
        .collect();
    let grant = make_grant_with_blocks("grant-boundary-b", persona_id, blocks);
    let json = access_grant_blocks_to_json(&grant).unwrap();
    assert!(
        json.len() <= MAX_BLOCKS_JSON_BYTES,
        "32-block minimal chain must fit in the JSON cap; got {} bytes",
        json.len()
    );
    validate_blocks_json_caps(&grant, &json).expect("exact MAX_BLOCKS must pass");
}

#[test]
fn validate_blocks_json_caps_accepts_exact_max_statements_per_block() {
    // Cap is inclusive at MAX_STATEMENTS_PER_BLOCK. Single block,
    // exactly 16 statements, must pass.
    let persona_id = "agent-boundary-stmts";
    let blocks = vec![dummy_signed_block(persona_id, MAX_STATEMENTS_PER_BLOCK)];
    let grant = make_grant_with_blocks("grant-boundary-s", persona_id, blocks);
    let json = access_grant_blocks_to_json(&grant).unwrap();
    validate_blocks_json_caps(&grant, &json).expect("exact MAX_STATEMENTS_PER_BLOCK must pass");
}

// --- ADR 135 §4: composite-grant action-key validator ---------------

// --- P69K-F04: overwrite_grant_blocks must full-verify chain under
// persona root before persisting. SQL-tampered blocks_json that
// replaces a real chain with a forged one must be rejected; the
// envelope `issued_by == row.persona_id` guard (shipped in #527) is
// not sufficient on its own — a forger who sets `issued_by` correctly
// but swaps, tampers, or re-signs the blocks must still be caught by
// `verify_chain`.

/// Build a signed single-statement block for the given persona so
/// tests can construct realistic chains without re-stating the
/// statement shape every time.
///
/// Statement shape matches the parent seeded by
/// `create_grant(.., "cred", "read", None)` (scope="read" projects
/// to `actions=["read"], resource=Exact{"cred"}`) so the P69K-A2-I4
/// bipartite dominance check passes and the crypto-verify tripwire
/// (tampered signature, reordered blocks, wrong persona root, phase-1
/// placeholder) is what fires.
fn signed_block_for(
    persona_id: &str,
    sid: &str,
    root: &RootKeyPair,
) -> grant_chain::SignedBlockOutput {
    let block = Block {
        statements: vec![Statement {
            sid: sid.into(),
            resource_type: ResourceType::Credential,
            actions: vec!["read".into()],
            resource: ResourceSelector::Exact {
                value: "cred".into(),
            },
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        }],
        nbf: None,
        expires_at: None,
        issued_by: persona_id.into(),
        issued_at: 0,
        approval: None,
        note: None,
    };
    grant_chain::sign_block_zero(root, &block).expect("sign block 0")
}

#[test]
fn overwrite_grant_blocks_rejects_tampered_signature() {
    // Chain whose signature has been flipped — internal chain is
    // otherwise well-formed. `verify_chain` must surface a
    // RootKeyMismatch (block-0) and overwrite must refuse to persist.
    let store = setup();
    let persona = store.create_persona("agent-overwrite-tamper").unwrap();
    let seeded = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();

    let root = store.persona_root_keypair(&persona.id).unwrap();
    let mut out = signed_block_for(&persona.id, "S0", &root);

    // Flip the last hex byte of the signature so it no longer
    // verifies under the persona root.
    let sig = out.signed.signature.clone();
    let flipped = format!(
        "{}{}",
        &sig[..sig.len() - 2],
        if sig.ends_with("00") { "ff" } else { "00" }
    );
    out.signed.signature = flipped;

    let grant = make_grant_with_blocks(&seeded.id, &persona.id, vec![out.signed]);

    let err = store
        .overwrite_grant_blocks(&seeded.id, &grant)
        .unwrap_err();
    match err {
        StoreError::InvalidInput(s) => assert!(
            s.contains("chain verification failed"),
            "expected chain verification error, got: {s}"
        ),
        other => panic!("expected InvalidInput, got {other:?}"),
    }

    // The row must be unchanged — the tampered chain was rejected
    // before the UPDATE executed.
    let after = store.get_access_grant(&seeded.id).unwrap();
    assert_eq!(after.id, seeded.id);
}

#[test]
fn overwrite_grant_blocks_rejects_reordered_blocks() {
    // Build a legitimate 3-block chain under the persona root, then
    // swap blocks 1 and 2. The swap breaks the pubkey_next linkage:
    // block 2 was signed by block-1's pubkey_next_secret, so placing
    // it at position 1 (where the verifier expects a signature from
    // block-0's pubkey_next) is a SignatureMismatch.
    let store = setup();
    let persona = store.create_persona("agent-overwrite-reorder").unwrap();
    let seeded = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();

    let root = store.persona_root_keypair(&persona.id).unwrap();
    let out0 = signed_block_for(&persona.id, "S0", &root);

    let b1 = Block {
        statements: vec![Statement {
            sid: "S1".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["read".into()],
            resource: ResourceSelector::Exact {
                value: "cred".into(),
            },
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        }],
        nbf: None,
        expires_at: None,
        issued_by: persona.id.clone(),
        issued_at: 1,
        approval: None,
        note: None,
    };
    let out1 = grant_chain::sign_appended_block(&out0.pubkey_next_secret, &b1).unwrap();

    let b2 = Block {
        statements: vec![Statement {
            sid: "S2".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["read".into()],
            resource: ResourceSelector::Exact {
                value: "cred".into(),
            },
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        }],
        nbf: None,
        expires_at: None,
        issued_by: persona.id.clone(),
        issued_at: 2,
        approval: None,
        note: None,
    };
    let out2 = grant_chain::sign_appended_block(&out1.pubkey_next_secret, &b2).unwrap();

    // Swap positions 1 and 2 — still starts at a root-signed block
    // (so block-0 verification passes), but the second block is now
    // signed under a pubkey_next the verifier doesn't have at that
    // position.
    let reordered = vec![out0.signed, out2.signed, out1.signed];
    let grant = make_grant_with_blocks(&seeded.id, &persona.id, reordered);

    let err = store
        .overwrite_grant_blocks(&seeded.id, &grant)
        .unwrap_err();
    match err {
        StoreError::InvalidInput(s) => assert!(
            s.contains("chain verification failed"),
            "expected chain verification error, got: {s}"
        ),
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[test]
fn overwrite_grant_blocks_rejects_wrong_persona_root() {
    // Forge a chain that is *internally* valid but was signed under
    // a different persona's root keypair. `issued_by` is set to the
    // target persona (so the envelope guard passes), but verify_chain
    // under the target persona's declared root must reject with
    // RootKeyMismatch.
    let store = setup();
    let victim = store.create_persona("agent-overwrite-victim").unwrap();
    let attacker = store.create_persona("agent-overwrite-attacker").unwrap();
    let seeded = store
        .create_grant(&victim.id, "cred", "read", None)
        .unwrap();

    // Sign a block under the attacker's root, but label issued_by
    // as the victim so it slips past the envelope check that fires
    // before verify_chain.
    let attacker_root = store.persona_root_keypair(&attacker.id).unwrap();
    let out = signed_block_for(&victim.id, "S0", &attacker_root);
    let grant = make_grant_with_blocks(&seeded.id, &victim.id, vec![out.signed]);

    let err = store
        .overwrite_grant_blocks(&seeded.id, &grant)
        .unwrap_err();
    match err {
        StoreError::InvalidInput(s) => assert!(
            s.contains("chain verification failed"),
            "expected chain verification error (wrong root), got: {s}"
        ),
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[test]
fn overwrite_grant_blocks_rejects_unsigned_phase1_placeholder() {
    // A block carrying the pre-Cycle-2 `unsigned-phase1` placeholder
    // in its signature must be rejected. Without the verify_chain
    // wiring, a forger could overwrite a real chain with an unsigned
    // one and launder authority through the placeholder.
    let store = setup();
    let persona = store.create_persona("agent-overwrite-unsigned").unwrap();
    let seeded = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();

    let root = store.persona_root_keypair(&persona.id).unwrap();
    let mut out = signed_block_for(&persona.id, "S0", &root);
    out.signed.signature = grant_chain::UNSIGNED_PHASE1_PLACEHOLDER.into();

    let grant = make_grant_with_blocks(&seeded.id, &persona.id, vec![out.signed]);

    let err = store
        .overwrite_grant_blocks(&seeded.id, &grant)
        .unwrap_err();
    match err {
        StoreError::InvalidInput(s) => assert!(
            s.contains("chain verification failed"),
            "expected chain verification error (unsigned-phase1), got: {s}"
        ),
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

// --- P69K-A2-I4: bipartite dominance on overwrite_grant_blocks ---
//
// ADR 073 §Attenuation mandates that every statement in the new chain
// be dominated by at least one statement in the old chain. Re-verifying
// the client-supplied signature alone is insufficient: a client with
// valid keys could otherwise widen actions, replace a narrow resource
// with Any, or escape a budget cap. These tests exercise each failure
// mode + the successful-attenuation happy path.

/// Build a signed block 0 carrying a single custom statement under
/// the persona's root key, then wrap it in the minimal envelope
/// `overwrite_grant_blocks` expects.
fn overwrite_attempt_grant(
    store: &DaemonStore,
    grant_id: &str,
    persona_id: &str,
    stmt: Statement,
) -> AccessGrant {
    let block = Block {
        statements: vec![stmt],
        nbf: None,
        expires_at: None,
        issued_by: persona_id.to_string(),
        issued_at: 0,
        approval: None,
        note: None,
    };
    let root = store.persona_root_keypair(persona_id).unwrap();
    let signed = sign_block_zero_with(&root, &block).unwrap();
    make_grant_with_blocks(grant_id, persona_id, vec![signed])
}

#[test]
fn overwrite_rejects_action_escalation() {
    // Parent seeded with scope="read" projects to actions=["read"];
    // child proposes actions=["write"] on the same resource. The
    // widened action is outside the parent's action set — must reject.
    let store = setup();
    let persona = store.create_persona("agent-escalate-action").unwrap();
    let seeded = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();

    let child_stmt = Statement {
        sid: "S0".into(),
        resource_type: ResourceType::Credential,
        actions: vec!["write".into()],
        resource: ResourceSelector::Exact {
            value: "cred".into(),
        },
        budget: None,
        usage: Usage::default(),
        conditions: vec![],
        can_delegate: None,
    };
    let attempt = overwrite_attempt_grant(&store, &seeded.id, &persona.id, child_stmt);

    let err = store
        .overwrite_grant_blocks(&seeded.id, &attempt)
        .expect_err("action escalation must be rejected");
    match err {
        StoreError::InvalidInput(s) => assert!(
            s.contains("attenuation violation")
                && s.contains("no parent with matching selector/actions"),
            "expected attenuation violation (no matching parent), got: {s}"
        ),
        other => panic!("expected InvalidInput, got {other:?}"),
    }

    // Row must be unchanged — attenuation check fires before UPDATE.
    let after = store.get_access_grant(&seeded.id).unwrap();
    let (_, s0) = after.statements().next().unwrap();
    assert_eq!(s0.actions, vec!["read".to_string()]);
}

#[test]
fn overwrite_rejects_resource_escalation() {
    // Parent seeded with scope="github:push:acme/*" projects to
    // resource=Glob{"acme/*"}; child proposes a sibling target
    // `other/repo` which the glob does NOT match — must reject.
    let store = setup();
    let persona = store.create_persona("agent-escalate-resource").unwrap();
    let seeded = store
        .create_grant(&persona.id, "gh-token", "github:push:acme/*", None)
        .unwrap();

    let child_stmt = Statement {
        sid: "S0".into(),
        resource_type: ResourceType::Credential,
        actions: vec!["github:push".into()],
        resource: ResourceSelector::Exact {
            value: "other/repo".into(),
        },
        budget: None,
        usage: Usage::default(),
        conditions: vec![],
        can_delegate: None,
    };
    let attempt = overwrite_attempt_grant(&store, &seeded.id, &persona.id, child_stmt);

    let err = store
        .overwrite_grant_blocks(&seeded.id, &attempt)
        .expect_err("resource escalation must be rejected");
    match err {
        StoreError::InvalidInput(s) => assert!(
            s.contains("attenuation violation"),
            "expected attenuation violation, got: {s}"
        ),
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[test]
fn overwrite_accepts_attenuated_replacement() {
    // Parent with actions=["read","write"] (two-action scope via the
    // parent's block-0 statement) narrowed to actions=["read"]. A
    // strict subset — must accept.
    //
    // Build the parent with an explicit multi-action statement via
    // an initial overwrite on a permissive "*" scope.
    let store = setup();
    let persona = store.create_persona("agent-attenuated-ok").unwrap();
    let seeded = store.create_grant(&persona.id, "cred", "*", None).unwrap();

    let parent_stmt = Statement {
        sid: "S0".into(),
        resource_type: ResourceType::Credential,
        actions: vec!["read".into(), "write".into()],
        resource: ResourceSelector::Any,
        budget: None,
        usage: Usage::default(),
        conditions: vec![],
        can_delegate: None,
    };
    let parent = overwrite_attempt_grant(&store, &seeded.id, &persona.id, parent_stmt);
    store
        .overwrite_grant_blocks(&seeded.id, &parent)
        .expect("parent narrow from '*' must succeed");

    // Now narrow from {read, write} to {read}.
    let child_stmt = Statement {
        sid: "S0".into(),
        resource_type: ResourceType::Credential,
        actions: vec!["read".into()],
        resource: ResourceSelector::Any,
        budget: None,
        usage: Usage::default(),
        conditions: vec![],
        can_delegate: None,
    };
    let attempt = overwrite_attempt_grant(&store, &seeded.id, &persona.id, child_stmt);

    store
        .overwrite_grant_blocks(&seeded.id, &attempt)
        .expect("read-only attenuation from {read,write} must succeed");

    // The narrowed chain is what's persisted.
    let after = store.get_access_grant(&seeded.id).unwrap();
    let (_, s0) = after.statements().next().unwrap();
    assert_eq!(s0.actions, vec!["read".to_string()]);
}

#[test]
fn overwrite_rejects_budget_escalation() {
    // Parent has budget.tokens=100; child proposes budget.tokens=200
    // on the same action/resource. Child exceeds parent's remaining
    // allowance — must reject.
    //
    // The parent is built explicitly so a bounded budget is in place;
    // a "create_grant(.., 'read', ..)" call projects to budget=None,
    // which would let any child budget pass.
    let store = setup();
    let persona = store.create_persona("agent-escalate-budget").unwrap();
    let seeded = store.create_grant(&persona.id, "cred", "*", None).unwrap();

    let parent_stmt = Statement {
        sid: "S0".into(),
        resource_type: ResourceType::Credential,
        actions: vec!["read".into()],
        resource: ResourceSelector::Any,
        budget: Some(Budget {
            tokens: Some(100),
            ..Default::default()
        }),
        usage: Usage::default(),
        conditions: vec![],
        can_delegate: None,
    };
    let parent = overwrite_attempt_grant(&store, &seeded.id, &persona.id, parent_stmt);
    store
        .overwrite_grant_blocks(&seeded.id, &parent)
        .expect("parent narrow from '*' with tokens=100 must succeed");

    // Child asks for tokens=200 — above parent's cap.
    let child_stmt = Statement {
        sid: "S0".into(),
        resource_type: ResourceType::Credential,
        actions: vec!["read".into()],
        resource: ResourceSelector::Any,
        budget: Some(Budget {
            tokens: Some(200),
            ..Default::default()
        }),
        usage: Usage::default(),
        conditions: vec![],
        can_delegate: None,
    };
    let attempt = overwrite_attempt_grant(&store, &seeded.id, &persona.id, child_stmt);

    let err = store
        .overwrite_grant_blocks(&seeded.id, &attempt)
        .expect_err("budget escalation must be rejected");
    match err {
        StoreError::InvalidInput(s) => assert!(
            s.contains("attenuation violation") && s.contains("tokens"),
            "expected attenuation violation on tokens, got: {s}"
        ),
        other => panic!("expected InvalidInput, got {other:?}"),
    }

    // The parent chain remains with tokens=100 — the attempt was
    // blocked before UPDATE executed.
    let after = store.get_access_grant(&seeded.id).unwrap();
    let (_, s0) = after.statements().next().unwrap();
    assert_eq!(
        s0.budget.as_ref().and_then(|b| b.tokens),
        Some(100),
        "parent budget must be untouched after rejected escalation"
    );
}

// --- P69K-F06-tests: delegate_grant_full verified-parent attenuation ---
//
// These tests lock in the F-06 function-body fix shipped in #522: the
// parent chain must route through `get_access_grant` (→ verify_chain)
// before any attenuation logic, and delegation must refuse on any
// mismatch between the flat parent row and the signed chain payload.

/// Happy path: a freshly-minted parent grant with no SQL tampering
/// delegates cleanly to a narrowed child scope/budget. Parent row
/// remains untouched.
#[test]
fn delegate_succeeds_on_pristine_parent() {
    let store = setup();
    let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

    let parent_before = store.get_grant(&parent_id).unwrap();

    let child = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(600),
            Some(Budget {
                tokens: Some(3_000),
                ..Default::default()
            }),
        )
        .expect("pristine parent — delegation must succeed");

    // Child is a new active grant linked to the parent.
    assert_eq!(child.status, "active");
    assert_eq!(child.parent_grant_id.as_deref(), Some(parent_id.as_str()));
    assert_eq!(child.budget.as_ref().and_then(|b| b.tokens), Some(3_000));

    // Parent row unchanged — no scope, status, or budget mutation as
    // a side effect of delegation.
    let parent_after = store.get_grant(&parent_id).unwrap();
    assert_eq!(parent_after.scope, parent_before.scope);
    assert_eq!(parent_after.status, parent_before.status);
    assert_eq!(
        parent_after.budget.as_ref().and_then(|b| b.tokens),
        parent_before.budget.as_ref().and_then(|b| b.tokens),
    );
}

/// Direct `UPDATE grants SET scope = '<expanded>'` on the parent row
/// must be rejected by `delegate_grant_full`: the flat scope column
/// no longer matches the scope encoded in the signed chain's first
/// statement, and the F-06 scope-consistency guard refuses rather
/// than minting a child with expanded authority.
#[test]
fn delegate_rejects_tampered_parent_scope() {
    let store = setup();
    let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

    // Tamper: expand the parent's scope column from `github:push:acme/*`
    // (what setup_parent_with_budget installed) to `github:push:*`.
    // blocks_json is untouched — only the flat column is mutated.
    store
        .conn()
        .execute(
            "UPDATE grants SET scope = ?1 WHERE id = ?2",
            rusqlite::params!["github:push:*", parent_id],
        )
        .unwrap();

    // Now try to delegate a scope that would be OUTSIDE the true
    // (chain-bound) parent but is allowed by the tampered flat scope.
    // Must be rejected.
    let err = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:other/repo",
            Some(600),
            Some(Budget {
                tokens: Some(1_000),
                ..Default::default()
            }),
        )
        .unwrap_err();

    match err {
        StoreError::InvalidInput(reason) => {
            assert!(
                reason.contains("scope") && reason.contains("chain"),
                "expected scope/chain divergence error, got: {reason}"
            );
        }
        other => panic!("expected InvalidInput tamper reject, got {other:?}"),
    }
}

/// Direct `UPDATE grants SET budget_json = '<inflated>'` on the parent
/// row must be rejected: `delegate_grant_full` reads the budget from
/// the VERIFIED chain Statement, not the flat column, so the inflated
/// column is ignored and attenuation checks against the true chain
/// budget. A child requesting beyond the chain budget fails.
#[test]
fn delegate_rejects_tampered_parent_budget() {
    let store = setup();
    // Parent chain budget: 10_000 tokens.
    let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

    // Tamper: inflate the flat budget_json column to a 10x amount.
    // blocks_json is untouched — only the flat column is mutated.
    let inflated = serde_json::to_string(&Budget {
        tokens: Some(100_000),
        ..Default::default()
    })
    .unwrap();
    store
        .conn()
        .execute(
            "UPDATE grants SET budget_json = ?1 WHERE id = ?2",
            rusqlite::params![inflated, parent_id],
        )
        .unwrap();

    // Child requests 20_000 tokens — would be allowed if attenuation
    // believed the tampered flat column (100_000), must be rejected
    // because the chain statement still carries only 10_000.
    let err = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(600),
            Some(Budget {
                tokens: Some(20_000),
                ..Default::default()
            }),
        )
        .unwrap_err();

    match err {
        StoreError::DelegationViolation { reason } => {
            assert!(
                reason.contains("tokens") || reason.contains("budget"),
                "reason should name the violating axis, got: {reason}"
            );
        }
        other => panic!("expected DelegationViolation, got {other:?}"),
    }
}

/// A revoked parent grant must never delegate — the status guard in
/// `delegate_grant_full` checks `parent_chain.status == Active` after
/// `get_access_grant` returns. Revocation takes precedence over any
/// attenuation math.
#[test]
fn delegate_rejects_revoked_parent() {
    let store = setup();
    let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

    // Revoke the parent — cascades would also revoke children, but
    // there are none yet.
    store.revoke_grant(&parent_id).unwrap();
    assert_eq!(store.get_grant(&parent_id).unwrap().status, "revoked");

    // Any delegation attempt now must fail, regardless of how narrow
    // the child scope/budget is.
    let err = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(60),
            Some(Budget {
                tokens: Some(100),
                ..Default::default()
            }),
        )
        .unwrap_err();

    match err {
        StoreError::InvalidInput(reason) => {
            assert!(
                reason.contains("active") || reason.contains("status"),
                "expected parent-not-active error, got: {reason}"
            );
        }
        other => panic!("expected InvalidInput status guard, got {other:?}"),
    }
}

// --- P69K-H1: extend_grant TOCTOU regression ---

/// Deterministic sequential test that mirrors the meter↔extend
/// interleave: after `increment_statement_usage` writes a usage
/// delta to `blocks_json`, a subsequent `extend_grant` MUST preserve
/// that usage (not rewind it) while also installing the new budget
/// and TTL. The fix wraps the extend read-compute-write in a
/// `BEGIN IMMEDIATE` transaction with an in-txn status re-check;
/// without the fix, extend's read could predate the meter's write
/// and its UPDATE would clobber the meter's usage.
///
/// SQLite file-locking via a shared on-disk path would serialize
/// two connections, but single-threaded in-memory is sufficient to
/// pin the invariant: after meter → extend, re-read must show the
/// meter's usage AND the extended budget/TTL.
#[test]
fn extend_grant_concurrent_meter_preserves_usage() {
    let store = setup();
    let persona = store.create_persona("extend-toctou").unwrap();
    // Single-statement grant with a budget; create_grant writes one
    // S0 block signed under the persona root key.
    let grant = store
        .create_grant(&persona.id, "api-key", "llm:generate", Some(3600))
        .unwrap();
    // Install a starting budget via the same helper the attenuation
    // tests use — so the chain Statement carries a tokens budget.
    attach_parent_constraints(
        &store,
        &grant.id,
        Some(Budget {
            tokens: Some(1_000),
            ..Default::default()
        }),
        3,
    );

    // Meter first: post a 100-token delta to S0. This writes a new
    // blocks_json with usage.tokens = 100.
    let meter_delta = store
        .increment_statement_usage(
            &grant.id,
            "S0",
            Usage {
                tokens: 100,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(meter_delta.current.tokens, 100);

    // Now extend: add 5_000 tokens of budget headroom + 600 more secs
    // of TTL. The fix's in-txn read must see the post-meter blocks_json
    // and preserve its usage when it re-signs block 0.
    let extended = store
        .extend_grant(&grant.id, Some(5_000), None, Some(600))
        .unwrap();

    // Budget extended: starting 1_000 + 5_000 = 6_000.
    assert_eq!(
        extended.budget.as_ref().and_then(|b| b.tokens),
        Some(6_000),
        "extend_grant must install the summed budget"
    );
    // TTL extended: new expires_at > original (non-None, later than now).
    assert!(
        extended.expires_at.is_some(),
        "extend_grant must carry an expiry"
    );

    // CRITICAL: the meter's usage=100 must still be there. A TOCTOU
    // rewind would show usage=0 (extend read a pre-meter snapshot
    // and its UPDATE overwrote the meter's commit).
    let chain = store.get_access_grant(&grant.id).unwrap();
    let s = chain
        .statements()
        .find(|(_, s)| s.sid == "S0")
        .expect("S0 present in extended chain");
    assert_eq!(
        s.1.usage.tokens, 100,
        "extend_grant must NOT rewind meter usage (TOCTOU regression)"
    );

    // Second meter delta to prove the extended grant is still
    // metereable and usage accumulates correctly on top of what
    // extend_grant preserved.
    let delta2 = store
        .increment_statement_usage(
            &grant.id,
            "S0",
            Usage {
                tokens: 50,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(delta2.prior.tokens, 100);
    assert_eq!(delta2.current.tokens, 150);
}

/// If a grant is revoked between the caller's first observation and
/// the `extend_grant` call, the in-transaction status re-check must
/// refuse the extend. This proves the TxGuard rollback path and
/// re-check work together: no partial write reaches the UPDATE.
#[test]
fn extend_grant_refuses_revoked_grant_after_initial_read() {
    let store = setup();
    let persona = store.create_persona("extend-revoke").unwrap();
    let grant = store
        .create_grant(&persona.id, "api-key", "llm:generate", Some(3600))
        .unwrap();

    // Revoke via the normal code path.
    store.revoke_grant(&grant.id).unwrap();

    // extend_grant must fail — either via the initial get_grant check
    // or the in-txn re-check. Both paths return InvalidInput with a
    // status-mentioning reason.
    let err = store
        .extend_grant(&grant.id, Some(500), None, Some(60))
        .unwrap_err();
    match err {
        StoreError::InvalidInput(reason) => {
            // Accept either the legacy status-guard message
            // ("revoked" / "status") or the post-Phase-C-2 state-machine
            // message ("grant state machine: invalid state for operation"
            // emitted by core_grants::GrantError::InvalidState).
            assert!(
                reason.contains("revoked")
                    || reason.contains("status")
                    || reason.contains("state machine")
                    || reason.contains("invalid state"),
                "expected status-guard or state-machine reject, got: {reason}"
            );
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }

    // And the grant row is still exactly 'revoked' — no partial
    // write rewound it to 'active'.
    let g = store.get_grant(&grant.id).unwrap();
    assert_eq!(g.status, "revoked");
}

// --- P69L.3 — standing parent grant with auto-delegation ---

fn setup_standing_parent(store: &DaemonStore, max_children_per_day: u64) -> (String, String) {
    let parent_persona = store.create_persona("agent-standing-parent").unwrap();
    let child_persona = store.create_persona("agent-standing-child").unwrap();
    let parent_grant = store
        .create_grant(
            &parent_persona.id,
            "delegate-key",
            "github:push:acme/*",
            Some(7 * 24 * 3600),
        )
        .unwrap();
    // Enable delegation and mark standing.
    store
        .conn()
        .execute(
            "UPDATE grants SET max_delegation_depth = 3 WHERE id = ?1",
            rusqlite::params![parent_grant.id],
        )
        .unwrap();
    store
        .mark_grant_standing(
            &parent_grant.id,
            max_children_per_day,
            Some("github:push:acme/cycle-<id>"),
        )
        .unwrap();
    (parent_grant.id, child_persona.id)
}

#[test]
fn standing_parent_creates_successfully() {
    let store = setup();
    let (parent_id, _child_persona_id) = setup_standing_parent(&store, 32);

    let info = store.get_grant(&parent_id).unwrap();
    assert!(info.is_standing, "parent must be flagged standing");
    assert_eq!(info.max_children_per_day, Some(32));
    assert_eq!(
        info.auto_delegate_scope_template.as_deref(),
        Some("github:push:acme/cycle-<id>")
    );
}

#[test]
fn mark_grant_standing_rejects_zero_limit() {
    let store = setup();
    let persona = store.create_persona("zero-limit").unwrap();
    let parent = store
        .create_grant(&persona.id, "k", "read", Some(3600))
        .unwrap();
    let err = store.mark_grant_standing(&parent.id, 0, None).unwrap_err();
    match err {
        StoreError::InvalidInput(msg) => assert!(msg.contains("> 0"), "got: {msg}"),
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[test]
fn delegate_within_limit_succeeds() {
    let store = setup();
    let (parent_id, child_persona_id) = setup_standing_parent(&store, 3);

    // Three delegations within limit all succeed.
    for i in 0..3 {
        let child = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(1800),
                None,
            )
            .unwrap_or_else(|e| panic!("delegation {i} should succeed: {e:?}"));
        assert_eq!(child.parent_grant_id.as_deref(), Some(parent_id.as_str()));
        assert_eq!(child.scope, "github:push:acme/widgets");
    }
}

#[test]
fn delegate_over_limit_rejected() {
    let store = setup();
    let (parent_id, child_persona_id) = setup_standing_parent(&store, 2);

    // First two succeed.
    for _ in 0..2 {
        store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(1800),
                None,
            )
            .unwrap();
    }

    // Third one is rejected with a ceiling-mentioning message.
    let err = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(1800),
            None,
        )
        .unwrap_err();
    match err {
        StoreError::InvalidInput(msg) => {
            assert!(
                msg.contains("standing-parent delegation ceiling"),
                "expected ceiling error, got: {msg}"
            );
            assert!(msg.contains("2/2"), "expected count/limit in msg: {msg}");
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[test]
fn non_standing_parent_skips_ceiling_gate() {
    // A classical one-shot parent with max_delegation_depth set should
    // not be subject to the standing-parent daily ceiling — even if
    // max_children_per_day were set (which it never is for these).
    let store = setup();
    let parent_persona = store.create_persona("parent-oneshot").unwrap();
    let child_persona = store.create_persona("child-oneshot").unwrap();
    let parent = store
        .create_grant(&parent_persona.id, "k", "github:push:acme/*", Some(3600))
        .unwrap();
    store
        .conn()
        .execute(
            "UPDATE grants SET max_delegation_depth = 3 WHERE id = ?1",
            rusqlite::params![parent.id],
        )
        .unwrap();

    // Three delegations should all succeed — no gate.
    for _ in 0..3 {
        store
            .delegate_grant_full(
                &parent.id,
                &child_persona.id,
                "github:push:acme/widgets",
                Some(600),
                None,
            )
            .unwrap();
    }
}

#[test]
fn revoke_standing_cascades() {
    ensure_test_identity();
    let store = setup();
    let (parent_id, child_persona_id) = setup_standing_parent(&store, 5);

    // Mint two children.
    let c1 = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(1800),
            None,
        )
        .unwrap();
    let c2 = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(1800),
            None,
        )
        .unwrap();
    seed_grant_claim_journal(
        &store,
        &c1.id,
        &child_persona_id,
        "github-token",
        "cascade-child-1",
    );
    seed_grant_claim_journal(
        &store,
        &c2.id,
        &child_persona_id,
        "github-token",
        "cascade-child-2",
    );
    assert_eq!(store.get_grant(&c1.id).unwrap().status, "active");
    assert_eq!(store.get_grant(&c2.id).unwrap().status, "active");

    // Revoke parent — children cascade.
    store.revoke_grant(&parent_id).unwrap();
    assert_eq!(store.get_grant(&parent_id).unwrap().status, "revoked");
    assert_eq!(store.get_grant(&c1.id).unwrap().status, "revoked");
    assert_eq!(store.get_grant(&c2.id).unwrap().status, "revoked");
    assert_composite_grant_v2_receipt(&store, &c1.id, TerminationReason::ParentCascadeRevoked);
    assert_composite_grant_v2_receipt(&store, &c2.id, TerminationReason::ParentCascadeRevoked);
}

#[test]
fn create_grant_emits_grant_minted_audit_event() {
    let store = setup();
    let persona = store.create_persona("agent-audit-mint").unwrap();
    let grant = store
        .create_grant_with_budget(&persona.id, "api-key", "read", Some(3600), None)
        .unwrap();

    let entries = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("grant.minted".to_string()),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(entries.len(), 1, "expected exactly one grant.minted entry");
    let entry = &entries[0];
    assert_eq!(entry.action, "grant.minted");
    assert_eq!(entry.agent_id.as_deref(), Some(persona.id.as_str()));
    assert_eq!(entry.credential.as_deref(), Some("api-key"));
    assert_eq!(entry.outcome, "minted");

    let details: serde_json::Value =
        serde_json::from_str(entry.details.as_deref().unwrap_or("{}")).unwrap();
    assert_eq!(details["grant_id"], grant.id);
    assert_eq!(details["statement_count"], 1);
    assert_eq!(details["creation_mode"], "single");
}

#[test]
fn delegate_grant_emits_grant_minted_audit_event() {
    let store = setup();
    let parent_persona = store.create_persona("agent-parent-mint").unwrap();
    let child_persona = store.create_persona("agent-child-mint").unwrap();

    let parent = store
        .create_grant(
            &parent_persona.id,
            "api-key",
            "github:push:acme/*",
            Some(3600),
        )
        .unwrap();
    store
        .conn()
        .execute(
            "UPDATE grants SET max_delegation_depth = 1 WHERE id = ?1",
            rusqlite::params![parent.id],
        )
        .unwrap();

    let child = store
        .delegate_grant_full(
            &parent.id,
            &child_persona.id,
            "github:push:acme/widgets",
            Some(1800),
            None,
        )
        .unwrap();

    let entries = store
        .query_audit(&crate::infra::audit::AuditFilter {
            action: Some("grant.minted".to_string()),
            ..Default::default()
        })
        .unwrap();

    // Both parent mint (creation_mode: "single") and child mint
    // (creation_mode: "delegate") should appear.
    assert!(
        entries.len() >= 2,
        "expected at least two grant.minted entries (parent + child)"
    );

    let delegate_entry = entries
        .iter()
        .find(|e| {
            e.details
                .as_deref()
                .and_then(|d| serde_json::from_str::<serde_json::Value>(d).ok())
                .map(|v| v["creation_mode"] == "delegate")
                .unwrap_or(false)
        })
        .expect("expected a grant.minted entry with creation_mode: delegate");

    let details: serde_json::Value =
        serde_json::from_str(delegate_entry.details.as_deref().unwrap_or("{}")).unwrap();
    assert_eq!(details["grant_id"], child.id);
    assert_eq!(details["creation_mode"], "delegate");
    assert_eq!(details["parent_grant_id"], parent.id);
}

/// Production spawn-witness emission — end-to-end:
///   1. Initialise the daemon identity (required by the emit path).
///   2. Create parent + child personas; mint a parent grant with
///      delegation depth.
///   3. Delegate to the child via `delegate_grant_full` — this is the
///      production code path the spawn-witness emitter is wired into.
///   4. Read back the persisted witness via
///      `list_spawn_witnesses_for_grants` and verify BOTH signatures
///      under their real trust anchors:
///        a. Envelope signature verifies under the daemon's pubkey
///           (proves emberd composed the receipt).
///        b. body.parent_signature verifies under the **parent
///           persona's real pubkey** loaded out of the personas
///           table — the acceptance criterion "integration test
///           verifies witness under real parent persona pubkey".
#[test]
fn delegate_grant_emits_spawn_witness_under_real_parent_persona_pubkey() {
    use core_crypto::{Ed25519Verifier, PublicKey};
    use core_events::receipt::sign::{verify_receipt_v2, verify_spawn_witness_parent_signature};

    // Daemon identity is required for the emit path — the spawn
    // witness emission no-ops when current_identity() is None.
    // Inline the same per-process tempdir pattern used by
    // `infra::receipt::tests::ensure_identity` so we share the
    // process-singleton identity rather than racing it.
    use once_cell::sync::OnceCell as SyncOnceCell;
    static INIT_DIR: SyncOnceCell<tempfile::TempDir> = SyncOnceCell::new();
    let dir = INIT_DIR.get_or_init(|| tempfile::tempdir().expect("tempdir"));
    let _ = crate::infra::receipt::init_identity(dir.path());
    let identity =
        crate::infra::receipt::current_identity().expect("identity initialised by the line above");
    let daemon_pubkey_hex = identity.pubkey_hex();

    let store = setup();
    let parent_persona = store.create_persona("agent-spawn-witness-parent").unwrap();
    let child_persona = store.create_persona("agent-spawn-witness-child").unwrap();

    let parent = store
        .create_grant(
            &parent_persona.id,
            "api-key",
            "github:push:acme/*",
            Some(3600),
        )
        .unwrap();
    store
        .conn()
        .execute(
            "UPDATE grants SET max_delegation_depth = 1 WHERE id = ?1",
            rusqlite::params![parent.id],
        )
        .unwrap();

    let child = store
        .delegate_grant_full(
            &parent.id,
            &child_persona.id,
            "github:push:acme/widgets",
            Some(1800),
            None,
        )
        .expect("delegation succeeds");

    // Read the persisted witnesses for the parent grant edge.
    let witnesses = store
        .list_spawn_witnesses_for_grants(&[parent.id.clone()])
        .expect("list_spawn_witnesses_for_grants succeeds");
    assert_eq!(
        witnesses.len(),
        1,
        "exactly one spawn.witness must be persisted for the parent→child edge"
    );
    let (envelope, parent_persona_id_in_row) = &witnesses[0];

    assert_eq!(envelope.kind, "spawn.witness");
    assert_eq!(parent_persona_id_in_row, &parent_persona.id);

    // Body shape: the four fields must reflect the delegation, with
    // a populated `parent_signature` in canonical wire form.
    let body = envelope.body.as_object().expect("body is object");
    assert_eq!(body["spawned_persona_id"], child_persona.id);
    assert_eq!(body["parent_persona_id"], parent_persona.id);
    assert_eq!(body["spawn_grant_id"], parent.id);
    assert!(
        body["parent_signature"]
            .as_str()
            .map(|s| s.starts_with("ed25519sig:"))
            .unwrap_or(false),
        "parent_signature must be in ed25519sig:<hex> form",
    );

    // (a) Envelope signature verifies under the daemon's pubkey.
    let daemon_pk = PublicKey(format!("ed25519:{daemon_pubkey_hex}"));
    verify_receipt_v2(envelope, &daemon_pk, &Ed25519Verifier)
        .expect("envelope signature verifies under daemon pubkey");

    // (b) body.parent_signature verifies under the REAL parent persona's
    //     pubkey loaded out of the personas table. This is the
    //     acceptance criterion — the witness must be cryptographically
    //     bound to the parent persona's actual key material, not to a
    //     daemon-stand-in.
    let parent_pubkey = store
        .get_persona(&parent_persona.id)
        .expect("parent persona row")
        .public_key;
    assert!(
        parent_pubkey.starts_with("ed25519:"),
        "persona pubkey stored in canonical wire form",
    );
    // The parent's persona pubkey MUST be distinct from the daemon's —
    // proves the dual-signature is meaningful, not two signatures from
    // the same key.
    assert_ne!(
        parent_pubkey,
        format!("ed25519:{daemon_pubkey_hex}"),
        "parent persona pubkey must differ from daemon pubkey",
    );
    verify_spawn_witness_parent_signature(
        &envelope.body,
        &PublicKey(parent_pubkey.clone()),
        &Ed25519Verifier,
    )
    .expect("body.parent_signature verifies under real parent persona pubkey");

    // CRIT-7 regression guard: swapping the trust anchors must fail
    // — otherwise the dual-signature design is collapsed.
    assert!(
        verify_spawn_witness_parent_signature(&envelope.body, &daemon_pk, &Ed25519Verifier)
            .is_err(),
        "parent_signature must NOT verify under the daemon pubkey",
    );
    assert!(
        verify_receipt_v2(envelope, &PublicKey(parent_pubkey), &Ed25519Verifier).is_err(),
        "envelope signature must NOT verify under the parent persona pubkey",
    );

    // The child grant row must still reference the parent.
    assert_eq!(child.parent_grant_id.as_deref(), Some(parent.id.as_str()));
}

// --- T2: DaemonGrantStore adapter tests (ADR 114 §5 T2) ---

fn parse_grant_uuid(id: &str) -> uuid::Uuid {
    let raw = id.strip_prefix("grant-").unwrap_or(id);
    uuid::Uuid::parse_str(raw).expect("valid grant uuid")
}

#[test]
fn test_daemon_grant_store_load_roundtrip() {
    let store = setup();
    let persona = store.create_persona("adapter-roundtrip").unwrap();
    let grant_info = store
        .create_grant(&persona.id, "api-key", "read", Some(3600))
        .unwrap();

    let adapter = DaemonGrantStore::new(&store);
    let uuid = parse_grant_uuid(&grant_info.id);
    let core_grant = GrantStore::load(&adapter, uuid).unwrap();

    assert_eq!(core_grant.id, uuid);
    assert_eq!(core_grant.issuer.0, persona.id);
    assert_eq!(core_grant.state, core_grants::GrantState::Active);
    assert!(core_grant.expires_at.is_some());
}

#[test]
fn test_daemon_grant_store_save_updates_status() {
    let store = setup();
    let persona = store.create_persona("adapter-save").unwrap();
    let grant_info = store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();

    let adapter = DaemonGrantStore::new(&store);
    let uuid = parse_grant_uuid(&grant_info.id);
    let mut core_grant = GrantStore::load(&adapter, uuid).unwrap();
    core_grant.state = core_grants::GrantState::Paused;
    GrantStore::save(&adapter, &core_grant).unwrap();

    let updated = store.get_grant(&grant_info.id).unwrap();
    assert_eq!(updated.status, "paused");
}

#[test]
fn test_daemon_grant_store_list_active() {
    let store = setup();
    let persona = store.create_persona("adapter-list").unwrap();
    let g1 = store
        .create_grant(&persona.id, "key-a", "read", None)
        .unwrap();
    let g2 = store
        .create_grant(&persona.id, "key-b", "read", None)
        .unwrap();
    // Revoke g2 so only g1 appears in list_active.
    store.revoke_grant(&g2.id).unwrap();

    let adapter = DaemonGrantStore::new(&store);
    let active = GrantStore::list_active(&adapter, &persona.id).unwrap();

    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, parse_grant_uuid(&g1.id));
}

#[test]
fn test_daemon_grant_store_revoke_via_adapter() {
    let store = setup();
    let persona = store.create_persona("adapter-revoke").unwrap();
    let grant_info = store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();

    let adapter = DaemonGrantStore::new(&store);
    adapter.revoke_grant(&grant_info.id).unwrap();

    let updated = store.get_grant(&grant_info.id).unwrap();
    assert_eq!(updated.status, "revoked");
}

#[test]
fn test_daemon_grant_store_pause_resume_via_adapter() {
    let store = setup();
    let persona = store.create_persona("adapter-pause-resume").unwrap();
    let grant_info = store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();

    let adapter = DaemonGrantStore::new(&store);
    adapter.pause_grant(&grant_info.id).unwrap();
    assert_eq!(store.get_grant(&grant_info.id).unwrap().status, "paused");

    adapter.resume_grant(&grant_info.id).unwrap();
    assert_eq!(store.get_grant(&grant_info.id).unwrap().status, "active");
}

#[test]
fn test_daemon_grant_store_revoke_cascade_via_adapter() {
    // Parent grant, child grant; revoke parent via adapter;
    // assert child is also revoked (cascade is handled by DaemonStore::revoke_grant).
    let store = setup();
    let parent_persona = store.create_persona("cascade-parent").unwrap();
    let child_persona = store.create_persona("cascade-child").unwrap();

    let parent = store
        .create_grant(
            &parent_persona.id,
            "api-key",
            "github:push:acme/*",
            Some(3600),
        )
        .unwrap();
    store
        .conn()
        .execute(
            "UPDATE grants SET max_delegation_depth = 1 WHERE id = ?1",
            rusqlite::params![parent.id],
        )
        .unwrap();
    let child = store
        .delegate_grant_full(
            &parent.id,
            &child_persona.id,
            "github:push:acme/widgets",
            Some(1800),
            None,
        )
        .unwrap();

    let adapter = DaemonGrantStore::new(&store);
    adapter.revoke_grant(&parent.id).unwrap();

    // Parent must be revoked.
    assert_eq!(store.get_grant(&parent.id).unwrap().status, "revoked");
    // Child must also be revoked (cascade).
    assert_eq!(store.get_grant(&child.id).unwrap().status, "revoked");
}

// ---- ADR191_PAYMENT_BUILD_AHEAD: payment reserve/settle lane ----------
// These tests exercise the preserved ADR 191 payment substrate
// (reserve_payment_tool_call → evaluate_payment_tool_call) directly. The
// PreToolUse hook that formerly entered this lane was retired;
// the payment lane itself is build-ahead and kept proven by these tests.

#[test]
fn payment_within_cap_emits_reserved_receipt() {
    ensure_test_identity();
    let store = setup();
    let persona = store.create_persona("payment-allow").unwrap();
    let grant_id = seed_multi_stmt_grant(
        &store,
        &persona.id,
        "clearbit-rail",
        vec![payment_stmt("P1", "clearbit", 75, 75)],
    );

    let decision = store
        .reserve_payment_tool_call(
            "payment-allow",
            "payment:charge",
            &serde_json::json!({
                "attempt_id": "attempt-allow-1",
                "vendor": "clearbit",
                "amount_cents": 49,
            }),
            None,
            Some(&grant_id),
        )
        .unwrap();

    assert!(
        decision.permit,
        "within-cap payment must permit: {decision:?}"
    );
    assert_eq!(decision.grant_id.as_deref(), Some(grant_id.as_str()));
    let receipts = payment_evaluated_receipts(&store, &grant_id);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].state, PaymentEvaluatedState::Reserved);
    assert_eq!(receipts[0].statement_sid, "P1");
    assert_eq!(receipts[0].amount_cents, 49);
    assert_eq!(receipts[0].vendor, "clearbit");
    assert!(receipts[0].reserved_until.is_some());
}

#[test]
fn payment_over_threshold_creates_approval_request() {
    ensure_test_identity();
    let store = setup();
    let persona = store.create_persona("payment-approval").unwrap();
    let grant_id = seed_multi_stmt_grant(
        &store,
        &persona.id,
        "clearbit-rail",
        vec![payment_stmt("P1", "clearbit", 500, 50)],
    );

    let decision = store
        .reserve_payment_tool_call(
            "payment-approval",
            "payment:charge",
            &serde_json::json!({
                "attempt_id": "attempt-approval-1",
                "vendor": "clearbit",
                "amount_cents": 120,
            }),
            None,
            Some(&grant_id),
        )
        .unwrap();

    assert!(!decision.permit);
    let approval_id = decision
        .await_approval_request_id
        .as_deref()
        .expect("over-threshold attempt must mint approval row");
    let approval = store.get_approval(approval_id).unwrap();
    assert_eq!(approval.status, "pending");
    let receipts = payment_evaluated_receipts(&store, &grant_id);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].state, PaymentEvaluatedState::EscalationRequired);
    assert_eq!(
        receipts[0].approval_request_id.as_deref(),
        Some(approval_id)
    );
}

#[test]
fn payment_retry_after_approval_allows_without_new_grant() {
    ensure_test_identity();
    let store = setup();
    let persona = store.create_persona("payment-approved").unwrap();
    let grant_id = seed_multi_stmt_grant(
        &store,
        &persona.id,
        "clearbit-rail",
        vec![payment_stmt("P1", "clearbit", 500, 50)],
    );
    let params = serde_json::json!({
        "attempt_id": "attempt-approved-1",
        "vendor": "clearbit",
        "amount_cents": 120,
    });

    let first = store
        .reserve_payment_tool_call(
            "payment-approved",
            "payment:charge",
            &params,
            None,
            Some(&grant_id),
        )
        .unwrap();
    let approval_id = first.await_approval_request_id.unwrap();
    store
        .resolve_approval(
            &approval_id,
            &crate::trust::approval::ApprovalOutcome::Approved,
        )
        .unwrap();

    let second = store
        .reserve_payment_tool_call(
            "payment-approved",
            "payment:charge",
            &params,
            None,
            Some(&grant_id),
        )
        .unwrap();

    assert!(second.permit, "approved retry must permit: {second:?}");
    assert_eq!(
        store.list_grants().unwrap().len(),
        1,
        "decision-only approval must not mint an extra grant"
    );
    let receipts = payment_evaluated_receipts(&store, &grant_id);
    assert_eq!(receipts.len(), 2);
    assert_eq!(
        receipts
            .iter()
            .map(|body| body.state)
            .collect::<Vec<PaymentEvaluatedState>>(),
        vec![
            PaymentEvaluatedState::EscalationRequired,
            PaymentEvaluatedState::Reserved
        ]
    );
}

#[test]
fn payment_sweeps_expired_reservations() {
    ensure_test_identity();
    let store = setup();
    let persona = store.create_persona("payment-expiry").unwrap();
    let grant_id = seed_multi_stmt_grant(
        &store,
        &persona.id,
        "clearbit-rail",
        vec![payment_stmt("P1", "clearbit", 75, 75)],
    );

    store
        .reserve_payment_tool_call(
            "payment-expiry",
            "payment:charge",
            &serde_json::json!({
                "attempt_id": "attempt-expire-1",
                "vendor": "clearbit",
                "amount_cents": 60,
            }),
            None,
            Some(&grant_id),
        )
        .unwrap();

    let (receipt_id, _, _, mut envelope) = store
        .list_receipts_v2_envelopes(&[grant_id.clone()])
        .unwrap()
        .into_iter()
        .find(|(_, kind, _, _)| kind == RECEIPT_KIND_PAYMENT_EVALUATED)
        .expect("reserved receipt");
    let mut body: PaymentEvaluatedBody = serde_json::from_value(envelope.body.clone()).unwrap();
    body.reserved_until = Some("2000-01-01T00:00:00Z".to_string());
    envelope.body = serde_json::to_value(&body).unwrap();
    store
        .conn()
        .execute(
            "UPDATE receipts SET receipt_json = ?1 WHERE id = ?2",
            rusqlite::params![serde_json::to_string(&envelope).unwrap(), receipt_id],
        )
        .unwrap();

    let decision = store
        .reserve_payment_tool_call(
            "payment-expiry",
            "payment:charge",
            &serde_json::json!({
                "attempt_id": "attempt-expire-2",
                "vendor": "clearbit",
                "amount_cents": 30,
            }),
            None,
            Some(&grant_id),
        )
        .unwrap();

    assert!(decision.permit, "expired reservation must release capacity");
    let settled = payment_settled_receipts(&store, &grant_id);
    assert!(settled.iter().any(|body| {
        body.state == PaymentSettledState::Expired && body.attempt_id == "attempt-expire-1"
    }));
}

#[tokio::test]
async fn settle_payment_attempt_with_mock_rail_refuses_unverified_commit() {
    ensure_test_identity();
    let store = setup();
    let persona = store.create_persona("payment-mock-inconsistent").unwrap();
    let grant_id = seed_multi_stmt_grant(
        &store,
        &persona.id,
        "clearbit-rail",
        vec![payment_stmt("P1", "clearbit", 500, 500)],
    );

    let decision = store
        .reserve_payment_tool_call(
            "payment-mock-inconsistent",
            "payment:charge",
            &serde_json::json!({
                "attempt_id": "attempt-mock-inconsistent-1",
                "vendor": "clearbit",
                "amount_cents": 49,
            }),
            None,
            Some(&grant_id),
        )
        .unwrap();
    assert!(decision.permit);

    let rail = MockRailAdapter::new();
    let accepted = rail
        .attempt(RailSpendAttempt {
            rail_scope: serde_json::json!({"publisher": "ember-systems", "account": "acct_demo"}),
            amount_minor: 49,
            currency: "usd".to_string(),
            contract_id: Some("contract-payment-demo".to_string()),
            action_ref: None,
            workspace_ref: None,
            caller_ref: None,
            authority_ref: Some(grant_id.clone()),
            idempotency_key: Some("idem-mock-inconsistent-1".to_string()),
            ephemeral_sign_public_key: None,
            reason: "unit test".to_string(),
            metadata: None,
        })
        .await
        .expect("attempt");
    let outcome = RailOutcomeReport {
        state: RailSettlementState::Committed,
        rail_reference: Some("mock-charge-inconsistent".to_string()),
        idempotency_key: Some("idem-mock-inconsistent-1".to_string()),
        committed_claim: None,
        metadata: None,
    };
    rail.report_outcome(&accepted.attempt_id, outcome.clone())
        .await
        .expect("report committed");
    rail.set_failure_mode(MockRailFailureMode::VerificationInconsistent);

    let err = store
        .settle_payment_attempt_with_rail(
            &grant_id,
            "attempt-mock-inconsistent-1",
            &accepted,
            &outcome,
            &rail,
        )
        .await
        .expect_err("inconsistent verification must refuse commit");
    assert!(
        err.to_string()
            .contains("could not confirm committed outcome"),
        "error should name failed side-channel verification: {err}"
    );
    assert!(
        payment_settled_receipts(&store, &grant_id).is_empty(),
        "unverified commit must not emit payment.settled"
    );
}

#[tokio::test]
async fn mock_rail_demo_path_walks_ceo_013_beats() {
    ensure_test_identity();
    let store = setup();
    let persona = store.create_persona("payment-demo").unwrap();
    let grant_id = seed_multi_stmt_grant(
        &store,
        &persona.id,
        "clearbit-rail",
        vec![Statement {
            sid: "P1".into(),
            resource_type: ResourceType::Payment,
            actions: vec!["payment:charge".into()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                cents: Some(50_000),
                ..Default::default()
            }),
            usage: Usage::default(),
            conditions: vec![
                Condition::MerchantAllowlist {
                    merchants: vec!["clearbit".into()],
                },
                Condition::Range {
                    field: "amount_cents".into(),
                    min: Some(0),
                    max: Some(7_500),
                },
            ],
            can_delegate: None,
        }],
    );

    let allow = store
        .reserve_payment_tool_call(
            "payment-demo",
            "payment:charge",
            &serde_json::json!({
                "attempt_id": "attempt-demo-allow-1",
                "vendor": "clearbit",
                "amount_cents": 4_900,
            }),
            None,
            Some(&grant_id),
        )
        .unwrap();
    assert!(allow.permit, "within-cap payment must reserve: {allow:?}");

    let rail = MockRailAdapter::new();
    let accepted = rail
        .attempt(RailSpendAttempt {
            rail_scope: serde_json::json!({
                "publisher": "ember-systems",
                "account": "acct_demo",
            }),
            amount_minor: 4_900,
            currency: "usd".to_string(),
            contract_id: Some("contract-payment-demo".to_string()),
            action_ref: None,
            workspace_ref: None,
            caller_ref: None,
            authority_ref: Some(grant_id.clone()),
            idempotency_key: Some("idem-demo-allow-1".to_string()),
            ephemeral_sign_public_key: None,
            reason: "ceo-013 demo".to_string(),
            metadata: Some(serde_json::json!({"merchant_ref": "demo-order-1"})),
        })
        .await
        .expect("rail accepts allowed attempt");
    let committed = RailOutcomeReport {
        state: RailSettlementState::Committed,
        rail_reference: Some("mock-charge-demo-1".to_string()),
        idempotency_key: Some("idem-demo-allow-1".to_string()),
        committed_claim: None,
        metadata: None,
    };
    rail.report_outcome(&accepted.attempt_id, committed.clone())
        .await
        .expect("mock rail records committed outcome");
    store
        .settle_payment_attempt_with_rail(
            &grant_id,
            "attempt-demo-allow-1",
            &accepted,
            &committed,
            &rail,
        )
        .await
        .expect("daemon settles committed outcome");

    let after_allow = store
        .get_access_grant(&grant_id)
        .expect("grant after allow");
    let stmt = after_allow
        .statements()
        .find(|(_, stmt)| stmt.sid == "P1")
        .expect("payment statement")
        .1;
    assert_eq!(stmt.usage.cents, 4_900);
    assert_eq!(stmt.usage.cents_micro, 4_900_000_000);
    let settled = payment_settled_receipts(&store, &grant_id);
    assert!(settled.iter().any(|body| {
        body.state == PaymentSettledState::Committed
            && body.attempt_id == "attempt-demo-allow-1"
            && body.rail_reference.as_deref() == Some("mock-charge-demo-1")
    }));

    let denied = store
        .reserve_payment_tool_call(
            "payment-demo",
            "payment:charge",
            &serde_json::json!({
                "attempt_id": "attempt-demo-deny-1",
                "vendor": "unknown-vendor",
                "amount_cents": 30_000,
            }),
            None,
            Some(&grant_id),
        )
        .unwrap();
    assert!(!denied.permit, "unknown vendor must deny");
    assert!(
        denied
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("allowlisted")),
        "denial reason should name the allowlist gate: {denied:?}"
    );

    let escalation_params = serde_json::json!({
        "attempt_id": "attempt-demo-escalate-1",
        "vendor": "clearbit",
        "amount_cents": 30_000,
    });
    let escalate = store
        .reserve_payment_tool_call(
            "payment-demo",
            "payment:charge",
            &escalation_params,
            None,
            Some(&grant_id),
        )
        .unwrap();
    assert!(
        !escalate.permit && escalate.await_approval_request_id.is_some(),
        "over-threshold payment must require approval: {escalate:?}"
    );
    let approval_id = escalate.await_approval_request_id.clone().unwrap();
    store
        .resolve_approval(
            &approval_id,
            &crate::trust::approval::ApprovalOutcome::Approved,
        )
        .unwrap();
    let approved_retry = store
        .reserve_payment_tool_call(
            "payment-demo",
            "payment:charge",
            &escalation_params,
            None,
            Some(&grant_id),
        )
        .unwrap();
    assert!(
        approved_retry.permit,
        "approved retry must reserve successfully: {approved_retry:?}"
    );

    store.revoke_grant(&grant_id).expect("revoke grant");
    let post_revoke = store
        .reserve_payment_tool_call(
            "payment-demo",
            "payment:charge",
            &serde_json::json!({
                "attempt_id": "attempt-demo-post-revoke-1",
                "vendor": "clearbit",
                "amount_cents": 2_000,
            }),
            None,
            Some(&grant_id),
        )
        .unwrap();
    assert!(
        !post_revoke.permit,
        "revoked grant must refuse further spend attempts"
    );
    assert!(
        post_revoke
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("no active grant")),
        "post-revoke denial should explain active grant absence: {post_revoke:?}"
    );

    let evaluated = payment_evaluated_receipts(&store, &grant_id);
    assert_eq!(
        evaluated
            .iter()
            .map(|body| body.state)
            .collect::<Vec<PaymentEvaluatedState>>(),
        vec![
            PaymentEvaluatedState::Reserved,
            PaymentEvaluatedState::Denied,
            PaymentEvaluatedState::EscalationRequired,
            PaymentEvaluatedState::Reserved,
        ]
    );
}

#[test]
fn tool_call_decision_round_trips_via_serde_json() {
    let d = ToolCallDecision {
        permit: true,
        reason: Some("hi".to_string()),
        grant_id: Some("grant-xyz".to_string()),
        emitted_event_id: "42".to_string(),
        await_approval_request_id: None,
    };
    let wire = serde_json::to_string(&d).unwrap();
    let back: ToolCallDecision = serde_json::from_str(&wire).unwrap();
    assert_eq!(back, d);
}

// --- derive_wall_clock_secs unit tests ---

#[test]
fn wall_clock_derive_mid_grant() {
    // Grant created at T=0, queried at T=30, budget cap 75s.
    // Expected: 30 (mid-flight, not clamped).
    let result = derive_wall_clock_secs(30, 0, None, Some(75));
    assert_eq!(result, 30);
}

#[test]
fn wall_clock_derive_post_expiry_clamped_to_cap() {
    // Grant created at T=0, budget cap 75s, expires_at=75, queried at T=80.
    // Expected: 75 (clamped to cap because now > expires_at).
    let result = derive_wall_clock_secs(80, 0, Some(75), Some(75));
    assert_eq!(result, 75);
}

#[test]
fn wall_clock_derive_post_expiry_no_cap() {
    // Grant with no wall_clock budget, created at T=100, expires at T=200,
    // queried at T=250. Expected: 100 (expires_at - created_at, not clamped).
    let result = derive_wall_clock_secs(250, 100, Some(200), None);
    assert_eq!(result, 100);
}

#[test]
fn wall_clock_derive_before_created_at_clamps_to_zero() {
    // Pathological: now < created_at (clock skew). Must not underflow.
    let result = derive_wall_clock_secs(5, 100, None, Some(200));
    assert_eq!(result, 0);
}

#[test]
fn wall_clock_derive_active_no_cap_returns_elapsed() {
    // TTL-only grant (no wall_clock budget), elapsed 42s.
    let result = derive_wall_clock_secs(1042, 1000, None, None);
    assert_eq!(result, 42);
}

#[test]
fn wall_clock_derive_expired_but_expires_at_after_cap() {
    // expires_at > cap: result still clamped to budget cap.
    // created=0, expires_at=200, cap=75, now=300.
    // effective_end = min(expires_at=200, now=300) = 200
    // elapsed = 200 - 0 = 200; clamped to cap=75 => 75.
    let result = derive_wall_clock_secs(300, 0, Some(200), Some(75));
    assert_eq!(result, 75);
}

/// Property: derive_wall_clock_secs always returns a value in [0, budget_cap].
#[test]
fn wall_clock_derive_property_in_budget_range() {
    // Enumerate a grid of (now, created_at, expires_at, cap) and assert invariant.
    for &created in &[0u64, 100, 1000] {
        for &elapsed in &[0u64, 1, 30, 75, 80, 200] {
            let now = created.saturating_add(elapsed);
            for &cap in &[None, Some(0u64), Some(1), Some(75), Some(200)] {
                for &expires_at in &[
                    None,
                    Some(created + 50),
                    Some(created + 75),
                    Some(created + 200),
                ] {
                    let result = derive_wall_clock_secs(now, created, expires_at, cap);
                    if let Some(c) = cap {
                        assert!(
                            result <= c,
                            "result={result} exceeded cap={c} \
                                 (now={now}, created={created}, expires_at={expires_at:?})"
                        );
                    }
                }
            }
        }
    }
}

// -----------------------------------------------------------------------
// ADR 205 §A.3 / §A.4 — store-backed verification seams (BKR-4b-4)
// -----------------------------------------------------------------------

use crate::trust::use_time_verify::{GrantAncestry, PersonaRootAuthority};

/// Build a real parent→child→grandchild delegation chain via the
/// production delegation path (so `parent_grant_id` is set the way the
/// daemon actually sets it). Returns `(parent_id, child_id, grandchild_id)`.
fn delegation_chain(store: &DaemonStore) -> (String, String, String) {
    let (parent_id, child_persona_id) = setup_parent_with_budget(store, 10_000, 1800);
    let child = store
        .delegate_grant_full(
            &parent_id,
            &child_persona_id,
            "github:push:acme/widgets",
            Some(600),
            Some(Budget {
                tokens: Some(3_000),
                ..Default::default()
            }),
        )
        .expect("child delegate approved");
    let grandchild_persona = store.create_persona("agent-grandchild").unwrap();
    let grandchild = store
        .delegate_grant_full(
            &child.id,
            &grandchild_persona.id,
            "github:push:acme/widgets",
            Some(60),
            Some(Budget {
                tokens: Some(1_000),
                ..Default::default()
            }),
        )
        .expect("grandchild delegate approved");
    (parent_id, child.id, grandchild.id)
}

#[test]
fn ancestor_ids_empty_for_apex_grant() {
    let store = setup();
    let (parent_id, _child, _gc) = delegation_chain(&store);
    // The apex (parent) grant has no `parent_grant_id` → no ancestry.
    assert!(store.ancestor_ids(&parent_id).is_empty());
}

#[test]
fn ancestor_ids_walks_chain_nearest_parent_first() {
    let store = setup();
    let (parent_id, child_id, grandchild_id) = delegation_chain(&store);
    assert_eq!(
        store.ancestor_ids(&grandchild_id),
        vec![child_id.clone(), parent_id.clone()]
    );
    assert_eq!(store.ancestor_ids(&child_id), vec![parent_id]);
}

#[test]
fn ancestor_grant_ids_accessor_matches_walk() {
    // BKR-4c (ADR 205 §A.2): the public ancestry accessor mirrors the
    // GrantAncestry walk (nearest-parent first, apex last).
    let store = setup();
    let (parent_id, child_id, grandchild_id) = delegation_chain(&store);
    assert!(store.ancestor_grant_ids(&parent_id).is_empty());
    assert_eq!(
        store.ancestor_grant_ids(&grandchild_id),
        vec![child_id, parent_id]
    );
}

#[test]
fn grant_chain_edges_projection_derives_depth_parent_and_summary() {
    // BKR-4c (ADR 205 §A.2): the chain-edges projection is DERIVED from the
    // canonical embed (parent_grant_id ancestry + each grant's signed
    // statements) — regenerable, carries no independent trust.
    let store = setup();
    let (parent_id, child_id, grandchild_id) = delegation_chain(&store);
    let edges = store.grant_chain_edges().expect("projection regenerates");
    let by_id = |id: &str| edges.iter().find(|e| e.grant_id == id).cloned();

    let apex = by_id(&parent_id).expect("apex edge present");
    assert_eq!(apex.depth, 0, "apex has no ancestry");
    assert_eq!(apex.parent_grant_id, None);
    assert_eq!(apex.status, "active");
    assert!(
        !apex.statement_summary.is_empty(),
        "summary derived from the embedded chain"
    );

    let child = by_id(&child_id).expect("child edge present");
    assert_eq!(child.depth, 1);
    assert_eq!(child.parent_grant_id.as_deref(), Some(parent_id.as_str()));

    let grandchild = by_id(&grandchild_id).expect("grandchild edge present");
    assert_eq!(grandchild.depth, 2);
    assert_eq!(
        grandchild.parent_grant_id.as_deref(),
        Some(child_id.as_str())
    );

    // Regenerable: a second materialization is byte-identical.
    assert_eq!(store.grant_chain_edges().unwrap(), edges);
}

#[test]
fn first_revoked_grant_ancestor_none_for_clean_chain() {
    let store = setup();
    let (_parent, _child, grandchild_id) = delegation_chain(&store);
    assert_eq!(store.first_revoked_grant_ancestor(&grandchild_id), None);
}

#[test]
fn first_revoked_grant_ancestor_catches_revoked_parent_with_active_leaf() {
    let store = setup();
    let (parent_id, child_id, grandchild_id) = delegation_chain(&store);

    // Simulate the eager `cascade_revoke_children` write NOT reaching the
    // descendants (crash mid-cascade / a race / a presented embed-chain):
    // flip ONLY the parent's status directly, leaving child + grandchild
    // `active`. The online walk must still refuse — this is the exact hole
    // §A.4 closes that `resolve_need_against_grants` (leaf-only) misses.
    store
        .conn()
        .execute(
            "UPDATE grants SET status = 'revoked' WHERE id = ?1",
            rusqlite::params![parent_id],
        )
        .unwrap();

    // Leaf grandchild is still `active`...
    assert_eq!(store.get_grant(&grandchild_id).unwrap().status, "active");
    // ...but the walk finds the revoked apex.
    let revoked = store
        .first_revoked_grant_ancestor(&grandchild_id)
        .expect("revoked parent must block descendant use");
    assert_eq!(revoked.grant_id, parent_id);
    assert_eq!(revoked.reason, core_grants::AncestorRevocation::Revoked);

    // The intermediate child (direct descendant of the revoked apex) is
    // blocked too.
    assert_eq!(
        store
            .first_revoked_grant_ancestor(&child_id)
            .map(|r| r.grant_id),
        Some(parent_id),
    );
}

#[test]
fn first_revoked_grant_ancestor_absent_when_ancestor_reaped() {
    let store = setup();
    let (parent_id, _child, grandchild_id) = delegation_chain(&store);

    // Reap the apex row entirely. A holder cannot prove a vanished ancestor
    // was still valid → fail-closed `Absent` (the nearest missing ancestor
    // is reported).
    store
        .conn()
        .execute(
            "DELETE FROM grants WHERE id = ?1",
            rusqlite::params![parent_id],
        )
        .unwrap();
    let revoked = store
        .first_revoked_grant_ancestor(&grandchild_id)
        .expect("reaped ancestor must fail closed");
    assert_eq!(revoked.grant_id, parent_id);
    assert_eq!(revoked.reason, core_grants::AncestorRevocation::Absent);
}

#[test]
fn authorized_root_pubkey_resolves_known_persona_and_none_for_unknown() {
    let store = setup();
    let persona = store.create_persona("agent-root-auth").unwrap();
    // A freshly-created persona has a stored Ed25519 root key → Some.
    assert!(
        PersonaRootAuthority::authorized_root_pubkey(&store, &persona.id).is_some(),
        "known persona must resolve a root pubkey (transitional dev0 impl)"
    );
    // An unknown persona resolves nothing → composition fails closed.
    assert!(
        PersonaRootAuthority::authorized_root_pubkey(&store, "persona-does-not-exist").is_none()
    );
}
