use super::*;
use crate::infra::store::DaemonStore;

/// Make sure the process-singleton identity is initialised, then
/// return it. We use a shared tempdir per-process so every receipt
/// test signs/verifies against the same keypair — eliminating the
/// race that bit us when each test generated its own identity but
/// `revoke_grant` used the OnceCell pubkey.
fn ensure_identity() -> &'static DaemonPersona {
    static INIT_DIR: OnceCell<tempfile::TempDir> = OnceCell::new();
    let dir = INIT_DIR.get_or_init(|| tempfile::tempdir().expect("tempdir"));
    let _ = init_identity(dir.path());
    current_identity().expect("identity was just initialised")
}

/// SEC-S5-V030-AUDIT-CHAIN-B — journal append + mode-drift refusal.
#[test]
fn receipts_journal_appends_line_at_mode_0600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let receipt = serde_json::json!({
        "kind": "test.receipt",
        "id": "01J0000000000000000000000B",
        "ts": "2026-05-13T23:59:00Z",
    });

    append_receipts_journal(dir.path(), &receipt).expect("first append");

    let path = dir.path().join("receipts.log");
    let meta = std::fs::metadata(&path).expect("metadata");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "receipts.log must be mode 0600, got {:#o}",
        mode
    );

    let body = std::fs::read_to_string(&path).expect("read");
    assert!(body.ends_with('\n'), "line terminator must be \\n");
    let parsed: serde_json::Value = serde_json::from_str(body.trim_end()).expect("parse");
    assert_eq!(parsed["kind"], "test.receipt");

    // Second append must not truncate the first.
    let receipt2 = serde_json::json!({"kind": "test.receipt", "id": "02"});
    append_receipts_journal(dir.path(), &receipt2).expect("second append");
    let body2 = std::fs::read_to_string(&path).expect("read 2");
    assert_eq!(
        body2.lines().count(),
        2,
        "second append should result in 2 lines, got {}",
        body2.lines().count()
    );

    // Drift the mode to 0644 and confirm the next write refuses.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod 0644");
    match append_receipts_journal(dir.path(), &serde_json::json!({"kind": "x"})) {
        Err(JournalError::InsecureMode { mode }) => {
            assert_eq!(
                mode & 0o777,
                0o644,
                "expected 0644 in error, got {:#o}",
                mode
            );
        }
        other => panic!("expected InsecureMode error, got {:?}", other),
    }
}

#[test]
fn identity_round_trips_through_file() {
    let dir = tempfile::tempdir().unwrap();
    let id1 = DaemonPersona::load_or_create(dir.path()).unwrap();
    let pk1 = id1.pubkey_hex();
    drop(id1);
    let id2 = DaemonPersona::load_or_create(dir.path()).unwrap();
    assert_eq!(id2.pubkey_hex(), pk1, "second load returns same pubkey");
    assert_eq!(pk1.len(), 64, "pubkey hex must be 64 chars");
}

#[test]
fn emit_receipt_creates_signed_artifact() {
    let identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-a").unwrap();
    let grant = store
        .create_grant(&persona.id, "github-token", "push", None)
        .unwrap();
    // revoke_grant triggers receipt emission via the OnceCell identity.
    store.revoke_grant(&grant.id).unwrap();

    let info = store.get_grant(&grant.id).unwrap();
    let rid = info.receipt_id.expect("terminal grant has receipt_id");
    let r = store.get_receipt(&rid).unwrap();
    assert_eq!(r.grant_id, grant.id);
    assert_eq!(r.evidence.canonical_version, CANONICAL_VERSION);
    assert_eq!(r.evidence.sig.len(), 128, "sig hex is 128 chars");
    assert_eq!(r.evidence.hash.len(), 64);
    assert_eq!(r.evidence.signer_pubkey, identity.pubkey_hex());
    verify_receipt(&r, &identity.pubkey_hex()).expect("own-signed receipt verifies");
}

// -----------------------------------------------------------------
// ADR 157 §Component 5 — `dev_mode_active` Receipt stamp tests.
// T2-shape (integration across binary_manifest's process-global
// flag + the receipt builder).
// -----------------------------------------------------------------

#[test]
fn receipt_stamps_dev_mode_active_false_in_prod_mode() {
    // Pre-condition: prod daemon (no `EMBER_TRUST_ROOTS` supplied)
    // leaves the process-global flag at its default `false`. Receipts
    // emitted during this run carry `dev_mode_active: false`.
    //
    // Defensive: explicitly set the flag to false in case a prior
    // test in the same binary flipped it to true.
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    crate::binary_manifest::set_dev_mode_active(false);

    let _identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-prod").unwrap();
    let grant = store
        .create_grant(&persona.id, "github-token", "push", None)
        .unwrap();
    store.revoke_grant(&grant.id).unwrap();
    let rid = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
    let r = store.get_receipt(&rid).unwrap();
    assert!(
        !r.dev_mode_active,
        "prod-mode receipt must stamp dev_mode_active: false; got {}",
        r.dev_mode_active
    );
}

#[test]
fn receipt_stamps_dev_mode_active_true_under_dev_trust_root_config() {
    // Pre-condition: dev daemon (operator supplied
    // `EMBER_TRUST_ROOTS=<dev>`) flips the process-global flag to
    // `true` at startup via `binary_manifest::set_dev_mode_active`.
    // Every Receipt this daemon emits carries the stamp.
    //
    // This is the T2 acceptance criterion ("Receipt body includes
    // dev_mode_active: true under dev trust-root config") routed
    // through the in-process flag rather than spawning a real
    // daemon — the flag IS the canonical surface that
    // `infra/runtime.rs` writes once at startup.
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    crate::binary_manifest::set_dev_mode_active(true);

    let _identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-dev").unwrap();
    let grant = store
        .create_grant(&persona.id, "github-token", "push", None)
        .unwrap();
    store.revoke_grant(&grant.id).unwrap();
    let rid = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
    let r = store.get_receipt(&rid).unwrap();
    assert!(
        r.dev_mode_active,
        "dev-trust-root-config receipt must stamp dev_mode_active: true; got {}",
        r.dev_mode_active
    );

    // Clear the flag so subsequent tests don't inherit the dev posture.
    crate::binary_manifest::set_dev_mode_active(false);
}

#[test]
fn trigger_is_idempotent() {
    let identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-idem").unwrap();
    let grant = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();
    // First revoke already triggers via the OnceCell path.
    store.revoke_grant(&grant.id).unwrap();
    let first = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
    // Second explicit trigger must no-op.
    let second = trigger_receipt_if_terminal(&store, identity, &grant.id, None)
        .unwrap()
        .unwrap();
    assert_eq!(first, second, "idempotent — same receipt id");
}

#[test]
fn trigger_noop_on_active_grant() {
    let identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-active").unwrap();
    let grant = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();
    // Grant is still active — no receipt.
    let r = trigger_receipt_if_terminal(&store, identity, &grant.id, None).unwrap();
    assert!(r.is_none());
    // Note: cannot assert `receipt_count() == 0` because tests share a
    // DaemonStore-per-test but the process identity is shared; the
    // store is isolated so its own count is still zero.
    assert_eq!(store.receipt_count().unwrap(), 0);
}

#[test]
fn tampered_receipt_fails_verify() {
    let identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-tamper").unwrap();
    let grant = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();
    store.revoke_grant(&grant.id).unwrap();
    let rid = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
    let mut r = store.get_receipt(&rid).unwrap();
    // Flip a summary field — recomputed hash will no longer match.
    r.summary.resource.push_str("-tampered");
    let err = verify_receipt(&r, &identity.pubkey_hex()).unwrap_err();
    assert!(
        matches!(err, ReceiptVerifyError::HashMismatch { .. }),
        "tampering changes hash, got {err}"
    );
}

#[test]
fn wrong_pubkey_fails_verify() {
    let _identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-wp").unwrap();
    let grant = store.create_grant(&persona.id, "c", "r", None).unwrap();
    store.revoke_grant(&grant.id).unwrap();
    let rid = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
    let r = store.get_receipt(&rid).unwrap();
    // An unrelated pubkey — verify must reject.
    let err = verify_receipt(&r, &"0".repeat(64)).unwrap_err();
    assert!(matches!(err, ReceiptVerifyError::SignerMismatch { .. }));
}

#[test]
fn list_receipts_orders_recent_first_and_filters_by_persona() {
    let _identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let a = store.create_persona("agent-l1").unwrap();
    let b = store.create_persona("agent-l2").unwrap();
    let g1 = store.create_grant(&a.id, "c", "r", None).unwrap();
    let g2 = store.create_grant(&b.id, "c", "r", None).unwrap();
    store.revoke_grant(&g1.id).unwrap();
    store.revoke_grant(&g2.id).unwrap();

    let all = store.list_receipts(None).unwrap();
    assert_eq!(all.len(), 2);

    let just_a = store.list_receipts(Some(&a.id)).unwrap();
    assert_eq!(just_a.len(), 1);
    assert_eq!(just_a[0].summary.persona_id, a.id);
}

#[test]
fn three_statement_receipt_preserves_per_statement_usage() {
    use core_grant_types::{Block, Budget, ResourceSelector, ResourceType, Statement};

    let identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-3stmt").unwrap();
    // Seed with a fully-permissive "*" scope so the P69K-A2-I4
    // bipartite dominance check accepts the three-statement
    // attenuation (credential:use / llm:generate / session:run).
    let grant = store
        .create_grant(&persona.id, "composite", "*", None)
        .unwrap();

    // Overwrite blocks with a three-statement chain.
    let statements = vec![
        Statement {
            sid: "S0".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["credential:use".into()],
            resource: ResourceSelector::Any,
            budget: None,
            usage: Usage {
                requests: 3,
                ..Default::default()
            },
            conditions: vec![],
            can_delegate: None,
        },
        Statement {
            sid: "S1".into(),
            resource_type: ResourceType::Session,
            actions: vec!["llm:generate".into()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                tokens: Some(1000),
                ..Default::default()
            }),
            usage: Usage {
                tokens: 250,
                ..Default::default()
            },
            conditions: vec![],
            can_delegate: None,
        },
        Statement {
            sid: "S2".into(),
            resource_type: ResourceType::Time,
            actions: vec!["session:run".into()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                wall_clock_secs: Some(3600),
                ..Default::default()
            }),
            usage: Usage {
                wall_clock_secs: 120,
                ..Default::default()
            },
            conditions: vec![],
            can_delegate: None,
        },
    ];
    let now = Utc::now().timestamp().max(0) as u64;
    let block = Block {
        statements,
        nbf: None,
        expires_at: None,
        issued_by: persona.id.clone(),
        issued_at: now,
        approval: None,
        note: None,
    };
    // W1 + W4: the read path verifies the chain, so seed a real
    // Ed25519 signature under the persona's root key instead of the
    // "unsigned-test" placeholder.
    let root = store.persona_root_keypair(&persona.id).unwrap();
    let signed = crate::trust::grant::sign_block_zero_with(&root, &block).unwrap();
    let composed = core_grant_types::AccessGrant {
        id: grant.id.clone(),
        version: 1,
        issuing_persona_id: persona.id.clone(),
        recipient_kind: core_event_types::PresentationAudienceKind::Service,
        recipient_id: "composite".into(),
        recipient_profile: core_grant_types::RecipientProfile::Agent,
        status: core_grant_types::GrantStatus::Active,
        mode: core_grant_types::GrantMode::OneShot,
        blocks: vec![signed],
        attestation: AttestationBinding::default(),
        created_at: now,
        updated_at: now,
        revoked_at: None,
        revoked_reason: None,
        last_used_at: None,
        label: None,
    };
    store.overwrite_grant_blocks(&grant.id, &composed).unwrap();

    store.revoke_grant(&grant.id).unwrap();
    let rid = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
    let r = store.get_receipt(&rid).unwrap();
    assert_eq!(r.per_statement_usage.len(), 3);
    let by_sid: std::collections::HashMap<_, _> = r
        .per_statement_usage
        .iter()
        .map(|(sid, u)| (sid.clone(), u.clone()))
        .collect();
    assert_eq!(by_sid.get("S0").unwrap().requests, 3);
    assert_eq!(by_sid.get("S1").unwrap().tokens, 250);
    assert_eq!(by_sid.get("S2").unwrap().wall_clock_secs, 120);
    verify_receipt(&r, &identity.pubkey_hex()).unwrap();
}

#[test]
fn canonical_hash_is_stable() {
    let _identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-ch").unwrap();
    let g = store.create_grant(&persona.id, "c", "r", None).unwrap();
    store.revoke_grant(&g.id).unwrap();
    let rid = store.get_grant(&g.id).unwrap().receipt_id.unwrap();
    let r = store.get_receipt(&rid).unwrap();
    // Recompute twice — must match.
    assert_eq!(canonical_hash(&r), canonical_hash(&r));
    // Must match the stored evidence.hash.
    assert_eq!(canonical_hash(&r), r.evidence.hash);
}

/// Approval chain is populated from audit log when a human approval
/// (source = "approval") is recorded before the grant is revoked.
#[test]
fn emit_receipt_populates_approval_chain_from_audit() {
    use crate::trust::approval::ApprovalOutcome as StoreApprovalOutcome;
    use core_grant_types::grant_receipt::{ApprovalActor, ApprovalOutcome};

    let identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-approval-chain").unwrap();

    // Simulate a human-approval flow: submit approval then resolve it.
    // resolve_approval creates the grant and logs "grant.issued" with
    // source = "approval".
    let req = store
        .submit_approval(
            &persona.id,
            "github-token",
            "push",
            None,
            "credential.access.github-token",
            "medium",
        )
        .unwrap();
    store
        .resolve_approval(&req.id, &StoreApprovalOutcome::Approved)
        .unwrap();

    // Retrieve the grant that was created by resolve_approval.
    let grants = store.list_grants().unwrap();
    assert_eq!(
        grants.len(),
        1,
        "resolve_approval must have created a grant"
    );
    let grant = &grants[0];

    store.revoke_grant(&grant.id).unwrap();
    let rid = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
    let r = store.get_receipt(&rid).unwrap();

    assert_eq!(
        r.approval_chain.len(),
        1,
        "expected exactly one approval event"
    );
    let ev = &r.approval_chain[0];
    assert_eq!(ev.actor, ApprovalActor::HumanDashboard);
    assert_eq!(ev.outcome, ApprovalOutcome::Approved);
    assert!(ev.at > 0, "approval event must have a non-zero timestamp");

    verify_receipt(&r, &identity.pubkey_hex()).expect("receipt with approval_chain must verify");
}

/// Approval chain entries are ordered ascending by timestamp regardless
/// of the audit log's descending query order.
#[test]
fn emit_receipt_approval_chain_ordered_by_time() {
    use core_grant_types::grant_receipt::ApprovalActor;

    let identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-order").unwrap();

    // Directly log three grant.issued events for the same grant_id in
    // order t1 < t2 < t3 to verify the chain sorts ascending.
    // We use a fixed grant (created but never touched by the standard
    // flow) so there is no race with revoke_grant's own log events.
    let grant = store.create_grant(&persona.id, "tok", "r", None).unwrap();
    let grant_id = grant.id.clone();

    // Seed three audit entries with distinct timestamps by using
    // wall-clock spacing. Each entry must reference the grant_id in
    // `details` so the filter picks it up.
    for i in 0u64..3 {
        let details = serde_json::json!({
            "grant_id": grant_id,
            "scope": "r",
            "source": "approval",
        })
        .to_string();
        store
            .log_event(
                Some(&persona.id),
                "grant.issued",
                Some("tok"),
                "allowed",
                Some(&details),
            )
            .unwrap();
        // Brief pause so RFC-3339 timestamps differ (SQLite stores TEXT).
        std::thread::sleep(std::time::Duration::from_millis(10 + i * 2));
    }

    store.revoke_grant(&grant_id).unwrap();
    let rid = store.get_grant(&grant_id).unwrap().receipt_id.unwrap();
    let r = store.get_receipt(&rid).unwrap();

    // We seeded 3 approval entries; revoke_grant does not add a
    // grant.issued so the count should be exactly 3.
    assert_eq!(r.approval_chain.len(), 3, "expected 3 approval events");
    assert!(
        r.approval_chain
            .iter()
            .all(|ev| ev.actor == ApprovalActor::HumanDashboard)
    );

    // Verify ascending order.
    for w in r.approval_chain.windows(2) {
        assert!(
            w[0].at <= w[1].at,
            "approval chain must be ordered ascending: {} > {}",
            w[0].at,
            w[1].at
        );
    }

    verify_receipt(&r, &identity.pubkey_hex()).expect("receipt verifies");
}

// ------------------------------------------------------------------
// generate_receipt / canonical_hash_receipt — task P69K-D scaffold
// ------------------------------------------------------------------

/// Flip the grant's SQL status directly so generate_receipt can see it.
/// Used by tests that want to exercise terminal paths without invoking
/// the OnceCell-backed revoke path (which also persists a receipt and
/// would muddy the assertion target).
fn force_status(store: &DaemonStore, grant_id: &str, status: &str) {
    store
        .conn()
        .execute(
            "UPDATE grants SET status = ?1 WHERE id = ?2",
            rusqlite::params![status, grant_id],
        )
        .expect("force_status update");
}

#[test]
fn generate_receipt_on_expired_grant_has_correct_terminal_reason() {
    let _identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-gen-expired").unwrap();
    let grant = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();
    force_status(&store, &grant.id, "expired");

    let now = 1_700_000_000u64;
    let receipt = generate_receipt(&store, &grant.id, TerminalReason::Expired, now).unwrap();

    assert_eq!(receipt.grant_id, grant.id);
    assert_eq!(receipt.lifecycle.terminated_at, now);
    assert!(matches!(
        receipt.lifecycle.terminal_reason,
        TerminalReason::Expired
    ));
    // Evidence must stay zeroed on the pure-logic path — signing is a
    // separate concern.
    assert_eq!(receipt.evidence, Evidence::default());
}

#[test]
fn generate_receipt_on_revoked_grant_captures_revoke_actor() {
    let _identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-gen-revoked").unwrap();
    let grant = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();
    force_status(&store, &grant.id, "revoked");

    let reason = TerminalReason::Revoked {
        by: RevokeActor::Agent,
        reason: "voluntary release".into(),
    };
    let now = 1_700_000_050u64;
    let receipt = generate_receipt(&store, &grant.id, reason.clone(), now).unwrap();

    match receipt.lifecycle.terminal_reason {
        TerminalReason::Revoked { by, reason: r } => {
            assert_eq!(by, RevokeActor::Agent);
            assert_eq!(r, "voluntary release");
        }
        other => panic!("expected Revoked, got {other:?}"),
    }
    assert_eq!(receipt.lifecycle.terminated_at, now);
}

#[test]
fn generate_receipt_on_abandoned_grant_captures_reason() {
    let _identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-gen-abandoned").unwrap();
    let grant = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();
    force_status(&store, &grant.id, "abandoned");

    let reason = TerminalReason::Abandoned {
        reason: "operator chose not to rebuild missing grant chain".into(),
    };
    let now = 1_700_000_075u64;
    let receipt = generate_receipt(&store, &grant.id, reason, now).unwrap();

    match receipt.lifecycle.terminal_reason {
        TerminalReason::Abandoned { reason } => {
            assert_eq!(reason, "operator chose not to rebuild missing grant chain");
        }
        other => panic!("expected Abandoned, got {other:?}"),
    }
    assert_eq!(receipt.lifecycle.terminated_at, now);
}

#[test]
fn generate_receipt_populates_per_statement_usage() {
    use core_grant_types::{Block, Budget, ResourceSelector, ResourceType, Statement};

    let _identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-gen-usage").unwrap();
    // Seed with a fully-permissive "*" scope so the P69K-A2-I4
    // bipartite dominance check accepts the two-statement
    // attenuation (credential:use + llm:generate).
    let grant = store
        .create_grant(&persona.id, "composite-usage", "*", None)
        .unwrap();

    // Overwrite the block chain with two statements carrying distinct
    // per-axis usage tallies.
    let statements = vec![
        Statement {
            sid: "S0".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["credential:use".into()],
            resource: ResourceSelector::Any,
            budget: None,
            usage: Usage {
                requests: 7,
                ..Default::default()
            },
            conditions: vec![],
            can_delegate: None,
        },
        Statement {
            sid: "S1".into(),
            resource_type: ResourceType::Session,
            actions: vec!["llm:generate".into()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                tokens: Some(10_000),
                ..Default::default()
            }),
            usage: Usage {
                tokens: 4_321,
                ..Default::default()
            },
            conditions: vec![],
            can_delegate: None,
        },
    ];
    let now_secs = Utc::now().timestamp().max(0) as u64;
    let block = Block {
        statements,
        nbf: None,
        expires_at: None,
        issued_by: persona.id.clone(),
        issued_at: now_secs,
        approval: None,
        note: None,
    };
    let root = store.persona_root_keypair(&persona.id).unwrap();
    let signed = crate::trust::grant::sign_block_zero_with(&root, &block).unwrap();
    let composed = core_grant_types::AccessGrant {
        id: grant.id.clone(),
        version: 1,
        issuing_persona_id: persona.id.clone(),
        recipient_kind: core_event_types::PresentationAudienceKind::Service,
        recipient_id: "composite-usage".into(),
        recipient_profile: core_grant_types::RecipientProfile::Agent,
        status: core_grant_types::GrantStatus::Active,
        mode: core_grant_types::GrantMode::OneShot,
        blocks: vec![signed],
        attestation: AttestationBinding::default(),
        created_at: now_secs,
        updated_at: now_secs,
        revoked_at: None,
        revoked_reason: None,
        last_used_at: None,
        label: None,
    };
    store.overwrite_grant_blocks(&grant.id, &composed).unwrap();
    force_status(&store, &grant.id, "expired");

    let receipt = generate_receipt(&store, &grant.id, TerminalReason::Expired, now_secs).unwrap();

    assert_eq!(receipt.per_statement_usage.len(), 2);
    let by_sid: std::collections::HashMap<_, _> = receipt
        .per_statement_usage
        .iter()
        .map(|(sid, u)| (sid.clone(), u.clone()))
        .collect();
    assert_eq!(by_sid.get("S0").unwrap().requests, 7);
    assert_eq!(by_sid.get("S1").unwrap().tokens, 4_321);
}

#[test]
fn generate_receipt_fails_on_unknown_grant_id() {
    let _identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let err = generate_receipt(
        &store,
        "grant-does-not-exist",
        TerminalReason::Expired,
        1_700_000_000,
    )
    .unwrap_err();
    assert!(
        matches!(err, StoreError::NotFound),
        "expected NotFound for unknown grant, got {err:?}"
    );
}

#[test]
fn generate_receipt_fails_on_non_terminal_grant() {
    let _identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-gen-active").unwrap();
    let grant = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();
    // Grant is active; generate_receipt must refuse.
    let err =
        generate_receipt(&store, &grant.id, TerminalReason::Expired, 1_700_000_000).unwrap_err();
    assert!(
        matches!(err, StoreError::InvalidInput(_)),
        "expected InvalidInput for active grant, got {err:?}"
    );
}

#[test]
fn canonical_hash_receipt_deterministic() {
    let _identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-hash-det").unwrap();
    let grant = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();
    force_status(&store, &grant.id, "expired");

    let now = 1_700_000_123u64;
    let r1 = generate_receipt(&store, &grant.id, TerminalReason::Expired, now).unwrap();
    let mut r2 = r1.clone();
    // Deterministic: identical content → identical hash, even though
    // generate_receipt mints a fresh uuid for the id on each call.
    // Force-match the id so the receipts really are identical.
    r2.id = r1.id.clone();

    let h1 = canonical_hash_receipt(&r1);
    let h2 = canonical_hash_receipt(&r2);
    assert_eq!(h1, h2, "canonical_hash_receipt must be deterministic");
    assert_eq!(h1.len(), 32, "sha256 digest must be 32 bytes");

    // The hex wrapper must agree with the raw-bytes result.
    assert_eq!(canonical_hash(&r1), hex::encode(h1));
}

#[test]
fn canonical_hash_receipt_evidence_fields_excluded() {
    let _identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-hash-evex").unwrap();
    let grant = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();
    force_status(&store, &grant.id, "expired");

    let now = 1_700_000_456u64;
    let base = generate_receipt(&store, &grant.id, TerminalReason::Expired, now).unwrap();
    let baseline_hash = canonical_hash_receipt(&base);

    // Mutate ONLY evidence fields. The canonical hash must stay stable.
    let mut with_hash = base.clone();
    with_hash.evidence.hash = "ff".repeat(32);
    assert_eq!(
        canonical_hash_receipt(&with_hash),
        baseline_hash,
        "evidence.hash must not influence canonical hash"
    );

    let mut with_sig = base.clone();
    with_sig.evidence.sig = "ab".repeat(64);
    assert_eq!(
        canonical_hash_receipt(&with_sig),
        baseline_hash,
        "evidence.sig must not influence canonical hash"
    );

    let mut with_pubkey = base.clone();
    with_pubkey.evidence.signer_pubkey = "cd".repeat(32);
    assert_eq!(
        canonical_hash_receipt(&with_pubkey),
        baseline_hash,
        "evidence.signer_pubkey must not influence canonical hash"
    );

    let mut with_version = base.clone();
    with_version.evidence.canonical_version = 99;
    assert_eq!(
        canonical_hash_receipt(&with_version),
        baseline_hash,
        "evidence.canonical_version must not influence canonical hash"
    );

    // Sanity: mutating a *non-evidence* field DOES change the hash.
    let mut with_summary = base.clone();
    with_summary.summary.resource.push_str("-tampered");
    assert_ne!(
        canonical_hash_receipt(&with_summary),
        baseline_hash,
        "non-evidence mutation must change canonical hash"
    );
}

/// verify_receipt uses the caller-supplied trust anchor (expected_pubkey_hex),
/// not the receipt's own signer_pubkey field. A receipt whose signer_pubkey
/// is set to an attacker's key but whose signature was made by a DIFFERENT
/// key must be rejected even if the attacker's key could verify some
/// crafted payload — the recomputed hash won't match what the real signer
/// signed, so BadSignature fires.
#[test]
fn verify_receipt_uses_caller_trust_anchor() {
    let identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-trust-anchor").unwrap();
    let grant = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();
    store.revoke_grant(&grant.id).unwrap();
    let rid = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
    let mut r = store.get_receipt(&rid).unwrap();

    // Generate a second (attacker-controlled) keypair.
    let attacker_seed = [0xABu8; 32];
    let attacker_key = ed25519_dalek::SigningKey::from_bytes(&attacker_seed);
    let attacker_pubkey_hex = hex::encode(attacker_key.verifying_key().to_bytes());

    // Swap signer_pubkey to the attacker's key while keeping the real sig.
    // verify_receipt must still use the CALLER-SUPPLIED identity pubkey
    // as the trust anchor, so it rejects with SignerMismatch (the
    // receipt's signer_pubkey no longer matches expected_pubkey_hex).
    r.evidence.signer_pubkey = attacker_pubkey_hex;
    let err = verify_receipt(&r, &identity.pubkey_hex()).unwrap_err();
    assert!(
        matches!(err, ReceiptVerifyError::SignerMismatch { .. }),
        "swapping signer_pubkey must produce SignerMismatch, got {err}"
    );

    // Confirm the original receipt (unmodified signer_pubkey) still verifies
    // correctly against the real trust anchor.
    let r_orig = store.get_receipt(&rid).unwrap();
    verify_receipt(&r_orig, &identity.pubkey_hex())
        .expect("original receipt verifies against real trust anchor");
}

/// A signed receipt that has been serialized to JSON bytes and read back
/// (the path the offline `ember receipt verify --file <PATH>` verifier
/// takes) must still verify against the original signing pubkey. Closes
/// CEO-009 §2: signed receipts must be third-party-verifiable outside the
/// vendor dashboard.
#[test]
fn verify_receipt_round_trips_through_serde_json() {
    let identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-roundtrip").unwrap();
    let grant = store
        .create_grant(&persona.id, "cred-roundtrip", "read", None)
        .unwrap();
    store.revoke_grant(&grant.id).unwrap();
    let rid = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
    let r = store.get_receipt(&rid).unwrap();

    let json_bytes = serde_json::to_vec(&r).expect("receipt serializes");
    let r2: GrantReceipt = serde_json::from_slice(&json_bytes).expect("receipt deserializes");
    verify_receipt(&r2, &identity.pubkey_hex()).expect("receipt verifies after JSON round-trip");
}

/// A receipt with an all-zeros placeholder signature returns PlaceholderSig,
/// not a generic BadSignature or Malformed error.
#[test]
fn verify_receipt_distinguishes_placeholder_signature() {
    let identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-placeholder-sig").unwrap();
    let grant = store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();
    store.revoke_grant(&grant.id).unwrap();
    let rid = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
    let mut r = store.get_receipt(&rid).unwrap();

    // Replace the real signature with the all-zeros phase-1 placeholder.
    r.evidence.sig = "00".repeat(64);
    let err = verify_receipt(&r, &identity.pubkey_hex()).unwrap_err();
    assert!(
        matches!(err, ReceiptVerifyError::PlaceholderSig),
        "all-zeros sig must return PlaceholderSig, got {err}"
    );
}

/// Legacy grants that have no grant.issued audit entries produce an
/// empty approval chain rather than a crash.
#[test]
fn emit_receipt_approval_chain_empty_when_no_audit_entries() {
    let identity = ensure_identity();
    let store = DaemonStore::open_in_memory().unwrap();
    let persona = store.create_persona("agent-legacy").unwrap();

    // Create and immediately revoke without any approval flow — no
    // grant.issued event is emitted by create_grant itself.
    // (create_grant does not call log_event; the caller in handler.rs
    //  does. In tests that call create_grant directly there is no log.)
    let grant = store
        .create_grant(&persona.id, "legacy-cred", "read", None)
        .unwrap();
    store.revoke_grant(&grant.id).unwrap();

    let rid = store.get_grant(&grant.id).unwrap().receipt_id.unwrap();
    let r = store.get_receipt(&rid).unwrap();

    assert!(
        r.approval_chain.is_empty(),
        "legacy grants with no audit entries must produce empty approval_chain, got {:?}",
        r.approval_chain
    );

    verify_receipt(&r, &identity.pubkey_hex()).expect("receipt verifies even with empty chain");
}

// -------------------------------------------------------------------------
// M1 — zeroize
// -------------------------------------------------------------------------

/// T1 zeroize: `sign()` returns a `Zeroizing<[u8;64]>` wrapper. We
/// verify:
///  - the return type compiles as `Zeroizing<[u8;64]>` (type inference
///    would fail if the signature changed to `[u8;64]`)
///  - the bytes are non-zero (a real Ed25519 signature over a known payload)
///  - the wrapper correctly zeroes bytes when manually invoked via
///    `zeroize::Zeroize::zeroize()`, exercising the same volatile-write path
///    that `ZeroizeOnDrop` uses on drop.
#[test]
fn sign_returns_zeroizing_wrapper_and_clears_bytes() {
    use zeroize::Zeroize;
    let dir = tempfile::tempdir().unwrap();
    let id = DaemonPersona::load_or_create(dir.path()).unwrap();
    let payload = b"test payload for zeroize check";

    let mut sig: Zeroizing<[u8; 64]> = id.sign(payload);
    // A real Ed25519 signature must have non-zero bytes.
    assert!(
        sig.iter().any(|b| *b != 0),
        "signature must have non-zero bytes"
    );
    // Explicitly invoke zeroize (same code path as ZeroizeOnDrop).
    sig.zeroize();
    assert!(
        sig.iter().all(|b| *b == 0),
        "Zeroizing::zeroize() must clear all bytes"
    );
}

/// T1 zeroize: `seed_bytes()` returns a `Zeroizing<[u8;32]>` wrapper.
/// Same verification pattern as `sign_returns_zeroizing_wrapper_and_clears_bytes`.
#[test]
fn seed_bytes_returns_zeroizing_wrapper_and_clears_bytes() {
    use zeroize::Zeroize;
    let dir = tempfile::tempdir().unwrap();
    let id = DaemonPersona::load_or_create(dir.path()).unwrap();

    let mut seed: Zeroizing<[u8; 32]> = id.seed_bytes();
    assert!(
        seed.iter().any(|b| *b != 0),
        "seed must have non-zero bytes"
    );
    seed.zeroize();
    assert!(
        seed.iter().all(|b| *b == 0),
        "Zeroizing::zeroize() must clear all bytes"
    );
}

// -------------------------------------------------------------------------
// M2 — mode-check
// -------------------------------------------------------------------------

/// T2 mode-check 0644: a key file with group/world read bits set must be
/// refused. The daemon returns `StoreError::KeyInsecureMode`.
#[test]
#[cfg(unix)]
fn load_or_create_refuses_world_readable_key_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    // Create a valid key file first.
    let _ = DaemonPersona::load_or_create(dir.path()).unwrap();
    // Widen the permissions to 0644 — simulating a backup restore or
    // operator copy that dropped the restrictive mode.
    let key_path = dir.path().join(IDENTITY_KEY_FILENAME);
    let mut perms = fs::metadata(&key_path).unwrap().permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&key_path, perms).unwrap();
    // A second load_or_create must refuse.
    let err = DaemonPersona::load_or_create(dir.path()).expect_err("should refuse 0644 key file");
    assert!(
        matches!(err, StoreError::KeyInsecureMode { .. }),
        "expected KeyInsecureMode, got: {err:?}"
    );
    // Verify the error message contains the path and a mode value that
    // includes the 644 octal digits (the full mode includes file-type bits
    // on some platforms, e.g. 0o100644, so we search for "644").
    let msg = err.to_string();
    assert!(
        msg.contains("daemon_persona.key"),
        "error must name the file: {msg}"
    );
    assert!(
        msg.contains("644"),
        "error must report the insecure mode: {msg}"
    );
}

/// T2 mode-check 0600: a correctly-permissioned key file loads without error.
#[test]
#[cfg(unix)]
fn load_or_create_accepts_correctly_permissioned_key_file() {
    let dir = tempfile::tempdir().unwrap();
    // First call generates and writes the key.
    let id1 = DaemonPersona::load_or_create(dir.path()).unwrap();
    let pk1 = id1.pubkey_hex();
    // Second call reads the key — must succeed and return the same pubkey.
    let id2 = DaemonPersona::load_or_create(dir.path()).unwrap();
    assert_eq!(
        id2.pubkey_hex(),
        pk1,
        "0600 key must load cleanly and return same pubkey"
    );
}

/// META-AP-RECEIPT-TREE-PUBKEY-CROSS-UID-READ (Option A):
/// `load_or_create` writes a `daemon_persona.pub` sidecar at mode
/// 0644 containing the hex pubkey, so cross-uid CLI callers can
/// resolve the trust anchor without 0600 read on the private key.
#[test]
#[cfg(unix)]
fn load_or_create_publishes_pubkey_sidecar() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let id = DaemonPersona::load_or_create(dir.path()).unwrap();
    let sidecar = identity_pubkey_sidecar_path(dir.path());
    assert!(
        sidecar.exists(),
        "load_or_create must write the 0644 pubkey sidecar"
    );
    let meta = std::fs::metadata(&sidecar).unwrap();
    assert_eq!(
        meta.permissions().mode() & 0o777,
        0o644,
        "pubkey sidecar must be world-readable (0644)"
    );
    let on_disk = std::fs::read_to_string(&sidecar).unwrap();
    assert_eq!(
        on_disk.trim(),
        id.pubkey_hex(),
        "sidecar must hold the hex-encoded pubkey"
    );
}

/// META-AP-RECEIPT-TREE-PUBKEY-CROSS-UID-READ (Option A):
/// `read_pubkey_sidecar_hex` round-trips the pubkey hex emitted
/// by `DaemonPersona::pubkey_hex`.
#[test]
#[cfg(unix)]
fn read_pubkey_sidecar_hex_round_trips_pubkey() {
    let dir = tempfile::tempdir().unwrap();
    let id = DaemonPersona::load_or_create(dir.path()).unwrap();
    let via_sidecar =
        read_pubkey_sidecar_hex(dir.path()).expect("sidecar must read after load_or_create");
    assert_eq!(via_sidecar, id.pubkey_hex());
}

/// META-AP-RECEIPT-TREE-PUBKEY-CROSS-UID-READ (Option A):
/// Reading the sidecar before `load_or_create` has run is an error
/// — callers (e.g. `ember receipt tree`) then fall back to the
/// legacy `load_or_create` path.
#[test]
fn read_pubkey_sidecar_hex_errors_when_absent() {
    let dir = tempfile::tempdir().unwrap();
    let err = read_pubkey_sidecar_hex(dir.path())
        .expect_err("missing sidecar must surface as Err so callers fall back");
    assert!(matches!(err, StoreError::InvalidInput(_)));
}
