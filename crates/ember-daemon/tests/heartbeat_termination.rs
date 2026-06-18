//! COHORT-A-V03-HEARTBEAT-TERMINATION T2 — heartbeat-lost dirty-exit.
//!
//! H1 invariant (cohort-A test plan): every grant terminates in a signed
//! Receipt across all four termination paths. This file pins the
//! **dirty-exit** path:
//!
//! 1. Mock launcher PID is "dead" (we use a high checkpoint PID that POSIX
//!    `kill(pid, 0)` reports `ESRCH` for — see
//!    [`heartbeat::pid_alive_false_for_unused_high_pid`]).
//! 2. The session's heartbeat sidecar timestamp is backdated >90 s.
//! 3. We invoke [`heartbeat::tick`] with a "now" advanced past the timeout.
//! 4. The watcher must:
//!    - Emit a signed v2 `session.claude_code` Receipt with
//!      `termination_reason: heartbeat_lost`,
//!      `last_heartbeat_at: <backdated ts>`,
//!      `pid_alive_at_check: false`.
//!    - Persist the Receipt to `<session_dir>/receipt.json`.
//!    - Close the session (rename `meta.json` → `meta.json.closed`).
//!    - Revoke the outstanding broker grant.
//!    - Append a `session.terminated_dirty` audit-log entry.
//!
//! T3 (real launcher under `qember.sh`, real SIGKILL) is out of scope for
//! this PR — see the `t3_real_launcher_sigkill` ignored stub at the bottom.

use std::rc::Rc;

use chrono::{Duration as ChronoDuration, TimeZone, Utc};
use core_events::receipt::{
    ClaudeCodeBody, ReceiptEnvelope, TerminationReason, sign::verify_receipt_v2,
};
use core_state::sessions::{SessionMeta, SessionStore};
use ember_daemon::infra::receipt::{current_identity, init_identity};
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use ember_daemon::session::heartbeat;
use tempfile::TempDir;

const TEST_VAULT_KEY: [u8; 32] = [0xCDu8; 32];

/// Checkpoint PID that the OS will report as `ESRCH` for `kill(pid, 0)` —
/// the watcher's PID-liveness check returns `false` for this value. Mirrors
/// the constant used in `session::heartbeat`'s own unit tests.
const FAKE_DEAD_PID: u32 = 0x7FFF_FFFE;

fn store_with_vault() -> DaemonStore {
    let store = DaemonStore::open_in_memory().expect("open in-memory store");
    store.set_vault(Rc::new(Vault::new(TEST_VAULT_KEY)));
    store
}

/// Initialise the daemon identity once per test binary. `init_identity`
/// is idempotent — first caller wins. Returns the tempdir so the file
/// stays on disk for the test's duration.
fn init_test_identity() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir for daemon identity");
    let _ = init_identity(dir.path());
    dir
}

/// Build a session whose heartbeat is backdated past the timeout AND
/// whose launcher PID is the fake-dead checkpoint.
fn create_terminating_session(
    sessions_dir: &std::path::Path,
    persona_id: &str,
    grant_id: &str,
) -> SessionMeta {
    let session_store = SessionStore::new(sessions_dir.to_path_buf());

    // Started 5 minutes ago — well past the 90 s heartbeat-timeout window
    // even before we backdate the heartbeat file.
    let started_at = Utc::now() - ChronoDuration::minutes(5);
    let meta = SessionMeta {
        session_id: "sess-heartbeat-lost".to_string(),
        persona: persona_id.to_string(),
        durable_persona: None,
        grant_id: grant_id.to_string(),
        caller_binding_id: None,
        started_at,
        launcher_pid: FAKE_DEAD_PID,
        authority_strict: false,
        delegation_id: None,
        delegation_template: None,
    };
    session_store.create(&meta).expect("create session meta");

    // Heartbeat sidecar — backdated 5 minutes (>>90 s timeout). On a real
    // launcher the file would be touched every 30 s.
    let session_dir = sessions_dir.join(&meta.session_id);
    let backdated = Utc::now() - ChronoDuration::minutes(5);
    heartbeat::write_heartbeat(&session_dir, backdated).expect("write backdated heartbeat");

    meta
}

#[test]
fn dead_pid_plus_stale_heartbeat_emits_signed_receipt_and_revokes_grant() {
    let _id_dir = init_test_identity();
    let identity = current_identity().expect("identity must be loaded");

    // T2 fixture: in-memory store + persona + active grant.
    let store = store_with_vault();
    let persona = store
        .create_persona("agent-heartbeat-test")
        .expect("create_persona");
    let grant = store
        .create_grant(&persona.id, "github-token", "repo:read", Some(3600))
        .expect("create_grant");
    assert_eq!(grant.status, "active");

    // Sessions live in their own tempdir to keep the test's filesystem
    // surface contained.
    let sessions_root = TempDir::new().expect("tempdir for sessions");
    let session_meta = create_terminating_session(sessions_root.path(), &persona.id, &grant.id);

    let session_store = SessionStore::new(sessions_root.path().to_path_buf());

    // Pre-condition: session is open, grant is active, no Receipt sidecar
    // contents yet (the placeholder is empty).
    assert_eq!(
        session_store.list_open().unwrap().len(),
        1,
        "session should be open before tick"
    );
    let receipt_path = sessions_root
        .path()
        .join(&session_meta.session_id)
        .join("receipt.json");
    let pre_contents = std::fs::read(&receipt_path).unwrap_or_default();
    assert!(pre_contents.is_empty(), "receipt.json placeholder is empty");

    // Advance clock past the 90 s heartbeat window — the heartbeat tick
    // takes "now" as a parameter so we don't need real wall-clock time
    // (or `tokio::time::advance`) for this T2.
    let now_advanced = Utc::now() + ChronoDuration::seconds(120);

    let transitioned = heartbeat::tick(&store, &session_store, sessions_root.path(), now_advanced);
    assert_eq!(transitioned, 1, "exactly one session should transition");

    // --- Receipt assertions ---
    let receipt_bytes = std::fs::read(&receipt_path).expect("receipt.json populated");
    assert!(
        !receipt_bytes.is_empty(),
        "receipt.json must be non-empty after dirty-exit"
    );
    let envelope: ReceiptEnvelope =
        serde_json::from_slice(&receipt_bytes).expect("receipt.json parses as v2 envelope");

    assert_eq!(envelope.kind, "session.claude_code");
    assert!(
        envelope.signature.is_some(),
        "v2 receipt must be signed by daemon persona"
    );

    // Verify under the daemon's pubkey. Mirrors the path
    // `ember receipt verify --strict <id>` would take.
    let pk_str = format!("ed25519:{}", identity.pubkey_hex());
    verify_receipt_v2(
        &envelope,
        &core_crypto::PublicKey(pk_str),
        &core_crypto::FixtureVerifier,
    )
    .expect("v2 receipt verifies under daemon persona pubkey");

    // Body shape assertions — the new termination triple.
    let body: ClaudeCodeBody = serde_json::from_value(envelope.body.clone()).unwrap();
    assert_eq!(
        body.termination_reason,
        Some(TerminationReason::HeartbeatLost),
        "body.termination_reason must be heartbeat_lost"
    );
    assert!(
        body.last_heartbeat_at.is_some(),
        "body.last_heartbeat_at must be populated on dirty-exit"
    );
    assert_eq!(
        body.pid_alive_at_check,
        Some(false),
        "body.pid_alive_at_check must be false (PID was dead at check)"
    );

    // --- Session-state assertions ---
    assert_eq!(
        session_store.list_open().unwrap().len(),
        0,
        "session must be closed after dirty-exit"
    );
    assert!(
        sessions_root
            .path()
            .join(&session_meta.session_id)
            .join("meta.json.closed")
            .exists(),
        "meta.json must have been renamed to meta.json.closed"
    );

    // --- Grant assertions ---
    let grant_after = store.get_grant(&grant.id).expect("grant still queryable");
    assert_eq!(
        grant_after.status, "revoked",
        "broker grant must be revoked in the same transaction"
    );

    // --- Audit-log assertions ---
    let audit_rows = store
        .query_audit(&ember_daemon::infra::audit::AuditFilter {
            action: Some("session.terminated_dirty".to_string()),
            ..Default::default()
        })
        .expect("query audit log");
    assert_eq!(
        audit_rows.len(),
        1,
        "exactly one session.terminated_dirty audit row"
    );
    assert_eq!(audit_rows[0].outcome, "heartbeat_lost");
}

#[test]
fn live_pid_with_stale_heartbeat_does_not_terminate() {
    // Defends the "PID-liveness is the load-bearing gate" invariant from
    // the heartbeat module's docstring: a stale heartbeat alone is NOT
    // sufficient to terminate — the launcher PID must also be dead.
    let _id_dir = init_test_identity();
    let _identity = current_identity().expect("identity loaded");

    let store = store_with_vault();
    let persona = store
        .create_persona("agent-live-pid")
        .expect("create_persona");
    let grant = store
        .create_grant(&persona.id, "github-token", "repo:read", Some(3600))
        .expect("create_grant");

    let sessions_root = TempDir::new().unwrap();
    let session_store = SessionStore::new(sessions_root.path().to_path_buf());

    // Session that points at the CURRENT process — kill(pid, 0) reports
    // alive — but has a stale heartbeat.
    let started_at = Utc::now() - ChronoDuration::minutes(5);
    let meta = SessionMeta {
        session_id: "sess-live-pid".to_string(),
        persona: persona.id.clone(),
        durable_persona: None,
        grant_id: grant.id.clone(),
        caller_binding_id: None,
        started_at,
        launcher_pid: std::process::id(),
        authority_strict: false,
        delegation_id: None,
        delegation_template: None,
    };
    session_store.create(&meta).expect("create session meta");
    let session_dir = sessions_root.path().join(&meta.session_id);
    heartbeat::write_heartbeat(&session_dir, Utc::now() - ChronoDuration::minutes(5))
        .expect("write stale heartbeat");

    let now_advanced = Utc::now() + ChronoDuration::seconds(120);
    let transitioned = heartbeat::tick(&store, &session_store, sessions_root.path(), now_advanced);
    assert_eq!(
        transitioned, 0,
        "stale heartbeat alone with live PID must NOT trigger termination"
    );
    assert_eq!(
        session_store.list_open().unwrap().len(),
        1,
        "session must remain open"
    );
    let grant_after = store.get_grant(&grant.id).expect("grant still active");
    assert_eq!(grant_after.status, "active", "grant must remain active");
}

#[test]
fn fresh_heartbeat_does_not_terminate_even_with_dead_pid() {
    // Within the heartbeat window, even a dead PID is ignored — fresh
    // heartbeats trump the PID check (the launcher must have written
    // recently to be considered live in spirit). Locks the "elapsed
    // > HEARTBEAT_TIMEOUT" gate at the top of `check_one`.
    let _id_dir = init_test_identity();
    let _identity = current_identity().expect("identity loaded");

    let store = store_with_vault();
    let persona = store
        .create_persona("agent-fresh-hb")
        .expect("create_persona");
    let grant = store
        .create_grant(&persona.id, "github-token", "repo:read", Some(3600))
        .expect("create_grant");

    let sessions_root = TempDir::new().unwrap();
    let session_store = SessionStore::new(sessions_root.path().to_path_buf());

    let meta = SessionMeta {
        session_id: "sess-fresh-hb".to_string(),
        persona: persona.id.clone(),
        durable_persona: None,
        grant_id: grant.id.clone(),
        caller_binding_id: None,
        started_at: Utc::now(),
        launcher_pid: FAKE_DEAD_PID,
        authority_strict: false,
        delegation_id: None,
        delegation_template: None,
    };
    session_store.create(&meta).expect("create session meta");
    let session_dir = sessions_root.path().join(&meta.session_id);
    heartbeat::write_heartbeat(&session_dir, Utc::now()).expect("write fresh heartbeat");

    // Even though PID is dead, advance only 30s — well within 90s window.
    let now_advanced = Utc::now() + ChronoDuration::seconds(30);
    let transitioned = heartbeat::tick(&store, &session_store, sessions_root.path(), now_advanced);
    assert_eq!(
        transitioned, 0,
        "fresh heartbeat must keep session alive even with dead PID"
    );
}

#[test]
fn heartbeat_timeout_boundary_is_90_seconds() {
    // Pins the 90 s boundary — the brief's acceptance criterion. At
    // exactly 90 s, no termination fires; at 91 s, it does (with a
    // dead PID).
    let _id_dir = init_test_identity();
    let _identity = current_identity().expect("identity loaded");

    let store = store_with_vault();
    let persona = store
        .create_persona("agent-90s-boundary")
        .expect("create_persona");
    let grant = store
        .create_grant(&persona.id, "github-token", "repo:read", Some(3600))
        .expect("create_grant");

    let sessions_root = TempDir::new().unwrap();
    let session_store = SessionStore::new(sessions_root.path().to_path_buf());

    // Heartbeat at a fixed "T". Now = T + 90 s exactly → no termination.
    // Now = T + 91 s → termination.
    let t_zero = Utc.with_ymd_and_hms(2026, 5, 8, 12, 0, 0).unwrap();

    let meta = SessionMeta {
        session_id: "sess-90s-boundary".to_string(),
        persona: persona.id.clone(),
        durable_persona: None,
        grant_id: grant.id.clone(),
        caller_binding_id: None,
        started_at: t_zero,
        launcher_pid: FAKE_DEAD_PID,
        authority_strict: false,
        delegation_id: None,
        delegation_template: None,
    };
    session_store.create(&meta).expect("create session meta");
    let session_dir = sessions_root.path().join(&meta.session_id);
    heartbeat::write_heartbeat(&session_dir, t_zero).expect("write heartbeat at T0");

    // At exactly 90 s → boundary excluded by `elapsed <= HEARTBEAT_TIMEOUT`
    let at_90s = t_zero + ChronoDuration::seconds(90);
    let transitioned = heartbeat::tick(&store, &session_store, sessions_root.path(), at_90s);
    assert_eq!(transitioned, 0, "at exactly 90 s no termination must fire");

    // At 91 s → first second the watcher fires.
    let at_91s = t_zero + ChronoDuration::seconds(91);
    let transitioned = heartbeat::tick(&store, &session_store, sessions_root.path(), at_91s);
    assert_eq!(transitioned, 1, "at 91 s the watcher must terminate");
}

#[test]
#[ignore = "T3 — real launcher under qember.sh; out of scope for COHORT-A-V03-HEARTBEAT-TERMINATION PR"]
fn t3_real_launcher_sigkill() {
    // T3 placeholder per the brief. Spawn a real launcher under
    // `qember.sh`, send SIGKILL, and verify the daemon emits the
    // Receipt within 120 s of wall-clock. Unlocked once the release
    // T3 harness is wired.
}
