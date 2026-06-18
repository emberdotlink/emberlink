//! COHORT-A-V03-V2-RECEIPT-COVERAGE-OTHER-LANES — T2 integration tests.
//!
//! Asserts that the two gap termination paths (TTL-expiry and explicit-revoke)
//! each emit signed v2 cohort-A Receipts with the correct `termination_reason`
//! variant. Pre-M3 follow-up, only clean-exit and dirty-exit (heartbeat-lost)
//! emitted v2 Receipts; TTL and revoke emitted v1 grant receipts only.
//!
//! v2_receipt_coverage_audit_v030_2026_05_09
//!
//! Test scope:
//!   T2a — TTL-expiry sweeper: signed v2 Receipt with `termination_reason =
//!          ttl_expired` persisted to `<sessions_dir>/<session_id>/receipt.json`.
//!   T2b — Explicit revoke: signed v2 Receipt with `termination_reason =
//!          explicit_revoke` emitted via the `revoke_grant` RPC arm; Receipt
//!          written to `<sessions_dir>/grant:<grant_id>/receipt.json` when
//!          sessions_dir is available on the RequestContext.
//!   T2c — Regression guard: dirty-exit path still produces a receipt with
//!          termination_reason = HeartbeatLost (non-regression).
//!   T2d — Tamper variants: each non-clean class rejects body mutation via
//!          the canonical v2 verifier.
//!
//! COHORT-A-V03-T3-FIX-CLEAN-EXIT-OVER-REVOKE — T3 regression tests.
//!
//! Guards the invariant that a CleanExit MUST NOT revoke the grant. A 24h
//! grant must support many sessions; revoking on CleanExit broke touch #2 of
//! the demo playbook (live-repro on 2026-05-09).
//!
//!   T3a — clean_exit_does_not_revoke_grant: open session against grant G;
//!          close with CleanExit; assert G is still Active in the store.
//!   T3b — ttl_expired_revokes_grant: open session; trigger TTL-expiry close;
//!          assert grant is Revoked.
//!   T3c — explicit_revoke_revokes_grant: call revoke_grant directly; assert
//!          grant is Revoked.

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use core_events::receipt::sign::{SignError, verify_receipt_v2};
use core_events::receipt::{ClaudeCodeBody, ReceiptEnvelope, TerminationReason};
use core_state::sessions::{SessionMeta, SessionStore};
use ember_daemon::infra::handler::{RequestContext, dispatch_method_with_context};
use ember_daemon::infra::rate_limit::RateLimiter;
use ember_daemon::infra::receipt::{current_identity, init_identity};
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use ember_daemon::session::heartbeat;
use ember_daemon::session::lifecycle::transition_to_terminated_dirty_at;
use ember_daemon::session_watcher::{
    close_session_clean_exit, close_session_heartbeat_orphan, close_session_ttl_expiry,
};
use ember_daemon::trust::policy::PolicyEngine;
use serde_json::json;
use tempfile::TempDir;

const TEST_VAULT_KEY: [u8; 32] = [0xABu8; 32];

fn store_with_vault() -> DaemonStore {
    let store = DaemonStore::open_in_memory().expect("open in-memory store");
    store.set_vault(Rc::new(Vault::new(TEST_VAULT_KEY)));
    store
}

/// Initialise the process-singleton identity (idempotent — first caller wins).
fn init_test_identity() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir for daemon identity");
    let _ = init_identity(dir.path());
    dir
}

fn test_policy() -> PolicyEngine {
    PolicyEngine::default()
}

fn test_rl() -> RefCell<RateLimiter> {
    RefCell::new(RateLimiter::default())
}

fn test_vault() -> Vault {
    Vault::new(TEST_VAULT_KEY)
}

/// Build a minimal SessionMeta fixture and write it to the sessions_dir.
fn create_session(
    session_store: &SessionStore,
    store: &DaemonStore,
    session_id: &str,
    persona_name: &str,
) -> SessionMeta {
    // Mint persona + grant
    let persona = store.create_persona(persona_name).expect("create_persona");
    let grant = store
        .create_grant(&persona.id, "test-token", "read", Some(3600))
        .expect("create_grant");

    let meta = SessionMeta {
        session_id: session_id.to_string(),
        persona: persona.id.clone(),
        durable_persona: None,
        grant_id: grant.id.clone(),
        caller_binding_id: None,
        launcher_pid: std::process::id(),
        started_at: chrono::Utc::now(),
        authority_strict: false,
        delegation_id: None,
        delegation_template: None,
    };
    session_store
        .create(&meta)
        .expect("create session in store");
    meta
}

/// Parse a v2 cohort-A Receipt envelope from disk and return both the envelope
/// and the decoded body so callers can assert individual fields.
fn load_receipt(receipt_path: &Path) -> (ReceiptEnvelope, ClaudeCodeBody) {
    let bytes = std::fs::read(receipt_path)
        .unwrap_or_else(|e| panic!("read receipt at {}: {e}", receipt_path.display()));
    let envelope: ReceiptEnvelope =
        serde_json::from_slice(&bytes).expect("deserialize ReceiptEnvelope");
    let body: ClaudeCodeBody =
        serde_json::from_value(envelope.body.clone()).expect("deserialize ClaudeCodeBody");
    (envelope, body)
}

fn assert_body_tamper_rejected<F>(
    envelope: &ReceiptEnvelope,
    public_key: &core_crypto::PublicKey,
    label: &str,
    mutate_body: F,
) where
    F: FnOnce(&mut serde_json::Value),
{
    let mut tampered = envelope.clone();
    mutate_body(&mut tampered.body);
    let err = verify_receipt_v2(&tampered, public_key, &core_crypto::FixtureVerifier)
        .expect_err("tampered receipt must fail verification");
    assert!(
        matches!(err, SignError::ReceiptIdMismatch { .. }),
        "{label}: expected receipt-id mismatch after body tamper, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// T2a — TTL-expiry path
// ---------------------------------------------------------------------------

/// TTL-expiry: session_watcher's close_session_ttl_expiry emits a signed v2
/// Receipt with `termination_reason = ttl_expired` and persists the sidecar
/// to `<sessions_dir>/<session_id>/receipt.json`.
#[test]
fn ttl_expiry_session_close_emits_v2_receipt_with_ttl_expired() {
    let _id_dir = init_test_identity();
    let identity = current_identity().expect("identity must be loaded");

    let sessions_dir_tmp = tempfile::tempdir().expect("sessions tempdir");
    let sessions_dir = sessions_dir_tmp.path().to_path_buf();
    let session_store = SessionStore::new(sessions_dir.clone());

    let store = store_with_vault();
    let session_id = "sess-ttl-v2-test";
    let meta = create_session(&session_store, &store, session_id, "persona-ttl-v2");

    // Pre-condition: receipt.json placeholder is empty (created by SessionStore::create).
    let receipt_path = sessions_dir.join(session_id).join("receipt.json");
    assert!(
        receipt_path.exists(),
        "receipt.json placeholder must exist after session creation"
    );
    let pre_content = std::fs::read(&receipt_path).expect("read pre-receipt");
    assert!(
        pre_content.is_empty(),
        "receipt.json must be empty before close"
    );

    // Invoke the TTL-expiry close path via the public helper that wraps
    // the internal close_session with TerminationReason::TtlExpired.
    close_session_ttl_expiry(
        &session_store,
        &store,
        session_id,
        &meta.grant_id,
        &sessions_dir,
    );

    // After close_session_ttl_expiry, receipt.json must be non-empty.
    let post_content = std::fs::read(&receipt_path).expect("read post-receipt");
    assert!(
        !post_content.is_empty(),
        "receipt.json must be populated after TTL-expiry close"
    );

    let (loaded_envelope, body) = load_receipt(&receipt_path);

    // 1. Signed v2 envelope.
    assert_eq!(loaded_envelope.version.0, "2", "must be v2 Receipt");
    assert!(
        loaded_envelope.signature.is_some(),
        "Receipt must carry a signature"
    );

    // 2. Termination reason = TtlExpired.
    assert_eq!(
        body.termination_reason,
        Some(TerminationReason::TtlExpired),
        "TTL-expiry path must set termination_reason = TtlExpired"
    );

    // 3. Heartbeat fields absent (only populated by HeartbeatLost path).
    assert!(
        body.last_heartbeat_at.is_none(),
        "TtlExpired receipt must not carry last_heartbeat_at"
    );
    assert!(
        body.pid_alive_at_check.is_none(),
        "TtlExpired receipt must not carry pid_alive_at_check"
    );

    // 4. Signature verifies under the daemon identity's public key.
    let pk = core_crypto::PublicKey(format!("ed25519:{}", identity.pubkey_hex()));
    verify_receipt_v2(&loaded_envelope, &pk, &core_crypto::FixtureVerifier)
        .expect("signed v2 Receipt must verify under daemon identity pubkey");
    assert_body_tamper_rejected(
        &loaded_envelope,
        &pk,
        "ttl_expired termination_reason",
        |body| {
            body["termination_reason"] = json!("clean_exit");
        },
    );
}

// ---------------------------------------------------------------------------
// T2b — Explicit-revoke path
// ---------------------------------------------------------------------------

/// Explicit revoke: `revoke_grant` RPC arm emits a signed v2 Receipt with
/// `termination_reason = explicit_revoke` and writes the sidecar to
/// `<sessions_dir>/grant:<grant_id>/receipt.json`.
#[tokio::test]
async fn explicit_revoke_emits_v2_receipt_with_explicit_revoke() {
    let _id_dir = init_test_identity();
    let identity = current_identity().expect("identity must be loaded");

    let sessions_dir_tmp = tempfile::tempdir().expect("sessions tempdir");
    let sessions_dir = sessions_dir_tmp.path().to_path_buf();

    let store = store_with_vault();
    let policy = test_policy();
    let rl = test_rl();
    let vault = test_vault();

    // Mint a persona + grant so revoke_grant has something to act on.
    let persona = store
        .create_persona("persona-revoke-v2")
        .expect("create_persona");
    let grant = store
        .create_grant(&persona.id, "test-cred", "read", Some(3600))
        .expect("create_grant");
    let grant_id = grant.id.clone();

    // Build a RequestContext that carries sessions_dir so the RPC arm can
    // persist the receipt sidecar.
    let mut ctx = RequestContext::internal("v2-receipt-test");
    ctx.sessions_dir = Some(sessions_dir.clone());

    // Invoke the revoke_grant RPC arm.
    let result = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "revoke_grant",
        &json!({"id": grant_id}),
    )
    .await
    .expect("revoke_grant must succeed");

    assert_eq!(
        result["revoked"],
        json!(true),
        "revoke_grant must return revoked=true"
    );

    // The receipt sidecar must exist at <sessions_dir>/grant:<grant_id>/receipt.json.
    let synthetic_session_id = format!("grant:{grant_id}");
    let receipt_path = sessions_dir
        .join(&synthetic_session_id)
        .join("receipt.json");
    assert!(
        receipt_path.exists(),
        "receipt.json sidecar must be written at {}: grant: {}",
        receipt_path.display(),
        grant_id
    );

    let (loaded_envelope, body) = load_receipt(&receipt_path);

    // 1. v2 Receipt.
    assert_eq!(loaded_envelope.version.0, "2", "must be v2 Receipt");
    assert!(
        loaded_envelope.signature.is_some(),
        "Receipt must be signed"
    );

    // 2. Correct termination reason.
    assert_eq!(
        body.termination_reason,
        Some(TerminationReason::ExplicitRevoke),
        "explicit-revoke path must set termination_reason = ExplicitRevoke"
    );

    // 3. Heartbeat fields absent.
    assert!(body.last_heartbeat_at.is_none());
    assert!(body.pid_alive_at_check.is_none());

    // 4. Signature verification.
    let pk = core_crypto::PublicKey(format!("ed25519:{}", identity.pubkey_hex()));
    verify_receipt_v2(&loaded_envelope, &pk, &core_crypto::FixtureVerifier)
        .expect("signed v2 Receipt must verify under daemon identity pubkey");
    assert_body_tamper_rejected(
        &loaded_envelope,
        &pk,
        "explicit_revoke termination_reason",
        |body| {
            body["termination_reason"] = json!("clean_exit");
        },
    );
}

// ---------------------------------------------------------------------------
// T2c — Regression: dirty-exit and clean-exit still work
// ---------------------------------------------------------------------------

/// Regression guard: the dirty-exit path (transition_to_terminated_dirty_at)
/// still emits a signed v2 Receipt with `termination_reason = HeartbeatLost`.
#[test]
fn dirty_exit_still_emits_heartbeat_lost_receipt() {
    let _id_dir = init_test_identity();
    let identity = current_identity().expect("identity must be loaded");

    let sessions_dir_tmp = tempfile::tempdir().expect("sessions tempdir");
    let sessions_dir = sessions_dir_tmp.path().to_path_buf();
    let session_store = SessionStore::new(sessions_dir.clone());

    let store = DaemonStore::open_in_memory().expect("open in-memory store");
    store.set_vault(Rc::new(Vault::new(TEST_VAULT_KEY)));

    let session_id = "sess-dirty-exit-regression";
    let meta = create_session(&session_store, &store, session_id, "persona-dirty-exit");
    let last_heartbeat = chrono::Utc::now() - chrono::Duration::minutes(2);

    let envelope = transition_to_terminated_dirty_at(
        &store,
        &session_store,
        &sessions_dir,
        &meta,
        last_heartbeat,
        false,
    )
    .expect("transition_to_terminated_dirty_at must succeed");

    // Receipt must be a signed v2 envelope.
    assert_eq!(envelope.version.0, "2");
    assert!(envelope.signature.is_some());

    let body: ClaudeCodeBody =
        serde_json::from_value(envelope.body.clone()).expect("deserialize ClaudeCodeBody");
    assert_eq!(
        body.termination_reason,
        Some(TerminationReason::HeartbeatLost),
        "dirty-exit must set termination_reason = HeartbeatLost"
    );
    assert_eq!(body.pid_alive_at_check, Some(false));

    // Verify signature.
    let pk = core_crypto::PublicKey(format!("ed25519:{}", identity.pubkey_hex()));
    verify_receipt_v2(&envelope, &pk, &core_crypto::FixtureVerifier)
        .expect("dirty-exit v2 Receipt must verify under daemon identity pubkey");
    assert_body_tamper_rejected(&envelope, &pk, "heartbeat_lost pid diagnostic", |body| {
        body["pid_alive_at_check"] = json!(true);
    });
}

/// Orphan sweep fallback: the legacy 60s watcher path also maps to
/// `HeartbeatLost`, and must carry the same heartbeat diagnostics as the
/// canonical heartbeat watcher transition.
#[test]
fn orphan_sweep_heartbeat_lost_receipt_carries_diagnostics_and_verifies() {
    let _id_dir = init_test_identity();
    let identity = current_identity().expect("identity must be loaded");

    let sessions_dir_tmp = tempfile::tempdir().expect("sessions tempdir");
    let sessions_dir = sessions_dir_tmp.path().to_path_buf();
    let session_store = SessionStore::new(sessions_dir.clone());

    let store = store_with_vault();
    let meta = create_session(
        &session_store,
        &store,
        "sess-orphan-heartbeat-diagnostics",
        "persona-orphan-heartbeat",
    );
    let heartbeat_at = chrono::Utc::now() - chrono::Duration::minutes(7);
    heartbeat::write_heartbeat(&sessions_dir.join(&meta.session_id), heartbeat_at)
        .expect("write stale heartbeat for orphan fixture");

    close_session_heartbeat_orphan(&session_store, &store, &meta, &sessions_dir);

    let orphan_receipt_path = sessions_dir.join(&meta.session_id).join("receipt.json");
    let (orphan_envelope, orphan_body) = load_receipt(&orphan_receipt_path);
    assert_eq!(orphan_envelope.kind, "session.claude_code");
    assert_eq!(orphan_envelope.daemon_root_id, identity.pubkey_hex());
    assert_eq!(
        orphan_body.termination_reason,
        Some(TerminationReason::HeartbeatLost)
    );
    let expected_heartbeat_at = heartbeat_at.to_rfc3339();
    assert_eq!(
        orphan_body.last_heartbeat_at.as_deref(),
        Some(expected_heartbeat_at.as_str())
    );
    assert_eq!(orphan_body.pid_alive_at_check, Some(false));

    let pk = core_crypto::PublicKey(format!("ed25519:{}", identity.pubkey_hex()));
    verify_receipt_v2(&orphan_envelope, &pk, &core_crypto::FixtureVerifier)
        .expect("orphan-sweep receipt must verify under daemon identity pubkey");
    assert_body_tamper_rejected(
        &orphan_envelope,
        &pk,
        "orphan heartbeat_lost last heartbeat diagnostic",
        |body| {
            body["last_heartbeat_at"] = json!("1970-01-01T00:00:00Z");
        },
    );

    let clean_meta = create_session(
        &session_store,
        &store,
        "sess-clean-equivalence",
        "persona-clean-equivalence",
    );
    close_session_clean_exit(
        &session_store,
        &store,
        &clean_meta.session_id,
        &clean_meta.grant_id,
        &sessions_dir,
    );
    let clean_receipt_path = sessions_dir
        .join(&clean_meta.session_id)
        .join("receipt.json");
    let (clean_envelope, _) = load_receipt(&clean_receipt_path);
    assert_eq!(
        orphan_envelope.daemon_root_id, clean_envelope.daemon_root_id,
        "orphan fallback and clean-exit receipts must share daemon provenance"
    );
    verify_receipt_v2(&clean_envelope, &pk, &core_crypto::FixtureVerifier)
        .expect("clean-exit comparison receipt must verify under same daemon identity pubkey");
}

// ---------------------------------------------------------------------------
// T3a — CleanExit MUST NOT revoke the grant
// (COHORT-A-V03-T3-FIX-CLEAN-EXIT-OVER-REVOKE)
// ---------------------------------------------------------------------------

/// T3a: After a CleanExit session close, the grant must remain Active.
///
/// This guards the multi-session-per-24h-grant invariant from the v0.3 test
/// plan. Regression introduced by COHORT-A-V03-V2-RECEIPT-COVERAGE-OTHER-LANES
/// M3 which unconditionally called revoke_grant inside close_session.
#[test]
fn clean_exit_does_not_revoke_grant() {
    let _id_dir = init_test_identity();

    let sessions_dir_tmp = tempfile::tempdir().expect("sessions tempdir");
    let sessions_dir = sessions_dir_tmp.path().to_path_buf();
    let session_store = SessionStore::new(sessions_dir.clone());

    let store = store_with_vault();
    let session_id = "sess-clean-exit-no-revoke";
    let meta = create_session(&session_store, &store, session_id, "persona-clean-exit");
    let grant_id = meta.grant_id.clone();

    // Pre-condition: grant must be Active before the close.
    let pre_grant = store.get_grant(&grant_id).expect("get_grant pre-close");
    assert_eq!(
        pre_grant.status, "active",
        "grant must be Active before clean-exit close"
    );

    // Close with CleanExit.
    close_session_clean_exit(&session_store, &store, session_id, &grant_id, &sessions_dir);

    // Post-condition: grant must still be Active — CleanExit MUST NOT revoke.
    let post_grant = store.get_grant(&grant_id).expect("get_grant post-close");
    assert_eq!(
        post_grant.status, "active",
        "CleanExit MUST NOT revoke the grant — multi-session per 24h grant is the contract \
         (COHORT-A-V03-T3-FIX-CLEAN-EXIT-OVER-REVOKE)"
    );
}

// ---------------------------------------------------------------------------
// T3d — handler close_session RPC arm MUST NOT revoke the grant on CleanExit
// (COHORT-A-V03-T3-FIX-HANDLER-CLEAN-EXIT-REVOKE)
// ---------------------------------------------------------------------------

/// T3d: After calling the handler's close_session RPC arm, the grant must
/// remain Active.
///
/// The launcher's clean-exit path goes through the `close_session` JSON-RPC
/// arm in handler.rs — NOT through session_watcher::close_session_clean_exit.
/// #2366 fixed session_watcher but missed this second revoke_grant call.
/// This test guards the handler path directly.
///
/// Invariant: a 24h grant supports many sessions. CleanExit closes the
/// session but MUST leave the grant Active for the next session.
/// (COHORT-A-V03-T3-FIX-HANDLER-CLEAN-EXIT-REVOKE)
#[tokio::test]
async fn handler_close_session_does_not_revoke_grant_on_clean_exit() {
    let _id_dir = init_test_identity();

    let sessions_dir_tmp = tempfile::tempdir().expect("sessions tempdir");
    let sessions_dir = sessions_dir_tmp.path().to_path_buf();

    let store = store_with_vault();
    let policy = test_policy();
    let rl = test_rl();
    let vault = test_vault();

    // Mint a persona + grant via the RPC arms (mirrors the launcher flow).
    let persona_resp = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        RequestContext::internal("handler-clean-exit-test"),
        "create_persona",
        &json!({"name": "handler-clean-exit-persona"}),
    )
    .await
    .expect("create_persona must succeed");
    let persona_id = persona_resp["id"].as_str().expect("persona id");

    let grant_resp = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        RequestContext::internal("handler-clean-exit-test"),
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "claude-code-default-v1",
            "scope": "claude-code",
            "ttl_secs": 86_400,
            "max_delegation_depth": 1,
            "force": true,
        }),
    )
    .await
    .expect("create_grant must succeed");
    let grant_id = grant_resp["id"].as_str().expect("grant id").to_string();

    // Pre-condition: grant Active.
    let pre_grant = store.get_grant(&grant_id).expect("get_grant pre-close");
    assert_eq!(
        pre_grant.status, "active",
        "grant must be Active before close"
    );

    // Register a session via the RPC arm.
    let mut ctx = RequestContext::internal("handler-clean-exit-test");
    ctx.sessions_dir = Some(sessions_dir.clone());

    let reg = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx.clone(),
        "register_session",
        &json!({
            "persona": "handler-clean-exit-persona",
            "launcher_pid": std::process::id(),
        }),
    )
    .await
    .expect("register_session must succeed");
    let session_id = reg["session_id"].as_str().expect("session_id").to_string();

    // Close the session via the handler's close_session RPC arm.
    let close = dispatch_method_with_context(
        &store,
        &vault,
        &policy,
        &rl,
        None,
        ctx,
        "close_session",
        &json!({ "session_id": session_id }),
    )
    .await
    .expect("close_session must succeed");
    assert_eq!(
        close["closed"],
        json!(true),
        "close_session must return closed:true"
    );

    // Post-condition: grant must remain Active — MUST NOT be revoked.
    // COHORT-A-V03-T3-FIX-HANDLER-CLEAN-EXIT-REVOKE
    let post_grant = store.get_grant(&grant_id).expect("get_grant post-close");
    assert_eq!(
        post_grant.status, "active",
        "handler close_session CleanExit MUST NOT revoke the grant \
         (COHORT-A-V03-T3-FIX-HANDLER-CLEAN-EXIT-REVOKE)"
    );
}

// ---------------------------------------------------------------------------
// T3b — TtlExpired MUST revoke the grant
// ---------------------------------------------------------------------------

/// T3b: After a TtlExpired session close, the grant must be Revoked.
///
/// Non-regression: the TTL-expiry path in session_watcher MUST still revoke
/// the grant after the CleanExit fix.
#[test]
fn ttl_expired_revokes_grant() {
    let _id_dir = init_test_identity();

    let sessions_dir_tmp = tempfile::tempdir().expect("sessions tempdir");
    let sessions_dir = sessions_dir_tmp.path().to_path_buf();
    let session_store = SessionStore::new(sessions_dir.clone());

    let store = store_with_vault();
    let session_id = "sess-ttl-revokes-grant";
    let meta = create_session(&session_store, &store, session_id, "persona-ttl-revokes");
    let grant_id = meta.grant_id.clone();

    // Pre-condition: grant Active.
    let pre_grant = store.get_grant(&grant_id).expect("get_grant pre-close");
    assert_eq!(pre_grant.status, "active");

    // Close via TTL-expiry path.
    close_session_ttl_expiry(&session_store, &store, session_id, &grant_id, &sessions_dir);

    // Post-condition: grant must be Revoked.
    let post_grant = store.get_grant(&grant_id).expect("get_grant post-close");
    assert_eq!(
        post_grant.status, "revoked",
        "TtlExpired MUST revoke the grant"
    );
}

// ---------------------------------------------------------------------------
// T3c — explicit revoke_grant MUST revoke the grant
// ---------------------------------------------------------------------------

/// T3c: Calling revoke_grant directly must set grant status to Revoked.
///
/// Non-regression: explicit revocation must still work after the CleanExit fix.
#[test]
fn explicit_revoke_revokes_grant() {
    let _id_dir = init_test_identity();

    let store = store_with_vault();

    // Mint persona + grant — no session needed; we call revoke_grant directly.
    let persona = store
        .create_persona("persona-explicit-revoke")
        .expect("create_persona");
    let grant = store
        .create_grant(&persona.id, "test-token", "read", Some(3600))
        .expect("create_grant");
    let grant_id = grant.id.clone();

    // Pre-condition: grant Active.
    let pre_grant = store.get_grant(&grant_id).expect("get_grant pre-revoke");
    assert_eq!(pre_grant.status, "active");

    // Explicit revocation via DaemonStore.
    store
        .revoke_grant(&grant_id)
        .expect("revoke_grant must succeed");

    // Post-condition: grant must be Revoked.
    let post_grant = store.get_grant(&grant_id).expect("get_grant post-revoke");
    assert_eq!(
        post_grant.status, "revoked",
        "explicit revoke_grant MUST revoke the grant"
    );
}
