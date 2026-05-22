use std::path::PathBuf;
use std::rc::Rc;

use chrono::{DateTime, Duration, Utc};
use core_events::receipt::{TerminationAuthority, TerminationReason};
use tracing::{info, warn};

use crate::infra::claim_journal::{
    close_session_scope_best_effort, close_summary_audit_fields,
    summarize_session_scope_best_effort,
};
use crate::infra::receipt::{
    current_identity,
    issue::{TerminationMeta, issue_cohort_a_receipt},
};
use crate::infra::store::DaemonStore;
use crate::session::lifecycle::DaemonPersonaSigner;
use core_state::sessions::SessionStore;

/// How long after a session's grant `created_at` before TTL backstop fires.
const GRANT_TTL: Duration = Duration::hours(24);

/// How long a launcher PID must be dead before the orphan sweep closes the session.
const ORPHAN_GRACE: Duration = Duration::minutes(5);

/// Check whether a process with the given PID is still alive.
///
/// Uses `kill(pid, 0)` — sends signal 0 which does no harm but returns an
/// error with `ESRCH` when the PID does not exist. Returns `true` when the
/// process is alive (or the caller lacks permission to signal it, which means
/// it exists).
fn pid_alive(pid: u32) -> bool {
    // SAFETY: kill(pid, 0) is a read-only syscall: it never delivers a signal.
    // The only side effect is an errno value returned to us.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    // Read errno via std so this compiles on macOS and Linux without
    // platform-specific accessor function selection.
    let os_err = std::io::Error::last_os_error();
    let raw = os_err.raw_os_error().unwrap_or(0);
    // ESRCH — process does not exist.
    // EPERM — process exists but we can't signal it; treat as alive.
    raw != libc::ESRCH
}

/// Derive the sessions directory from the data directory.
///
/// Convention: `~/.ember/data/` → `~/.ember/sessions/`. We walk up one level
/// from `data_dir` and append `sessions/`. If the parent is unavailable we
/// fall back to `data_dir/../sessions` which is the same path on a standard
/// install.
pub fn sessions_dir_from_data(data_dir: &std::path::Path) -> PathBuf {
    data_dir.parent().unwrap_or(data_dir).join("sessions")
}

/// Background task: heartbeat + TTL session watcher.
///
/// Spawned via `spawn_local` on the daemon's `LocalSet` so it shares the same
/// single-threaded context as `DaemonStore` (which is `!Send`).
///
/// Loop cadence: 60 seconds. For each open session:
///
/// 1. **Orphan check** — if `launcher_pid` is dead AND the session has been
///    running for more than `ORPHAN_GRACE` (5 min), close it with reason
///    `"heartbeat-orphan"`.
/// 2. **TTL backstop** — if the session's grant `created_at + 24h` is in the
///    past, close it with reason `"ttl-expired"`.
///
/// Closing a session:
/// - calls `SessionStore::close` (renames `meta.json` → `meta.json.closed`)
/// - logs a `session.closed` event into the daemon audit log with the reason
///   as the `outcome` field.
pub async fn run(store: Rc<DaemonStore>, sessions_dir: PathBuf) {
    let session_store = SessionStore::new(sessions_dir.clone());
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        interval.tick().await;

        let sessions = match session_store.list_open() {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "session watcher: failed to list open sessions");
                continue;
            }
        };

        for session in sessions {
            let now = Utc::now();
            let session_id = &session.session_id;

            // --- Orphan check ---
            if !pid_alive(session.launcher_pid) {
                let age = now.signed_duration_since(session.started_at);
                if age > ORPHAN_GRACE {
                    info!(
                        session_id = %session_id,
                        launcher_pid = session.launcher_pid,
                        age_secs = age.num_seconds(),
                        "session watcher: orphaned session — closing"
                    );
                    // Orphan close: use HeartbeatLost (launcher PID gone).
                    close_session(
                        &session_store,
                        &store,
                        session_id,
                        &session.grant_id,
                        "heartbeat-orphan",
                        TerminationReason::HeartbeatLost,
                        &sessions_dir,
                    );
                    continue;
                }
            }

            // --- TTL backstop ---
            let grant_expired = match store.get_grant(&session.grant_id) {
                Ok(grant_info) => match grant_info.created_at.parse::<DateTime<Utc>>() {
                    Ok(created_at) => {
                        let expiry = created_at + GRANT_TTL;
                        now > expiry
                    }
                    Err(e) => {
                        warn!(
                            session_id = %session_id,
                            grant_id = %session.grant_id,
                            error = %e,
                            "session watcher: could not parse grant created_at — skipping TTL check"
                        );
                        false
                    }
                },
                Err(crate::infra::store::StoreError::NotFound) => {
                    // Grant is gone — treat as TTL expired.
                    true
                }
                Err(e) => {
                    warn!(
                        session_id = %session_id,
                        grant_id = %session.grant_id,
                        error = %e,
                        "session watcher: grant lookup failed — skipping TTL check"
                    );
                    false
                }
            };

            if grant_expired {
                info!(
                    session_id = %session_id,
                    grant_id = %session.grant_id,
                    "session watcher: grant TTL expired — closing session"
                );
                // v2_receipt_coverage_audit_v030_2026_05_09: extend Receipt to TTL/revoke per M3 follow-up
                close_session(
                    &session_store,
                    &store,
                    session_id,
                    &session.grant_id,
                    "ttl-expired",
                    TerminationReason::TtlExpired,
                    &sessions_dir,
                );
            }
        }
    }
}

/// Public entry point for tests and callers that need to directly trigger a
/// TTL-expiry session close with a signed v2 Receipt. Wraps [`close_session`]
/// with `TerminationReason::TtlExpired` so test code does not need access to
/// the private `close_session` signature.
///
/// Returns the v2 Receipt envelope on success; `None` if the daemon identity
/// is not initialised or issuance fails (same best-effort posture as the
/// background sweep).
pub fn close_session_ttl_expiry(
    session_store: &SessionStore,
    daemon_store: &DaemonStore,
    session_id: &str,
    grant_id: &str,
    sessions_dir: &std::path::Path,
) {
    close_session(
        session_store,
        daemon_store,
        session_id,
        grant_id,
        "ttl-expired",
        TerminationReason::TtlExpired,
        sessions_dir,
    );
}

/// Public entry point for tests and callers that need to directly trigger a
/// clean-exit session close with a signed v2 Receipt. Wraps [`close_session`]
/// with `TerminationReason::CleanExit` so test code does not need access to
/// the private `close_session` signature.
///
/// implementation-note-390: clean_exit MUST NOT revoke
/// the grant — multiple sessions per 24h grant is the contract.
pub fn close_session_clean_exit(
    session_store: &SessionStore,
    daemon_store: &DaemonStore,
    session_id: &str,
    grant_id: &str,
    sessions_dir: &std::path::Path,
) {
    close_session(
        session_store,
        daemon_store,
        session_id,
        grant_id,
        "clean-exit",
        TerminationReason::CleanExit,
        sessions_dir,
    );
}

/// Emit a signed v2 cohort-A Receipt for the given session, persist the
/// sidecar to `<sessions_dir>/<session_id>/receipt.json`, close the session
/// via [`SessionStore::close`], conditionally revoke the broker grant, and
/// audit-log the transition.
///
/// `termination_reason` distinguishes TTL-expiry from orphan (heartbeat-lost)
/// sweeps so the signed body accurately records the actual cause.
///
/// # Grant revocation policy
///
/// implementation-note-390: clean_exit MUST NOT revoke
/// the grant — multiple sessions per 24h grant is the contract.
///
/// Grant revocation is performed ONLY for:
/// - `TerminationReason::TtlExpired` — the 24h window has closed; no new sessions.
/// - `TerminationReason::ExplicitRevoke` — operator-initiated; grant is terminal.
/// - `TerminationReason::HeartbeatLost` — dirty exit (orphan sweep); treat as
///   unclean termination; the grant is revoked so stale credentials cannot be
///   re-used by a process that disappeared without ceremony.
///
/// `TerminationReason::CleanExit` does NOT revoke the grant. The grant remains
/// `Active` and supports further sessions within the 24h window. This matches
/// the v0.3 test-plan invariant H3: "a 24h grant supports many sessions".
///
/// Receipt emission is best-effort: if the daemon identity is not yet
/// initialised (test harness, pre-startup paths), this function logs a
/// warning and continues — the session still gets closed and the audit row
/// still lands so operators see the transition.
fn close_session(
    session_store: &SessionStore,
    daemon_store: &DaemonStore,
    session_id: &str,
    grant_id: &str,
    reason: &str,
    termination_reason: TerminationReason,
    sessions_dir: &std::path::Path,
) {
    // Evaluate revocation policy before moving termination_reason into the Receipt.
    //
    // implementation-note-390: clean_exit MUST NOT revoke
    // the grant — multiple sessions per 24h grant is the contract.
    let should_revoke = !matches!(termination_reason, TerminationReason::CleanExit);

    // 1. Emit a signed v2 cohort-A Receipt before mutating state so the
    //    audit trail is complete even on partial failure.
    //    v2_receipt_coverage_audit_v030_2026_05_09: extend Receipt to TTL/revoke per M3 follow-up
    let claim_summary =
        summarize_session_scope_best_effort(daemon_store, session_id, "session_watcher::close_session");
    if let Some(identity) = current_identity() {
        let signer = DaemonPersonaSigner::new(identity);
        let issue_result = if let Some(summary) = claim_summary.as_ref() {
            crate::infra::receipt::issue::issue_cohort_a_receipt_from_closed_scope(
                session_id,
                summary,
                None,
                TerminationAuthority::DaemonPersona,
                &identity.pubkey_hex(),
                Some(TerminationMeta {
                    reason: termination_reason,
                    last_heartbeat_at: None,
                    pid_alive_at_check: None,
                }),
                &signer,
            )
        } else {
            issue_cohort_a_receipt(
                session_id,
                Vec::new(),
                None,
                TerminationAuthority::DaemonPersona,
                &identity.pubkey_hex(),
                Some(TerminationMeta {
                    reason: termination_reason,
                    last_heartbeat_at: None,
                    pid_alive_at_check: None,
                }),
                &signer,
            )
        };
        match issue_result {
            Ok(envelope) => {
                let receipt_path = sessions_dir.join(session_id).join("receipt.json");
                match serde_json::to_vec_pretty(&envelope) {
                    Ok(bytes) => {
                        if let Err(e) = std::fs::write(&receipt_path, &bytes) {
                            warn!(
                                session_id = %session_id,
                                path = %receipt_path.display(),
                                error = %e,
                                "session watcher: failed to persist v2 Receipt sidecar"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            session_id = %session_id,
                            error = %e,
                            "session watcher: failed to serialize v2 Receipt"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    session_id = %session_id,
                    error = %e,
                    "session watcher: failed to issue v2 cohort-A Receipt"
                );
            }
        }
    } else {
        warn!(
            session_id = %session_id,
            "session watcher: daemon identity not initialised — skipping v2 Receipt emission"
        );
    }

    // 2. Close the session (renames meta.json → meta.json.closed).
    if let Err(e) = session_store.close(session_id) {
        warn!(
            session_id = %session_id,
            error = %e,
            "session watcher: failed to close session"
        );
        return;
    }
    let _ = crate::infra::interactive_unlock::release_session_pin(session_id);
    let claim_summary = close_session_scope_best_effort(
        daemon_store,
        session_id,
        "session_watcher::close_session",
    )
    .or(claim_summary);

    // 3. Revoke the broker grant — cascades to children.
    //
    // Revoke only on terminal/dirty termination reasons (see policy at top of
    // function). CleanExit leaves the grant Active.
    if should_revoke && let Err(e) = daemon_store.revoke_grant(grant_id) {
        match e {
            crate::infra::store::StoreError::NotFound => {
                warn!(
                    session_id = %session_id,
                    grant_id = %grant_id,
                    "session watcher: grant absent at close — likely already terminal"
                );
            }
            other => {
                warn!(
                    session_id = %session_id,
                    grant_id = %grant_id,
                    error = %other,
                    "session watcher: failed to revoke grant"
                );
            }
        }
    }

    let mut details = format!("session_id={session_id} grant_id={grant_id}");
    if let Some(summary) = claim_summary.as_ref() {
        details.push(' ');
        details.push_str(&close_summary_audit_fields(summary));
    }

    // 4. Audit-log the transition.
    if let Err(e) = daemon_store.log_event(
        None,
        "session.closed",
        None,
        reason,
        Some(&details),
    ) {
        warn!(
            session_id = %session_id,
            reason = %reason,
            error = %e,
            "session watcher: failed to log session.closed audit event"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use core_events::receipt::{ClaudeCodeBody, ReceiptEnvelope};
    use core_state::sessions::SessionMeta;
    use tempfile::TempDir;
    use crate::infra::claim_journal::{
        AuditEvidenceInput, ClaimJournal, ClaimScopeKind, ScopeRef, SqliteClaimJournal,
        SuccessfulClaimInput,
    };
    use core_events::receipt::ClaimKind;

    #[test]
    fn close_session_clean_exit_releases_interactive_unlock_pin() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::infra::interactive_unlock::reset_for_tests();

        let sessions_root = TempDir::new().expect("temp sessions root");
        let sessions_dir = sessions_root.path().to_path_buf();
        let session_store = SessionStore::new(sessions_dir.clone());
        let daemon_store = DaemonStore::open_in_memory().expect("in-memory daemon store");

        let meta = SessionMeta {
            session_id: "sess_watch_test".to_string(),
            persona: "persona_test".to_string(),
            grant_id: "grant_test".to_string(),
            started_at: Utc::now(),
            launcher_pid: std::process::id(),
            workflow_id: None,
            workflow_template: None,
        };
        session_store.create(&meta).expect("create session meta");
        assert!(
            crate::infra::interactive_unlock::acquire_session_pin(&meta.session_id),
            "session-open pin should register before clean-exit close"
        );
        assert_eq!(crate::infra::interactive_unlock::pin_count(), 1);

        close_session_clean_exit(
            &session_store,
            &daemon_store,
            &meta.session_id,
            &meta.grant_id,
            &sessions_dir,
        );

        assert_eq!(
            crate::infra::interactive_unlock::pin_count(),
            0,
            "clean-exit watcher close must release the interactive pin"
        );
        assert!(
            sessions_dir
                .join(&meta.session_id)
                .join("meta.json.closed")
                .exists(),
            "session meta must be renamed closed"
        );
    }

    #[test]
    fn close_session_clean_exit_closes_claim_journal_scope() {
        let sessions_root = TempDir::new().expect("temp sessions root");
        let sessions_dir = sessions_root.path().to_path_buf();
        let identity_dir = TempDir::new().expect("temp identity root");
        let _ = crate::infra::receipt::init_identity(identity_dir.path());
        let session_store = SessionStore::new(sessions_dir.clone());
        let daemon_store = DaemonStore::open_in_memory().expect("in-memory daemon store");
        let journal = SqliteClaimJournal::new(&daemon_store, 64);

        let meta = SessionMeta {
            session_id: "sess_claim_journal_close".to_string(),
            persona: "persona_test".to_string(),
            grant_id: "grant_test".to_string(),
            started_at: Utc::now(),
            launcher_pid: std::process::id(),
            workflow_id: None,
            workflow_template: None,
        };
        session_store.create(&meta).expect("create session meta");

        let scope = ScopeRef {
            kind: ClaimScopeKind::Session,
            id: meta.session_id.clone(),
        };
        journal
            .record_successful_claim(
                &scope,
                &SuccessfulClaimInput {
                    source_key: "source-1".to_string(),
                    occurred_at: "2026-05-22T12:00:00Z".to_string(),
                    claim_kind: ClaimKind::CredentialVended,
                    tool: "Claude".to_string(),
                    input_hash: "h1".to_string(),
                    input_redacted: serde_json::json!({"cmd": "deploy"}),
                    resolved: serde_json::json!({"allowed": true}),
                    audit: AuditEvidenceInput {
                        agent_id: Some(meta.persona.clone()),
                        action: "broker.resolve.materialized".to_string(),
                        credential: Some("anthropic".to_string()),
                        outcome: "ok".to_string(),
                        details: Some("session-scoped".to_string()),
                    },
                    persona_id: Some(meta.persona.clone()),
                    device_id: Some("device-test".to_string()),
                    workflow_id: None,
                    materialization_id: Some("materialization-1".to_string()),
                    credential_name: Some("anthropic".to_string()),
                },
            )
            .expect("append claim row");

        close_session_clean_exit(
            &session_store,
            &daemon_store,
            &meta.session_id,
            &meta.grant_id,
            &sessions_dir,
        );

        let status: String = daemon_store
            .conn()
            .query_row(
                "SELECT status
                   FROM claim_journal_scopes
                  WHERE scope_kind = 'session' AND scope_id = ?1",
                rusqlite::params![meta.session_id],
                |row| row.get(0),
            )
            .expect("claim journal scope row");
        assert_eq!(status, "closed");

        let receipt_bytes = std::fs::read(
            sessions_dir
                .join(&meta.session_id)
                .join("receipt.json"),
        )
        .expect("receipt written");
        let receipt: ReceiptEnvelope =
            serde_json::from_slice(&receipt_bytes).expect("receipt envelope parses");
        let body: ClaudeCodeBody =
            serde_json::from_value(receipt.body).expect("receipt body parses");
        assert_eq!(body.base.claim_count_total, Some(1));
        assert!(!body.base.claim_events_truncated);
        assert_eq!(body.base.claim_segment_summaries.len(), 1);
        assert!(!body.base.claim_history_merkle_root.is_empty());
        assert!(!body.base.permits_merkle_root.is_empty());
    }
}
