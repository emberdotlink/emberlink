use std::path::{Path, PathBuf};
use std::rc::Rc;

use chrono::{DateTime, Duration, Utc};
use core_events::receipt::{TerminationAuthority, TerminationReason};
use core_state::sessions::{SessionMeta, SessionStore};
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
/// How long after a session's grant `created_at` before TTL backstop fires.
const GRANT_TTL: Duration = Duration::hours(24);

/// How long a launcher PID must be dead before the orphan sweep closes the session.
const ORPHAN_GRACE: Duration = Duration::minutes(5);

#[derive(Debug, Clone)]
struct HeartbeatDiagnostics {
    last_heartbeat_at: DateTime<Utc>,
    pid_alive_at_check: bool,
}

/// Check whether a process with the given PID is still alive.
///
/// Uses the shared daemon PID liveness helper so macOS separate-uid posture
/// can distinguish "cross-uid process hidden behind sandboxed kill(0)" from
/// "process truly gone".
fn pid_alive(pid: u32) -> bool {
    crate::infra::pid::process_exists(pid)
}

/// Derive the sessions directory from the data directory.
///
/// Per ADR 218 (operator-locked 2026-06-14) `data_dir == state_root` —
/// the legacy `~/.ember/data/` split is collapsed (see
/// `crate::paths::DaemonPaths::system()`), so sessions live as a direct
/// child of `data_dir`, NOT as a sibling.
///
/// macOS prod: `/Library/Application Support/Emberlink/sessions/`.
/// Linux prod: `/var/lib/ember/sessions/`.
/// For test fixtures using `DaemonPaths::for_test(tmp)`, same shape:
/// `tmp/sessions/`.
///
/// The pre-ADR-218 convention walked `data_dir.parent()` (which assumed
/// `data_dir = <root>/data/` and sessions was a sibling at `<root>/sessions/`).
/// That walk-up now escapes the state-root tree on prod hosts —
/// `parent("/Library/Application Support/Emberlink") = "/Library/Application Support"`
/// — and `create_dir` there returns EPERM because the daemon owns nothing
/// at that level, plus the sandbox profile only allowlists the state root.
pub fn sessions_dir_from_data(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("sessions")
}

fn heartbeat_diagnostics_for_session(
    sessions_dir: &Path,
    session: &SessionMeta,
    pid_alive_at_check: bool,
) -> HeartbeatDiagnostics {
    let session_dir = sessions_dir.join(&session.session_id);
    let last_heartbeat_at =
        crate::session::heartbeat::read_heartbeat(&session_dir).unwrap_or(session.started_at);
    HeartbeatDiagnostics {
        last_heartbeat_at,
        pid_alive_at_check,
    }
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
                    close_session_heartbeat_orphan(&session_store, &store, &session, &sessions_dir);
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
                    None,
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
        None,
    );
}

/// Public entry point for tests and callers that need to directly trigger a
/// clean-exit session close with a signed v2 Receipt. Wraps [`close_session`]
/// with `TerminationReason::CleanExit` so test code does not need access to
/// the private `close_session` signature.
///
/// COHORT-A-V03-T3-FIX-CLEAN-EXIT-OVER-REVOKE: clean_exit MUST NOT revoke
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
        None,
    );
}

/// Public entry point for tests and callers that need to directly trigger the
/// orphan-sweep close path. The signed Receipt uses `HeartbeatLost` and carries
/// the same heartbeat diagnostics as the canonical heartbeat watcher path.
pub fn close_session_heartbeat_orphan(
    session_store: &SessionStore,
    daemon_store: &DaemonStore,
    session: &SessionMeta,
    sessions_dir: &Path,
) {
    let diagnostics = heartbeat_diagnostics_for_session(sessions_dir, session, false);
    close_session(
        session_store,
        daemon_store,
        &session.session_id,
        &session.grant_id,
        "heartbeat-orphan",
        TerminationReason::HeartbeatLost,
        sessions_dir,
        Some(diagnostics),
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
/// COHORT-A-V03-T3-FIX-CLEAN-EXIT-OVER-REVOKE: clean_exit MUST NOT revoke
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
// Session-teardown plumbing signature — structurally many params (stores, ids, reason, paths, diagnostics).
#[allow(clippy::too_many_arguments)]
fn close_session(
    session_store: &SessionStore,
    daemon_store: &DaemonStore,
    session_id: &str,
    grant_id: &str,
    reason: &str,
    termination_reason: TerminationReason,
    sessions_dir: &std::path::Path,
    heartbeat_diagnostics: Option<HeartbeatDiagnostics>,
) {
    // Evaluate revocation policy before moving termination_reason into the Receipt.
    //
    // COHORT-A-V03-T3-FIX-CLEAN-EXIT-OVER-REVOKE: clean_exit MUST NOT revoke
    // the grant — multiple sessions per 24h grant is the contract.
    let should_revoke = !matches!(termination_reason, TerminationReason::CleanExit);
    let meta = session_store.read(session_id).ok().flatten();
    let remaining_attachments = meta
        .as_ref()
        .map(|session| session_store.count_other_open_attachments(session))
        .transpose()
        .ok()
        .flatten()
        .unwrap_or(0);
    let is_runtime_attachment = meta
        .as_ref()
        .is_some_and(|session| session.is_runtime_attachment());
    let terminate_runtime = is_runtime_attachment && remaining_attachments == 0;
    let runtime_kept_alive = is_runtime_attachment && remaining_attachments > 0;

    // 1. Emit a signed v2 cohort-A Receipt before mutating state so the
    //    audit trail is complete even on partial failure.
    //    v2_receipt_coverage_audit_v030_2026_05_09: extend Receipt to TTL/revoke per M3 follow-up
    let claim_summary = summarize_session_scope_best_effort(
        daemon_store,
        session_id,
        "session_watcher::close_session",
    );
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
                    reason: termination_reason.clone(),
                    last_heartbeat_at: heartbeat_diagnostics
                        .as_ref()
                        .map(|d| d.last_heartbeat_at.to_rfc3339()),
                    pid_alive_at_check: heartbeat_diagnostics
                        .as_ref()
                        .map(|d| d.pid_alive_at_check),
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
                    reason: termination_reason.clone(),
                    last_heartbeat_at: heartbeat_diagnostics
                        .as_ref()
                        .map(|d| d.last_heartbeat_at.to_rfc3339()),
                    pid_alive_at_check: heartbeat_diagnostics
                        .as_ref()
                        .map(|d| d.pid_alive_at_check),
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
    let claim_summary =
        close_session_scope_best_effort(daemon_store, session_id, "session_watcher::close_session")
            .or(claim_summary);
    // 3. Revoke the broker grant — cascades to children.
    //
    // Revoke only on terminal/dirty termination reasons (see policy at top of
    // function). CleanExit leaves the grant Active.
    if should_revoke && terminate_runtime {
        if let Some(meta) = meta.as_ref()
            && let Err(e) = daemon_store.revoke_persona(&meta.persona)
        {
            match e {
                crate::infra::store::StoreError::NotFound => {
                    warn!(
                        session_id = %session_id,
                        runtime_persona_id = %meta.persona,
                        "session watcher: runtime persona absent at close — likely already terminal"
                    );
                }
                other => {
                    warn!(
                        session_id = %session_id,
                        runtime_persona_id = %meta.persona,
                        error = %other,
                        "session watcher: failed to revoke runtime persona"
                    );
                }
            }
        }
    } else if should_revoke
        && !is_runtime_attachment
        && let Err(e) = daemon_store.revoke_grant(grant_id)
    {
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

    let mut details = format!(
        "session_id={session_id} grant_id={grant_id} remaining_attachments={remaining_attachments} runtime_terminated={terminate_runtime} runtime_kept_alive={runtime_kept_alive}"
    );
    if let Some(diagnostics) = heartbeat_diagnostics.as_ref() {
        details.push_str(&format!(
            " last_heartbeat_at={} pid_alive_at_check={}",
            diagnostics.last_heartbeat_at.to_rfc3339(),
            diagnostics.pid_alive_at_check
        ));
    }
    if let Some(summary) = claim_summary.as_ref() {
        details.push(' ');
        details.push_str(&close_summary_audit_fields(summary));
    }

    // 4. Audit-log the transition.
    if let Err(e) = daemon_store.log_event(None, "session.closed", None, reason, Some(&details)) {
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
    use crate::infra::claim_journal::{
        AuditEvidenceInput, ClaimJournal, ClaimScopeKind, ScopeRef, SqliteClaimJournal,
        SuccessfulClaimInput,
    };
    use chrono::Utc;
    use core_events::receipt::ClaimKind;
    use core_events::receipt::{ClaudeCodeBody, ReceiptEnvelope};
    use core_state::sessions::SessionMeta;
    use tempfile::TempDir;

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
            durable_persona: None,
            grant_id: "grant_test".to_string(),
            caller_binding_id: None,
            started_at: Utc::now(),
            launcher_pid: std::process::id(),
            authority_strict: false,
            delegation_id: None,
            delegation_template: None,
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
            durable_persona: None,
            grant_id: "grant_test".to_string(),
            caller_binding_id: None,
            started_at: Utc::now(),
            launcher_pid: std::process::id(),
            authority_strict: false,
            delegation_id: None,
            delegation_template: None,
        };
        session_store.create(&meta).expect("create session meta");

        let scope = ScopeRef {
            kind: ClaimScopeKind::AuthorityLane,
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
                    action_ref: None,
                    runner_class: None,
                    execution_domain: None,
                    materialization_class: None,
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
                    grant_id: None,
                    device_id: Some("device-test".to_string()),
                    delegation_id: None,
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

        let receipt_bytes = std::fs::read(sessions_dir.join(&meta.session_id).join("receipt.json"))
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

    #[test]
    fn close_session_ttl_expiry_keeps_runtime_alive_while_sibling_attachment_remains() {
        let sessions_root = TempDir::new().expect("temp sessions root");
        let sessions_dir = sessions_root.path().to_path_buf();
        let session_store = SessionStore::new(sessions_dir.clone());
        let daemon_store = DaemonStore::open_in_memory().expect("in-memory daemon store");

        let runtime_persona = daemon_store
            .create_persona("runtime-watcher-persona")
            .expect("create runtime persona");
        let runtime_grant = daemon_store
            .create_grant(&runtime_persona.id, "github-token", "repo:read", Some(3600))
            .expect("create runtime grant");

        let attachment_a = SessionMeta {
            session_id: "sess-runtime-a".to_string(),
            persona: runtime_persona.id.clone(),
            durable_persona: Some("persona-durable".to_string()),
            grant_id: runtime_grant.id.clone(),
            caller_binding_id: Some("binding-runtime-1".to_string()),
            started_at: Utc::now(),
            launcher_pid: std::process::id(),
            authority_strict: false,
            delegation_id: None,
            delegation_template: None,
        };
        let attachment_b = SessionMeta {
            session_id: "sess-runtime-b".to_string(),
            persona: runtime_persona.id.clone(),
            durable_persona: Some("persona-durable".to_string()),
            grant_id: runtime_grant.id.clone(),
            caller_binding_id: Some("binding-runtime-1".to_string()),
            started_at: Utc::now(),
            launcher_pid: std::process::id() + 1,
            authority_strict: false,
            delegation_id: None,
            delegation_template: None,
        };

        session_store
            .create(&attachment_a)
            .expect("create attachment a");
        session_store
            .create(&attachment_b)
            .expect("create attachment b");

        close_session_ttl_expiry(
            &session_store,
            &daemon_store,
            &attachment_a.session_id,
            &attachment_a.grant_id,
            &sessions_dir,
        );

        assert!(
            session_store
                .read(&attachment_b.session_id)
                .expect("read sibling attachment")
                .is_some(),
            "sibling attachment must remain open"
        );
        assert_eq!(
            daemon_store
                .get_grant(&runtime_grant.id)
                .expect("runtime grant still queryable")
                .status,
            "active",
            "ttl-expiring one attachment must not revoke the shared runtime grant"
        );
        assert_eq!(
            daemon_store
                .get_persona(&runtime_persona.id)
                .expect("runtime persona still queryable")
                .status,
            "active",
            "ttl-expiring one attachment must not revoke the shared runtime persona"
        );

        close_session_ttl_expiry(
            &session_store,
            &daemon_store,
            &attachment_b.session_id,
            &attachment_b.grant_id,
            &sessions_dir,
        );

        assert_eq!(
            daemon_store
                .get_grant(&runtime_grant.id)
                .expect("runtime grant still queryable")
                .status,
            "revoked",
            "ttl-expiring the last attachment must revoke the runtime grant"
        );
        assert_eq!(
            daemon_store
                .get_persona(&runtime_persona.id)
                .expect("runtime persona still queryable")
                .status,
            "revoked",
            "ttl-expiring the last attachment must revoke the runtime persona"
        );
    }
}
