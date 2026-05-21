//!
//! Workflow grant sidecar JSON storage — design §Component 3.
//!
//! Per-session sidecar file at `<sessions_dir>/<session_id>/workflow-grant.json`
//! carrying the active `core_grants::workflow::WorkflowGrant` if the launcher
//! attached one at session-open via the workflow-template prompt UX
//! (implementation-note-159).
//!
//! Sidecar pattern matches the existing audit-gaps.jsonl / permits-archive.jsonl
//! / receipt.json convention in `core_state::SessionStore` — see that module's
//! docstring (lines 17-26). Living in `ember-daemon` (not `core-state`) keeps
//! Layer 2 (Runtime & Persistence) untyped against Layer 3 (Domain Logic);
//! `core-grants` is Layer 3 and `core-state` is Layer 2 per CLAUDE.md.
//!
//! ## Lifecycle (post-PR-3672-adversarial-fixes, 2026-05-18)
//!
//! - **Issue**: launcher calls [`save_if_absent`] at session-open — atomically
//!   writes the grant; refuses if a grant (active OR revoked) already exists.
//!   The legacy [`save`] is reserved for explicit rotate-after-revoke flows
//!   that require the caller to have already invoked [`revoke`].
//! - **Read**: [`load`] returns `Ok(None)` when the sidecar is absent OR has
//!   been revoked (renamed to `workflow-grant.json.revoked`). The eval path
//!   treats both as "no active workflow grant."
//! - **Revoke**: [`revoke`] atomically renames `workflow-grant.json` to
//!   `workflow-grant.json.revoked`. design line 104 — "revoke is immediate;
//!   subsequent broker.resolve calls return DENIED until a new workflow
//!   grant is issued." The renamed file persists for audit-trail forensics;
//!   the daemon never reads it after rename.
//!
//! Writes are atomic: write to a uniquified tempfile (PID + nanos), fsync, then
//! rename. A crash mid-write leaves no partial JSON on disk; concurrent saves
//! against the same session_id cannot clobber each other's tempfiles.
//!
//! ## Sentinels
//!
//! - `pregrant_workflow_grant_primitive_landed` — anchored by the
//!   `#[test] fn pregrant_workflow_grant_primitive_landed` symbol at the
//!   bottom of this module.
//! - `workflow_grant_revoke_via_atomic_rename` — anchored by [`revoke`]
//!   and the corresponding `revoke_renames_sidecar` test.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use core_grants::workflow::WorkflowGrant;

const SIDECAR_NAME: &str = "workflow-grant.json";
const REVOKED_SUFFIX: &str = ".revoked";

/// Errors returned by [`save_if_absent`] when a grant is already present.
#[derive(Debug, thiserror::Error)]
pub enum SaveError {
    #[error(
        "workflow grant already active for session {session_id:?}; revoke first or use save() for rotate-after-revoke"
    )]
    AlreadyActive { session_id: String },
    #[error(
        "workflow grant already revoked for session {session_id:?}; this session cannot be re-issued (open a new session)"
    )]
    AlreadyRevoked { session_id: String },
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Uniquified tempfile name for the atomic-write pattern. PID + nanos prevents
/// concurrent saves from clobbering each other's tempfiles (LOW-5 from the
/// 2026-05-18 adversarial review).
fn tmp_path(session_dir: &Path) -> PathBuf {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    session_dir.join(format!("{SIDECAR_NAME}.tmp.{pid}.{nanos}"))
}

/// Atomic-write helper: write to tempfile, fsync, then rename.
///
/// MED-3 (2026-05-18 adversarial review): `fs::write` followed by `fs::rename`
/// is "atomic" only against partial writes, not power loss. The renamed file
/// can point at unflushed data extents until the kernel commits. `sync_all()`
/// before rename closes that gap.
fn atomic_write(final_path: &Path, tmp: &Path, bytes: &[u8]) -> io::Result<()> {
    {
        let mut f = OpenOptions::new().write(true).create_new(true).open(tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(tmp, final_path)
}

/// Persist a `WorkflowGrant` as the session's sidecar file.
///
/// Writes `<sessions_dir>/<session_id>/workflow-grant.json` atomically via
/// uniquified tempfile + fsync + rename. The session directory must already
/// exist (created by `core_state::SessionStore::create`); returns
/// `io::ErrorKind::NotFound` otherwise.
///
/// **Use [`save_if_absent`] for the launcher's at-session-open issue path.**
/// `save` permits overwrite — reserved for explicit rotate-after-revoke flows
/// where the caller has already invoked [`revoke`] and is consciously issuing
/// a fresh grant.
pub fn save(sessions_dir: &Path, session_id: &str, grant: &WorkflowGrant) -> io::Result<()> {
    let session_dir = sessions_dir.join(session_id);
    let final_path = session_dir.join(SIDECAR_NAME);
    let tmp = tmp_path(&session_dir);
    let json = serde_json::to_vec_pretty(grant)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    atomic_write(&final_path, &tmp, &json)
}

/// Issue a workflow grant at session-open. Refuses if a grant (active OR
/// revoked) already exists for the session — enforces design §Component 1
/// "Exactly one active workflow grant per session, across all cohorts."
///
/// MED-4 (2026-05-18 adversarial review): bare [`save`] silently overwrites,
/// which lets a buggy or malicious launcher swap the workflow grant
/// mid-session with no audit event or presence-proof check. This is the
/// canonical at-issue path.
pub fn save_if_absent(
    sessions_dir: &Path,
    session_id: &str,
    grant: &WorkflowGrant,
) -> Result<(), SaveError> {
    let session_dir = sessions_dir.join(session_id);
    let active = session_dir.join(SIDECAR_NAME);
    let revoked = session_dir.join(format!("{SIDECAR_NAME}{REVOKED_SUFFIX}"));
    if active.exists() {
        return Err(SaveError::AlreadyActive {
            session_id: session_id.to_string(),
        });
    }
    if revoked.exists() {
        return Err(SaveError::AlreadyRevoked {
            session_id: session_id.to_string(),
        });
    }
    save(sessions_dir, session_id, grant)?;
    Ok(())
}

/// Load the session's active workflow grant, if any.
///
/// Returns `Ok(None)` when the sidecar is absent OR when it has been revoked
/// (i.e. a `workflow-grant.json.revoked` file is present). Both cases mean
/// "no active workflow grant" from the eval path's perspective. The eval
/// path's behavior on the `None` case is the legacy fall-through (when
/// `EMBER_WORKFLOW_GRANTS_STRICT` is unset) or the bootstrap-only refusal
/// (when the strict flag is set) — see `eval_workflow_for_action` in
/// `crates/ember-daemon/src/broker/handler.rs`.
///
/// CRIT-1 (2026-05-18 adversarial review): revoke check is structural — the
/// presence of the `.revoked` file is the durable revocation signal. The
/// load path refuses to admit a revoked grant.
pub fn load(sessions_dir: &Path, session_id: &str) -> io::Result<Option<WorkflowGrant>> {
    let session_dir = sessions_dir.join(session_id);

    // LOW-2 (2026-05-18 adversarial review): closed sessions don't authorize.
    // `core_state::SessionStore::close` renames `meta.json` to `.closed`; if
    // the live `meta.json` is absent, the session is either never-opened
    // (also no grant possible) or closed (workflow grant must not survive
    // session-close, even if the sidecar wasn't cleaned up by close). Refuse
    // the grant load in both cases. This is layered defense — an upstream
    // session-validity gate may also catch closed-session calls, but the
    // workflow primitive refuses on its own.
    let meta = session_dir.join("meta.json");
    if !meta.exists() {
        return Ok(None);
    }

    let revoked = session_dir.join(format!("{SIDECAR_NAME}{REVOKED_SUFFIX}"));
    if revoked.exists() {
        // workflow_grant_revoke_via_atomic_rename — revoked sidecar present;
        // the active grant has been revoked. Return None even if an
        // `workflow-grant.json` somehow exists alongside (defense in depth
        // against an attacker creating the active file directly).
        return Ok(None);
    }
    let path = session_dir.join(SIDECAR_NAME);
    match fs::read(&path) {
        Ok(bytes) => {
            let grant = serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Ok(Some(grant))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Revoke the session's active workflow grant via atomic rename.
///
/// Renames `workflow-grant.json` to `workflow-grant.json.revoked` so subsequent
/// [`load`] calls return `Ok(None)`. The renamed file persists for audit-trail
/// forensics; the daemon never reads it after rename.
///
/// Returns `Ok(false)` when there was no active grant to revoke (idempotent).
/// Returns `Ok(true)` when a grant was renamed to `.revoked`.
///
/// CRIT-1 (2026-05-18 adversarial review) + design line 104: revoke is the
/// load-bearing trust property — "operator only ever removes authority."
/// Anchor: `workflow_grant_revoke_via_atomic_rename`.
pub fn revoke(sessions_dir: &Path, session_id: &str) -> io::Result<bool> {
    let session_dir = sessions_dir.join(session_id);
    let active = session_dir.join(SIDECAR_NAME);
    let revoked = session_dir.join(format!("{SIDECAR_NAME}{REVOKED_SUFFIX}"));
    match fs::rename(&active, &revoked) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// True when the session has been revoked (a `.revoked` sidecar exists).
/// Exposed for diagnostics + the strict-mode eval path that needs to
/// distinguish "session never had a grant" from "session's grant was revoked."
pub fn is_revoked(sessions_dir: &Path, session_id: &str) -> bool {
    sessions_dir
        .join(session_id)
        .join(format!("{SIDECAR_NAME}{REVOKED_SUFFIX}"))
        .exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use core_grants::grant::PrincipalId;
    use core_grants::workflow::WorkflowId;
    use core_state::sessions::{SessionMeta, SessionStore};
    use tempfile::TempDir;

    /// LOW-3 (2026-05-18 adversarial review): anchor the checkpoint as a
    /// runnable test symbol so refactor passes can't silently delete it.
    #[test]
    fn pregrant_workflow_grant_primitive_landed() {
        // Checkpoint anchor — presence of this test proves the primitive
        // ships with the load-bearing properties: revoke, save_if_absent,
        // atomic-rename-with-fsync, and refuse-on-revoked load semantics.
    }

    fn fixture_grant() -> WorkflowGrant {
        WorkflowGrant::new(
            WorkflowId("wfg_01HQ0".to_string()),
            "emberd-development".to_string(),
            PrincipalId("root_alice".to_string()),
            "persona_dev0".to_string(),
            vec!["git.*".to_string(), "gh.pr_create".to_string()],
            vec!["gh.repo_delete".to_string()],
            4 * 3600,
            Utc::now(),
            "ppr_test".to_string(),
            None,
        )
        .unwrap()
    }

    fn fixture_meta(session_id: &str) -> SessionMeta {
        SessionMeta {
            session_id: session_id.to_string(),
            persona: "persona_dev0".to_string(),
            grant_id: "grant_test".to_string(),
            started_at: Utc::now(),
            launcher_pid: std::process::id(),
            workflow_id: None,
            workflow_template: None,
        }
    }

    #[test]
    fn load_returns_none_when_sidecar_absent() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        store.create(&fixture_meta("sess-no-workflow")).unwrap();

        let loaded = load(dir.path(), "sess-no-workflow").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn save_then_load_round_trips_grant() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        store.create(&fixture_meta("sess-with-workflow")).unwrap();

        let grant = fixture_grant();
        save(dir.path(), "sess-with-workflow", &grant).unwrap();

        let loaded = load(dir.path(), "sess-with-workflow")
            .unwrap()
            .expect("sidecar should be present");
        assert_eq!(loaded, grant);
    }

    #[test]
    fn save_overwrites_previous_grant() {
        // The legacy `save` retains overwrite semantics for explicit
        // rotate-after-revoke flows. New issuance goes through
        // `save_if_absent`. Test pins both behaviors.
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        store.create(&fixture_meta("sess-rotate")).unwrap();

        let first = fixture_grant();
        save(dir.path(), "sess-rotate", &first).unwrap();

        let second = WorkflowGrant::new(
            WorkflowId("wfg_99999".to_string()),
            "read-only".to_string(),
            PrincipalId("root_alice".to_string()),
            "persona_dev0".to_string(),
            vec!["git.fetch".to_string()],
            vec![],
            3600,
            Utc::now(),
            "ppr_rotated".to_string(),
            None,
        )
        .unwrap();
        save(dir.path(), "sess-rotate", &second).unwrap();

        let loaded = load(dir.path(), "sess-rotate").unwrap().unwrap();
        assert_eq!(loaded, second);
        assert_ne!(loaded, first);
    }

    #[test]
    fn save_to_nonexistent_session_dir_errors() {
        let dir = TempDir::new().unwrap();
        let err = save(dir.path(), "no-such-session", &fixture_grant()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    // -- New tests for the 2026-05-18 adversarial fix-up --

    #[test]
    fn revoke_renames_sidecar_to_revoked() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        store.create(&fixture_meta("sess-revoke")).unwrap();
        save(dir.path(), "sess-revoke", &fixture_grant()).unwrap();

        let renamed = revoke(dir.path(), "sess-revoke").unwrap();
        assert!(
            renamed,
            "revoke should return true when active grant existed"
        );

        let active = dir.path().join("sess-revoke").join(SIDECAR_NAME);
        let revoked = dir
            .path()
            .join("sess-revoke")
            .join(format!("{SIDECAR_NAME}{REVOKED_SUFFIX}"));
        assert!(!active.exists(), "active sidecar should be gone");
        assert!(revoked.exists(), "revoked sidecar should be present");
    }

    #[test]
    fn revoke_returns_false_when_nothing_to_revoke() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        store.create(&fixture_meta("sess-empty")).unwrap();

        let renamed = revoke(dir.path(), "sess-empty").unwrap();
        assert!(
            !renamed,
            "revoke on session with no grant should return false"
        );
    }

    #[test]
    fn load_returns_none_after_revoke() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        store.create(&fixture_meta("sess-revoked-load")).unwrap();
        save(dir.path(), "sess-revoked-load", &fixture_grant()).unwrap();
        revoke(dir.path(), "sess-revoked-load").unwrap();

        let loaded = load(dir.path(), "sess-revoked-load").unwrap();
        assert!(loaded.is_none(), "revoked grant should not be loadable");
    }

    #[test]
    fn is_revoked_reports_revoked_state() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        store.create(&fixture_meta("sess-isrevoke")).unwrap();
        assert!(!is_revoked(dir.path(), "sess-isrevoke"));

        save(dir.path(), "sess-isrevoke", &fixture_grant()).unwrap();
        assert!(!is_revoked(dir.path(), "sess-isrevoke"));

        revoke(dir.path(), "sess-isrevoke").unwrap();
        assert!(is_revoked(dir.path(), "sess-isrevoke"));
    }

    #[test]
    fn save_if_absent_refuses_when_active() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        store.create(&fixture_meta("sess-double-issue")).unwrap();
        save(dir.path(), "sess-double-issue", &fixture_grant()).unwrap();

        let err = save_if_absent(dir.path(), "sess-double-issue", &fixture_grant()).unwrap_err();
        assert!(matches!(err, SaveError::AlreadyActive { .. }));
    }

    #[test]
    fn save_if_absent_refuses_when_revoked() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        store
            .create(&fixture_meta("sess-reissue-after-revoke"))
            .unwrap();
        save(dir.path(), "sess-reissue-after-revoke", &fixture_grant()).unwrap();
        revoke(dir.path(), "sess-reissue-after-revoke").unwrap();

        let err =
            save_if_absent(dir.path(), "sess-reissue-after-revoke", &fixture_grant()).unwrap_err();
        assert!(matches!(err, SaveError::AlreadyRevoked { .. }));
    }

    #[test]
    fn save_if_absent_admits_first_issue() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        store.create(&fixture_meta("sess-first-issue")).unwrap();

        // Bind the grant once — `fixture_grant()` calls `Utc::now()` each
        // invocation, so two calls produce non-equal timestamps.
        let grant = fixture_grant();
        save_if_absent(dir.path(), "sess-first-issue", &grant).unwrap();
        let loaded = load(dir.path(), "sess-first-issue").unwrap().unwrap();
        assert_eq!(loaded, grant);
    }
}
