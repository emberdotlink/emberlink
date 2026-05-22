use std::fs;
use std::io;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMeta {
    pub session_id: String,
    pub persona: String,
    pub grant_id: String,
    pub started_at: DateTime<Utc>,
    pub launcher_pid: u32,
    /// design §Component 3 — ULID of the workflow grant active for this
    /// session, if the launcher attached one at session-open. None for
    /// pre-workflow-grant sessions and for sessions that opened without
    /// selecting a workflow template. The sidecar `workflow-grant.json`
    /// in the session directory carries the full `core_grants::WorkflowGrant`
    /// when this field is `Some`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    /// design §Component 3 — Human-readable workflow template name
    /// (e.g. "emberd-development"). Paired with `workflow_id`; both should
    /// be `Some` together or `None` together.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_template: Option<String>,
}

/// Filesystem-backed session store.
///
/// Layout:
/// ```text
/// <base_dir>/
///   <session_id>/
///     meta.json          # written by `create`, removed by `close`
///     audit-gaps.jsonl   # placeholder — implementation-note-16 writes this
///     permits-archive.jsonl  # placeholder — implementation-note-47 sidecar
///     hook-errors.jsonl  # placeholder — implementation-note-16 panic catch
///     receipt.json       # placeholder — implementation-note-47 termination receipt
/// ```
///
/// `close` moves `meta.json` to `meta.json.closed` so the session directory
/// itself remains on disk for sidecar files (audit-gaps, receipt, etc.) that
/// other tasks may write after termination. `list_open` skips any session
/// directory where `meta.json` is absent or cannot be parsed.
pub struct SessionStore {
    base_dir: PathBuf,
}

impl SessionStore {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    /// Create the session directory and write `meta.json` atomically.
    ///
    /// Creates `<base_dir>/<session_id>/` and all placeholder sidecar files.
    /// `meta.json` is written via a tempfile + rename so a crash mid-write
    /// leaves no partial JSON on disk.
    pub fn create(&self, meta: &SessionMeta) -> io::Result<()> {
        let session_dir = self.base_dir.join(&meta.session_id);
        fs::create_dir_all(&session_dir)?;

        // Atomic write: write to a tempfile in the same directory then rename.
        let tmp_path = session_dir.join("meta.json.tmp");
        let json = serde_json::to_vec_pretty(meta)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&tmp_path, &json)?;
        fs::rename(&tmp_path, session_dir.join("meta.json"))?;

        // Touch placeholder sidecar files so downstream tasks (implementation-note-47,
        // implementation-note-16) can append without creating their own directories.
        for name in &[
            "audit-gaps.jsonl",
            "permits-archive.jsonl",
            "hook-errors.jsonl",
            "receipt.json",
        ] {
            let p = session_dir.join(name);
            if !p.exists() {
                fs::write(&p, b"")?;
            }
        }

        Ok(())
    }

    /// Read the `SessionMeta` for an open session.
    ///
    /// Returns `Ok(None)` when the session directory exists but `meta.json` is
    /// absent (session has been closed) or when the session directory does not
    /// exist at all.
    pub fn read(&self, id: &str) -> io::Result<Option<SessionMeta>> {
        let meta_path = self.base_dir.join(id).join("meta.json");
        match fs::read(&meta_path) {
            Ok(bytes) => {
                let meta = serde_json::from_slice(&bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Ok(Some(meta))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Close a session by renaming `meta.json` → `meta.json.closed`.
    ///
    /// The session directory stays on disk so sidecar writers (implementation-note-47,
    /// implementation-note-16) can still append to their files after termination.
    /// A no-op (returns `Ok(())`) when the session is already closed or does
    /// not exist.
    pub fn close(&self, id: &str) -> io::Result<()> {
        let session_dir = self.base_dir.join(id);
        let meta_path = session_dir.join("meta.json");
        let closed_path = session_dir.join("meta.json.closed");
        match fs::rename(&meta_path, &closed_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// List all currently open sessions (those with a readable `meta.json`).
    ///
    /// Skips entries that are not directories, sessions whose `meta.json` is
    /// absent (closed), and sessions whose `meta.json` fails to parse (logs a
    /// warning via `eprintln!` — caller can promote to tracing if needed).
    pub fn list_open(&self) -> io::Result<Vec<SessionMeta>> {
        let mut sessions = Vec::new();
        match fs::read_dir(&self.base_dir) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(sessions),
            Err(e) => return Err(e),
            Ok(entries) => {
                for entry in entries {
                    let entry = entry?;
                    if !entry.file_type()?.is_dir() {
                        continue;
                    }
                    let meta_path = entry.path().join("meta.json");
                    match fs::read(&meta_path) {
                        Ok(bytes) => match serde_json::from_slice::<SessionMeta>(&bytes) {
                            Ok(meta) => sessions.push(meta),
                            Err(e) => {
                                eprintln!(
                                    "sessions: skipping {:?} — meta.json parse error: {e}",
                                    entry.path()
                                );
                            }
                        },
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {
                            // Closed session — skip.
                        }
                        Err(e) => {
                            eprintln!(
                                "sessions: skipping {:?} — meta.json read error: {e}",
                                entry.path()
                            );
                        }
                    }
                }
            }
        }
        Ok(sessions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::TempDir;

    fn make_meta(id: &str) -> SessionMeta {
        SessionMeta {
            session_id: id.to_string(),
            persona: "test-persona".to_string(),
            grant_id: "grant-abc123".to_string(),
            started_at: Utc::now(),
            launcher_pid: std::process::id(),
            workflow_id: None,
            workflow_template: None,
        }
    }

    #[test]
    fn create_read_round_trip() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        let meta = make_meta("sess-001");

        store.create(&meta).unwrap();

        let read_back = store.read("sess-001").unwrap().expect("should be Some");
        assert_eq!(read_back.session_id, "sess-001");
        assert_eq!(read_back.persona, "test-persona");
        assert_eq!(read_back.grant_id, "grant-abc123");
        assert_eq!(read_back.launcher_pid, meta.launcher_pid);
    }

    #[test]
    fn read_missing_returns_none() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        assert!(store.read("nonexistent").unwrap().is_none());
    }

    #[test]
    fn close_removes_from_list_open() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());

        store.create(&make_meta("sess-a")).unwrap();
        store.create(&make_meta("sess-b")).unwrap();

        let open = store.list_open().unwrap();
        assert_eq!(open.len(), 2);

        store.close("sess-a").unwrap();

        let open = store.list_open().unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].session_id, "sess-b");
    }

    #[test]
    fn close_idempotent() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        store.create(&make_meta("sess-x")).unwrap();
        store.close("sess-x").unwrap();
        // Second close is a no-op, not an error.
        store.close("sess-x").unwrap();
    }

    #[test]
    fn read_returns_none_after_close() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        store.create(&make_meta("sess-y")).unwrap();
        store.close("sess-y").unwrap();
        assert!(store.read("sess-y").unwrap().is_none());
    }

    #[test]
    fn sidecar_placeholders_created() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        store.create(&make_meta("sess-z")).unwrap();

        let session_dir = dir.path().join("sess-z");
        for name in &[
            "audit-gaps.jsonl",
            "permits-archive.jsonl",
            "hook-errors.jsonl",
            "receipt.json",
        ] {
            assert!(
                session_dir.join(name).exists(),
                "placeholder {name} should exist"
            );
        }
    }

    #[test]
    fn list_open_empty_when_base_dir_missing() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().join("nonexistent"));
        let open = store.list_open().unwrap();
        assert!(open.is_empty());
    }
}
