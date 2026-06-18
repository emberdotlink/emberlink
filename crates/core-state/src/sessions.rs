use std::fs;
use std::io;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

const ATTACHMENT_ENDPOINT_FILE: &str = "attachment-endpoint.json";
const WORKSPACE_BINDING_FILE: &str = "workspace-binding.json";

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMeta {
    pub session_id: String,
    /// Runtime Persona id for attachment-scoped launches. Legacy sessions
    /// keep the durable persona id here.
    pub persona: String,
    pub grant_id: String,
    pub started_at: DateTime<Utc>,
    pub launcher_pid: u32,
    /// Authority posture fallback bit for this caller binding.
    ///
    /// `false` keeps the default JIT/coalesced fallback chain active when
    /// no delegated grant authorizes the action. `true` denies instead of
    /// prompting or falling through.
    #[serde(default, skip_serializing_if = "is_false")]
    pub authority_strict: bool,
    /// ADR 158 §Component 3 — ULID of the delegation grant active for this
    /// session, if the launcher attached one at session-open. None for
    /// pre-delegation-grant sessions and for sessions that opened without
    /// selecting a delegation template. Legacy (pre-BKR-4c): a sidecar
    /// `delegation-grant.json` in the session directory carried the full
    /// standing grant object when this field was `Some`; per ADR 205 §6 the
    /// sidecar is gone and authority lives on the persona's `StandingGrant`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_id: Option<String>,
    /// ADR 158 §Component 3 — Human-readable delegation template name
    /// (e.g. "emberd-development"). Paired with `delegation_id`; both should
    /// be `Some` together or `None` together.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_template: Option<String>,
    /// Durable parent persona for runtime-persona attachments. Absent on
    /// legacy sessions that predate ADR 190.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable_persona: Option<String>,
    /// Shared caller-binding id for sibling attachments on one runtime lane.
    /// Legacy sessions leave it absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_binding_id: Option<String>,
}

impl SessionMeta {
    pub fn is_runtime_attachment(&self) -> bool {
        self.durable_persona.is_some() && self.caller_binding_id.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachmentEndpoint {
    pub attachment_id: String,
    pub endpoint_token: String,
    pub state: String,
    pub created_at: DateTime<Utc>,
}

impl AttachmentEndpoint {
    pub fn active(attachment_id: String, endpoint_token: String) -> Self {
        Self {
            attachment_id,
            endpoint_token,
            state: "active".to_string(),
            created_at: Utc::now(),
        }
    }

    pub fn is_rebinding(&self) -> bool {
        self.state == "rebinding"
    }

    pub fn is_active(&self) -> bool {
        self.state == "active"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionWorkspaceBinding {
    pub workspace_ref: String,
    pub worktree_path: PathBuf,
}

/// Filesystem-backed session store.
///
/// Layout:
/// ```text
/// <base_dir>/
///   <session_id>/
///     meta.json          # written by `create`, removed by `close`
///     audit-gaps.jsonl   # placeholder — audit-gap sidecar writer
///     permits-archive.jsonl  # placeholder — permit-archive sidecar
///     hook-errors.jsonl  # placeholder — hook-error panic-catch sidecar
///     receipt.json       # placeholder — termination receipt sidecar
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

        // Touch placeholder sidecar files so downstream sidecar writers can
        // append without creating their own directories.
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
    /// The session directory stays on disk so sidecar writers can still
    /// append to their files after termination.
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

    pub fn write_attachment_endpoint(
        &self,
        session_id: &str,
        endpoint: &AttachmentEndpoint,
    ) -> io::Result<()> {
        let session_dir = self.base_dir.join(session_id);
        fs::create_dir_all(&session_dir)?;
        let tmp_path = session_dir.join(format!("{ATTACHMENT_ENDPOINT_FILE}.tmp"));
        let json = serde_json::to_vec_pretty(endpoint)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&tmp_path, &json)?;
        fs::rename(&tmp_path, session_dir.join(ATTACHMENT_ENDPOINT_FILE))?;
        Ok(())
    }

    pub fn read_attachment_endpoint(
        &self,
        session_id: &str,
    ) -> io::Result<Option<AttachmentEndpoint>> {
        let path = self
            .base_dir
            .join(session_id)
            .join(ATTACHMENT_ENDPOINT_FILE);
        match fs::read(&path) {
            Ok(bytes) => {
                let endpoint = serde_json::from_slice(&bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Ok(Some(endpoint))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn write_workspace_binding(
        &self,
        session_id: &str,
        binding: &SessionWorkspaceBinding,
    ) -> io::Result<()> {
        let session_dir = self.base_dir.join(session_id);
        fs::create_dir_all(&session_dir)?;
        let tmp_path = session_dir.join(format!("{WORKSPACE_BINDING_FILE}.tmp"));
        let json = serde_json::to_vec_pretty(binding)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&tmp_path, &json)?;
        fs::rename(&tmp_path, session_dir.join(WORKSPACE_BINDING_FILE))?;
        Ok(())
    }

    pub fn read_workspace_binding(
        &self,
        session_id: &str,
    ) -> io::Result<Option<SessionWorkspaceBinding>> {
        let path = self.base_dir.join(session_id).join(WORKSPACE_BINDING_FILE);
        match fs::read(&path) {
            Ok(bytes) => {
                let binding = serde_json::from_slice(&bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Ok(Some(binding))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn set_attachment_state(&self, session_id: &str, state: &str) -> io::Result<bool> {
        let Some(mut endpoint) = self.read_attachment_endpoint(session_id)? else {
            return Ok(false);
        };
        endpoint.state = state.to_string();
        self.write_attachment_endpoint(session_id, &endpoint)?;
        Ok(true)
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

    /// Count other open attachments on the same caller binding.
    ///
    /// Legacy sessions that have no caller-binding metadata always return 0.
    pub fn count_other_open_attachments(&self, meta: &SessionMeta) -> io::Result<usize> {
        let Some(binding_id) = meta.caller_binding_id.as_deref() else {
            return Ok(0);
        };
        Ok(self
            .list_open()?
            .into_iter()
            .filter(|candidate| {
                candidate.session_id != meta.session_id
                    && candidate.caller_binding_id.as_deref() == Some(binding_id)
            })
            .count())
    }

    /// Return one open attachment for a given runtime persona id.
    pub fn find_open_by_runtime_persona(
        &self,
        runtime_persona_id: &str,
    ) -> io::Result<Option<SessionMeta>> {
        Ok(self
            .list_open()?
            .into_iter()
            .find(|meta| meta.persona == runtime_persona_id && meta.is_runtime_attachment()))
    }

    pub fn resolve_attachment_endpoint(
        &self,
        attachment_id: &str,
        endpoint_token: &str,
    ) -> io::Result<Option<(SessionMeta, AttachmentEndpoint)>> {
        let mut resolved = None;
        for meta in self.list_open()? {
            let Some(endpoint) = self.read_attachment_endpoint(&meta.session_id)? else {
                continue;
            };
            // ADR 197 §security-req-2: the endpoint token is the bearer
            // secret for this attachment. Compare it in constant time so a
            // sibling operator-uid process cannot recover it byte-by-byte
            // via response-timing variance. `attachment_id` is a
            // non-secret selector, so its `==` short-circuit is fine — it
            // only reveals which attachment matched, never the token.
            if endpoint.attachment_id == attachment_id
                && bool::from(
                    endpoint
                        .endpoint_token
                        .as_bytes()
                        .ct_eq(endpoint_token.as_bytes()),
                )
                && meta.is_runtime_attachment()
            {
                if resolved.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("duplicate live attachment endpoint id: {attachment_id}"),
                    ));
                }
                resolved = Some((meta, endpoint));
            }
        }
        Ok(resolved)
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
            authority_strict: false,
            delegation_id: None,
            delegation_template: None,
            durable_persona: None,
            caller_binding_id: None,
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

    #[test]
    fn count_other_open_attachments_tracks_binding_siblings() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        let mut a = make_meta("sess-a");
        a.persona = "persona-runtime-1".to_string();
        a.durable_persona = Some("persona-durable-1".to_string());
        a.caller_binding_id = Some("binding-1".to_string());
        let mut b = make_meta("sess-b");
        b.persona = "persona-runtime-1".to_string();
        b.durable_persona = Some("persona-durable-1".to_string());
        b.caller_binding_id = Some("binding-1".to_string());
        let mut c = make_meta("sess-c");
        c.persona = "persona-runtime-2".to_string();
        c.durable_persona = Some("persona-durable-2".to_string());
        c.caller_binding_id = Some("binding-2".to_string());

        store.create(&a).unwrap();
        store.create(&b).unwrap();
        store.create(&c).unwrap();

        assert_eq!(store.count_other_open_attachments(&a).unwrap(), 1);
        assert_eq!(store.count_other_open_attachments(&b).unwrap(), 1);
        assert_eq!(store.count_other_open_attachments(&c).unwrap(), 0);
    }

    #[test]
    fn find_open_by_runtime_persona_skips_legacy_sessions() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());

        let mut legacy = make_meta("sess-legacy");
        legacy.persona = "persona-runtime-1".to_string();
        let mut runtime = make_meta("sess-runtime");
        runtime.persona = "persona-runtime-1".to_string();
        runtime.durable_persona = Some("persona-durable-1".to_string());
        runtime.caller_binding_id = Some("binding-1".to_string());

        store.create(&legacy).unwrap();
        store.create(&runtime).unwrap();

        let found = store
            .find_open_by_runtime_persona("persona-runtime-1")
            .unwrap()
            .expect("runtime attachment should be found");
        assert_eq!(found.session_id, "sess-runtime");
    }

    #[test]
    fn attachment_endpoint_round_trip_resolves_open_runtime_attachment() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        let mut meta = make_meta("sess-runtime");
        meta.persona = "persona-runtime-1".to_string();
        meta.durable_persona = Some("persona-durable-1".to_string());
        meta.caller_binding_id = Some("binding-1".to_string());
        let endpoint =
            AttachmentEndpoint::active("att-1".to_string(), "endpoint-token-1".to_string());

        store.create(&meta).unwrap();
        store
            .write_attachment_endpoint(&meta.session_id, &endpoint)
            .unwrap();

        let (resolved_meta, resolved_endpoint) = store
            .resolve_attachment_endpoint("att-1", "endpoint-token-1")
            .unwrap()
            .expect("endpoint should resolve");
        assert_eq!(resolved_meta.session_id, "sess-runtime");
        assert_eq!(resolved_endpoint, endpoint);

        assert!(
            store
                .resolve_attachment_endpoint("att-1", "wrong-token")
                .unwrap()
                .is_none()
        );

        // ADR 197 §security-req-2: a same-length but differing token must
        // also fail to resolve — exercises the constant-time equal-length
        // comparison branch (ct_eq), not just the length-mismatch path.
        assert_eq!("endpoint-token-1".len(), "endpoint-token-2".len());
        assert!(
            store
                .resolve_attachment_endpoint("att-1", "endpoint-token-2")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn workspace_binding_round_trip() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        let meta = make_meta("sess-runtime");
        let binding = SessionWorkspaceBinding {
            workspace_ref: "managed_worktree:rt-test".to_string(),
            worktree_path: dir.path().join("repo/.ember/worktrees/demo"),
        };

        store.create(&meta).unwrap();
        store
            .write_workspace_binding(&meta.session_id, &binding)
            .unwrap();

        let read_back = store
            .read_workspace_binding(&meta.session_id)
            .unwrap()
            .expect("workspace binding");
        assert_eq!(read_back, binding);
    }

    #[test]
    fn attachment_state_update_is_visible() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        let meta = make_meta("sess-runtime");
        store.create(&meta).unwrap();
        store
            .write_attachment_endpoint(
                &meta.session_id,
                &AttachmentEndpoint::active("att-1".to_string(), "token".to_string()),
            )
            .unwrap();

        assert!(
            store
                .set_attachment_state(&meta.session_id, "rebinding")
                .unwrap()
        );
        let endpoint = store
            .read_attachment_endpoint(&meta.session_id)
            .unwrap()
            .expect("endpoint");
        assert!(endpoint.is_rebinding());
    }
}
