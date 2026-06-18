//! Managed worktree/session metadata primitives for harness launchers.

use std::io;
use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};

use crate::launcher::harness::HarnessKind;

pub const WORKTREE_DIR_BASENAME: &str = "worktrees";
pub const MANAGED_WORKTREE_ROOT_BASENAME: &str = ".ember";
pub const LEGACY_MANAGED_WORKTREE_ROOT_BASENAME: &str = ".claude";
const SESSION_META_FILE: &str = ".agent-session";
const LIVE_META_FILE: &str = ".agent-live";
const DEFAULT_BASE_REF: &str = "origin/main";
pub const WORKSPACE_REF_ENV: &str = "EMBER_WORKSPACE_REF";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMetadata {
    pub session_name: String,
    pub branch: String,
    pub harness: HarnessKind,
    pub purpose: String,
    pub created_at: String,
    pub base_ref: String,
    pub worktree_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveMetadata {
    pub session_name: String,
    pub harness: HarnessKind,
    pub launcher_pid: u32,
    pub parent_pid: Option<u32>,
    pub started_at: String,
    pub worktree_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveState {
    None,
    Live(u32),
    Stale(Option<u32>),
}

pub fn slugify(input: &str) -> String {
    let mut out = String::new();
    let mut last_was_dash = false;
    for ch in input.chars().flat_map(char::to_lowercase) {
        let keep = ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-');
        if keep {
            out.push(ch);
            last_was_dash = false;
        } else if !last_was_dash {
            out.push('-');
            last_was_dash = true;
        }
    }
    while out.starts_with('-') {
        out.remove(0);
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

pub fn legacy_worktrees_dir(repo_root: &Path) -> PathBuf {
    repo_root
        .join(LEGACY_MANAGED_WORKTREE_ROOT_BASENAME)
        .join(WORKTREE_DIR_BASENAME)
}

pub fn primary_worktrees_dir(repo_root: &Path) -> PathBuf {
    repo_root
        .join(MANAGED_WORKTREE_ROOT_BASENAME)
        .join(WORKTREE_DIR_BASENAME)
}

fn configured_worktrees_dir(repo_root: &Path) -> PathBuf {
    if let Ok(root) = std::env::var("EMBER_MANAGED_WORKTREE_ROOT")
        && !root.trim().is_empty()
    {
        return repo_root.join(root).join(WORKTREE_DIR_BASENAME);
    }
    primary_worktrees_dir(repo_root)
}

pub fn worktrees_dir(repo_root: &Path) -> PathBuf {
    configured_worktrees_dir(repo_root)
}

pub fn runtime_id_for_worktree(worktree_path: &Path) -> String {
    let hash = blake3::hash(worktree_path.to_string_lossy().as_bytes());
    format!("rt-{}", &hex::encode(hash.as_bytes())[..8])
}

pub fn workspace_ref_for_worktree(worktree_path: &Path) -> String {
    format!(
        "managed_worktree:{}",
        runtime_id_for_worktree(worktree_path)
    )
}

pub fn worktree_path_for_session(repo_root: &Path, session_name: &str) -> io::Result<PathBuf> {
    let slug = slugify(session_name);
    if slug.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("session name '{session_name}' slugified to empty"),
        ));
    }
    let configured = worktrees_dir(repo_root).join(&slug);
    if configured.exists() {
        return Ok(configured);
    }

    if std::env::var_os("EMBER_MANAGED_WORKTREE_ROOT").is_none() {
        let legacy = legacy_worktrees_dir(repo_root).join(&slug);
        if legacy.exists() {
            return Ok(legacy);
        }
    }

    Ok(configured)
}

pub fn git_current_branch(path: &Path) -> io::Result<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "git rev-parse --abbrev-ref HEAD failed for {} with exit {}",
            path.display(),
            output.status.code().unwrap_or(-1)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn resolve_branch_for_launch(
    worktree_path: &Path,
    session_name: &str,
    requested: Option<&str>,
) -> io::Result<String> {
    if let Some(branch) = requested {
        return Ok(branch.to_string());
    }
    if worktree_path.exists() {
        return git_current_branch(worktree_path);
    }
    default_branch_for_session(session_name, &timestamp_branch_now())
}

pub fn resolve_repo_root() -> io::Result<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "git rev-parse --show-toplevel exited {}",
            output.status.code().unwrap_or(-1)
        )));
    }
    let show_toplevel = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());

    let output = std::process::Command::new("git")
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .output()?;
    if !output.status.success() {
        return Ok(show_toplevel);
    }
    let git_common_dir = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    if git_common_dir
        .file_name()
        .is_some_and(|name| name == ".git")
    {
        Ok(git_common_dir
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or(show_toplevel))
    } else {
        Ok(show_toplevel)
    }
}

pub fn validate_branch(branch: &str) -> io::Result<()> {
    if branch.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "branch must not be empty",
        ));
    }
    if branch.starts_with('-')
        || branch.starts_with('/')
        || branch.ends_with('/')
        || branch.contains("..")
        || branch.contains(' ')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid branch name '{branch}'"),
        ));
    }
    Ok(())
}

pub fn timestamp_branch_now() -> String {
    Utc::now().format("%Y%m%d-%H%M%S").to_string()
}

pub fn default_branch_for_session(session_name: &str, timestamp: &str) -> io::Result<String> {
    let slug = slugify(session_name);
    if slug.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("session name '{session_name}' slugified to empty"),
        ));
    }
    Ok(format!("agent/{slug}/{timestamp}"))
}

pub fn session_meta_path(worktree_path: &Path) -> PathBuf {
    worktree_path.join(SESSION_META_FILE)
}

pub fn live_meta_path(worktree_path: &Path) -> PathBuf {
    worktree_path.join(LIVE_META_FILE)
}

pub fn write_session_meta(meta: &SessionMetadata) -> io::Result<()> {
    let runtime_id = runtime_id_for_worktree(&meta.worktree_path);
    let workspace_ref = workspace_ref_for_worktree(&meta.worktree_path);
    std::fs::write(
        session_meta_path(&meta.worktree_path),
        format!(
            "session_name: {}\nruntime_id: {}\nworkspace_ref: {}\nbranch: {}\nharness: {}\npurpose: {}\ncreated_at: {}\nbase_ref: {}\nworktree_path: {}\n",
            meta.session_name,
            runtime_id,
            workspace_ref,
            meta.branch,
            meta.harness,
            meta.purpose,
            meta.created_at,
            meta.base_ref,
            meta.worktree_path.display()
        ),
    )
}

pub fn write_live_meta(meta: &LiveMetadata) -> io::Result<()> {
    let parent_pid = meta
        .parent_pid
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    std::fs::write(
        live_meta_path(&meta.worktree_path),
        format!(
            "session_name: {}\nharness: {}\nlauncher_pid: {}\nparent_pid: {}\nstarted_at: {}\nworktree_path: {}\n",
            meta.session_name,
            meta.harness,
            meta.launcher_pid,
            parent_pid,
            meta.started_at,
            meta.worktree_path.display()
        ),
    )
}

pub fn read_live_meta(worktree_path: &Path) -> io::Result<Option<LiveMetadata>> {
    let path = live_meta_path(worktree_path);
    if !path.exists() {
        return Ok(None);
    }
    let body = std::fs::read_to_string(&path)?;
    let launcher_pid = meta_value(&body, "launcher_pid").and_then(|v| v.parse::<u32>().ok());
    let Some(launcher_pid) = launcher_pid else {
        return Ok(None);
    };
    Ok(Some(LiveMetadata {
        session_name: meta_value(&body, "session_name")
            .unwrap_or_default()
            .to_string(),
        harness: parse_harness(meta_value(&body, "harness")),
        launcher_pid,
        parent_pid: meta_value(&body, "parent_pid").and_then(|v| v.parse::<u32>().ok()),
        started_at: meta_value(&body, "started_at")
            .map(str::to_owned)
            .unwrap_or_else(timestamp_utc_now),
        worktree_path: worktree_path.to_path_buf(),
    }))
}

pub fn live_state_for_path(worktree_path: &Path) -> io::Result<LiveState> {
    let Some(meta) = read_live_meta(worktree_path)? else {
        return Ok(LiveState::None);
    };
    Ok(if pid_alive(meta.launcher_pid) {
        LiveState::Live(meta.launcher_pid)
    } else {
        LiveState::Stale(Some(meta.launcher_pid))
    })
}

pub fn clear_stale_live_lock(worktree_path: &Path) -> io::Result<bool> {
    let live_path = live_meta_path(worktree_path);
    match live_state_for_path(worktree_path)? {
        LiveState::Stale(_) => {
            std::fs::remove_file(live_path)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub fn ensure_worktree_from_base(
    repo_root: &Path,
    worktree_path: &Path,
    branch: &str,
    base_ref: &str,
) -> io::Result<()> {
    validate_branch(branch)?;
    std::fs::create_dir_all(worktrees_dir(repo_root))?;
    if worktree_path.exists() {
        return Ok(());
    }
    if base_ref == DEFAULT_BASE_REF {
        let _ = std::process::Command::new("git")
            .arg("-C")
            .arg(repo_root)
            .args(["fetch", "origin", "main"])
            .status();
    }
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["worktree", "add", "-b", branch])
        .arg(worktree_path)
        .arg(base_ref)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "git worktree add failed for {} on {} from {} with exit {}",
            worktree_path.display(),
            branch,
            base_ref,
            status.code().unwrap_or(-1)
        )))
    }
}

pub fn new_session_metadata(
    session_name: &str,
    branch: &str,
    harness: HarnessKind,
    purpose: &str,
    worktree_path: &Path,
) -> SessionMetadata {
    SessionMetadata {
        session_name: session_name.to_string(),
        branch: branch.to_string(),
        harness,
        purpose: purpose.to_string(),
        created_at: timestamp_utc_now(),
        base_ref: DEFAULT_BASE_REF.to_string(),
        worktree_path: worktree_path.to_path_buf(),
    }
}

pub fn new_live_metadata(
    session_name: &str,
    harness: HarnessKind,
    launcher_pid: u32,
    parent_pid: Option<u32>,
    worktree_path: &Path,
) -> LiveMetadata {
    LiveMetadata {
        session_name: session_name.to_string(),
        harness,
        launcher_pid,
        parent_pid,
        started_at: timestamp_utc_now(),
        worktree_path: worktree_path.to_path_buf(),
    }
}

fn timestamp_utc_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn meta_value<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}: ");
    body.lines().find_map(|line| line.strip_prefix(&prefix))
}

fn parse_harness(value: Option<&str>) -> HarnessKind {
    match value.unwrap_or("other") {
        "claude" => HarnessKind::Claude,
        "codex" => HarnessKind::Codex,
        "cursor" => HarnessKind::Cursor,
        _ => HarnessKind::Other,
    }
}

fn pid_alive(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as i32, 0) };
    rc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CwdGuard {
        cwd: PathBuf,
    }

    impl CwdGuard {
        fn set(path: &Path) -> Self {
            let cwd = std::env::current_dir().expect("capture cwd");
            std::env::set_current_dir(path).expect("set cwd");
            Self { cwd }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.cwd);
        }
    }

    struct ManagedWorktreeRootEnvGuard(Option<String>);

    impl ManagedWorktreeRootEnvGuard {
        fn capture() -> Self {
            Self(std::env::var("EMBER_MANAGED_WORKTREE_ROOT").ok())
        }
    }

    impl Drop for ManagedWorktreeRootEnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.0 {
                    Some(value) => std::env::set_var("EMBER_MANAGED_WORKTREE_ROOT", value),
                    None => std::env::remove_var("EMBER_MANAGED_WORKTREE_ROOT"),
                }
            }
        }
    }

    fn run_git(repo: &Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git -C {} {} failed with {}\nstdout:\n{}\nstderr:\n{}",
            repo.display(),
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn write_seed_commit(repo: &Path) {
        run_git(repo, &["init", "-q", "-b", "main"]);
        run_git(repo, &["config", "user.email", "test@example.com"]);
        run_git(repo, &["config", "user.name", "Ember Test"]);
        std::fs::write(repo.join("README.md"), "seed\n").expect("write readme");
        run_git(repo, &["add", "README.md"]);
        run_git(repo, &["commit", "-qm", "seed"]);
    }

    #[test]
    fn resolve_repo_root_returns_repo_root_when_common_dir_is_relative_dot_git() {
        let _guard = crate::PROCESS_ENV_CWD_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let repo = tempfile::tempdir().expect("tempdir");
        write_seed_commit(repo.path());
        run_git(repo.path(), &["checkout", "--detach", "HEAD"]);
        let _cwd = CwdGuard::set(repo.path());

        let resolved = resolve_repo_root().expect("resolve repo root");

        assert_eq!(
            resolved.canonicalize().expect("canonical resolved"),
            repo.path().canonicalize().expect("canonical repo"),
            "relative .git common-dir must not resolve to an empty clone source"
        );
        assert!(
            !resolved.as_os_str().is_empty(),
            "repo root must never be an empty path"
        );
    }

    #[test]
    fn resolve_repo_root_returns_primary_root_from_linked_worktree() {
        let _guard = crate::PROCESS_ENV_CWD_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let repo = tempfile::tempdir().expect("tempdir");
        write_seed_commit(repo.path());
        let linked = tempfile::tempdir().expect("linked tempdir");
        let linked_path = linked.path().join("linked-worktree");
        run_git(
            repo.path(),
            &[
                "worktree",
                "add",
                "--detach",
                linked_path.to_str().expect("utf8 linked path"),
                "HEAD",
            ],
        );
        let _cwd = CwdGuard::set(&linked_path);

        let resolved = resolve_repo_root().expect("resolve repo root");

        assert_eq!(
            resolved.canonicalize().expect("canonical resolved"),
            repo.path().canonicalize().expect("canonical repo"),
            "linked worktrees must clone Sandvault sessions from the primary repo root"
        );
    }

    #[test]
    fn worktree_path_for_session_prefers_primary_root_for_new_sessions() {
        let _guard = ManagedWorktreeRootEnvGuard::capture();
        unsafe {
            std::env::remove_var("EMBER_MANAGED_WORKTREE_ROOT");
        }

        let repo = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(repo.path().join(".claude/worktrees")).expect("legacy root");

        let path = worktree_path_for_session(repo.path(), "dogfood-surface-proof").expect("path");
        assert_eq!(
            path,
            repo.path().join(".ember/worktrees/dogfood-surface-proof")
        );
    }

    #[test]
    fn workspace_ref_for_worktree_uses_managed_worktree_namespace() {
        let path = PathBuf::from(".ember/worktrees/yankee");
        assert_eq!(
            workspace_ref_for_worktree(&path),
            format!("managed_worktree:{}", runtime_id_for_worktree(&path))
        );
    }

    #[test]
    fn worktree_path_for_session_preserves_existing_legacy_session_path() {
        let _guard = ManagedWorktreeRootEnvGuard::capture();
        unsafe {
            std::env::remove_var("EMBER_MANAGED_WORKTREE_ROOT");
        }

        let repo = tempfile::tempdir().expect("tempdir");
        let legacy = repo.path().join(".claude/worktrees/dogfood-surface-proof");
        std::fs::create_dir_all(&legacy).expect("legacy session path");

        let path = worktree_path_for_session(repo.path(), "dogfood-surface-proof").expect("path");
        assert_eq!(path, legacy);
    }
}
