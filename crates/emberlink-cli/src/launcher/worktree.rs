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

pub fn worktrees_dir(repo_root: &Path) -> PathBuf {
    let primary = primary_worktrees_dir(repo_root);
    if primary.exists() {
        return primary;
    }

    let legacy = legacy_worktrees_dir(repo_root);
    if legacy.exists() {
        return legacy;
    }

    primary
}

pub fn runtime_id_for_worktree(worktree_path: &Path) -> String {
    let hash = blake3::hash(worktree_path.to_string_lossy().as_bytes());
    format!("rt-{}", &hex::encode(hash.as_bytes())[..8])
}

pub fn worktree_path_for_session(repo_root: &Path, session_name: &str) -> io::Result<PathBuf> {
    let slug = slugify(session_name);
    if slug.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("session name '{session_name}' slugified to empty"),
        ));
    }
    Ok(worktrees_dir(repo_root).join(slug))
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
        .args(["rev-parse", "--git-common-dir"])
        .output()?;
    if !output.status.success() {
        return Ok(show_toplevel);
    }
    let git_common_dir = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    if git_common_dir.file_name().is_some_and(|name| name == ".git") {
        Ok(git_common_dir
            .parent()
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
    std::fs::write(
        session_meta_path(&meta.worktree_path),
        format!(
            "session_name: {}\nruntime_id: {}\nbranch: {}\nharness: {}\npurpose: {}\ncreated_at: {}\nbase_ref: {}\nworktree_path: {}\n",
            meta.session_name,
            runtime_id,
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
        _ => HarnessKind::Other,
    }
}

fn pid_alive(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as i32, 0) };
    rc == 0
}
