//! Shared on-disk layout for Construct runtime events and permission gaps.
//!
//! Paths are resolved from the primary worktree so the daemon and its
//! mediated tool surfaces observe the same runtime state.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

pub const ENGINE_EVENTS_FILE: &str = ".ember/runtime/events.jsonl";
pub const PERMISSION_GAPS_FILE: &str = ".ember/runtime/permission-gaps.jsonl";

pub fn primary_worktree_root() -> Result<PathBuf> {
    if let Ok(override_path) = std::env::var("EMBER_FORGE_PRIMARY_WORKTREE_ROOT") {
        if !override_path.is_empty() {
            return Ok(PathBuf::from(override_path));
        }
    }

    let common_dir = run_git(&["rev-parse", "--git-common-dir"])?
        .ok_or_else(|| anyhow::anyhow!("not in a git repository"))?;
    let raw = PathBuf::from(&common_dir);
    match raw.canonicalize() {
        Ok(canonical) => {
            let parent = canonical.parent().ok_or_else(|| {
                anyhow::anyhow!("git common dir has no parent: {}", canonical.display())
            })?;
            Ok(parent.to_path_buf())
        }
        Err(canon_err) => {
            let fallback = run_git(&["rev-parse", "--show-toplevel"])?
                .map(PathBuf::from)
                .ok_or(canon_err)?;
            Ok(fallback)
        }
    }
}

pub fn append_line(path: &std::path::Path, line: &str) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write as _;

    let parent = path
        .parent()
        .filter(|candidate| !candidate.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating parent dir for {}", path.display()))?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {} for append", path.display()))?;
    writeln!(file, "{}", line.trim_end_matches('\n'))?;
    Ok(())
}

fn run_git(args: &[&str]) -> Result<Option<String>> {
    let output = Command::new("git")
        .args(args)
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8(output.stdout)?.trim().to_string();
    Ok(if text.is_empty() { None } else { Some(text) })
}
