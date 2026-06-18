//! CLASSIFICATION: PUBLIC
//! Shared ember engine on-disk layout conventions.
//!
//! The daemon (`emberd`) and the autopilot engine (`internal-automation`) both touch
//! the same `.ember/engine/` substrate on disk: the engine appends lifecycle
//! events to `events.jsonl`, the orchestrator records authority gaps in
//! `permission-gaps.jsonl`, and both resolve those files relative to the
//! repository's primary worktree root. Those conventions are a *contract*
//! shared across the trust boundary, not a private detail of either side.
//!
//! Per ADR 183/184 the daemon is the authority root and the engine is an
//! application above it; the daemon must not reach *up* into the engine crate
//! to learn where the substrate lives. This module hosts the shared layout
//! contract at the core layer so both consume it as a peer dependency
//! (`ember-daemon` and `internal-automation` already sit on `core-construct-runtime`).
//!
//! `internal-automation` keeps its richer [`git`](../../internal-automation/src/git.rs)
//! resolver (test-override `RwLock`, caching) for its own callers; this is the
//! minimal, dependency-light resolver the daemon and the gap-log reader need.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::Result;

/// Relative path of the engine's append-only event log, anchored at the
/// primary worktree root. Written by the engine and (best-effort) by the
/// daemon's spawn-checkpoint emitter.
pub const ENGINE_EVENTS_FILE: &str = ".ember/engine/events.jsonl";

/// Relative path of the authority permission-gap log, anchored at the primary
/// worktree root. Appended by the orchestrator on `harness denied` releases
/// and read by the daemon's `headless_preflight_gaps` socket method.
pub const PERMISSION_GAPS_FILE: &str = ".ember/engine/permission-gaps.jsonl";

/// Resolve the repository's **primary** worktree root.
///
/// Resolution order:
///   1. `EMBER_FORGE_PRIMARY_WORKTREE_ROOT` env hatch (verbatim) — the
///      documented back-compat override that state-mutating tests set to a
///      tempdir so they don't race the production state files.
///   2. `git rev-parse --git-common-dir` + canonicalize → the parent of the
///      shared `.git` common dir is the primary worktree root (stable across
///      `git worktree add`-ed siblings, which all share one common dir).
///   3. On canonicalize failure (dangling symlink / removed worktree), fall
///      back to `git rev-parse --show-toplevel` (the *current* worktree root).
///
/// This mirrors `ember_forge::git::resolve_primary_worktree_root` so a process
/// resolving via either path observes the same `.ember/engine/` directory.
/// Unlike the forge resolver it carries no test-override `RwLock` and no cache:
/// its callers (the daemon's checkpoint emitter and the gap-log reader) hit it
/// rarely and run with cwd already at the repo root.
pub fn primary_worktree_root() -> Result<PathBuf> {
    if let Ok(override_path) = std::env::var("EMBER_FORGE_PRIMARY_WORKTREE_ROOT")
        && !override_path.is_empty()
    {
        return Ok(PathBuf::from(override_path));
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
            // Dangling symlink, removed worktree, or other FS corruption —
            // fall back to the current worktree's top level.
            let fallback = run_git(&["rev-parse", "--show-toplevel"])?
                .map(PathBuf::from)
                .ok_or(canon_err)?;
            Ok(fallback)
        }
    }
}

/// Append a single line to `path` under the engine substrate, creating the
/// file (and parent dirs) if necessary. The `.ember/engine/*.jsonl` logs are
/// append-only and best-effort, so a plain buffered append is sufficient.
/// Shared by every writer of the engine logs (the orchestrator's gap log, the
/// daemon/proxy event-checkpoint echo) so the on-disk write discipline lives
/// in one place below the engine.
pub fn append_line(path: &std::path::Path, line: &str) -> Result<()> {
    use anyhow::Context as _;
    use std::fs::OpenOptions;
    use std::io::Write as _;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating parent dir for {}", path.display()))?;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {} for append", path.display()))?;
    writeln!(f, "{}", line.trim_end_matches('\n'))?;
    Ok(())
}

/// Run `git <args>`, returning trimmed stdout. `Ok(None)` when git exits
/// non-zero (e.g. not a repository) or prints nothing.
fn run_git(args: &[&str]) -> Result<Option<String>> {
    let out = Command::new("git")
        .args(args)
        .stderr(Stdio::null())
        .output()?;
    if !out.status.success() {
        return Ok(None);
    }
    let s = String::from_utf8(out.stdout)?.trim().to_string();
    Ok(if s.is_empty() { None } else { Some(s) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both resolution paths in one test: process-global env is shared across
    /// parallel test threads, so the env-hatch and git-resolution cases must
    /// run sequentially in a single test to avoid racing on the override var.
    #[test]
    fn primary_worktree_root_resolution_paths() {
        let key = "EMBER_FORGE_PRIMARY_WORKTREE_ROOT";

        // 1. git resolution (env unset): inside the emberlink repo, the
        //    resolved root must contain a `crates/` dir (the workspace root).
        // SAFETY: single-threaded test body.
        unsafe { std::env::remove_var(key) };
        let root = primary_worktree_root().expect("resolves in-repo");
        assert!(
            root.join("crates").is_dir(),
            "resolved root {} should contain crates/",
            root.display()
        );

        // 2. env hatch wins verbatim when set.
        unsafe { std::env::set_var(key, "/tmp/ember-layout-test-root") };
        let overridden = primary_worktree_root().expect("env hatch resolves");
        unsafe { std::env::remove_var(key) };
        assert_eq!(overridden, PathBuf::from("/tmp/ember-layout-test-root"));
    }

    #[test]
    fn layout_consts_are_engine_relative() {
        assert_eq!(ENGINE_EVENTS_FILE, ".ember/engine/events.jsonl");
        assert_eq!(PERMISSION_GAPS_FILE, ".ember/engine/permission-gaps.jsonl");
    }
}
