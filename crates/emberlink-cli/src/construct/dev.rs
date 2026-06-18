//! `ember construct dev` — author-side dev-path registry per the L1
//! authoring loop spec (T-CONSTRUCT-AUTHORING-MODE-DEV-PATH-REGISTRY,
//! ADRs 124 + 135).
//!
//! L1 (Script Construct) is for the AUTHORING loop; L2 (Compiled
//! Construct) is for production. Distribution channel makes the
//! distinction structural — end-user installs only ever ship L2 binaries
//! and have no L1 distribution path. This module is the authoring-side
//! opt-in: the author runs `ember construct dev .` in their worktree to
//! register the path; the daemon then accepts `broker.resolve` calls that
//! originate from the registered path. Receipts emitted from registered
//! paths are tagged `authoring = true` in the canonical Receipt body so
//! production audit chains aren't polluted with iteration noise.
//!
//! The registry persists to `~/.ember/authoring-paths.toml` (or the
//! `HOME`-relative equivalent on the running uid). Permissions are 600
//! (only readable by the ember uid). There's no automatic discovery;
//! every entry was placed by the author explicitly.
//!
//! Subcommands:
//!
//! - `ember construct dev <path>`   — register a path (idempotent).
//! - `ember construct dev --list`   — print all registered paths.
//! - `ember construct dev --unregister <path>` — remove a registered path.
//!
//! Glass-box trust-boundary brief: the dev-path registry IS a trust
//! boundary. Anything that lives in a registered path can broker.resolve.
//! Per ADR 094 §"Subprocess identity spoofing" the n=1 self-attack threat
//! model is acceptable for the author's own machine — the author trusts
//! their own iteration loop.

use std::path::{Path, PathBuf};

use clap::Parser;
use serde::{Deserialize, Serialize};

/// Arguments for `ember construct dev`.
#[derive(Debug, Parser)]
pub struct DevConstructArgs {
    /// Path to register (a directory in the author's worktree, e.g.
    /// `~/code/my-construct/`). Mutually exclusive with `--list` /
    /// `--unregister`.
    pub path: Option<PathBuf>,

    /// Print all currently-registered authoring paths and exit.
    #[arg(long, conflicts_with_all = ["path", "unregister"])]
    pub list: bool,

    /// Unregister a path. The argument is the path that was previously
    /// registered.
    #[arg(long, conflicts_with_all = ["path", "list"], value_name = "PATH")]
    pub unregister: Option<PathBuf>,
}

/// Parsed `~/.ember/authoring-paths.toml` envelope. Single-table layout
/// keeps the file human-readable (the author can `cat` it and audit what
/// was registered).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuthoringPaths {
    /// Each registered path, canonicalized at registration time so the
    /// daemon's path-prefix check works regardless of how the caller
    /// expresses the path (`./foo` vs `/abs/foo`).
    #[serde(default)]
    pub paths: Vec<PathBuf>,
}

/// Resolve `~/.ember/authoring-paths.toml`, honoring `$HOME`. Returns
/// `None` when `$HOME` cannot be resolved (caller surfaces a clear error
/// rather than silently reading from `/`).
pub fn registry_path() -> Option<PathBuf> {
    dirs_next::home_dir().map(|h| h.join(".ember").join("authoring-paths.toml"))
}

/// Load the on-disk registry. Returns an empty registry when the file
/// does not exist (a fresh install has no authoring paths) and the file
/// is therefore equivalent to `paths = []`.
///
/// # Errors
///
/// Returns a boxed error if the file exists but cannot be parsed (corrupt
/// registry — caller should surface the parse error so the author can fix
/// it manually rather than silently pretending it's empty).
pub fn load_registry(path: &Path) -> Result<AuthoringPaths, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(AuthoringPaths::default());
    }
    let s = std::fs::read_to_string(path)?;
    let parsed: AuthoringPaths = toml::from_str(&s)?;
    Ok(parsed)
}

/// Persist the registry to disk with mode 600 (owner-only). Idempotent
/// — overwrites any prior contents. Creates `~/.ember/` if missing.
///
/// # Errors
///
/// Returns a boxed error if the parent directory cannot be created or
/// the write fails.
pub fn save_registry(
    path: &Path,
    registry: &AuthoringPaths,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let s = toml::to_string_pretty(registry)?;
    std::fs::write(path, s.as_bytes())?;
    // Lock down to 0600 so the file is only readable by the ember uid.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// Add `path` to the registry if not already present. Returns `true`
/// when the registry actually changed (caller may print a friendlier
/// message than the no-op case).
///
/// # Errors
///
/// Returns a boxed error if `path` cannot be canonicalized (typically
/// because it does not exist on disk yet — a pre-condition check the
/// author surfaces immediately).
pub fn register_authoring_path(
    registry: &mut AuthoringPaths,
    path: &Path,
) -> Result<bool, Box<dyn std::error::Error>> {
    let canonical = std::fs::canonicalize(path)?;
    if registry.paths.iter().any(|p| p == &canonical) {
        return Ok(false);
    }
    registry.paths.push(canonical);
    Ok(true)
}

/// Remove `path` from the registry. Returns `true` when the registry
/// actually changed.
///
/// # Errors
///
/// Returns a boxed error when `path` cannot be canonicalized; falls back
/// to comparing against the as-given path so an author can unregister a
/// directory they have since deleted.
pub fn unregister_authoring_path(
    registry: &mut AuthoringPaths,
    path: &Path,
) -> Result<bool, Box<dyn std::error::Error>> {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let before = registry.paths.len();
    registry.paths.retain(|p| p != &canonical && p != path);
    Ok(registry.paths.len() != before)
}

/// Returns true when `script_path` resides under any registered authoring
/// path. Used by the daemon's `broker.resolve` gate to decide whether a
/// caller is in authoring mode (Receipts tagged `authoring = true`) or in
/// the production refuse-unsigned-scripts mode (registry empty / not
/// matched → refuse with `authoring_path_not_registered`).
///
/// Path comparison is prefix-based on canonicalized inputs so symlink
/// trickery cannot escape the registered scope.
pub fn script_is_in_authoring_path(registry: &AuthoringPaths, script_path: &Path) -> bool {
    let canonical = match std::fs::canonicalize(script_path) {
        Ok(p) => p,
        Err(_) => script_path.to_path_buf(),
    };
    registry
        .paths
        .iter()
        .any(|registered| canonical.starts_with(registered))
}

/// Run the `ember construct dev` subcommand. Pure orchestration over
/// the registry primitives above.
///
/// # Errors
///
/// Returns a boxed error if `$HOME` is not resolvable, the registry file
/// cannot be parsed, or a path operation fails.
pub fn dev_construct(args: &DevConstructArgs) -> Result<(), Box<dyn std::error::Error>> {
    let registry_file = registry_path()
        .ok_or_else(|| "could not resolve $HOME to find authoring-paths.toml".to_string())?;
    let mut registry = load_registry(&registry_file)?;

    if args.list {
        if registry.paths.is_empty() {
            eprintln!("[construct dev] no authoring paths registered");
        } else {
            eprintln!("[construct dev] registered authoring paths:");
            for p in &registry.paths {
                eprintln!("  {}", p.display());
            }
        }
        return Ok(());
    }

    if let Some(path) = args.unregister.as_ref() {
        let changed = unregister_authoring_path(&mut registry, path)?;
        if changed {
            save_registry(&registry_file, &registry)?;
            eprintln!("[construct dev] unregistered {}", path.display());
        } else {
            eprintln!(
                "[construct dev] {} was not in the registry (no-op)",
                path.display()
            );
        }
        return Ok(());
    }

    let path = args.path.as_ref().ok_or_else(|| {
        "ember construct dev: missing PATH argument (use --list to view, --unregister to remove)".to_string()
    })?;
    let changed = register_authoring_path(&mut registry, path)?;
    if changed {
        save_registry(&registry_file, &registry)?;
        eprintln!("[construct dev] registered {}", path.display());
        eprintln!(
            "[construct dev] receipts emitted from this path will be tagged authoring = true"
        );
    } else {
        eprintln!(
            "[construct dev] {} already registered (no-op)",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_registry_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn registers_new_path_and_persists() {
        let tmp = fresh_registry_dir();
        let registry_file = tmp.path().join("authoring-paths.toml");
        let worktree = tmp.path().join("my-construct");
        std::fs::create_dir_all(&worktree).unwrap();

        let mut reg = AuthoringPaths::default();
        let changed = register_authoring_path(&mut reg, &worktree).unwrap();
        assert!(changed, "first registration must change the registry");
        save_registry(&registry_file, &reg).unwrap();

        let reloaded = load_registry(&registry_file).unwrap();
        assert_eq!(reloaded.paths.len(), 1);
        assert_eq!(reloaded.paths[0], std::fs::canonicalize(&worktree).unwrap());
    }

    #[test]
    fn registering_same_path_twice_is_idempotent() {
        let tmp = fresh_registry_dir();
        let worktree = tmp.path().join("my-construct");
        std::fs::create_dir_all(&worktree).unwrap();

        let mut reg = AuthoringPaths::default();
        register_authoring_path(&mut reg, &worktree).unwrap();
        let changed = register_authoring_path(&mut reg, &worktree).unwrap();
        assert!(!changed, "second registration must be a no-op");
        assert_eq!(reg.paths.len(), 1);
    }

    #[test]
    fn unregister_removes_canonical_path() {
        let tmp = fresh_registry_dir();
        let worktree = tmp.path().join("my-construct");
        std::fs::create_dir_all(&worktree).unwrap();

        let mut reg = AuthoringPaths::default();
        register_authoring_path(&mut reg, &worktree).unwrap();
        let changed = unregister_authoring_path(&mut reg, &worktree).unwrap();
        assert!(changed);
        assert!(reg.paths.is_empty());
    }

    #[test]
    fn unregister_unknown_path_is_noop() {
        let tmp = fresh_registry_dir();
        let mut reg = AuthoringPaths::default();
        let changed =
            unregister_authoring_path(&mut reg, &tmp.path().join("never-registered")).unwrap();
        assert!(!changed);
    }

    #[test]
    fn script_in_authoring_path_matches_prefix() {
        let tmp = fresh_registry_dir();
        let worktree = tmp.path().join("my-construct");
        std::fs::create_dir_all(&worktree).unwrap();
        let script = worktree.join("scripts/run.py");
        std::fs::create_dir_all(script.parent().unwrap()).unwrap();
        std::fs::write(&script, b"print('hi')").unwrap();

        let mut reg = AuthoringPaths::default();
        register_authoring_path(&mut reg, &worktree).unwrap();

        assert!(script_is_in_authoring_path(&reg, &script));
    }

    #[test]
    fn script_outside_authoring_path_is_rejected() {
        let tmp = fresh_registry_dir();
        let worktree = tmp.path().join("my-construct");
        std::fs::create_dir_all(&worktree).unwrap();
        let outside = tmp.path().join("not-registered/run.py");
        std::fs::create_dir_all(outside.parent().unwrap()).unwrap();
        std::fs::write(&outside, b"print('hi')").unwrap();

        let mut reg = AuthoringPaths::default();
        register_authoring_path(&mut reg, &worktree).unwrap();

        assert!(!script_is_in_authoring_path(&reg, &outside));
    }

    #[test]
    fn empty_registry_refuses_all_scripts() {
        // End-user install (no registration): every script is outside the
        // registry → script_is_in_authoring_path returns false → daemon's
        // refuse path fires with `authoring_path_not_registered`.
        let tmp = fresh_registry_dir();
        let any_script = tmp.path().join("script.py");
        std::fs::write(&any_script, b"# anywhere").unwrap();
        let reg = AuthoringPaths::default();
        assert!(!script_is_in_authoring_path(&reg, &any_script));
    }

    #[test]
    fn save_registry_sets_mode_600_on_unix() {
        let tmp = fresh_registry_dir();
        let registry_file = tmp.path().join("authoring-paths.toml");
        let reg = AuthoringPaths::default();
        save_registry(&registry_file, &reg).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&registry_file)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "authoring-paths.toml must be 0600 (owner-only): got {mode:o}"
            );
        }
    }
}
