//! PATH-shadow directory installer for `ember claude` and analogous launchers.
//!
//! CLASSIFICATION: PUBLIC
//!
//! Implements ADR 124 §3 PATH-shadow doctrine sub-A (ARCH-COHORT-A-LAUNCHER-SHADOW-INSTALLER).
//! The launcher prepends `~/.ember/shadow/bin/` to the child process's PATH so that
//! tool invocations like `gh pr create` transparently resolve to the ember-gh
//! Construct binary rather than the system binary. This module populates the
//! `bin/` subdirectory of the shadow root with the required symlinks.
//!
//! Layout:
//! - `~/.ember/shadow/bin/`  — shim binaries (PATH-prepended); managed by this module.
//! - `~/.ember/shadow/`      — credential / config / state files; NOT PATH-prepended.
//!
//! Callers (sub-B WIRING) call [`install_path_shadow`] before exec'ing the child;
//! they are responsible for prepending `shadow_bin_dir(shadow_dir)` to the child
//! env's PATH. This module does NOT touch PATH itself and does NOT spawn any processes.

use std::io;
use std::path::{Path, PathBuf};

/// A single shim mapping: the name that appears in PATH (`tool_name`) and the
/// real binary it should delegate to (`target_binary`).
#[derive(Debug, Clone)]
pub struct ConstructSpec {
    /// The filename that will appear in the shadow directory (e.g. `"gh"`).
    pub tool_name: String,
    /// The absolute path to the ember Construct binary (e.g. `/usr/local/bin/ember-gh`).
    pub target_binary: PathBuf,
}

/// Return the `bin/` subdirectory of `shadow_dir` that is prepended to PATH.
///
/// Shim binaries live under `<shadow_dir>/bin/`; credential and config files
/// live directly under `<shadow_dir>/`. Callers must prepend the return value
/// of this function (not `shadow_dir` itself) to the child process's PATH.
pub fn shadow_bin_dir(shadow_dir: &Path) -> PathBuf {
    shadow_dir.join("bin")
}

pub(crate) fn shadow_tool_aliases(tool_name: &str) -> Vec<String> {
    if tool_name.starts_with("ember-") {
        Vec::new()
    } else {
        vec![format!("ember-{tool_name}")]
    }
}

fn install_shadow_symlink(shim_path: &Path, target_binary: &Path) -> io::Result<()> {
    match shim_path.symlink_metadata() {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            std::os::unix::fs::symlink(target_binary, shim_path).map_err(|e| {
                io::Error::other(format!("create symlink {}: {e}", shim_path.display()))
            })?;
        }
        Err(e) => {
            return Err(io::Error::other(format!(
                "stat {}: {e}",
                shim_path.display()
            )));
        }
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                match std::fs::read_link(shim_path) {
                    Ok(existing) if existing == target_binary => {
                        return Ok(());
                    }
                    Ok(_) => {
                        std::fs::remove_file(shim_path).map_err(|e| {
                            io::Error::other(format!(
                                "remove stale symlink {}: {e}",
                                shim_path.display()
                            ))
                        })?;
                        std::os::unix::fs::symlink(target_binary, shim_path).map_err(|e| {
                            io::Error::other(format!("create symlink {}: {e}", shim_path.display()))
                        })?;
                    }
                    Err(e) => {
                        return Err(io::Error::other(format!(
                            "read_link {}: {e}",
                            shim_path.display()
                        )));
                    }
                }
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "regular file already exists at shadow path {}; \
                         remove it manually before installing the shim",
                        shim_path.display()
                    ),
                ));
            }
        }
    }

    Ok(())
}

/// Populate the `bin/` subdirectory of `shadow_dir` with symlinks described
/// by `constructs`.
///
/// - Creates `<shadow_dir>/bin/` (mode 0700) if it does not exist. Idempotent
///   if the directory already exists with the same mode.
/// - For each [`ConstructSpec`], creates `<shadow_dir>/bin/<tool_name> -> target_binary`.
///   For ambient tool names like `gh`, also creates the direct Construct alias
///   `<shadow_dir>/bin/ember-gh -> target_binary`.
///   - If a symlink already points to the correct target: no-op.
///   - If a symlink exists with a different target: removes it and re-creates.
///   - If a regular file (or other non-symlink filesystem object) exists at the
///     path: returns `Err` with kind [`io::ErrorKind::AlreadyExists`].
/// - Propagates all other I/O errors with file context preserved via
///   [`io::Error::other`].
///
/// On success returns `Ok(())`. Callers may retry after resolving conflicts.
pub fn install_path_shadow(shadow_dir: &Path, constructs: &[ConstructSpec]) -> io::Result<()> {
    // Shim binaries go into the bin/ subdirectory, not the shadow root.
    let bin_dir = shadow_bin_dir(shadow_dir);
    // Create the bin directory if absent, then enforce 0700.
    std::fs::create_dir_all(&bin_dir)?;
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(&bin_dir, perms)?;
    }

    for spec in constructs {
        install_shadow_symlink(&bin_dir.join(&spec.tool_name), &spec.target_binary)?;
        for alias in shadow_tool_aliases(&spec.tool_name) {
            install_shadow_symlink(&bin_dir.join(alias), &spec.target_binary)?;
        }
    }

    Ok(())
}

/// Outcome of a `--migrate` run over the shadow path layout. Carries
/// enough state for the CLI to print an honest summary to the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// `layout=none`: neither old-layout shim files nor new-layout
    /// `bin/` symlinks exist. The host has never been initialized for
    /// PATH-shadow; `--migrate` is a no-op and the operator should run
    /// `ember init --for claude` (without `--migrate`) instead.
    NoShimsAtAll,
    /// `layout=new`: only the new `<shadow>/bin/<name>` entries exist.
    /// Nothing to migrate.
    AlreadyMigrated,
    /// `layout=both` with old paths already symlinked to the new bin/
    /// entries. Idempotent re-run of a prior successful migration.
    AlreadyMigratedSymlinksInPlace,
    /// `layout=old` (or mixed with stale symlinks): one or more
    /// regular-file shims were present at the shadow root. They have
    /// been replaced by symlinks pointing into `<shadow>/bin/`, and
    /// the new-layout entries were created (or refreshed) along the
    /// way. `count` is the number of old-path shims relocated.
    MigratedFromOldLayout { count: usize },
}

/// Relocate old-layout PATH-shadow shims under `<shadow_dir>/<tool>` to
/// the new `<shadow_dir>/bin/<tool>` layout, replacing the old paths
/// with symlinks pointing into `bin/` so any PATH or wrapper still
/// referencing the old location keeps working for one release window.
///
/// Idempotent:
/// - `layout=none` → no-op + `NoShimsAtAll` so the operator gets an
///   actionable hint (run the non-migrate init first).
/// - `layout=new` → no-op + `AlreadyMigrated`.
/// - `layout=both` with old paths already symlinking to the new entries
///   → no-op + `AlreadyMigratedSymlinksInPlace`.
/// - `layout=old` (or any path with regular-file shims at the root) →
///   migrate + `MigratedFromOldLayout { count }`.
///
/// Refuses to clobber a regular file or wrong-target symlink at the
/// new-layout target paths — defers to the underlying
/// [`install_path_shadow`]'s safety semantics.
///
/// shadow_path_migrate_flag_landed.
pub fn migrate_path_shadow_layout(
    shadow_dir: &Path,
    constructs: &[ConstructSpec],
) -> io::Result<MigrationOutcome> {
    let bin_dir = shadow_bin_dir(shadow_dir);

    let mut had_old_regular_file = false;
    let mut had_old_other_symlink = false;
    let mut had_old_symlink_to_new = false;
    let mut had_new_layout = false;

    for spec in constructs {
        let old_path = shadow_dir.join(&spec.tool_name);
        let new_path = bin_dir.join(&spec.tool_name);

        match old_path.symlink_metadata() {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    match std::fs::read_link(&old_path) {
                        Ok(target) if target == new_path => {
                            had_old_symlink_to_new = true;
                        }
                        _ => {
                            had_old_other_symlink = true;
                        }
                    }
                } else if meta.is_file() {
                    had_old_regular_file = true;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(io::Error::other(format!(
                    "stat {}: {e}",
                    old_path.display()
                )));
            }
        }

        if new_path.exists() || new_path.symlink_metadata().is_ok() {
            had_new_layout = true;
        }
    }

    // Decision tree.
    let any_old = had_old_regular_file || had_old_other_symlink || had_old_symlink_to_new;
    if !any_old && !had_new_layout {
        return Ok(MigrationOutcome::NoShimsAtAll);
    }
    if !any_old && had_new_layout {
        return Ok(MigrationOutcome::AlreadyMigrated);
    }
    if !had_old_regular_file && !had_old_other_symlink && had_old_symlink_to_new && had_new_layout {
        return Ok(MigrationOutcome::AlreadyMigratedSymlinksInPlace);
    }

    // Migrate. Refresh / create the new layout first so the symlinks
    // we're about to plant at the old paths have valid targets.
    install_path_shadow(shadow_dir, constructs)?;

    let mut count = 0usize;
    for spec in constructs {
        let old_path = shadow_dir.join(&spec.tool_name);
        let new_path = bin_dir.join(&spec.tool_name);

        match old_path.symlink_metadata() {
            Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {
                std::fs::remove_file(&old_path).map_err(|e| {
                    io::Error::other(format!(
                        "remove old-layout shim {}: {e}",
                        old_path.display()
                    ))
                })?;
                std::os::unix::fs::symlink(&new_path, &old_path).map_err(|e| {
                    io::Error::other(format!(
                        "create back-compat symlink {} -> {}: {e}",
                        old_path.display(),
                        new_path.display()
                    ))
                })?;
                count += 1;
            }
            Ok(meta) if meta.file_type().is_symlink() => {
                match std::fs::read_link(&old_path) {
                    Ok(target) if target == new_path => {
                        // Already correct — no-op.
                    }
                    _ => {
                        // Stale symlink at the old path. Replace with the
                        // correct one so the back-compat surface points
                        // at the canonical bin/ entry.
                        std::fs::remove_file(&old_path).map_err(|e| {
                            io::Error::other(format!(
                                "remove stale old-path symlink {}: {e}",
                                old_path.display()
                            ))
                        })?;
                        std::os::unix::fs::symlink(&new_path, &old_path).map_err(|e| {
                            io::Error::other(format!(
                                "refresh back-compat symlink {}: {e}",
                                old_path.display()
                            ))
                        })?;
                        count += 1;
                    }
                }
            }
            _ => {}
        }
    }

    Ok(MigrationOutcome::MigratedFromOldLayout { count })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn installs_creates_bin_dir_and_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let shadow = tmp.path().join("shadow");
        let bin_a = tmp.path().join("ember-gh");
        let bin_b = tmp.path().join("ember-git");
        std::fs::write(&bin_a, b"").unwrap();
        std::fs::write(&bin_b, b"").unwrap();

        let specs = vec![
            ConstructSpec {
                tool_name: "gh".to_string(),
                target_binary: bin_a.clone(),
            },
            ConstructSpec {
                tool_name: "git".to_string(),
                target_binary: bin_b.clone(),
            },
        ];

        install_path_shadow(&shadow, &specs).unwrap();

        // The bin/ subdirectory must exist with mode 0700.
        let bin_dir = shadow_bin_dir(&shadow);
        let meta = std::fs::metadata(&bin_dir).unwrap();
        assert!(meta.is_dir());
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        }

        // Shim symlinks must be under bin/, not the shadow root.
        assert_eq!(std::fs::read_link(bin_dir.join("gh")).unwrap(), bin_a);
        assert_eq!(std::fs::read_link(bin_dir.join("git")).unwrap(), bin_b);
        assert_eq!(std::fs::read_link(bin_dir.join("ember-gh")).unwrap(), bin_a);
        assert_eq!(
            std::fs::read_link(bin_dir.join("ember-git")).unwrap(),
            bin_b
        );
    }

    #[test]
    fn shadow_bin_dir_is_bin_subdir_of_shadow_root() {
        let shadow = std::path::Path::new("/home/user/.ember/shadow");
        let bin = shadow_bin_dir(shadow);
        assert_eq!(bin, std::path::Path::new("/home/user/.ember/shadow/bin"));
    }

    #[test]
    fn idempotent_on_correct_target() {
        let tmp = tempfile::tempdir().unwrap();
        let shadow = tmp.path().join("shadow");
        let bin = tmp.path().join("ember-gh");
        std::fs::write(&bin, b"").unwrap();

        let specs = vec![ConstructSpec {
            tool_name: "gh".to_string(),
            target_binary: bin.clone(),
        }];

        install_path_shadow(&shadow, &specs).unwrap();
        // Second call — must succeed without error.
        install_path_shadow(&shadow, &specs).unwrap();

        assert_eq!(
            std::fs::read_link(shadow_bin_dir(&shadow).join("gh")).unwrap(),
            bin
        );
    }

    #[test]
    fn replaces_wrong_target_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let shadow = tmp.path().join("shadow");
        let bin_dir = shadow_bin_dir(&shadow);
        std::fs::create_dir_all(&bin_dir).unwrap();

        let stale_target = tmp.path().join("old-binary");
        let correct_target = tmp.path().join("ember-gh");
        std::fs::write(&stale_target, b"").unwrap();
        std::fs::write(&correct_target, b"").unwrap();

        // Pre-install a symlink pointing at the stale target.
        symlink(&stale_target, bin_dir.join("gh")).unwrap();

        let specs = vec![ConstructSpec {
            tool_name: "gh".to_string(),
            target_binary: correct_target.clone(),
        }];

        install_path_shadow(&shadow, &specs).unwrap();

        // Symlink must now point to the correct target.
        assert_eq!(
            std::fs::read_link(bin_dir.join("gh")).unwrap(),
            correct_target
        );
    }

    fn specs_gh_git(tmp: &tempfile::TempDir) -> Vec<ConstructSpec> {
        let bin_a = tmp.path().join("ember-gh");
        let bin_b = tmp.path().join("ember-git");
        std::fs::write(&bin_a, b"").unwrap();
        std::fs::write(&bin_b, b"").unwrap();
        vec![
            ConstructSpec {
                tool_name: "gh".to_string(),
                target_binary: bin_a,
            },
            ConstructSpec {
                tool_name: "git".to_string(),
                target_binary: bin_b,
            },
        ]
    }

    #[test]
    fn migrate_no_shims_at_all_returns_no_shims() {
        let tmp = tempfile::tempdir().unwrap();
        let shadow = tmp.path().join("shadow");
        let specs = specs_gh_git(&tmp);
        let outcome = migrate_path_shadow_layout(&shadow, &specs).unwrap();
        assert_eq!(outcome, MigrationOutcome::NoShimsAtAll);
    }

    #[test]
    fn migrate_new_layout_only_returns_already_migrated() {
        let tmp = tempfile::tempdir().unwrap();
        let shadow = tmp.path().join("shadow");
        let specs = specs_gh_git(&tmp);
        // Install new layout up front.
        install_path_shadow(&shadow, &specs).unwrap();
        let outcome = migrate_path_shadow_layout(&shadow, &specs).unwrap();
        assert_eq!(outcome, MigrationOutcome::AlreadyMigrated);
    }

    #[test]
    fn migrate_old_layout_relocates_files_and_creates_symlinks() {
        // shadow_path_migrate_flag_landed — checkpoint mirrored in test body
        // so a grep covers production + test paths.
        let tmp = tempfile::tempdir().unwrap();
        let shadow = tmp.path().join("shadow");
        let specs = specs_gh_git(&tmp);
        // Seed old-layout shims as regular files at the shadow root.
        std::fs::create_dir_all(&shadow).unwrap();
        std::fs::write(shadow.join("gh"), b"#!/bin/sh\necho old-gh\n").unwrap();
        std::fs::write(shadow.join("git"), b"#!/bin/sh\necho old-git\n").unwrap();

        let outcome = migrate_path_shadow_layout(&shadow, &specs).unwrap();
        assert_eq!(
            outcome,
            MigrationOutcome::MigratedFromOldLayout { count: 2 }
        );

        let bin_dir = shadow_bin_dir(&shadow);
        // New-layout entries exist as symlinks pointing at the real binaries.
        assert!(bin_dir.join("gh").is_symlink());
        assert!(bin_dir.join("git").is_symlink());
        // Old-layout paths are now symlinks pointing at the new entries.
        assert!(shadow.join("gh").is_symlink());
        assert_eq!(
            std::fs::read_link(shadow.join("gh")).unwrap(),
            bin_dir.join("gh")
        );
        assert_eq!(
            std::fs::read_link(shadow.join("git")).unwrap(),
            bin_dir.join("git")
        );
    }

    #[test]
    fn migrate_idempotent_on_layout_both() {
        let tmp = tempfile::tempdir().unwrap();
        let shadow = tmp.path().join("shadow");
        let specs = specs_gh_git(&tmp);
        // Seed old-layout shims then migrate to set up `layout=both`.
        std::fs::create_dir_all(&shadow).unwrap();
        std::fs::write(shadow.join("gh"), b"").unwrap();
        std::fs::write(shadow.join("git"), b"").unwrap();
        let first = migrate_path_shadow_layout(&shadow, &specs).unwrap();
        assert!(matches!(
            first,
            MigrationOutcome::MigratedFromOldLayout { .. }
        ));
        // Second invocation must be a no-op.
        let second = migrate_path_shadow_layout(&shadow, &specs).unwrap();
        assert_eq!(second, MigrationOutcome::AlreadyMigratedSymlinksInPlace);
    }

    #[test]
    fn migrate_refreshes_stale_old_path_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let shadow = tmp.path().join("shadow");
        let specs = specs_gh_git(&tmp);
        // Install new layout, then plant a stale symlink at the old path
        // pointing somewhere else.
        install_path_shadow(&shadow, &specs).unwrap();
        let stale_target = tmp.path().join("stale-target");
        std::fs::write(&stale_target, b"").unwrap();
        std::os::unix::fs::symlink(&stale_target, shadow.join("gh")).unwrap();

        let outcome = migrate_path_shadow_layout(&shadow, &specs).unwrap();
        // Stale symlink at old path counts as needing migration —
        // refresh to point at the bin/ entry.
        assert!(matches!(
            outcome,
            MigrationOutcome::MigratedFromOldLayout { count } if count >= 1
        ));
        assert_eq!(
            std::fs::read_link(shadow.join("gh")).unwrap(),
            shadow_bin_dir(&shadow).join("gh")
        );
    }

    #[test]
    fn errors_on_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let shadow = tmp.path().join("shadow");
        let bin_dir = shadow_bin_dir(&shadow);
        std::fs::create_dir_all(&bin_dir).unwrap();

        // Place a regular file where the shim should go.
        std::fs::write(bin_dir.join("gh"), b"I am a regular file").unwrap();

        let bin = tmp.path().join("ember-gh");
        std::fs::write(&bin, b"").unwrap();

        let specs = vec![ConstructSpec {
            tool_name: "gh".to_string(),
            target_binary: bin,
        }];

        let err = install_path_shadow(&shadow, &specs).unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::AlreadyExists,
            "regular file at shim path must produce AlreadyExists"
        );
    }
}
