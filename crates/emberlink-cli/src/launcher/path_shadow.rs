//! PATH-shadow directory installer for `ember claude-code` and analogous launchers.
//!
//!
//! Implements design §3 PATH-shadow doctrine sub-A (implementation-note-434).
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

/// Populate the `bin/` subdirectory of `shadow_dir` with symlinks described
/// by `constructs`.
///
/// - Creates `<shadow_dir>/bin/` (mode 0700) if it does not exist. Idempotent
///   if the directory already exists with the same mode.
/// - For each [`ConstructSpec`], creates `<shadow_dir>/bin/<tool_name> -> target_binary`.
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
        let shim_path = bin_dir.join(&spec.tool_name);

        match shim_path.symlink_metadata() {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Nothing there — create the symlink.
                std::os::unix::fs::symlink(&spec.target_binary, &shim_path).map_err(|e| {
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
                    // Check if it already points to the right target.
                    match std::fs::read_link(&shim_path) {
                        Ok(existing) if existing == spec.target_binary => {
                            // Already correct — no-op.
                            continue;
                        }
                        Ok(_) => {
                            // Wrong target — remove and re-create.
                            std::fs::remove_file(&shim_path).map_err(|e| {
                                io::Error::other(format!(
                                    "remove stale symlink {}: {e}",
                                    shim_path.display()
                                ))
                            })?;
                            std::os::unix::fs::symlink(&spec.target_binary, &shim_path).map_err(
                                |e| {
                                    io::Error::other(format!(
                                        "create symlink {}: {e}",
                                        shim_path.display()
                                    ))
                                },
                            )?;
                        }
                        Err(e) => {
                            return Err(io::Error::other(format!(
                                "read_link {}: {e}",
                                shim_path.display()
                            )));
                        }
                    }
                } else {
                    // Regular file or other non-symlink object — refuse to clobber.
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
    }

    Ok(())
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
