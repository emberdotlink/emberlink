//! `ember dev sync` — incremental rebuild + diff + kickstart of the dev daemon.
//!
//! design §Component 4. After editing daemon or construct code, the operator
//! runs `ember dev sync` to rebuild, detect changed binaries (content-hash
//! diff), copy them to the dev install root, and restart the dev daemon.
//! Target wall-clock: ~30 seconds (dominated by `cargo build --release`).
//!
//! # Phase-1 scope (this slice)
//!
//! - Step 1: incremental cargo build (`--release -p ember-daemon -p ember-construct`).
//! - Step 2: content-hash diff (SHA-256) — detect which built binaries changed.
//! - Step 3: copy changed binaries to the dev install root (code-signing is a
//!   TODO stub; signing pipeline lands in implementation-note-419).
//! - Step 5: `launchctl kickstart -k system/sh.emberlink.daemon.dev` (skipped
//!   when `--no-launchctl` is passed).
//! - Steps 4 + 6 (manifest re-gen + daemon-verify) are TODO stubs; they depend
//!   on EMBER-DEV-INSTALL slice-B (manifest gen) landing.
//!
//! # Checkpoint
//!
//! `dev_prod_parity_ember_dev_sync_landed`
//!

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::install_paths::DEV_INSTALL_ROOT;

/// Checkpoint — `dev_prod_parity_ember_dev_sync_landed`.
#[doc(hidden)]
pub const SENTINEL_DEV_PROD_PARITY_EMBER_DEV_SYNC_LANDED: &str =
    "dev_prod_parity_ember_dev_sync_landed";

/// Binary targets built and synced by `ember dev sync`.
const SYNC_TARGETS: &[&str] = &["ember-daemon", "ember-construct"];

/// Arguments for `ember dev sync`.
pub struct SyncArgs {
    /// When true, skip the `launchctl kickstart` step (for hosts without the
    /// dev daemon installed yet, or when running in CI).
    pub no_launchctl: bool,
    /// Workspace root. Defaults to the directory containing `Cargo.toml`
    /// discovered by walking up from `$PWD`. Injected by callers for testing.
    pub workspace_root: Option<PathBuf>,
}

/// Compute the SHA-256 digest of `path` and return it as a hex string.
///
/// Returns an error if the file cannot be read.
pub fn sha256_hex(path: &Path) -> io::Result<String> {
    let bytes = std::fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    Ok(hex::encode(digest))
}

/// Returns the installed path for a built binary under `DEV_INSTALL_ROOT`.
///
/// The dev install root mirrors the prod layout:
/// `{DEV_INSTALL_ROOT}/bin/<name>` on Linux, or
/// `{DEV_INSTALL_ROOT}/emberd.app/Contents/MacOS/<name>` on macOS for the
/// daemon binary. For phase-1 simplicity we use a flat `bin/` layout for all
/// targets and leave the macOS bundle layout for the full install slice.
pub fn installed_path(name: &str) -> PathBuf {
    PathBuf::from(DEV_INSTALL_ROOT).join("bin").join(name)
}

/// Returns the `target/release/<name>` path for a built binary, relative to
/// `workspace_root`.
pub fn built_path(workspace_root: &Path, name: &str) -> PathBuf {
    workspace_root.join("target").join("release").join(name)
}

/// Determine whether `built` differs from `installed` by comparing their
/// SHA-256 digests.
///
/// Returns `Ok(true)` when the binary changed (or the installed copy is
/// absent), `Ok(false)` when they are identical.
pub fn binary_changed(built: &Path, installed: &Path) -> io::Result<bool> {
    if !installed.exists() {
        return Ok(true);
    }
    let built_hash = sha256_hex(built)?;
    let installed_hash = sha256_hex(installed)?;
    Ok(built_hash != installed_hash)
}

/// Copy `src` to `dest`, creating the parent directory if absent.
///
/// Sets the executable bit on Unix (`0o755`).
fn copy_binary(src: &Path, dest: &Path) -> io::Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(src, dest)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(dest)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(dest, perms)?;
    }
    Ok(())
}

/// Run `cargo build --release` for the sync targets.
///
/// Returns an error if `cargo` exits non-zero. Output (stdout + stderr) is
/// forwarded to the terminal so the operator sees compile errors inline.
fn cargo_build(workspace_root: &Path) -> io::Result<()> {
    let mut args = vec!["build", "--release"];
    for target in SYNC_TARGETS {
        args.push("-p");
        args.push(target);
    }
    let status = Command::new("cargo")
        .args(&args)
        .current_dir(workspace_root)
        .status()?;
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "cargo build --release exited {}",
                status.code().unwrap_or(-1)
            ),
        ));
    }
    Ok(())
}

/// Kick the dev daemon via `launchctl kickstart -k system/<label>`.
///
/// On a host where the dev LaunchDaemon is not loaded, launchctl exits
/// non-zero; we surface the error so the operator can diagnose rather than
/// silently swallowing it.
fn launchctl_kickstart(label: &str) -> io::Result<()> {
    let target = format!("system/{label}");
    let status = Command::new("launchctl")
        .args(["kickstart", "-k", &target])
        .status()?;
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "launchctl kickstart -k {target} exited {}",
                status.code().unwrap_or(-1)
            ),
        ));
    }
    Ok(())
}

/// Resolve the workspace root: use `args.workspace_root` if set; otherwise
/// walk up from `$PWD` looking for a `Cargo.toml`.
fn resolve_workspace_root(args: &SyncArgs) -> io::Result<PathBuf> {
    if let Some(ref root) = args.workspace_root {
        return Ok(root.clone());
    }
    // Walk up from CWD to find the workspace Cargo.toml.
    let cwd = std::env::current_dir()?;
    let mut candidate = cwd.as_path();
    loop {
        if candidate.join("Cargo.toml").exists() {
            return Ok(candidate.to_path_buf());
        }
        match candidate.parent() {
            Some(p) => candidate = p,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "could not locate workspace Cargo.toml walking up from $PWD",
                ));
            }
        }
    }
}

/// Run `ember dev sync`.
///
/// # Errors
///
/// Returns an `io::Error` describing the first failure encountered. Partial
/// progress is printed to stderr before returning.
pub fn run(args: &SyncArgs) -> io::Result<()> {
    let workspace_root = resolve_workspace_root(args)?;

    // --- Step 1: incremental cargo build ---
    eprintln!("[dev sync] building {} …", SYNC_TARGETS.join(", "));
    cargo_build(&workspace_root)?;
    eprintln!("[dev sync] build OK");

    // --- Step 2+3: content-hash diff + copy changed binaries ---
    let mut changed_count = 0usize;
    for &target in SYNC_TARGETS {
        let built = built_path(&workspace_root, target);
        let installed = installed_path(target);

        if !built.exists() {
            eprintln!(
                "[dev sync] warning: built binary not found at {} — skipping",
                built.display()
            );
            continue;
        }

        let changed = binary_changed(&built, &installed)?;
        if changed {
            // TODO(phase-2): run the dev IdentityRoot sign pipeline here
            // (implementation-note-419 phase 6) before copying.
            eprintln!(
                "[dev sync] {} changed — copying to {}",
                target,
                installed.display()
            );
            copy_binary(&built, &installed)?;
            changed_count += 1;
        } else {
            eprintln!("[dev sync] {} unchanged — skipping", target);
        }
    }

    // --- Step 4: manifest re-gen (TODO stub) ---
    if changed_count > 0 {
        eprintln!(
            "[dev sync] TODO: follow-up subtask — re-generate dev manifest (EMBER-DEV-INSTALL slice-B)"
        );
    }

    // --- Step 5: launchctl kickstart ---
    if args.no_launchctl {
        eprintln!("[dev sync] --no-launchctl set — skipping daemon kickstart");
    } else {
        eprintln!("[dev sync] kicking dev daemon …");
        launchctl_kickstart(crate::install_paths::DEV_PLIST_LABEL)?;
        eprintln!("[dev sync] daemon kickstarted");
    }

    // --- Step 6: daemon verify (TODO stub) ---
    eprintln!(
        "[dev sync] TODO: follow-up subtask — poll dev socket + verify daemon liveness (EMBER-DEV-INSTALL slice-B)"
    );

    if changed_count > 0 {
        eprintln!("[dev sync] done — {changed_count} binary(s) updated");
    } else {
        eprintln!("[dev sync] done — no binaries changed");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn scratch() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    // --- sha256_hex determinism ---

    #[test]
    fn sha256_hex_is_deterministic() {
        let tmp = scratch();
        let path = tmp.path().join("file.bin");
        fs::write(&path, b"hello world").unwrap();

        let h1 = sha256_hex(&path).unwrap();
        let h2 = sha256_hex(&path).unwrap();
        assert_eq!(h1, h2, "sha256_hex must be deterministic");
    }

    #[test]
    fn sha256_hex_differs_for_different_content() {
        let tmp = scratch();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        fs::write(&a, b"content A").unwrap();
        fs::write(&b, b"content B").unwrap();

        let ha = sha256_hex(&a).unwrap();
        let hb = sha256_hex(&b).unwrap();
        assert_ne!(ha, hb, "different content must produce different hashes");
    }

    #[test]
    fn sha256_hex_same_content_same_hash() {
        let tmp = scratch();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        fs::write(&a, b"same content").unwrap();
        fs::write(&b, b"same content").unwrap();

        let ha = sha256_hex(&a).unwrap();
        let hb = sha256_hex(&b).unwrap();
        assert_eq!(ha, hb, "identical content must produce the same hash");
    }

    #[test]
    fn sha256_hex_error_on_missing_file() {
        let tmp = scratch();
        let missing = tmp.path().join("does_not_exist");
        assert!(sha256_hex(&missing).is_err());
    }

    // --- binary_changed ---

    #[test]
    fn binary_changed_true_when_installed_absent() {
        let tmp = scratch();
        let built = tmp.path().join("built");
        let installed = tmp.path().join("installed");
        fs::write(&built, b"new binary").unwrap();
        // `installed` does not exist

        assert!(
            binary_changed(&built, &installed).unwrap(),
            "must report changed when installed copy is absent"
        );
    }

    #[test]
    fn binary_changed_false_when_identical() {
        let tmp = scratch();
        let built = tmp.path().join("built");
        let installed = tmp.path().join("installed");
        fs::write(&built, b"same binary content").unwrap();
        fs::write(&installed, b"same binary content").unwrap();

        assert!(
            !binary_changed(&built, &installed).unwrap(),
            "must report unchanged when content is identical"
        );
    }

    #[test]
    fn binary_changed_true_when_content_differs() {
        let tmp = scratch();
        let built = tmp.path().join("built");
        let installed = tmp.path().join("installed");
        fs::write(&built, b"new version").unwrap();
        fs::write(&installed, b"old version").unwrap();

        assert!(
            binary_changed(&built, &installed).unwrap(),
            "must report changed when content differs"
        );
    }

    // --- installed_path / built_path shape checks ---

    #[test]
    fn installed_path_is_under_dev_install_root() {
        let p = installed_path("ember-daemon");
        let root = PathBuf::from(DEV_INSTALL_ROOT);
        assert!(
            p.starts_with(&root),
            "installed_path must be under DEV_INSTALL_ROOT: {}",
            p.display()
        );
    }

    #[test]
    fn built_path_is_under_target_release() {
        let workspace = PathBuf::from("/tmp/workspace");
        let p = built_path(&workspace, "ember-daemon");
        assert!(
            p.starts_with("/tmp/workspace/target/release"),
            "built_path must be under target/release: {}",
            p.display()
        );
    }

    #[test]
    fn installed_paths_for_different_targets_are_distinct() {
        let p1 = installed_path("ember-daemon");
        let p2 = installed_path("ember-construct");
        assert_ne!(
            p1, p2,
            "different targets must have different install paths"
        );
    }
}
