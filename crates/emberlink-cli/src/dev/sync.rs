//! `ember dev sync` — incremental rebuild + diff + kickstart of the current
//! worktree dev runtime.
//!
//! ADR 157 §Component 4. After editing CLI, daemon, or construct code, the
//! operator runs `ember dev sync` to rebuild, detect changed binaries
//! (content-hash diff), copy them to the dev install root, and restart the
//! dev daemon. Target wall-clock: ~30 seconds (dominated by
//! `cargo build --release`).
//!
//! # Phase-1 scope (this slice)
//!
//! - Step 1: incremental cargo build (`--release -p emberlink-cli -p
//!   ember-daemon -p ember-construct`).
//! - Step 2: content-hash diff (SHA-256) — detect which built binaries changed.
//! - Step 3: copy changed binaries to the dev install root (code-signing is a
//!   TODO stub; signing pipeline lands in META-DEV-PROD-PARITY-EMBER-DEV-INSTALL).
//! - Step 4: re-generate and re-sign the dev manifest when synced binaries
//!   changed.
//! - Step 5: `launchctl kickstart -k system/sh.emberlink.daemon.dev` (skipped
//!   when `--no-launchctl` is passed).
//! - Step 6: post-kickstart readiness verification via the same install-time
//!   runtime truth surface.
//!
//! # Checkpoint
//!
//! `dev_prod_parity_ember_dev_sync_landed`
//!
//! CLASSIFICATION: PUBLIC

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::dev::identity_root;
use crate::dev_install_slice_c::{CommandRunner, RealCommandRunner, manifest, verify};
use crate::dev_runtime::{
    DevRuntimeEnv, resolve_dev_runtime_for_workspace_root, resolve_workspace_root,
};
use crate::dev_runtime_artifacts::{build_packages, runtime_artifacts};

/// Checkpoint — `dev_prod_parity_ember_dev_sync_landed`.
#[doc(hidden)]
pub const SENTINEL_DEV_PROD_PARITY_EMBER_DEV_SYNC_LANDED: &str =
    "dev_prod_parity_ember_dev_sync_landed";

const SYNC_VERIFY_TIMEOUT_SECS: u64 = 10;

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

/// Returns the installed path for a built binary under the worktree-scoped
/// dev runtime install root.
pub fn installed_path(runtime: &DevRuntimeEnv, name: &str) -> PathBuf {
    runtime.install_root.join(name)
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

fn io_other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

/// Run `cargo build --release` for the dev-runtime packages.
///
/// Returns an error if `cargo` exits non-zero. Output (stdout + stderr) is
/// forwarded to the terminal so the operator sees compile errors inline.
fn cargo_build(workspace_root: &Path) -> io::Result<()> {
    let mut args = vec!["build", "--release"];
    for package in build_packages() {
        args.push("-p");
        args.push(package);
    }
    let status = Command::new("cargo")
        .args(&args)
        .current_dir(workspace_root)
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "cargo build --release exited {}",
            status.code().unwrap_or(-1)
        )));
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
        return Err(io::Error::other(format!(
            "launchctl kickstart -k {target} exited {}",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

fn rewrite_manifest_with(
    runner: &dyn CommandRunner,
    signer: &SigningKey,
    dest_dir: &Path,
) -> io::Result<usize> {
    let entries = manifest::scan_tool_binaries(runner).map_err(|e| io_other(e.to_string()))?;
    let toml = manifest::render_manifest(&entries);
    let signature =
        manifest::sign_manifest(toml.as_bytes(), signer).map_err(|e| io_other(e.to_string()))?;
    manifest::write_manifest(&toml, &signature, dest_dir).map_err(|e| io_other(e.to_string()))?;
    Ok(entries.len())
}

fn rewrite_dev_manifest(runtime: &DevRuntimeEnv) -> io::Result<usize> {
    let signing_key = identity_root::read_existing_dev_identity_root_signing_key()
        .map_err(io_other)?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "dev IdentityRoot missing; run `ember dev install` first",
            )
        })?;
    let dest_dir = manifest::manifest_dest_dir(&runtime.manifest_path).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "manifest destination not resolvable (no HOME?)",
        )
    })?;
    rewrite_manifest_with(&RealCommandRunner, &signing_key, &dest_dir)
}

fn verify_report_ready(report: &verify::DevInstallVerifyReport) -> io::Result<()> {
    let issues = verify::readiness_issues(report);
    if issues.is_empty() {
        Ok(())
    } else {
        Err(io_other(format!(
            "dev daemon not ready: {}",
            issues.join("; ")
        )))
    }
}

fn verify_ready_with_timeout(timeout: Duration, runtime: &DevRuntimeEnv) -> io::Result<()> {
    let deadline = Instant::now() + timeout;

    loop {
        let err = match verify::verify_dev_install_for(runtime) {
            Ok(report) => match verify_report_ready(&report) {
                Ok(()) => return Ok(()),
                Err(err) => err,
            },
            Err(err) => io_other(err.to_string()),
        };

        if Instant::now() >= deadline {
            return Err(err);
        }

        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Resolve the workspace root: use `args.workspace_root` if set; otherwise
/// walk up from `$PWD` looking for a `Cargo.toml`.
fn resolve_workspace_root_arg(args: &SyncArgs) -> io::Result<PathBuf> {
    if let Some(ref root) = args.workspace_root {
        return Ok(root.clone());
    }
    resolve_workspace_root().map_err(io_other)
}

/// Run `ember dev sync`.
///
/// # Errors
///
/// Returns an `io::Error` describing the first failure encountered. Partial
/// progress is printed to stderr before returning.
pub fn run(args: &SyncArgs) -> io::Result<()> {
    let workspace_root = resolve_workspace_root_arg(args)?;
    let runtime = resolve_dev_runtime_for_workspace_root(&workspace_root).map_err(io_other)?;
    let artifacts = runtime_artifacts();

    eprintln!(
        "[dev sync] runtime {}",
        crate::dev_runtime::compact_runtime_banner(&runtime)
    );

    // --- Step 1: incremental cargo build ---
    eprintln!("[dev sync] building {} …", build_packages().join(", "));
    cargo_build(&workspace_root)?;
    eprintln!("[dev sync] build OK");

    // --- Step 2+3: content-hash diff + copy changed binaries ---
    let mut changed_count = 0usize;
    for artifact in &artifacts {
        let built = built_path(&workspace_root, &artifact.binary_name);
        let installed = installed_path(&runtime, &artifact.binary_name);

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
            // (META-DEV-PROD-PARITY-EMBER-DEV-INSTALL phase 6) before copying.
            eprintln!(
                "[dev sync] {} changed — copying to {}",
                artifact.binary_name,
                installed.display()
            );
            copy_binary(&built, &installed)?;
            changed_count += 1;
        } else {
            eprintln!("[dev sync] {} unchanged — skipping", artifact.binary_name);
        }
    }

    // --- Step 4: manifest re-gen ---
    if changed_count > 0 {
        let entry_count = rewrite_dev_manifest(&runtime)?;
        eprintln!(
            "[dev sync] manifest refreshed — {entry_count} tool entr{} signed",
            if entry_count == 1 { "y" } else { "ies" }
        );
    }

    // --- Step 5: launchctl kickstart ---
    if args.no_launchctl {
        eprintln!("[dev sync] --no-launchctl set — skipping daemon kickstart");
    } else {
        eprintln!("[dev sync] kicking dev daemon …");
        launchctl_kickstart(&runtime.plist_label)?;
        eprintln!("[dev sync] daemon kickstarted");
    }

    // --- Step 6: daemon verify ---
    if args.no_launchctl {
        eprintln!("[dev sync] --no-launchctl set — skipping daemon readiness verify");
    } else {
        verify_ready_with_timeout(Duration::from_secs(SYNC_VERIFY_TIMEOUT_SECS), &runtime)?;
        eprintln!("[dev sync] daemon verify OK");
    }

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
    use ed25519_dalek::SigningKey;
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
    fn installed_path_is_under_worktree_dev_install_root() {
        let runtime = crate::dev_runtime::derive_dev_runtime_env(
            Path::new("/home/test-operator"),
            Path::new("/tmp/emberlink-dev/worktree-a"),
        );
        let p = installed_path(&runtime, "ember");
        assert!(
            p.starts_with(&runtime.install_root),
            "installed_path must be under worktree install root: {}",
            p.display()
        );
    }

    #[test]
    fn built_path_is_under_target_release() {
        let workspace = PathBuf::from("/tmp/workspace");
        let p = built_path(&workspace, "ember");
        assert!(
            p.starts_with("/tmp/workspace/target/release"),
            "built_path must be under target/release: {}",
            p.display()
        );
    }

    #[test]
    fn installed_paths_for_different_targets_are_distinct() {
        let runtime = crate::dev_runtime::derive_dev_runtime_env(
            Path::new("/home/test-operator"),
            Path::new("/tmp/emberlink-dev/worktree-a"),
        );
        let p1 = installed_path(&runtime, "ember");
        let p2 = installed_path(&runtime, "ember-gh");
        assert_ne!(
            p1, p2,
            "different targets must have different install paths"
        );
    }

    #[test]
    fn dev_sync_build_packages_include_cli_daemon_and_construct_package() {
        assert_eq!(
            build_packages(),
            vec!["ember-construct", "ember-daemon", "emberlink-cli"]
        );
    }

    #[test]
    fn verify_report_ready_rejects_missing_runtime_truth() {
        let report = verify::DevInstallVerifyReport {
            daemon_pid: None,
            manifest_fingerprint: Some("abc".to_string()),
            registered_broker_count: Some(0),
            trust_roots: Some(vec![]),
            missing_runtime_artifacts: Vec::new(),
        };
        let err = verify_report_ready(&report).expect_err("missing readiness must fail");
        assert!(
            err.to_string().contains("not ready"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_report_ready_accepts_ready_report() {
        let report = verify::DevInstallVerifyReport {
            daemon_pid: Some(42),
            manifest_fingerprint: Some("abc".to_string()),
            registered_broker_count: Some(3),
            trust_roots: Some(vec!["root".to_string()]),
            missing_runtime_artifacts: Vec::new(),
        };
        verify_report_ready(&report).expect("populated report must be ready");
    }

    struct SyncManifestRunner {
        tools: std::collections::HashMap<String, PathBuf>,
    }

    impl SyncManifestRunner {
        fn new(tools: std::collections::HashMap<String, PathBuf>) -> Self {
            Self { tools }
        }
    }

    impl CommandRunner for SyncManifestRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            if program == "which" {
                let tool = args.first().copied().unwrap_or_default();
                return match self.tools.get(tool) {
                    Some(path) => Ok(format!("{}\n", path.display()).into_bytes()),
                    None => Err(format!("which: {tool} not found").into()),
                };
            }
            let tool = self
                .tools
                .keys()
                .find(|candidate| candidate.as_str() == program)
                .ok_or_else(|| format!("{program}: command not found"))?;
            Ok(format!("{tool} version 1.0.0\n").into_bytes())
        }
    }

    #[test]
    fn rewrite_manifest_with_writes_signed_manifest_files() {
        let tmp = scratch();
        let tools_dir = tmp.path().join("tools");
        fs::create_dir_all(&tools_dir).unwrap();
        let gh_path = tools_dir.join("gh");
        let git_path = tools_dir.join("git");
        fs::write(&gh_path, b"gh-binary").unwrap();
        fs::write(&git_path, b"git-binary").unwrap();

        let mut tools = std::collections::HashMap::new();
        tools.insert("gh".to_string(), gh_path.clone());
        tools.insert("git".to_string(), git_path.clone());

        let runner = SyncManifestRunner::new(tools);
        let dest_dir = tmp.path().join("manifest-out");
        let signer = SigningKey::from_bytes(&[7u8; 32]);

        let count = rewrite_manifest_with(&runner, &signer, &dest_dir).expect("rewrite manifest");
        assert_eq!(count, 2, "expected gh + git entries");
        assert!(dest_dir.join("manifest.toml").exists());
        assert!(dest_dir.join("manifest.toml.sig").exists());
        let manifest_text = fs::read_to_string(dest_dir.join("manifest.toml")).unwrap();
        assert!(manifest_text.contains("name = \"gh\""));
        assert!(manifest_text.contains("name = \"git\""));
    }
}
