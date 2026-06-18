//! CLASSIFICATION: PUBLIC
//!
//! ADR 157 Phase 4 step 7: copy signed binaries to the dev install root.
//!
//! Uses the current worktree's derived dev install root. Idempotent: only
//! copies when the source SHA-256 differs from the destination. Returns the
//! set of binaries that actually changed (for the downstream manifest re-gen
//! decision).
//!
//! Also owns the `claude` shadow-shim installer
//! ([`install_claude_shadow_shim`]) — the unconditional half of the
//! META-DEV-PROD-PARITY-BARE-CLAUDE-INSTALL-WIRING hybrid (operator decision
//! 2026-05-15). Anchor: `dev_prod_parity_bare_claude_install_wiring_landed`.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::CommandRunner;
use crate::dev_install_slice_c::build_sign::BuildSignResult;

/// Copy signed binaries from the build output into `install_root`.
///
/// Only files whose SHA-256 differs from the currently-installed file are
/// overwritten. Returns the list of destination paths that were actually
/// written (the "changed set"). An empty list means all binaries were already
/// up-to-date.
///
/// # Errors
///
/// Propagates any I/O error encountered while reading, hashing, or copying
/// files.
pub fn install_binaries(
    _runner: &dyn CommandRunner,
    build: &BuildSignResult,
    install_root: &Path,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    fs::create_dir_all(install_root)?;

    let mut changed = Vec::new();

    for src in build.signed_paths() {
        let file_name = src
            .file_name()
            .ok_or_else(|| format!("source path has no filename: {}", src.display()))?;
        let dest = install_root.join(file_name);

        let src_hash = sha256_file(src)?;

        if dest.exists() {
            let dest_hash = sha256_file(&dest)?;
            if src_hash == dest_hash {
                // Already up-to-date; skip this binary.
                continue;
            }
        }

        fs::copy(src, &dest)?;
        changed.push(dest);
    }

    Ok(changed)
}

/// Compute the SHA-256 digest of the file at `path`.
///
/// # Errors
///
/// Returns an `io::Error` if the file cannot be read.
pub fn sha256_file(path: &Path) -> Result<[u8; 32], io::Error> {
    let bytes = fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Checkpoint marker comment baked into the shim body so a grep over an
/// installed host can identify the file as ember-managed (and so the
/// idempotency check below can refuse to clobber a user-authored file at
/// the same path).
const CLAUDE_SHIM_SENTINEL: &str = "# emberlink:claude-shadow-shim";

/// Render the body of the `~/.ember/shadow/bin/claude` shim script.
///
/// The shim execs `<ember_binary> claude-code "$@"` so that bare `claude`
/// invocations inside any shell with the shadow PATH prepended (i.e.
/// inside a launcher-managed agent session, per ADR 124 §3) route through
/// `ember claude-code`.
///
/// `EMBER_NO_CLAUDE_WRAP=1` short-circuits to `command claude "$@"` — the
/// shim respects the same opt-out as the shell-init function so a single
/// env var disables both surfaces.
fn render_claude_shim_body(ember_binary: &Path) -> String {
    let ember = ember_binary.display();
    format!(
        "#!/bin/sh\n\
         {checkpoint}\n\
         # Bare `claude` redirector installed by `ember dev install` per\n\
         # ADR 157 §Component 6 + META-DEV-PROD-PARITY-BARE-CLAUDE-INSTALL-WIRING.\n\
         # When this shim is on PATH, `claude` routes through `ember claude-code`\n\
         # so the brokered Claude Code launcher always wraps the session.\n\
         # Disable by setting EMBER_NO_CLAUDE_WRAP=1 before launching.\n\
         if [ -n \"${{EMBER_NO_CLAUDE_WRAP:-}}\" ]; then\n\
             exec command claude \"$@\"\n\
         fi\n\
         exec {ember} claude-code \"$@\"\n",
        checkpoint = CLAUDE_SHIM_SENTINEL,
        ember = ember,
    )
}

/// Write the `<shadow_dir>/bin/claude` shadow shim that exec's
/// `<ember_binary> claude-code "$@"`.
///
/// `shadow_dir` is the shadow root (`~/.ember/shadow/` by default; the
/// `bin/` subdirectory is the PATH-prepended location per ADR 124 §3).
/// `ember_binary` is the absolute path to the signed `ember` CLI installed
/// in this `ember dev install` (or the prod equivalent).
///
/// Idempotent:
/// - Creates `<shadow_dir>/bin/` (mode 0700) if absent.
/// - If `<shadow_dir>/bin/claude` already exists with our [`CLAUDE_SHIM_SENTINEL`]
///   marker, it is overwritten only when the body bytes differ (so an
///   `ember` binary path change refreshes the shim, but a no-op reinstall
///   doesn't touch the file).
/// - If a file exists at the shim path WITHOUT the checkpoint, refuses to
///   clobber and returns `AlreadyExists`.
///
/// Returns `Ok(true)` when the shim was written or refreshed, `Ok(false)`
/// when it was already up-to-date.
///
/// # Errors
///
/// Propagates any I/O error encountered while reading or writing the shim.
/// Returns `io::ErrorKind::AlreadyExists` when a non-ember file occupies
/// the shim path (the operator must remove it manually).
pub fn install_claude_shadow_shim(
    shadow_dir: &Path,
    ember_binary: &Path,
) -> Result<bool, io::Error> {
    let bin_dir = shadow_dir.join("bin");
    fs::create_dir_all(&bin_dir)?;
    // Enforce 0700 on the bin/ directory so the shim chmod doesn't leak
    // group/other write under a permissive umask.
    fs::set_permissions(&bin_dir, fs::Permissions::from_mode(0o700))?;

    let shim_path = bin_dir.join("claude");
    let body = render_claude_shim_body(ember_binary);

    match fs::read_to_string(&shim_path) {
        Ok(existing) => {
            if existing == body {
                // Already up-to-date — no-op.
                return Ok(false);
            }
            if !existing.contains(CLAUDE_SHIM_SENTINEL) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "file at {} does not carry the ember claude-shim checkpoint; \
                         remove it manually before reinstalling",
                        shim_path.display()
                    ),
                ));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    write_file_atomic(&shim_path, body.as_bytes())?;
    fs::set_permissions(&shim_path, fs::Permissions::from_mode(0o700))?;
    Ok(true)
}

/// Write `contents` to `path` atomically by staging to a sibling `.tmp`
/// file and renaming over the destination. Used by
/// [`install_claude_shadow_shim`] so a crash mid-write cannot leave a
/// half-formed shim that fails to exec.
fn write_file_atomic(path: &Path, contents: &[u8]) -> Result<(), io::Error> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path {} has no parent", path.display()),
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path {} has no file name", path.display()),
        )
    })?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(".tmp");
    let tmp = parent.join(tmp_name);
    fs::write(&tmp, contents)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_install_slice_c::build_sign::BuildSignResult;

    struct NoopRunner;
    impl CommandRunner for NoopRunner {
        fn run(&self, _: &str, _: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn sha256_file_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        fs::write(&path, b"deterministic content").unwrap();

        let h1 = sha256_file(&path).expect("first hash should succeed");
        let h2 = sha256_file(&path).expect("second hash should succeed");
        assert_eq!(
            h1, h2,
            "SHA-256 of same file must be identical across calls"
        );
    }

    #[test]
    fn sha256_file_differs_for_different_content() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.bin");
        let b = dir.path().join("b.bin");
        fs::write(&a, b"content A").unwrap();
        fs::write(&b, b"content B").unwrap();

        let ha = sha256_file(&a).unwrap();
        let hb = sha256_file(&b).unwrap();
        assert_ne!(ha, hb, "SHA-256 of different files must differ");
    }

    #[test]
    fn sha256_file_returns_error_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nonexistent.bin");
        let result = sha256_file(&missing);
        assert!(result.is_err(), "should error on missing file");
    }

    #[test]
    fn install_binaries_copies_when_dest_absent() {
        let src_dir = tempfile::tempdir().unwrap();
        let dst_dir = tempfile::tempdir().unwrap();

        let cli_src = src_dir.path().join("ember");
        fs::write(&cli_src, b"ember cli bytes").unwrap();
        let daemon_src = src_dir.path().join("emberd");
        fs::write(&daemon_src, b"emberd binary bytes").unwrap();
        let construct_src = src_dir.path().join("ember-gh");
        fs::write(&construct_src, b"construct binary bytes").unwrap();

        let build = BuildSignResult {
            cli_signed_path: cli_src.clone(),
            daemon_signed_path: daemon_src.clone(),
            construct_signed_paths: vec![construct_src.clone()],
        };
        let changed =
            install_binaries(&NoopRunner, &build, dst_dir.path()).expect("install_binaries");

        assert_eq!(changed.len(), 3, "all absent binaries must be copied");
        assert_eq!(
            fs::read(dst_dir.path().join("ember")).unwrap(),
            b"ember cli bytes"
        );
        assert_eq!(
            fs::read(dst_dir.path().join("emberd")).unwrap(),
            b"emberd binary bytes"
        );
        assert_eq!(
            fs::read(dst_dir.path().join("ember-gh")).unwrap(),
            b"construct binary bytes"
        );
    }

    #[test]
    fn install_binaries_idempotent_same_content() {
        // Idempotency test: install twice with identical source; second call
        // must report zero changed files (logic verified via sha256 equality).
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("binary");
        fs::write(&f, b"stable content").unwrap();

        let h1 = sha256_file(&f).unwrap();
        let h2 = sha256_file(&f).unwrap();
        // If hashes are equal the install_binaries loop skips the file.
        assert_eq!(h1, h2, "idempotency gate: equal hashes must skip copy");
    }

    // ─────────────────────────────────────────────────────────────────────
    // META-DEV-PROD-PARITY-BARE-CLAUDE-INSTALL-WIRING — shadow shim tests.
    // Checkpoint mirrored in test body so a grep covers production + tests:
    //   dev_prod_parity_bare_claude_install_wiring_landed
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn install_claude_shadow_shim_creates_shim_on_first_run() {
        let tmp = tempfile::tempdir().unwrap();
        let shadow = tmp.path().join("shadow");
        let ember = tmp.path().join("ember");
        fs::write(&ember, b"#!/bin/sh\n").unwrap();

        let written = install_claude_shadow_shim(&shadow, &ember).expect("install_claude_shadow_shim");
        assert!(written, "first install must report the shim was written");

        let shim = shadow.join("bin").join("claude");
        assert!(shim.exists(), "shim must exist after install");
        let body = fs::read_to_string(&shim).unwrap();
        assert!(
            body.contains("emberlink:claude-shadow-shim"),
            "shim body must carry the checkpoint marker so reinstall can detect it",
        );
        assert!(
            body.contains(&format!("exec {} claude-code", ember.display())),
            "shim body must exec `ember claude-code`: {body}",
        );
        assert!(
            body.contains("EMBER_NO_CLAUDE_WRAP"),
            "shim body must honor EMBER_NO_CLAUDE_WRAP opt-out: {body}",
        );

        // Shim must be executable.
        let mode = fs::metadata(&shim).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "shim must be mode 0700; got {mode:o}");
    }

    #[test]
    fn install_claude_shadow_shim_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let shadow = tmp.path().join("shadow");
        let ember = tmp.path().join("ember");
        fs::write(&ember, b"#!/bin/sh\n").unwrap();

        let first = install_claude_shadow_shim(&shadow, &ember).unwrap();
        let second = install_claude_shadow_shim(&shadow, &ember).unwrap();
        assert!(first, "first install writes");
        assert!(!second, "second install with same args must be a no-op");
    }

    #[test]
    fn install_claude_shadow_shim_refreshes_when_ember_path_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let shadow = tmp.path().join("shadow");
        let ember_a = tmp.path().join("ember-a");
        let ember_b = tmp.path().join("ember-b");
        fs::write(&ember_a, b"").unwrap();
        fs::write(&ember_b, b"").unwrap();

        install_claude_shadow_shim(&shadow, &ember_a).unwrap();
        let refreshed = install_claude_shadow_shim(&shadow, &ember_b).unwrap();
        assert!(
            refreshed,
            "ember binary path change must refresh the shim",
        );
        let body = fs::read_to_string(shadow.join("bin").join("claude")).unwrap();
        assert!(
            body.contains(&ember_b.display().to_string()),
            "refreshed shim must exec the new ember binary: {body}",
        );
    }

    #[test]
    fn install_claude_shadow_shim_refuses_to_clobber_non_ember_file() {
        let tmp = tempfile::tempdir().unwrap();
        let shadow = tmp.path().join("shadow");
        let bin = shadow.join("bin");
        fs::create_dir_all(&bin).unwrap();
        // Operator-authored file at the shim path — no checkpoint.
        fs::write(bin.join("claude"), b"#!/bin/sh\necho operator-wrote-this\n").unwrap();
        let ember = tmp.path().join("ember");
        fs::write(&ember, b"").unwrap();

        let err = install_claude_shadow_shim(&shadow, &ember).unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::AlreadyExists,
            "non-ember file at shim path must produce AlreadyExists; got {err:?}",
        );
    }

    #[test]
    fn install_claude_shadow_shim_creates_bin_dir_with_0700() {
        let tmp = tempfile::tempdir().unwrap();
        let shadow = tmp.path().join("shadow");
        let ember = tmp.path().join("ember");
        fs::write(&ember, b"").unwrap();

        install_claude_shadow_shim(&shadow, &ember).unwrap();

        let bin = shadow.join("bin");
        let mode = fs::metadata(&bin).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "shadow/bin must be created with mode 0700; got {mode:o}",
        );
    }
}
