//! CLASSIFICATION: PUBLIC
//!
//! Shell-init wrap for bare `claude` invocations — the opt-in half of
//! the META-DEV-PROD-PARITY-BARE-CLAUDE-INSTALL-WIRING hybrid (operator
//! decision 2026-05-15, ADR 157 §Component 6 follow-up).
//!
//! The unconditional half is the `~/.ember/shadow/bin/claude` shim
//! installed by [`crate::dev_install_slice_c::install_binaries::install_claude_shadow_shim`].
//! That covers bare-`claude` invocations from inside any
//! launcher-managed agent shell — the shadow PATH is already prepended,
//! so the shim wins over the system `claude` binary.
//!
//! Operators inside a plain login shell (NOT launched via `ember
//! claude-code`) bypass that PATH-shadow because `~/.ember/shadow/bin`
//! is not on PATH. The opt-in wrap installed here closes that gap by
//! adding a shell function to `~/.zshrc` / `~/.bashrc` that
//! transparently routes bare `claude` through `ember claude-code`.
//!
//! The wrap is checkpoint-fenced
//! (`# emberlink:claude-wrap-begin` / `# emberlink:claude-wrap-end`)
//! and idempotent — reruns of `ember install` detect the existing block
//! and skip the append rather than duplicating it. The function honors
//! the `EMBER_NO_CLAUDE_WRAP=1` opt-out so an operator can disable the
//! wrap session-locally without editing their rc file.
//!
//! Anchor: `dev_prod_parity_bare_claude_install_wiring_landed`

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Marker line that opens the ember-managed claude-wrap block. Used by
/// [`block_present`] and [`append_block`] for idempotency.
pub const SENTINEL_BEGIN: &str = "# emberlink:claude-wrap-begin";
/// Marker line that closes the ember-managed claude-wrap block.
pub const SENTINEL_END: &str = "# emberlink:claude-wrap-end";

/// Outcome of [`install_claude_wrap_block`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallOutcome {
    /// Checkpoint-fenced block was already present; file untouched.
    AlreadyPresent,
    /// Block was appended to the file.
    Appended,
    /// File did not exist; created with the block as initial content.
    Created,
}

/// Render the shell function block. The body is identical regardless of
/// target rc file — the same function works in both zsh and bash because
/// it only uses POSIX-portable syntax (`command claude`, `$@`, `if ...
/// then ... else ... fi`).
///
/// The block is delimited by [`SENTINEL_BEGIN`] / [`SENTINEL_END`] so a
/// rerun can detect and skip the append.
pub fn render_wrap_block() -> String {
    format!(
        "{begin}\n\
         # Added by `ember install` — see ADR 157 §Component 6\n\
         # and META-DEV-PROD-PARITY-BARE-CLAUDE-INSTALL-WIRING.\n\
         # Bare `claude` invocations route through `ember claude-code` so the\n\
         # brokered Claude Code launcher always wraps the session.\n\
         # Disable by setting EMBER_NO_CLAUDE_WRAP=1 in your shell before\n\
         # launching Claude Code.\n\
         claude() {{\n\
         \x20\x20if [ -n \"${{EMBER_NO_CLAUDE_WRAP:-}}\" ]; then\n\
         \x20\x20\x20\x20command claude \"$@\"\n\
         \x20\x20else\n\
         \x20\x20\x20\x20ember claude-code \"$@\"\n\
         \x20\x20fi\n\
         }}\n\
         {end}\n",
        begin = SENTINEL_BEGIN,
        end = SENTINEL_END,
    )
}

/// Return `true` if the file at `path` already contains a checkpoint-fenced
/// claude-wrap block. Used by [`install_claude_wrap_block`] for
/// idempotency.
///
/// Detects only the begin checkpoint — if a partial / corrupted block
/// exists (begin without end, or vice versa), the caller is expected to
/// surface the situation rather than silently re-append. We don't try to
/// repair: an operator who edited the block manually deserves a chance
/// to inspect the state before the wizard mutates it.
pub fn block_present(path: &Path) -> Result<bool, io::Error> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(contents.contains(SENTINEL_BEGIN)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Resolve the standard rc-file targets for the operator (the files
/// commonly sourced by login shells on macOS and Linux).
///
/// Returns the set of (target, exists-or-should-be-created) pairs that
/// [`install_claude_wrap_block`] should write to. We always target
/// `~/.zshrc` and `~/.bashrc` because the operator may switch shells; if
/// neither file exists yet, the wizard creates the one matching `$SHELL`
/// only, so we don't pollute the home dir with empty rc files.
pub fn default_rc_targets(home: &Path) -> Vec<PathBuf> {
    vec![home.join(".zshrc"), home.join(".bashrc")]
}

/// Append the claude-wrap block to `path` if it isn't already present.
///
/// Atomic: writes to a sibling `.tmp` file then renames over the
/// destination. Preserves the file's existing permissions (so we don't
/// accidentally relax mode bits on the operator's rc file). When the
/// file doesn't exist, it is created with mode 0644 (the conventional
/// rc-file mode).
///
/// # Errors
///
/// Propagates I/O errors. Returns `Ok(InstallOutcome::AlreadyPresent)`
/// when the block was already there.
pub fn install_claude_wrap_block(path: &Path) -> Result<InstallOutcome, io::Error> {
    if block_present(path)? {
        return Ok(InstallOutcome::AlreadyPresent);
    }

    let block = render_wrap_block();
    match fs::read_to_string(path) {
        Ok(existing) => {
            let mut new_contents = existing;
            // Make sure there's a clean newline separating the prior
            // content from our block — common in hand-edited rc files
            // missing the trailing newline.
            if !new_contents.is_empty() && !new_contents.ends_with('\n') {
                new_contents.push('\n');
            }
            new_contents.push('\n');
            new_contents.push_str(&block);
            // Preserve the existing file mode.
            let original_mode = fs::metadata(path)?.permissions().mode() & 0o777;
            write_file_atomic(path, new_contents.as_bytes(), Some(original_mode))?;
            Ok(InstallOutcome::Appended)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            write_file_atomic(path, block.as_bytes(), Some(0o644))?;
            Ok(InstallOutcome::Created)
        }
        Err(e) => Err(e),
    }
}

/// Install the wrap block into all `targets`, returning the per-target
/// outcome. A failure on one target does not abort the others — the
/// caller can decide how to surface partial success to the operator.
pub fn install_claude_wrap_blocks(
    targets: &[PathBuf],
) -> Vec<(PathBuf, Result<InstallOutcome, io::Error>)> {
    targets
        .iter()
        .map(|p| {
            let outcome = install_claude_wrap_block(p);
            (p.clone(), outcome)
        })
        .collect()
}

/// Write `contents` to `path` atomically by staging to a sibling
/// `.<name>.tmp` file then renaming over the destination. If
/// `mode_bits` is `Some`, applies it to the destination after rename.
fn write_file_atomic(
    path: &Path,
    contents: &[u8],
    mode_bits: Option<u32>,
) -> Result<(), io::Error> {
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
    if let Some(mode) = mode_bits {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Checkpoint mirrored in test body so a grep over the test corpus
    // also lights up:
    //   dev_prod_parity_bare_claude_install_wiring_landed

    #[test]
    fn render_wrap_block_carries_sentinels_and_function() {
        let body = render_wrap_block();
        assert!(body.contains(SENTINEL_BEGIN));
        assert!(body.contains(SENTINEL_END));
        assert!(body.contains("claude()"));
        assert!(body.contains("ember claude-code"));
        assert!(
            body.contains("EMBER_NO_CLAUDE_WRAP"),
            "wrap function must honor the env opt-out: {body}",
        );
    }

    #[test]
    fn install_creates_file_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join(".zshrc");
        let outcome = install_claude_wrap_block(&rc).unwrap();
        assert_eq!(outcome, InstallOutcome::Created);
        let body = fs::read_to_string(&rc).unwrap();
        assert!(body.contains(SENTINEL_BEGIN));
        assert!(body.contains(SENTINEL_END));
        let mode = fs::metadata(&rc).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "created rc file must be mode 0644; got {mode:o}");
    }

    #[test]
    fn install_appends_to_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join(".bashrc");
        let prior = "# user content\nexport FOO=bar\n";
        fs::write(&rc, prior).unwrap();

        let outcome = install_claude_wrap_block(&rc).unwrap();
        assert_eq!(outcome, InstallOutcome::Appended);

        let body = fs::read_to_string(&rc).unwrap();
        assert!(
            body.starts_with(prior),
            "prior content must be preserved verbatim: {body}",
        );
        assert!(body.contains(SENTINEL_BEGIN));
        assert!(body.contains(SENTINEL_END));
    }

    #[test]
    fn install_is_idempotent_via_sentinel_fence() {
        // Checkpoint-fence-based idempotency: rerun must NOT duplicate the
        // function block.
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join(".zshrc");

        let first = install_claude_wrap_block(&rc).unwrap();
        let second = install_claude_wrap_block(&rc).unwrap();
        assert_eq!(first, InstallOutcome::Created);
        assert_eq!(second, InstallOutcome::AlreadyPresent);

        let body = fs::read_to_string(&rc).unwrap();
        let begin_count = body.matches(SENTINEL_BEGIN).count();
        let end_count = body.matches(SENTINEL_END).count();
        assert_eq!(begin_count, 1, "begin checkpoint must appear exactly once: {body}");
        assert_eq!(end_count, 1, "end checkpoint must appear exactly once: {body}");
    }

    #[test]
    fn install_preserves_existing_mode_bits() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join(".zshrc");
        fs::write(&rc, "# existing\n").unwrap();
        fs::set_permissions(&rc, fs::Permissions::from_mode(0o600)).unwrap();

        install_claude_wrap_block(&rc).unwrap();
        let mode = fs::metadata(&rc).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "append must preserve the existing rc file mode; got {mode:o}",
        );
    }

    #[test]
    fn block_present_detects_partial_blocks() {
        // A file with the begin marker but no end marker still counts as
        // "present" (the caller surfaces this to the operator rather
        // than re-appending).
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join(".zshrc");
        fs::write(&rc, format!("# leading\n{SENTINEL_BEGIN}\n# truncated\n")).unwrap();
        assert!(block_present(&rc).unwrap());
    }

    #[test]
    fn default_rc_targets_returns_zshrc_and_bashrc() {
        let home = PathBuf::from("/home/me");
        let targets = default_rc_targets(&home);
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&PathBuf::from("/home/me/.zshrc")));
        assert!(targets.contains(&PathBuf::from("/home/me/.bashrc")));
    }

    #[test]
    fn install_claude_wrap_blocks_writes_to_all_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join(".zshrc");
        let b = tmp.path().join(".bashrc");
        let results = install_claude_wrap_blocks(&[a.clone(), b.clone()]);
        assert_eq!(results.len(), 2);
        for (path, outcome) in &results {
            let outcome = outcome.as_ref().expect("install must succeed");
            assert_eq!(
                *outcome,
                InstallOutcome::Created,
                "{} should be created on fresh tempdir",
                path.display(),
            );
        }
    }

    #[test]
    fn install_block_inserts_clean_separator_when_prior_lacks_newline() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join(".bashrc");
        fs::write(&rc, "no_trailing_newline").unwrap();
        install_claude_wrap_block(&rc).unwrap();
        let body = fs::read_to_string(&rc).unwrap();
        // Checkpoint begins on its own line (preceded by a blank-line gap).
        assert!(
            body.contains(&format!("\n\n{SENTINEL_BEGIN}")),
            "wrap block must be separated from prior content by a blank line: {body}",
        );
    }
}
