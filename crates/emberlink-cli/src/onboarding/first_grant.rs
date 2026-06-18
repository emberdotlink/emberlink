//! CLASSIFICATION: PUBLIC
//! First-grant walkthrough — the closing step of `ember init` that converts
//! every install into a witness of the wedge artifact (Grant Receipt).
//!
//! EMBER-INIT-FIRST-GRANT-WALKTHROUGH (v1, tips-only):
//! Prints an educational three-step tutorial pointing the user at daemon
//! startup, grant issuance, and Receipt inspection.
//!
//! EMBER-INIT-FIRST-GRANT-RECEIPT-EMIT (v2, real signed Receipt):
//! Issues a 60-second illustrative grant from the root persona to a fake
//! local agent persona ("first-grant-tutorial"), immediately revokes it,
//! signs the resulting Grant Receipt v2 envelope with the root persona's
//! Ed25519 key via `sign_receipt_v2` (ADR 118 / ADR 133), and writes the
//! signed JSON to `<data_dir>/receipts/first.json`.
//!
//! The checkpoint `init_first_grant_receipt_emit` is embedded as a constant
//! so the autopilot ranker can grep for it as the shipped-state indicator
//! of EMBER-INIT-FIRST-GRANT-RECEIPT-EMIT.
//!
//! Idempotency: presence of `<data_dir>/receipts/first.json` suppresses
//! re-emission on subsequent `ember init` calls — the file-exists check
//! gates the v2 path, and `.first-grant-tips-shown` gates the v1 tips.
//!
//! The receipt is also verifiable offline: `ember receipt verify
//! <data_dir>/receipts/first.json --pubkey <persona_public_key_hex>`.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use core_crypto::Signer;
use ember_daemon::infra::init_first_grant::{BuildError, build_first_grant_receipt_file};
pub use ember_daemon::infra::init_first_grant::{
    FirstGrantEvidence, FirstGrantIssuer, FirstGrantLifecycle, FirstGrantReceiptFile,
};

/// Checkpoint filename. Presence in `<data_dir>` means the tips block has
/// already been shown to this operator on this machine.
pub const TIPS_SHOWN_SENTINEL: &str = ".first-grant-tips-shown";

/// `init_first_grant_walkthrough` — the literal checkpoint string the
/// autopilot ranker greps for to detect the shipped state of
/// EMBER-INIT-FIRST-GRANT-WALKTHROUGH. Embedded as a constant so a code
/// reader sees it explicitly and the `target_state_anchor` value in
/// `tasks.toml` matches against the binary's strings.
pub const INIT_FIRST_GRANT_WALKTHROUGH_SENTINEL: &str = "init_first_grant_walkthrough";

/// `init_first_grant_receipt_emit` — autopilot ranker checkpoint for
/// EMBER-INIT-FIRST-GRANT-RECEIPT-EMIT. Presence in this source file
/// marks the v2 receipt-emit path as shipped.
pub const INIT_FIRST_GRANT_RECEIPT_EMIT_SENTINEL: &str = "init_first_grant_receipt_emit";

/// Filename of the first-grant Receipt written to `<data_dir>/receipts/`.
pub const FIRST_RECEIPT_FILENAME: &str = "receipts/first.json";

/// Errors raised by [`emit_first_grant_receipt`].
#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    #[error("create receipts dir: {0}")]
    CreateDir(#[from] std::io::Error),
    #[error("build receipt: {0}")]
    Build(#[from] BuildError),
    #[error("serialize receipt: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Return the path of the first-grant Receipt file under `data_dir`.
pub fn first_receipt_path(data_dir: &Path) -> PathBuf {
    data_dir.join(FIRST_RECEIPT_FILENAME)
}

/// True when the first-grant Receipt has already been written to disk.
/// Used by [`emit_first_grant_receipt`] to enforce idempotency.
pub fn first_receipt_exists(data_dir: &Path) -> bool {
    first_receipt_path(data_dir).exists()
}

/// Return early when the receipt-emit path should be skipped entirely.
///
/// Used by both the direct signer path and the daemon-built receipt path so
/// they share the same idempotency and CI behavior.
pub fn short_circuit_first_grant_receipt_emit(data_dir: &Path) -> Option<PathBuf> {
    let receipt_path = first_receipt_path(data_dir);

    if std::env::var("EMBER_AUTOMATION").as_deref() == Ok("1") {
        return Some(receipt_path);
    }

    if receipt_path.exists() {
        return Some(receipt_path);
    }

    None
}

/// Persist a pre-built first-grant receipt file to `<data_dir>/receipts/first.json`.
pub fn write_first_grant_receipt_file(
    data_dir: &Path,
    file: &FirstGrantReceiptFile,
) -> Result<PathBuf, EmitError> {
    let receipt_path = first_receipt_path(data_dir);

    if let Some(parent) = receipt_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file_json = serde_json::to_string_pretty(file)?;
    fs::write(&receipt_path, file_json.as_bytes())?;

    Ok(receipt_path)
}

/// Emit a signed Grant Receipt v2 envelope to `<data_dir>/receipts/first.json`.
///
/// Issues a 60-second illustrative grant from `persona_id` to a fake local
/// agent persona (`"first-grant-tutorial"`), immediately revokes it, signs
/// the resulting `ReceiptEnvelope` with `signer` via `sign_receipt_v2`
/// (the ADR 133 single-builder rule), and writes the on-disk
/// `FirstGrantReceiptFile` JSON.
///
/// **Idempotent:** if `first.json` already exists the function returns its
/// path with an `Ok` without re-signing.
///
/// **EMBER_AUTOMATION guard:** when `EMBER_AUTOMATION=1` is set in the
/// environment the function returns `Ok(path)` immediately without writing
/// anything (non-interactive / CI path).
///
/// Returns the written path. Human-facing rendering lives at the CLI layer.
pub fn emit_first_grant_receipt(
    data_dir: &Path,
    persona_id: &str,
    _persona_public_key: &str,
    signer: &dyn Signer,
) -> Result<PathBuf, EmitError> {
    if let Some(receipt_path) = short_circuit_first_grant_receipt_emit(data_dir) {
        return Ok(receipt_path);
    }

    let file = build_first_grant_receipt_file(persona_id, signer)?;
    write_first_grant_receipt_file(data_dir, &file)
}

/// Path to the checkpoint file under the operator's data directory.
pub fn sentinel_path(data_dir: &Path) -> PathBuf {
    data_dir.join(TIPS_SHOWN_SENTINEL)
}

/// True when the checkpoint exists. Caller uses this to decide whether to
/// skip the tips block.
pub fn tips_already_shown(data_dir: &Path) -> bool {
    sentinel_path(data_dir).exists()
}

/// Mark tips as shown by writing the checkpoint file. Best-effort: failure
/// to write the checkpoint does not block init.
pub fn mark_tips_shown(data_dir: &Path) -> io::Result<()> {
    fs::write(sentinel_path(data_dir), b"first-grant-tips-shown\n")
}

/// Print the first-grant tips block to the writer. The block is the
/// closing-step content for `cmd_init` — three steps, one explanatory
/// paragraph, one signpost link.
///
/// `persona_id_short` is a short rendering of the freshly-created root
/// persona id (already printed by `cmd_init` above this block); we don't
/// repeat it. We do reference the data directory so the user knows where
/// receipts will land.
pub fn write_first_grant_tips<W: Write>(out: &mut W, data_dir: &Path) -> io::Result<()> {
    let receipts_dir = data_dir.join("receipts");

    writeln!(out)?;
    writeln!(out, "—— Your first grant ——")?;
    writeln!(out)?;
    writeln!(
        out,
        "Every action an agent takes through ember produces a signed Grant"
    )?;
    writeln!(
        out,
        "Receipt — durable, exportable, verifiable offline by anyone."
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "  1. Ensure the managed daemon is installed and running:"
    )?;
    writeln!(out, "       ember status")?;
    writeln!(
        out,
        "       sudo ember daemon install   # if status says the daemon is missing"
    )?;
    writeln!(out)?;
    writeln!(out, "  2. Issue your first grant (5-minute scope):")?;
    writeln!(out, "       ember grant create --to test-agent \\")?;
    writeln!(out, "         --scope github:repo:read --ttl 5m")?;
    writeln!(out)?;
    writeln!(
        out,
        "  3. When the grant terminates, the daemon writes a Receipt to:"
    )?;
    writeln!(out, "       {}", receipts_dir.display())?;
    writeln!(
        out,
        "     Inspect it: any JSON tool. Verify it: `ember receipt verify <path>`."
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "Why this matters: the Receipt — not the credential boundary — is"
    )?;
    writeln!(
        out,
        "the durable artifact. Anyone you choose can confirm the chain of"
    )?;
    writeln!(
        out,
        "authority outside our infrastructure, with no vendor in the loop."
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "Walkthrough: docs/getting-started.md  ({})",
        INIT_FIRST_GRANT_WALKTHROUGH_SENTINEL
    )?;

    Ok(())
}

/// Convenience entry point: run the tips block against stdout if the
/// checkpoint hasn't already been written, then mark it shown. Idempotent
/// — repeat calls are no-ops on the second and later invocation.
///
/// Checkpoint write is best-effort; failure is logged via `eprintln!` but
/// does not propagate (init has already done the load-bearing work by
/// this point and the tutorial block is purely additive).
pub fn run(data_dir: &Path) {
    if tips_already_shown(data_dir) {
        return;
    }
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    if let Err(e) = write_first_grant_tips(&mut handle, data_dir) {
        eprintln!("warning: first-grant tips block write failed: {e}");
        return;
    }
    if let Err(e) = mark_tips_shown(data_dir) {
        eprintln!(
            "warning: failed to write first-grant tips checkpoint ({}): {e}",
            sentinel_path(data_dir).display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_first_grant_tips_contains_sentinel_and_three_steps() {
        let dir = tempdir().expect("tempdir");
        let mut buf: Vec<u8> = Vec::new();
        write_first_grant_tips(&mut buf, dir.path()).expect("write");
        let s = String::from_utf8(buf).expect("utf8");

        // The target_state_anchor checkpoint — the autopilot ranker uses
        // this to detect shipped state.
        assert!(
            s.contains(INIT_FIRST_GRANT_WALKTHROUGH_SENTINEL),
            "tips block must contain the init_first_grant_walkthrough checkpoint"
        );

        // Three numbered steps + the managed-daemon repair guidance.
        assert!(s.contains("1. Ensure the managed daemon is installed and running"));
        assert!(s.contains("ember status"));
        assert!(s.contains("sudo ember daemon install"));
        assert!(s.contains("2. Issue your first grant"));
        assert!(s.contains("ember grant create"));
        assert!(s.contains("3. When the grant terminates"));

        // Receipts-dir reference points at the data_dir/receipts path.
        let expected = dir.path().join("receipts").display().to_string();
        assert!(
            s.contains(&expected),
            "tips block must reference receipts dir under data_dir, got:\n{s}"
        );

        // Wedge framing — the Receipt-as-durable-artifact line.
        assert!(s.contains("durable artifact"));
        assert!(s.contains("verify offline") || s.contains("outside our infrastructure"));
    }

    #[test]
    fn run_writes_sentinel_then_skips_on_repeat() {
        let dir = tempdir().expect("tempdir");
        // First run — tips printed, checkpoint written.
        assert!(!tips_already_shown(dir.path()));
        run(dir.path());
        assert!(
            tips_already_shown(dir.path()),
            "checkpoint must exist after first run"
        );

        // Second run — short-circuits via tips_already_shown; no-op.
        let before_mtime = fs::metadata(sentinel_path(dir.path()))
            .expect("checkpoint meta")
            .modified()
            .ok();
        run(dir.path());
        let after_mtime = fs::metadata(sentinel_path(dir.path()))
            .expect("checkpoint meta")
            .modified()
            .ok();
        // The checkpoint write is skipped on repeat — mtime should not
        // change. (We only assert "no panic + checkpoint still present"
        // since mtime resolution can race on fast filesystems.)
        let _ = (before_mtime, after_mtime);
        assert!(tips_already_shown(dir.path()));
    }

    #[test]
    fn sentinel_path_lives_under_data_dir() {
        let dir = tempdir().expect("tempdir");
        let p = sentinel_path(dir.path());
        assert!(p.starts_with(dir.path()));
        assert_eq!(p.file_name().unwrap(), TIPS_SHOWN_SENTINEL);
    }
}
