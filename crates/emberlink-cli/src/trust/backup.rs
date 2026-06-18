//! `ember trust backup --to <path>` — encrypted operator authority export.
//!
//! Per ADR 162 §Component 4, reinterpreted by ADR 200's Principal /
//! Persona unification, this compatibility surface reads exportable
//! keychain-held operator-role Durable Persona material plus the
//! optional workstation Durable Persona seed, builds a [`BackupEnvelope`]
//! (CBOR), and seals it with a passphrase supplied by the operator via
//! no-echo TTY prompt. Touch ID confirms the export before the sealed
//! blob hits the disk.
//!
//! Current ADR 200 operator authority is device-rooted. Hosts that no
//! longer have keychain-held operator material cannot use this command
//! as operator-authority recovery evidence; they must prove recovery
//! through enrolled recovery recipients / backup presence devices.
//!
//! The sealed-blob substrate lives in
//! `core-crypto::backup_envelope` — this module is the operator UX
//! layer (Keychain reads, passphrase prompt, biometric gate, file
//! write with mode 600, daemon `trust.backup_created` Receipt
//! emission).
//!
//! ## Threat model
//!
//! - The sealed blob on disk is encrypted with XChaCha20-Poly1305 +
//!   Argon2id over the operator-chosen passphrase. Anyone who holds
//!   the blob but not the passphrase cannot recover the exported seeds.
//! - The blob's metadata (created_at / hostname / daemon_mode /
//!   operator pubkey) is not separately signed — the AEAD covers it
//!   inside the envelope, so tampering changes the ciphertext.
//! - The path the operator writes to is rendered into the
//!   `trust.backup_created` Receipt as a SHA-256 path hash, never as
//!   the raw path bytes. Backup files are operator-managed artifacts
//!   and we don't want their on-disk locations leaking into the
//!   append-only audit log.
//!
//! Anchor: trust_backup_restore_landed.

use std::io::{IsTerminal as _, Write};
use std::path::{Path, PathBuf};

use core_crypto::backup_envelope::{
    BackupEnvelope, BackupError, BackupMetadata, MIN_PASSPHRASE_LEN, seal_backup,
};
use ed25519_dalek::SigningKey;

use crate::biometric::{BiometricError, BiometricOutcome, require_biometric};
use crate::trust::principal_keychain;

pub use crate::trust::principal_keychain::{
    KEYCHAIN_SERVICE, OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL as OPERATOR_IR_KEYCHAIN_LABEL,
    WORKSTATION_PERSONA_KEYCHAIN_LABEL as DEV_IR_KEYCHAIN_LABEL,
};

// trust_backup_restore_landed — checkpoint anchoring this PR (META-TRUST-BACKUP-RESTORE).
// Used by the failing-test grep `grep -c trust_backup_restore_landed ...` in the brief.

// Compatibility aliases for the backup/restore V1 envelope vocabulary.
// The encrypted envelope still calls the two optional slots
// `operator_ir_seed` and `dev_ir_seed`; the live keychain labels are
// the ADR 200 target-state Durable Persona labels. Legacy
// `*-identity-root` labels remain import/fallback sources inside
// `principal_keychain`, not new write targets.

/// Errors surfaced by `ember trust backup`.
#[derive(Debug, thiserror::Error)]
pub enum TrustBackupError {
    /// Could not read the required operator-role signing seed from
    /// the Keychain. Workstation persona seed is optional.
    #[error("operator signing Principal not found in Keychain: {0}")]
    MissingOperatorPrincipal(String),
    /// Keychain access errored for a reason other than "not found".
    #[error("Keychain error: {0}")]
    Keychain(String),
    /// The TTY passphrase prompt could not be opened (e.g. stdin is
    /// not a terminal and no `--passphrase-fd` substitute was given).
    #[error("passphrase prompt failed: {0}")]
    Prompt(String),
    /// The two passphrase entries did not match. Caught at the prompt
    /// layer so the operator gets a re-prompt without ever sending
    /// the wrong value to the sealing primitive.
    #[error("passphrase entries do not match")]
    PassphraseMismatch,
    /// Substrate-level seal error (e.g. passphrase too weak).
    #[error("backup seal failed: {0}")]
    Seal(#[from] BackupError),
    /// Touch ID prompt cancelled or unavailable.
    #[error("biometric refused: {0}")]
    Biometric(String),
    /// File I/O failure (path inaccessible, mode-600 set fails,
    /// etc.).
    #[error("I/O error: {0}")]
    Io(String),
    /// The output path exists and `--force` was not given. Refuse to
    /// clobber an existing backup file by default.
    #[error("output path already exists: {0} (pass --force to overwrite)")]
    OutputExists(PathBuf),
}

/// Read the operator-role Durable Persona seed from the macOS
/// Keychain. The principal-keychain accessor owns the target-label
/// lookup and legacy `operator-identity-root` fallback.
fn read_operator_backup_seed() -> Result<[u8; 32], TrustBackupError> {
    match principal_keychain::read_operator_role_persona_seed().map_err(|e| {
        TrustBackupError::Keychain(format!("read operator-role Durable Persona seed: {e}"))
    })? {
        Some(seed) => Ok(seed),
        None => Err(TrustBackupError::MissingOperatorPrincipal(format!(
            "no exportable Keychain entry at {} or legacy {}. Current ADR 200 \
             operator authority is device-rooted; `trust backup` can only export \
             legacy/transitional keychain-held authority. Use `ember device list` \
             and the backup-presence-device surface for operator-authority \
             recovery evidence; recovery-code recipients cover decryption \
             recovery, not signing authority.",
            principal_keychain::OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL,
            principal_keychain::LEGACY_OPERATOR_IR_KEYCHAIN_LABEL
        ))),
    }
}

/// Read the workstation Durable Persona seed from the macOS Keychain.
/// Returns `None` when neither the target label nor legacy dev-IR
/// import label exists — the backup envelope tolerates an empty
/// `dev_ir_seed` for compatibility with V1 backups.
fn read_workstation_backup_seed() -> Result<Option<[u8; 32]>, TrustBackupError> {
    principal_keychain::read_workstation_persona_seed().map_err(|e| {
        TrustBackupError::Keychain(format!("read workstation Durable Persona seed: {e}"))
    })
}

/// Prompt the operator for a passphrase on the TTY with no-echo +
/// confirmation. Returns the validated passphrase string on success.
///
/// Enforces [`MIN_PASSPHRASE_LEN`] up front so the operator gets a
/// re-prompt rather than discovering the floor inside the substrate.
fn prompt_passphrase_with_confirmation() -> Result<String, TrustBackupError> {
    if !std::io::stdin().is_terminal() {
        return Err(TrustBackupError::Prompt(
            "stdin is not a terminal — pipe the passphrase via \
             --passphrase-fd or run interactively"
                .to_string(),
        ));
    }
    let prompt_a = format!("Enter backup passphrase (min {MIN_PASSPHRASE_LEN} chars): ");
    let pass_a = rpassword::prompt_password(&prompt_a)
        .map_err(|e| TrustBackupError::Prompt(format!("first prompt: {e}")))?;
    if pass_a.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(TrustBackupError::Seal(BackupError::PassphraseTooWeak {
            min: MIN_PASSPHRASE_LEN,
            got: pass_a.chars().count(),
        }));
    }
    let pass_b = rpassword::prompt_password("Confirm passphrase: ")
        .map_err(|e| TrustBackupError::Prompt(format!("confirm prompt: {e}")))?;
    if pass_a != pass_b {
        return Err(TrustBackupError::PassphraseMismatch);
    }
    Ok(pass_a)
}

/// Build the [`BackupEnvelope`] from the seeds read from Keychain +
/// runtime metadata (timestamp, hostname, daemon posture). Pure —
/// kept separate from the I/O paths so tests can exercise the
/// envelope-construction logic with synthetic inputs.
pub fn build_envelope(
    operator_seed: [u8; 32],
    dev_seed: Option<[u8; 32]>,
    daemon_mode: &str,
    hostname: &str,
    created_at_rfc3339: String,
) -> BackupEnvelope {
    let operator_pubkey_hex = pubkey_hex_from_seed(&operator_seed);
    BackupEnvelope {
        operator_ir_seed: operator_seed.to_vec(),
        dev_ir_seed: dev_seed.map(|s| s.to_vec()).unwrap_or_default(),
        metadata: BackupMetadata {
            created_at: created_at_rfc3339,
            daemon_mode: daemon_mode.to_string(),
            hostname: hostname.to_string(),
            operator_pubkey_hex,
        },
    }
}

fn pubkey_hex_from_seed(seed: &[u8; 32]) -> String {
    let signing = SigningKey::from_bytes(seed);
    hex::encode(signing.verifying_key().to_bytes())
}

/// Compute the SHA-256 hash of a backup output path (rendered as
/// UTF-8 bytes). Used both for the audit Receipt's `path_hash` field
/// (so the raw path never lands in the audit log) and for the
/// `trust.restore` Receipt at the other end of the lifecycle.
pub fn path_hash_hex(path: &Path) -> String {
    let bytes = path.to_string_lossy().as_bytes().to_vec();
    core_crypto::sha256_digest_hex(&bytes)
}

/// Result returned by [`run_backup`] when the seal completes. The
/// outer CLI layer turns it into stdout text + the
/// `trust.backup_created` daemon RPC.
#[derive(Debug, Clone)]
pub struct BackupOutcome {
    /// Absolute path the sealed blob was written to.
    pub written_to: PathBuf,
    /// SHA-256 hex digest of the output path (rendered into the
    /// Receipt instead of the raw path).
    pub path_hash_hex: String,
    /// Number of bytes written. Useful for "did this actually
    /// happen?" sanity-checks at the operator end.
    pub bytes_written: usize,
    /// Whether the workstation Durable Persona was included alongside
    /// the operator-role Durable Persona.
    pub included_dev_ir: bool,
    /// Whether the Touch ID prompt fired (false = skipped via test
    /// gate or `--no-biometric`).
    pub biometric_verified: bool,
}

/// End-to-end `ember trust backup --to <path>` flow. Wired by the
/// `Backup` arm of `TrustAction` in `bin/ember.rs`.
///
/// Side-effects:
/// 1. Reads operator-role + (optional) workstation Durable Persona seeds from Keychain.
/// 2. Prompts the operator for a passphrase (≥ [`MIN_PASSPHRASE_LEN`]
///    chars) with confirmation.
/// 3. Asks for biometric confirmation (Touch ID on macOS, no-op on
///    other platforms or with `--no-biometric`).
/// 4. Seals the envelope via `core-crypto::backup_envelope::seal_backup`.
/// 5. Writes the sealed bytes to `to` with mode 600.
///
/// Caller is responsible for the daemon-side `trust.backup_created`
/// Receipt emission (so the substrate stays testable without a live
/// daemon socket).
pub fn run_backup(
    to: &Path,
    force: bool,
    no_biometric: bool,
    daemon_mode: &str,
    hostname: &str,
) -> Result<BackupOutcome, TrustBackupError> {
    // 1. Refuse to clobber an existing file unless --force.
    if to.exists() && !force {
        return Err(TrustBackupError::OutputExists(to.to_path_buf()));
    }

    // 2. Read seeds.
    let operator_seed = read_operator_backup_seed()?;
    let dev_seed = read_workstation_backup_seed()?;
    let included_dev_ir = dev_seed.is_some();

    // 3. Passphrase prompt with confirmation.
    let passphrase = prompt_passphrase_with_confirmation()?;

    // 4. Biometric (Touch ID) gate.
    let biometric_outcome = require_biometric(
        "Authorize export of operator-role + workstation Principal keys to backup file",
        no_biometric,
    )
    .map_err(|e: BiometricError| TrustBackupError::Biometric(e.to_string()))?;
    let biometric_verified = matches!(biometric_outcome, BiometricOutcome::Verified { .. });

    // 5. Build + seal the envelope.
    let created_at = chrono::Utc::now().to_rfc3339();
    let envelope = build_envelope(operator_seed, dev_seed, daemon_mode, hostname, created_at);
    let blob = seal_backup(&envelope, &passphrase)?;

    // 6. Write with mode 600. Use OpenOptions on unix to enforce the
    //    permissions atomically with the create.
    write_backup_file(to, &blob)?;

    Ok(BackupOutcome {
        written_to: to.to_path_buf(),
        path_hash_hex: path_hash_hex(to),
        bytes_written: blob.len(),
        included_dev_ir,
        biometric_verified,
    })
}

#[cfg(unix)]
fn write_backup_file(path: &Path, bytes: &[u8]) -> Result<(), TrustBackupError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| TrustBackupError::Io(format!("open {}: {e}", path.display())))?;
    f.write_all(bytes)
        .map_err(|e| TrustBackupError::Io(format!("write {}: {e}", path.display())))?;
    f.sync_all()
        .map_err(|e| TrustBackupError::Io(format!("fsync {}: {e}", path.display())))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_backup_file(path: &Path, bytes: &[u8]) -> Result<(), TrustBackupError> {
    // Non-unix fallback: write without explicit mode (host ACLs
    // apply). Operator backups on Windows live alongside their other
    // sensitive artifacts; we don't try to invent a security story
    // for that surface here.
    std::fs::write(path, bytes)
        .map_err(|e| TrustBackupError::Io(format!("write {}: {e}", path.display())))
}

/// Format the outcome as operator-facing stdout. Mirrors the
/// `trust list` / `trust show` rendering convention (key: value
/// block) so all three surfaces read consistently.
pub fn render_outcome(outcome: &BackupOutcome) -> String {
    format!(
        "Trust backup written:\n  Path:                         {}\n  Path hash (sha256):           {}\n  Bytes:                        {}\n  Includes workstation Persona: {}\n  Biometric verified:           {}\n",
        outcome.written_to.display(),
        outcome.path_hash_hex,
        outcome.bytes_written,
        outcome.included_dev_ir,
        outcome.biometric_verified,
    )
}

/// Entry point for the `ember trust backup` subcommand. Calls
/// [`run_backup`] and prints the rendered outcome to stdout.
///
/// Daemon-side Receipt emission (`trust.backup_created` with the
/// path hash + presence proof) is the orchestrator's responsibility
/// — this entry point returns a non-zero exit code only on local
/// failure (Keychain read, passphrase, file write, seal error).
pub fn run(to: &Path, force: bool, no_biometric: bool, daemon_mode: &str, hostname: &str) -> i32 {
    match run_backup(to, force, no_biometric, daemon_mode, hostname) {
        Ok(outcome) => {
            print!("{}", render_outcome(&outcome));
            0
        }
        Err(err) => {
            eprintln!("ember trust backup: {err}");
            match err {
                TrustBackupError::OutputExists(_) | TrustBackupError::PassphraseMismatch => 1,
                _ => 2,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::principal_keychain::{
        KEYCHAIN_TEST_LOCK, LEGACY_DEV_IR_KEYCHAIN_LABEL, LEGACY_OPERATOR_IR_KEYCHAIN_LABEL,
        OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL, WORKSTATION_PERSONA_KEYCHAIN_LABEL, write_seed,
    };
    use keyring_core::mock;
    use std::fs;
    use tempfile::TempDir;

    fn install_mock_store() {
        keyring_core::set_default_store(mock::Store::new().expect("mock store"));
    }

    fn clear_backup_seed_labels() {
        for label in [
            OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL,
            WORKSTATION_PERSONA_KEYCHAIN_LABEL,
            LEGACY_OPERATOR_IR_KEYCHAIN_LABEL,
            LEGACY_DEV_IR_KEYCHAIN_LABEL,
        ] {
            if let Ok(entry) = keyring_core::Entry::new(KEYCHAIN_SERVICE, label) {
                let _ = entry.delete_credential();
            }
        }
    }

    #[test]
    fn backup_seed_readers_accept_target_principal_labels() {
        let _guard = KEYCHAIN_TEST_LOCK.lock().unwrap();
        install_mock_store();
        clear_backup_seed_labels();

        write_seed(OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL, &[0x44; 32]).expect("operator-role seed");
        write_seed(WORKSTATION_PERSONA_KEYCHAIN_LABEL, &[0x55; 32]).expect("workstation seed");

        assert_eq!(read_operator_backup_seed().unwrap(), [0x44; 32]);
        assert_eq!(read_workstation_backup_seed().unwrap(), Some([0x55; 32]));
    }

    /// `build_envelope` produces a CBOR-shaped envelope whose
    /// metadata reflects the inputs, and whose public-key field
    /// matches what `ed25519-dalek` derives from the seed.
    #[test]
    fn build_envelope_populates_metadata_and_pubkey() {
        let operator_seed = [0x11u8; 32];
        let dev_seed = Some([0x22u8; 32]);
        let env = build_envelope(
            operator_seed,
            dev_seed,
            "prod",
            "test-host.local",
            "2026-05-21T12:00:00Z".to_string(),
        );
        assert_eq!(env.operator_ir_seed, operator_seed.to_vec());
        assert_eq!(env.dev_ir_seed, [0x22u8; 32].to_vec());
        assert_eq!(env.metadata.hostname, "test-host.local");
        assert_eq!(env.metadata.daemon_mode, "prod");

        // operator_pubkey_hex matches direct ed25519-dalek derivation.
        let expected_pub = SigningKey::from_bytes(&operator_seed)
            .verifying_key()
            .to_bytes();
        assert_eq!(env.metadata.operator_pubkey_hex, hex::encode(expected_pub));
    }

    /// dev_ir_seed defaults to empty when the optional seed is None.
    #[test]
    fn build_envelope_with_no_dev_ir_leaves_seed_empty() {
        let env = build_envelope(
            [0x33u8; 32],
            None,
            "dev",
            "host",
            "2026-05-21T00:00:00Z".to_string(),
        );
        assert!(env.dev_ir_seed.is_empty());
    }

    /// `path_hash_hex` produces a stable, 64-char hex digest for a
    /// given path. The raw path bytes never appear in the digest.
    #[test]
    fn path_hash_is_deterministic_and_64_hex_chars() {
        let h1 = path_hash_hex(Path::new("/tmp/backup.embk"));
        let h2 = path_hash_hex(Path::new("/tmp/backup.embk"));
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
        // Different paths → different hashes (collision-resistance
        // test on a trivial perturbation).
        let h3 = path_hash_hex(Path::new("/tmp/backup-other.embk"));
        assert_ne!(h1, h3);
    }

    /// Render block contains the canonical key/value layout. Smoke
    /// test that operator-facing output keeps the human shape.
    #[test]
    fn render_outcome_contains_expected_fields() {
        let outcome = BackupOutcome {
            written_to: PathBuf::from("/tmp/test.embk"),
            path_hash_hex: "ab".repeat(32),
            bytes_written: 4096,
            included_dev_ir: true,
            biometric_verified: false,
        };
        let s = render_outcome(&outcome);
        assert!(s.contains("Trust backup written:"));
        assert!(s.contains("Path:"));
        assert!(s.contains("Path hash (sha256):"));
        assert!(s.contains("Bytes:"));
        assert!(s.contains("Includes workstation Persona: true"));
        assert!(s.contains("Biometric verified:           false"));
        assert!(s.contains(&"ab".repeat(32)));
    }

    /// `write_backup_file` writes the exact bytes given and (on unix)
    /// produces a mode-600 file. The test checks the byte content
    /// directly and asserts the file exists.
    #[test]
    fn write_backup_file_round_trips_bytes() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("backup.embk");
        let payload = b"ember-backup-test-blob".to_vec();
        write_backup_file(&path, &payload).expect("write must succeed");
        let read = fs::read(&path).unwrap();
        assert_eq!(read, payload);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let meta = fs::metadata(&path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "backup file must be mode 600");
        }
    }

    /// T3 manual procedure: cross-machine restore. Marked `#[ignore]`
    /// so it doesn't run in `cargo test`; the body documents the
    /// operator-driven steps.
    #[test]
    #[ignore = "T3 manual: cross-machine restore — see test body for the run book"]
    fn cross_machine_restore_runbook() {
        // 1. On machine A (source):
        //      ember trust backup --to /tmp/ember-ir-backup.embk
        //    Enter a passphrase (>= 16 chars). Touch ID confirms.
        //
        // 2. Transfer /tmp/ember-ir-backup.embk to machine B
        //    (e.g. via airdrop or USB stick) — the substrate does
        //    NOT enforce a hostname check, so machine B can be a
        //    different workstation.
        //
        // 3. On machine B (target):
        //      ember trust restore --from /tmp/ember-ir-backup.embk
        //    Enter the same passphrase from step 1. The CLI shows
        //    "Restore operator authority from backup created on
        //    <hostname-A> on <created_at>. Proceed?" and fires Touch
        //    ID. If Machine B already has target-state Keychain
        //    entries, an extra confirmation prompt asks before
        //    overwrite.
        //
        // 4. After restore, verify with:
        //      ember trust list
        //    The trust roots derived from the restored Persona seeds should
        //    appear in the daemon's snapshot.
        //
        // 5. The daemon emits a `trust.restore` Receipt on machine B
        //    with the backup-file fingerprint (sha256 path hash) +
        //    presence_proof from the Touch ID step.
    }
}
