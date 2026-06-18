//! `ember trust restore --from <path>` — decrypt + write back exportable
//! keychain-held operator/workstation Durable Persona seeds from a
//! backup file produced by `ember trust backup`.
//!
//! Per ADR 162 §Component 4 and META-TRUST-BACKUP-RESTORE.
//!
//! ## Flow
//!
//! 1. Read the sealed-backup file at `--from`.
//! 2. Prompt the operator for the passphrase via no-echo TTY.
//! 3. Decrypt + parse the envelope via
//!    `core-crypto::backup_envelope::open_backup`.
//! 4. Render the embedded metadata (hostname + created_at + daemon
//!    mode + operator pubkey) so the operator sees context before
//!    biometric.
//! 5. Touch ID confirmation: "Restore operator authority from backup
//!    created on `<hostname>` on `<date>`. Proceed?"
//! 6. If Keychain already holds an operator-role or workstation
//!    Durable Persona entry, ask a second confirmation before overwrite.
//! 7. Write the seeds to Keychain at the ADR 200 target-state labels.
//! 8. Caller emits the daemon-side `trust.restore` Receipt.
//!
//! ## Portability
//!
//! Cross-workstation restore is PERMITTED — the hostname in the
//! metadata is rendered for operator context but never blocks the
//! flow. Operator confirmed 2026-05-15 (portable mode).
//!
//! Checkpoint covered by `backup.rs` (`trust_backup_restore_landed`).

use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use core_crypto::backup_envelope::{BackupEnvelope, BackupError, open_backup};

use crate::biometric::{BiometricError, BiometricOutcome, require_biometric};
use crate::trust::backup::{
    DEV_IR_KEYCHAIN_LABEL, KEYCHAIN_SERVICE, OPERATOR_IR_KEYCHAIN_LABEL, path_hash_hex,
};

/// Errors surfaced by `ember trust restore`.
#[derive(Debug, thiserror::Error)]
pub enum TrustRestoreError {
    /// The `--from` file could not be read.
    #[error("read backup file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// TTY passphrase prompt could not be opened.
    #[error("passphrase prompt failed: {0}")]
    Prompt(String),
    /// `open_backup` rejected the blob (bad magic, wrong passphrase,
    /// tampered ciphertext, etc.).
    #[error("backup open failed: {0}")]
    Open(#[from] BackupError),
    /// Touch ID prompt cancelled or unavailable.
    #[error("biometric refused: {0}")]
    Biometric(String),
    /// Operator declined the overwrite-existing-Keychain prompt.
    #[error("operator declined to overwrite existing Keychain entries")]
    OperatorDeclinedOverwrite,
    /// Keychain write errored.
    #[error("Keychain error: {0}")]
    Keychain(String),
    /// Operator declined the "Proceed?" Touch ID question.
    #[error("operator cancelled restore at confirmation prompt")]
    OperatorCancelled,
}

/// Outcome of the restore flow, returned to the CLI entry point so
/// the daemon-side `trust.restore` Receipt has structured fields to
/// populate.
#[derive(Debug, Clone)]
pub struct RestoreOutcome {
    /// Path the backup was read from.
    pub read_from: PathBuf,
    /// SHA-256 hex digest of the backup-file path (same algorithm as
    /// `backup::path_hash_hex` so the audit log can pair backup and
    /// restore events).
    pub path_hash_hex: String,
    /// Hostname stamped into the backup metadata at create-time.
    /// Surfaced for the Receipt so audit reviewers can cross-check
    /// the source workstation.
    pub source_hostname: String,
    /// RFC3339 timestamp from the backup metadata.
    pub source_created_at: String,
    /// Daemon posture at backup time (`"prod"` / `"dev"`).
    pub source_daemon_mode: String,
    /// Operator-role Durable Persona pubkey hex (32-byte raw).
    /// Restating it lets the audit pair the restore Receipt back to
    /// the signing Principal it just enrolled.
    pub operator_pubkey_hex: String,
    /// Whether the workstation Durable Persona was restored alongside
    /// the operator-role Durable Persona.
    pub restored_dev_ir: bool,
    /// Whether the Touch ID prompt fired.
    pub biometric_verified: bool,
}

/// Read the backup file at `from` and decrypt it. Pure helper — kept
/// separate from the I/O orchestration so tests can drive it on
/// in-memory blobs.
pub fn decrypt_backup_file(
    from: &Path,
    passphrase: &str,
) -> Result<BackupEnvelope, TrustRestoreError> {
    let blob = std::fs::read(from).map_err(|e| TrustRestoreError::ReadFile {
        path: from.to_path_buf(),
        source: e,
    })?;
    let envelope = open_backup(&blob, passphrase)?;
    Ok(envelope)
}

/// Format the metadata block the operator sees before biometric. Pure
/// rendering — no side effects.
pub fn render_restore_preview(envelope: &BackupEnvelope) -> String {
    let dev_ir_state = if envelope.dev_ir_seed.is_empty() {
        "no"
    } else {
        "yes"
    };
    format!(
        "Backup metadata:\n  Hostname:                     {}\n  Created at:                   {}\n  Daemon mode:                  {}\n  Operator-role Persona pubkey: {}\n  Includes workstation Persona: {}\n",
        envelope.metadata.hostname,
        envelope.metadata.created_at,
        envelope.metadata.daemon_mode,
        envelope.metadata.operator_pubkey_hex,
        dev_ir_state,
    )
}

fn prompt_passphrase() -> Result<String, TrustRestoreError> {
    if !std::io::stdin().is_terminal() {
        return Err(TrustRestoreError::Prompt(
            "stdin is not a terminal — restore requires interactive input".to_string(),
        ));
    }
    rpassword::prompt_password("Enter backup passphrase: ")
        .map_err(|e| TrustRestoreError::Prompt(format!("read passphrase: {e}")))
}

/// Ask the operator a yes/no question on stdout/stderr and read the
/// response from stdin. Returns `Ok(true)` only for an exact `"y"` /
/// `"yes"` (case-insensitive). Used for the "overwrite existing
/// Keychain entries?" second-confirmation prompt.
fn confirm_yes_no(question: &str) -> Result<bool, TrustRestoreError> {
    if !std::io::stdin().is_terminal() {
        return Err(TrustRestoreError::Prompt(
            "stdin is not a terminal — overwrite-confirmation requires \
             interactive input"
                .to_string(),
        ));
    }
    eprint!("{question} [y/N]: ");
    std::io::stderr().flush().ok();
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| TrustRestoreError::Prompt(format!("read confirm: {e}")))?;
    let trimmed = input.trim().to_lowercase();
    Ok(matches!(trimmed.as_str(), "y" | "yes"))
}

/// Check whether a Keychain entry already exists at the given label.
fn keychain_entry_exists(label: &str) -> Result<bool, TrustRestoreError> {
    let entry = keyring_core::Entry::new(KEYCHAIN_SERVICE, label)
        .map_err(|e| TrustRestoreError::Keychain(format!("open keyring entry {label}: {e}")))?;
    match entry.get_password() {
        Ok(_) => Ok(true),
        Err(keyring_core::Error::NoEntry) => Ok(false),
        Err(e) => Err(TrustRestoreError::Keychain(format!("probe {label}: {e}"))),
    }
}

/// Write a 32-byte seed to Keychain at `label`. Overwrites any
/// existing entry. The caller is responsible for asking the operator
/// before clobbering.
fn write_seed_to_keychain(label: &str, seed: &[u8]) -> Result<(), TrustRestoreError> {
    let entry = keyring_core::Entry::new(KEYCHAIN_SERVICE, label)
        .map_err(|e| TrustRestoreError::Keychain(format!("open keyring entry {label}: {e}")))?;
    let hex_seed = hex::encode(seed);
    entry
        .set_password(&hex_seed)
        .map_err(|e| TrustRestoreError::Keychain(format!("set {label}: {e}")))
}

/// End-to-end `ember trust restore --from <path>` flow.
pub fn run_restore(from: &Path, no_biometric: bool) -> Result<RestoreOutcome, TrustRestoreError> {
    // 1. Prompt for passphrase (single entry — restore doesn't
    //    confirm because the operator already entered it at backup
    //    time; a typo here surfaces as Decrypt).
    let passphrase = prompt_passphrase()?;

    // 2. Decrypt the blob.
    let envelope = decrypt_backup_file(from, &passphrase)?;

    // 3. Show the metadata preview so the operator sees what they're
    //    about to enroll BEFORE Touch ID.
    eprint!("{}", render_restore_preview(&envelope));

    // 4. Biometric confirmation.
    let biometric_outcome = require_biometric(
        &format!(
            "Restore operator authority from backup created on {} on {}. Proceed?",
            envelope.metadata.hostname, envelope.metadata.created_at
        ),
        no_biometric,
    )
    .map_err(|e: BiometricError| TrustRestoreError::Biometric(e.to_string()))?;
    let biometric_verified = matches!(biometric_outcome, BiometricOutcome::Verified { .. });

    // 5. Overwrite-existing check. Both target-state Keychain entries
    //    are probed independently so a partial state still gets the prompt.
    let operator_exists = keychain_entry_exists(OPERATOR_IR_KEYCHAIN_LABEL)?;
    let dev_exists = keychain_entry_exists(DEV_IR_KEYCHAIN_LABEL)?;
    let dev_present = !envelope.dev_ir_seed.is_empty();
    if operator_exists || (dev_exists && dev_present) {
        let confirmed = confirm_yes_no("Existing Keychain entries will be overwritten. Continue?")?;
        if !confirmed {
            return Err(TrustRestoreError::OperatorDeclinedOverwrite);
        }
    }

    // 6. Write operator-role Durable Persona (always present in a valid envelope).
    if envelope.operator_ir_seed.len() != 32 {
        return Err(TrustRestoreError::Open(BackupError::Cbor(format!(
            "operator_ir_seed length {} (expected 32)",
            envelope.operator_ir_seed.len()
        ))));
    }
    write_seed_to_keychain(OPERATOR_IR_KEYCHAIN_LABEL, &envelope.operator_ir_seed)?;

    // 7. Write workstation Durable Persona when present in the envelope.
    let restored_dev_ir = dev_present;
    if restored_dev_ir {
        if envelope.dev_ir_seed.len() != 32 {
            return Err(TrustRestoreError::Open(BackupError::Cbor(format!(
                "dev_ir_seed length {} (expected 32)",
                envelope.dev_ir_seed.len()
            ))));
        }
        write_seed_to_keychain(DEV_IR_KEYCHAIN_LABEL, &envelope.dev_ir_seed)?;
    }

    Ok(RestoreOutcome {
        read_from: from.to_path_buf(),
        path_hash_hex: path_hash_hex(from),
        source_hostname: envelope.metadata.hostname.clone(),
        source_created_at: envelope.metadata.created_at.clone(),
        source_daemon_mode: envelope.metadata.daemon_mode.clone(),
        operator_pubkey_hex: envelope.metadata.operator_pubkey_hex.clone(),
        restored_dev_ir,
        biometric_verified,
    })
}

/// Format the restore outcome for stdout.
pub fn render_outcome(outcome: &RestoreOutcome) -> String {
    format!(
        "Trust restore complete:\n  Source path:                   {}\n  Source path hash:              {}\n  Source hostname:               {}\n  Source created at:             {}\n  Source daemon mode:            {}\n  Operator-role Persona pubkey:  {}\n  Restored workstation Persona:  {}\n  Biometric verified:            {}\n",
        outcome.read_from.display(),
        outcome.path_hash_hex,
        outcome.source_hostname,
        outcome.source_created_at,
        outcome.source_daemon_mode,
        outcome.operator_pubkey_hex,
        outcome.restored_dev_ir,
        outcome.biometric_verified,
    )
}

/// Entry point for the `ember trust restore` subcommand.
pub fn run(from: &Path, no_biometric: bool) -> i32 {
    match run_restore(from, no_biometric) {
        Ok(outcome) => {
            print!("{}", render_outcome(&outcome));
            0
        }
        Err(err) => {
            eprintln!("ember trust restore: {err}");
            match err {
                TrustRestoreError::OperatorDeclinedOverwrite
                | TrustRestoreError::OperatorCancelled => 1,
                TrustRestoreError::Open(BackupError::Decrypt) => 1,
                _ => 2,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::backup_envelope::{BackupMetadata, seal_backup};
    use tempfile::TempDir;

    fn envelope_fixture() -> BackupEnvelope {
        BackupEnvelope {
            operator_ir_seed: vec![0xaau8; 32],
            dev_ir_seed: vec![0xbbu8; 32],
            metadata: BackupMetadata {
                created_at: "2026-05-21T12:00:00Z".to_string(),
                daemon_mode: "prod".to_string(),
                hostname: "source-mac.local".to_string(),
                operator_pubkey_hex: "cc".repeat(32),
            },
        }
    }

    /// `decrypt_backup_file` reads bytes from disk and recovers the
    /// original envelope under the right passphrase.
    #[test]
    fn decrypt_round_trips_from_disk() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.embk");
        let env = envelope_fixture();
        let blob = seal_backup(&env, "test-passphrase-1234").expect("seal");
        std::fs::write(&path, &blob).unwrap();

        let recovered = decrypt_backup_file(&path, "test-passphrase-1234").expect("open");
        assert_eq!(recovered.operator_ir_seed, env.operator_ir_seed);
        assert_eq!(recovered.dev_ir_seed, env.dev_ir_seed);
        assert_eq!(recovered.metadata.hostname, "source-mac.local");
    }

    /// Wrong passphrase surfaces `BackupError::Decrypt` wrapped as
    /// `TrustRestoreError::Open`. The error type carries enough
    /// context for the operator-facing layer to render a non-fatal
    /// "wrong passphrase" hint.
    #[test]
    fn decrypt_with_wrong_passphrase_surfaces_decrypt_error() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.embk");
        let env = envelope_fixture();
        let blob = seal_backup(&env, "right-passphrase-1234").expect("seal");
        std::fs::write(&path, &blob).unwrap();

        let err = decrypt_backup_file(&path, "wrong-passphrase-1234").unwrap_err();
        match err {
            TrustRestoreError::Open(BackupError::Decrypt) => {}
            other => panic!("expected Open(Decrypt), got {other:?}"),
        }
    }

    /// Missing file surfaces `ReadFile`, not `Open` — distinguish
    /// "operator pointed at the wrong path" from "blob is bad".
    #[test]
    fn decrypt_missing_file_surfaces_read_error() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("does-not-exist.embk");
        let err = decrypt_backup_file(&path, "any-passphrase-1234").unwrap_err();
        match err {
            TrustRestoreError::ReadFile { .. } => {}
            other => panic!("expected ReadFile, got {other:?}"),
        }
    }

    /// Preview rendering surfaces every metadata field the operator
    /// needs to recognise the backup before Touch ID.
    #[test]
    fn preview_renders_metadata_fields() {
        let env = envelope_fixture();
        let s = render_restore_preview(&env);
        assert!(s.contains("Hostname:                     source-mac.local"));
        assert!(s.contains("Created at:                   2026-05-21T12:00:00Z"));
        assert!(s.contains("Daemon mode:                  prod"));
        assert!(s.contains(&"cc".repeat(32)));
        assert!(s.contains("Includes workstation Persona: yes"));
    }

    /// Empty workstation seed renders "no" in the preview.
    #[test]
    fn preview_renders_no_dev_ir_when_absent() {
        let mut env = envelope_fixture();
        env.dev_ir_seed = Vec::new();
        let s = render_restore_preview(&env);
        assert!(s.contains("Includes workstation Persona: no"));
    }

    /// `render_outcome` block contains the canonical fields. Smoke
    /// test on the audit-visible shape.
    #[test]
    fn outcome_renders_all_audit_fields() {
        let outcome = RestoreOutcome {
            read_from: PathBuf::from("/tmp/test.embk"),
            path_hash_hex: "dd".repeat(32),
            source_hostname: "from-host".to_string(),
            source_created_at: "2026-05-21T00:00:00Z".to_string(),
            source_daemon_mode: "dev".to_string(),
            operator_pubkey_hex: "ee".repeat(32),
            restored_dev_ir: true,
            biometric_verified: false,
        };
        let s = render_outcome(&outcome);
        assert!(s.contains("Trust restore complete:"));
        assert!(s.contains("Source path:"));
        assert!(s.contains("Source path hash:"));
        assert!(s.contains("Source hostname:               from-host"));
        assert!(s.contains("Source daemon mode:            dev"));
        assert!(s.contains("Restored workstation Persona:  true"));
        assert!(s.contains(&"dd".repeat(32)));
        assert!(s.contains(&"ee".repeat(32)));
    }
}
