//! Operator-facing vault I/O — `ember vault list/get/put/export/import`.
//!
//! Per ARCH-CRED-STORE-E-CLI-EXTENSIONS this module hosts the testable
//! core of the new `ember vault` subcommands (sub-piece E of ADR 137).
//! The argv-parsing surface lives in `bin/ember.rs`; the binary forwards
//! into these helpers so they can be exercised from T2 integration tests
//! against an in-memory daemon vault without spawning a child process.
//!
//! # What lives here
//!
//! - [`mask_credential_for_display`] — `****<last4>` masking for `get`.
//! - [`encode_export_envelope`] — produce the JSON envelope `export` writes.
//! - [`decode_import_envelope`] — atomically decrypt every entry from the
//!   envelope `import` reads, before any vault write happens.
//!
//! The argv shells (`VaultListArgs`, `VaultExportArgs`, `VaultImportArgs`
//! in `bin/ember.rs`) carry the operator-supplied paths; this module
//! takes the post-resolve byte/string forms so it never touches the
//! filesystem directly. That keeps unit tests pure.

use core_crypto::{unwrap_armored_with_identity, wrap_secret_to_recipient_armored};
use core_types::ValidationError;
use serde::{Deserialize, Serialize};

/// Mask a credential value for display, keeping only the trailing 4 chars.
///
/// Values shorter than 4 chars render as `****` (no chars revealed). Used
/// by `ember vault get` (no `--unmask`) so the default UX never spills
/// secrets onto a screen-recorded terminal.
pub fn mask_credential_for_display(value: &[u8]) -> String {
    let s = String::from_utf8_lossy(value);
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 4 {
        return "****".to_string();
    }
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("****{tail}")
}

/// One credential entry inside the export envelope.
///
/// `name` is plaintext (operators inspecting the export need to see what
/// was stored); `value_age_armored` is sealed to the operator's age
/// recipient via [`wrap_secret_to_recipient_armored`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultExportEntry {
    pub name: String,
    pub value_age_armored: String,
}

/// JSON envelope produced by `ember vault export` and consumed by
/// `ember vault import`. Versioned so future schema changes can branch
/// on `version` without breaking older exports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultExportEnvelope {
    pub version: u32,
    pub exported_at: String,
    pub recipient: String,
    pub entries: Vec<VaultExportEntry>,
}

/// Errors returned by the export/import helpers.
#[derive(Debug, thiserror::Error)]
pub enum VaultIoError {
    #[error("failed to encrypt {name}: {source}")]
    Encrypt {
        name: String,
        #[source]
        source: ValidationError,
    },
    #[error("failed to decrypt entry[{index}] ({name}): {source}")]
    Decrypt {
        index: usize,
        name: String,
        #[source]
        source: ValidationError,
    },
}

/// Build the export envelope for `entries` (a list of `(name, plaintext)`
/// tuples drawn from `vault.list(VaultScope::Interactive, )` + `vault.get(VaultScope::Interactive, )` calls), encrypting
/// each value individually under `recipient_age_pub`.
///
/// Names are visible in the envelope; values are sealed.
pub fn encode_export_envelope(
    recipient_age_pub: &str,
    entries: &[(String, Vec<u8>)],
    exported_at_rfc3339: String,
) -> Result<VaultExportEnvelope, VaultIoError> {
    let mut out: Vec<VaultExportEntry> = Vec::with_capacity(entries.len());
    for (name, value) in entries {
        let armored =
            wrap_secret_to_recipient_armored(recipient_age_pub, value).map_err(|source| {
                VaultIoError::Encrypt {
                    name: name.clone(),
                    source,
                }
            })?;
        out.push(VaultExportEntry {
            name: name.clone(),
            value_age_armored: armored,
        });
    }
    Ok(VaultExportEnvelope {
        version: 1,
        exported_at: exported_at_rfc3339,
        recipient: recipient_age_pub.to_string(),
        entries: out,
    })
}

/// Decrypt every entry in `envelope` using `identity_age_secret`.
///
/// Returns the full `(name, plaintext)` list on success; returns
/// [`VaultIoError::Decrypt`] on the first decryption failure WITHOUT
/// having written anything. The caller is expected to drive
/// `vault.put(name, value)` for each restored entry only after this fn
/// returns `Ok` — that's the atomic-import contract.
pub fn decode_import_envelope(
    identity_age_secret: &str,
    envelope: &VaultExportEnvelope,
) -> Result<Vec<(String, Vec<u8>)>, VaultIoError> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::with_capacity(envelope.entries.len());
    for (index, entry) in envelope.entries.iter().enumerate() {
        let plaintext = unwrap_armored_with_identity(identity_age_secret, &entry.value_age_armored)
            .map_err(|source| VaultIoError::Decrypt {
                index,
                name: entry.name.clone(),
                source,
            })?;
        out.push((entry.name.clone(), plaintext.to_vec()));
    }
    Ok(out)
}

/// Mirror types for argv-shape tests in `tests/vault_cli.rs`.
///
/// The binary's `VaultPutArgs` (in `bin/ember.rs`) is not reachable
/// from integration tests — bins don't expose their items to the
/// `tests/` target. We mirror just the parse-shape here so the
/// `put_refuses_value_argv_form` test can exercise clap's accept-then-
/// dispatch-refuses contract without depending on the binary surface.
pub mod testing {
    use clap::Args;

    /// Parse-shape mirror of `VaultPutArgs` — keep flag names and
    /// `conflicts_with` rules in sync with `bin/ember.rs`.
    #[derive(Debug, Args)]
    pub struct VaultPutArgsMirror {
        #[arg(long)]
        pub name: String,
        #[arg(long, hide = true)]
        pub value: Option<String>,
        #[arg(long, conflicts_with_all = ["value", "file"])]
        pub stdin: bool,
        #[arg(long, conflicts_with_all = ["value", "stdin"])]
        pub file: Option<std::path::PathBuf>,
        #[arg(long, requires = "file")]
        pub delete_source: bool,
        #[arg(long, requires = "file")]
        pub from_downloads: bool,
        #[arg(long)]
        pub metadata: Option<String>,
        #[arg(long)]
        pub require_biometric: bool,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_short_value_reveals_nothing() {
        assert_eq!(mask_credential_for_display(b"abc"), "****");
        assert_eq!(mask_credential_for_display(b""), "****");
        assert_eq!(mask_credential_for_display(b"a"), "****");
        assert_eq!(mask_credential_for_display(b"abcd"), "****");
    }

    #[test]
    fn mask_long_value_keeps_last_four() {
        assert_eq!(mask_credential_for_display(b"longabcd"), "****abcd");
        assert_eq!(
            mask_credential_for_display(b"sk-anthropic-secret-XYZQ"),
            "****XYZQ"
        );
    }
}
