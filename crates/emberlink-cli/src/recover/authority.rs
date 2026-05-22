//!
//! `ember recover authority` — recover authority surfaces per design.
//!
//! Scope routing:
//! - `workflow` — rotate a workflow grant
//! - `identity-root` — rotate the device's identity-root keypair
//! - `keychain` — re-pair the macOS Keychain entries
//!
//! Authority-modifying actions are gated by `PresenceProof` (Touch ID
//! on macOS). The scaffold prints the gate contract; the real call
//! lands with each per-F-code implementation.

use clap::{Args, ValueEnum};

use super::{RecoverResult, note_presence_contract, note_receipt_contract};

#[derive(Args, Debug)]
pub struct RecoverAuthorityArgs {
    /// Narrow the recovery to a single sub-component. When omitted,
    /// the scaffold prints which scopes are available.
    #[arg(long, value_enum)]
    pub scope: Option<AuthorityScope>,

    /// Fallback authentication factor when Touch ID is unavailable.
    /// Today only `pam` is recognized; per design §F-AUTHORITY-2.
    #[arg(long, value_enum)]
    pub fallback: Option<AuthorityFallback>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum AuthorityScope {
    /// Rotate a workflow grant.
    Workflow,
    /// Rotate the device's identity-root keypair.
    IdentityRoot,
    /// Re-pair the macOS Keychain entries.
    Keychain,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum AuthorityFallback {
    /// Fall back to PAM (sudo-style password prompt).
    Pam,
}

impl AuthorityScope {
    fn as_str(self) -> &'static str {
        match self {
            AuthorityScope::Workflow => "workflow",
            AuthorityScope::IdentityRoot => "identity-root",
            AuthorityScope::Keychain => "keychain",
        }
    }
}

pub fn handle(args: RecoverAuthorityArgs) -> RecoverResult {
    let scope = args
        .scope
        .map(|s| s.as_str().to_string())
        .unwrap_or_else(|| "workflow".to_string());

    println!(
        "ember recover authority (scope={scope}): scaffold only — per-F-code \
         implementations land as implementation-note-520-* tasks ship. See \
         `ember recover --explain F-AUTHORITY-1` (or 2, 3, 4) for the \
         F-code-anchored runbook."
    );
    note_presence_contract("authority", &scope);
    note_receipt_contract("authority", &scope);
    if let Some(fallback) = args.fallback {
        eprintln!(
            "  [scaffold] requested fallback: {:?} (recognized; not yet wired to PAM)",
            fallback
        );
    }
    Ok(())
}
