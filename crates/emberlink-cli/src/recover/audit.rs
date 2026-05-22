//!
//! `ember recover audit` — recover audit-chain state per design.
//!
//! Scope routing:
//! - `rotate` — start a fresh audit segment with a cordon transition
//! - `verify` — run the audit verifier and report any chain failure
//! - `repair` — invoke `audit.repair_chain` to truncate-after-row a
//!   broken segment (design v2)

use clap::{Args, ValueEnum};

use super::{RecoverResult, note_receipt_contract};

#[derive(Args, Debug)]
pub struct RecoverAuditArgs {
    /// Narrow the recovery to a single sub-component. When omitted,
    /// the scaffold prints which scopes are available.
    #[arg(long, value_enum)]
    pub scope: Option<AuditScope>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum AuditScope {
    /// Start a fresh audit segment with a cordon transition.
    Rotate,
    /// Run the audit verifier and report any chain failure.
    Verify,
    /// Invoke `audit.repair_chain` to truncate-after-row a broken segment.
    Repair,
}

impl AuditScope {
    fn as_str(self) -> &'static str {
        match self {
            AuditScope::Rotate => "rotate",
            AuditScope::Verify => "verify",
            AuditScope::Repair => "repair",
        }
    }
}

pub fn handle(args: RecoverAuditArgs) -> RecoverResult {
    let scope = args
        .scope
        .map(|s| s.as_str().to_string())
        .unwrap_or_else(|| "verify".to_string());

    println!(
        "ember recover audit (scope={scope}): scaffold only — per-F-code \
         implementations land as implementation-note-518-* tasks ship. See \
         `ember recover --explain F-implementation-note-519` (or 2) for the F-code-anchored runbook."
    );
    note_receipt_contract("audit", &scope);
    Ok(())
}
