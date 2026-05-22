//!
//! `ember recover broker` — recover credential-broker state per design.
//!
//! Scope routing:
//! - `creds` — re-prompt + re-seal upstream credentials for a provider
//! - `allowlist` — reload the provider allowlist from disk
//! - `cache` — drop the broker's in-memory materialization cache
//!
//! Per-provider: `--provider <NAME>` (e.g. `github`, `anthropic`).

use clap::Args;

use super::{RecoverResult, note_receipt_contract};

#[derive(Args, Debug)]
pub struct RecoverBrokerArgs {
    /// Provider identifier (e.g. `github`, `anthropic`). When omitted,
    /// recovery applies to every registered provider.
    #[arg(long)]
    pub provider: Option<String>,

    /// Narrow the recovery to a single sub-component. When omitted,
    /// the scaffold prints which scopes are available.
    #[arg(long, value_enum)]
    pub scope: Option<BrokerScope>,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
pub enum BrokerScope {
    /// Re-prompt + re-seal upstream credentials for the named provider.
    Creds,
    /// Reload the provider allowlist from disk.
    Allowlist,
    /// Drop the in-memory materialization cache.
    Cache,
}

impl BrokerScope {
    fn as_str(self) -> &'static str {
        match self {
            BrokerScope::Creds => "creds",
            BrokerScope::Allowlist => "allowlist",
            BrokerScope::Cache => "cache",
        }
    }
}

pub fn handle(args: RecoverBrokerArgs) -> RecoverResult {
    let provider = args
        .provider
        .clone()
        .unwrap_or_else(|| "<all>".to_string());
    let scope = args
        .scope
        .map(|s| s.as_str().to_string())
        .unwrap_or_else(|| "creds".to_string());

    println!(
        "ember recover broker (provider={provider}, scope={scope}): scaffold only — \
         per-F-code implementations land as implementation-note-521-* tasks ship. See \
         `ember recover --explain F-implementation-note-522` (or 2, 3) for the F-code-anchored runbook."
    );
    note_receipt_contract("broker", &scope);
    Ok(())
}
