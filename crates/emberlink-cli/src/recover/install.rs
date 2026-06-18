//! CLASSIFICATION: PUBLIC
//!
//! `ember recover install` — recover install-time state per ADR 161.
//!
//! Scope routing:
//! - `shadow` — re-create the `~/.ember/shadow/` PATH-shim tree
//! - `manifest` — re-fetch + re-verify the install manifest
//! - `plist` — re-install the launchd plist (macOS) or systemd unit (Linux)
//! - `binaries` — re-sync daemon + helper binaries from disk
//! - `subuid` — repair Linux subuid/subgid range collisions

use clap::{Args, ValueEnum};

use super::{RecoverOutcome, RecoverResult, note_receipt_contract};

#[derive(Args, Debug)]
pub struct RecoverInstallArgs {
    /// Recover the dev-mode install.
    #[arg(long, group = "mode")]
    pub dev: bool,

    /// Recover the prod-mode install.
    #[arg(long, group = "mode")]
    pub prod: bool,

    /// Narrow the recovery to a single sub-component. When omitted,
    /// the scaffold prints which scopes are available.
    #[arg(long, value_enum)]
    pub scope: Option<InstallScope>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum InstallScope {
    /// Re-create the `~/.ember/shadow/` PATH-shim tree.
    Shadow,
    /// Re-fetch + re-verify the install manifest.
    Manifest,
    /// Re-install the launchd plist (macOS) or systemd unit (Linux).
    Plist,
    /// Re-sync daemon + helper binaries from disk.
    Binaries,
    /// Repair Linux subuid/subgid range collisions.
    Subuid,
}

impl InstallScope {
    fn as_str(self) -> &'static str {
        match self {
            InstallScope::Shadow => "shadow",
            InstallScope::Manifest => "manifest",
            InstallScope::Plist => "plist",
            InstallScope::Binaries => "binaries",
            InstallScope::Subuid => "subuid",
        }
    }
}

pub fn handle(args: RecoverInstallArgs) -> RecoverResult {
    let mode = if args.prod {
        "prod"
    } else if args.dev {
        "dev"
    } else {
        "default"
    };
    let scope = args
        .scope
        .map(|s| s.as_str().to_string())
        .unwrap_or_else(|| "shadow".to_string());

    println!(
        "ember recover install (mode={mode}, scope={scope}): scaffold only — \
         per-F-code implementations land as META-RECOVER-F-INSTALL-* tasks ship. \
         See `ember recover --explain F-INSTALL-1` (or 2, 3, 4) for the \
         F-code-anchored runbook."
    );
    note_receipt_contract("install", &scope);
    Ok(RecoverOutcome::ok())
}
