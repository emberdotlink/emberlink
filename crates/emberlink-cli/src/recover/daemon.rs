//!
//! `ember recover daemon` — recover daemon-side state per design
//! §Component 1.
//!
//! Scope routing:
//! - `state` — full restart from scratch (calls into the existing
//!   `ember daemon recover-fresh` path once wired)
//! - `socket` — unlink a stale socket file
//! - `db` — rebuild the audit-store / session-store SQLite database
//! - `pid` — re-pair daemon PID file with the running process
//!
//! Today this module is a scaffold; per-F-code implementations land
//! progressively as `implementation-note-523-*` tasks ship.

use clap::{Args, ValueEnum};

use super::{RecoverResult, note_receipt_contract};

/// `ember recover daemon [--dev|--prod] [--scope state|socket|db|pid]`.
#[derive(Args, Debug)]
pub struct RecoverDaemonArgs {
    /// Recover the dev-mode daemon.
    #[arg(long, group = "mode")]
    pub dev: bool,

    /// Recover the prod-mode daemon.
    #[arg(long, group = "mode")]
    pub prod: bool,

    /// Narrow the recovery to a single sub-component. When omitted,
    /// the scaffold prints which scopes are available.
    #[arg(long, value_enum)]
    pub scope: Option<DaemonScope>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum DaemonScope {
    /// Full restart from scratch (audit-preserving via recover-fresh).
    State,
    /// Unlink a stale daemon.sock file.
    Socket,
    /// Rebuild the SQLite database (audit or session store).
    Db,
    /// Re-pair the daemon PID file with the running process.
    Pid,
}

impl DaemonScope {
    fn as_str(self) -> &'static str {
        match self {
            DaemonScope::State => "state",
            DaemonScope::Socket => "socket",
            DaemonScope::Db => "db",
            DaemonScope::Pid => "pid",
        }
    }
}

pub fn handle(args: RecoverDaemonArgs) -> RecoverResult {
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
        .unwrap_or_else(|| "state".to_string());

    println!(
        "ember recover daemon (mode={mode}, scope={scope}): scaffold only — \
         per-F-code implementations land as implementation-note-523-* tasks ship. \
         See `ember recover --explain F-DAEMON-1` (or 2, 3, …) for the \
         F-code-anchored runbook."
    );
    note_receipt_contract("daemon", &scope);
    Ok(())
}
