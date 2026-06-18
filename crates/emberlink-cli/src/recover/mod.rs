//! CLASSIFICATION: PUBLIC
//!
//! `ember recover ...` — operator recovery surface per ADR 161 §Component 1
//! and ADR 195's lifecycle recovery plane.
//!
//! Each class entry point routes to a sub-module (`daemon`, `authority`,
//! `broker`, `audit`, `install`) that is incrementally populated as
//! per-F-code implementations land. Today the scaffold exposes the verb
//! surface and the `--explain F-CODE` runbook bridge; per-F-code recovery
//! work is tracked as `META-RECOVER-F-*` tasks shipping progressively.
//!
//! Each recovery action emits a Receipt of kind `recovery.action` once the
//! per-F-code implementation lands. Authority-modifying recovery is gated
//! by the existing `PresenceProof` primitive (Touch ID on macOS). The
//! scaffold-level handlers print the Receipt-emission contract and the
//! Touch-ID-gating contract without doing the work — the per-F-code task
//! that wires the real action also wires the Receipt + presence-proof call.
//!
//! ## Checkpoint for `target_state_anchor`
//!
//! `recover_cli_scaffold_landed` is anchored in this module's docstring.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use clap::Subcommand;

pub mod audit;
pub mod audit_chain;
pub mod authority;
pub mod broker;
pub mod daemon;
pub mod diagnose;
pub mod grant;
pub mod install;
pub mod persona;
pub mod symptoms;
pub mod trust;
pub mod vault;

/// Top-level CLI subcommand surface for `ember recover`.
///
/// Each variant routes to its class sub-module via [`dispatch`]. The
/// `--explain F-CODE` flag is a peer dispatch that prints a runbook
/// excerpt instead of routing to a class.
#[derive(Subcommand, Debug)]
pub enum RecoverCmd {
    /// Diagnose the local recovery posture and print one bounded next step.
    ///
    /// This lifecycle umbrella composes the daemon status, vault status,
    /// persona/grant summary, and audit verification primitives. It emits a
    /// daemon-signed `recovery.action` receipt before rendering the result.
    Diagnose(diagnose::RecoverDiagnoseArgs),

    /// Guided audit-chain lifecycle recovery (P14-S3 scaffold).
    #[command(name = "audit-chain")]
    AuditChain(audit_chain::RecoverAuditChainArgs),

    /// Guided vault lifecycle recovery: unlock-retry, rotate-key (guidance), verify-backup.
    Vault(vault::RecoverVaultArgs),

    /// Guided trust-list lifecycle recovery: list-audit provenance walk.
    Trust(trust::RecoverTrustArgs),

    /// Guided grant lifecycle recovery: rebuild-chain probe or abandon with provenance.
    Grant(grant::RecoverGrantArgs),

    /// Guided persona lifecycle recovery: restore eligibility probe or abandon with provenance.
    Persona(persona::RecoverPersonaArgs),

    /// Recover daemon-side state (process, socket, db, pid).
    ///
    /// See `F-DAEMON-*` in `docs/runbook/recovery.md`.
    Daemon(daemon::RecoverDaemonArgs),

    /// Recover authority (delegated authority, identity root, keychain).
    ///
    /// See `F-AUTHORITY-*` in `docs/runbook/recovery.md`. Authority-
    /// modifying actions require Touch ID via `PresenceProof`.
    Authority(authority::RecoverAuthorityArgs),

    /// Recover broker state (creds, allowlist, cache) per provider.
    ///
    /// See `F-BROKER-*` in `docs/runbook/recovery.md`.
    Broker(broker::RecoverBrokerArgs),

    /// Recover audit chain state (rotate, verify, repair).
    ///
    /// See `F-AUDIT-*` in `docs/runbook/recovery.md`.
    Audit(audit::RecoverAuditArgs),

    /// Recover install state (shadow path, manifest, plist, binaries).
    ///
    /// See `F-INSTALL-*` in `docs/runbook/recovery.md`.
    Install(install::RecoverInstallArgs),

    /// Print the runbook excerpt for a single F-code.
    ///
    /// `ember recover --explain F-DAEMON-2` prints the
    /// `## F-DAEMON-2 — …` section of `docs/runbook/recovery.md` to
    /// stdout. F-codes are case-insensitive.
    Explain {
        /// F-code identifier (e.g. `F-DAEMON-2`, case-insensitive).
        #[arg(value_name = "F_CODE")]
        f_code: String,
    },
}

#[derive(Clone, Debug, Default)]
pub struct RecoverContext {
    pub socket_path: Option<PathBuf>,
}

impl RecoverContext {
    pub fn with_socket_path(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: Some(socket_path.as_ref().to_path_buf()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoverOutcome {
    exit_code: i32,
}

impl RecoverOutcome {
    pub fn ok() -> Self {
        Self { exit_code: 0 }
    }

    pub fn issue_found() -> Self {
        Self { exit_code: 2 }
    }

    pub fn exit_code(self) -> i32 {
        self.exit_code
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverError {
    message: String,
    exit_code: i32,
}

impl RecoverError {
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 1,
        }
    }

    pub fn authority(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 3,
        }
    }

    /// ADR 195 §9 exit-4 — state changed between dry-run and execute; the
    /// operator must rerun the dry-run. Used by `recover vault rotate-key
    /// --execute` when the daemon reports `vault_rotate_drift` (ADR 198
    /// amendment 1: the rotation plan's state digest no longer matches).
    pub fn drift(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 4,
        }
    }

    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }
}

impl std::fmt::Display for RecoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RecoverError {}

/// Result of a recover-subcommand handler call.
///
/// The handler returns a stable outcome code or a structured error the bin
/// wrapper surfaces to stderr.
pub type RecoverResult = Result<RecoverOutcome, RecoverError>;

/// Dispatch a `RecoverCmd` to its class sub-module (or runbook bridge).
///
/// `runbook_path` defaults to `docs/runbook/recovery.md` relative to the
/// repository root. Override for tests via the `--runbook` plumbing once
/// the per-F-code handlers begin to need it.
pub fn dispatch(
    cmd: RecoverCmd,
    runbook_path: Option<PathBuf>,
    context: RecoverContext,
) -> RecoverResult {
    match cmd {
        RecoverCmd::Diagnose(args) => diagnose::handle(args, context),
        RecoverCmd::AuditChain(args) => audit_chain::handle(args, context),
        RecoverCmd::Vault(args) => vault::handle(args, context),
        RecoverCmd::Trust(args) => trust::handle(args, context),
        RecoverCmd::Grant(args) => grant::handle(args, context),
        RecoverCmd::Persona(args) => persona::handle(args, context),
        RecoverCmd::Daemon(args) => daemon::handle(args, context),
        RecoverCmd::Authority(args) => authority::handle(args, context),
        RecoverCmd::Broker(args) => broker::handle(args),
        RecoverCmd::Audit(args) => audit::handle(args),
        RecoverCmd::Install(args) => install::handle(args),
        RecoverCmd::Explain { f_code } => explain_f_code(&f_code, runbook_path),
    }
}

/// Read `docs/runbook/recovery.md` and print the section whose header
/// matches the supplied F-code (case-insensitive, anchored on `## F-…`).
///
/// On miss, lists the available F-codes from the runbook headers.
pub fn explain_f_code(f_code: &str, runbook_path: Option<PathBuf>) -> RecoverResult {
    let path = runbook_path.unwrap_or_else(|| PathBuf::from("docs/runbook/recovery.md"));
    let body = fs::read_to_string(&path).map_err(|e| {
        RecoverError::usage(format!(
            "could not read runbook at {}: {}",
            path.display(),
            e
        ))
    })?;
    let needle = f_code.to_ascii_uppercase();

    let lines = body.lines().peekable();
    let mut in_section = false;
    let mut printed = false;
    let mut available: Vec<&str> = Vec::new();
    for line in lines {
        if let Some(header) = line.strip_prefix("## ") {
            let code = header.split_whitespace().next().unwrap_or("");
            if code.starts_with("F-") {
                available.push(code);
            }
            if in_section {
                break;
            }
            if code.eq_ignore_ascii_case(&needle) {
                in_section = true;
                println!("{line}");
                printed = true;
                continue;
            }
        }
        if in_section {
            println!("{line}");
        }
    }

    if !printed {
        let mut msg = format!("no F-code matching `{f_code}` found in {}", path.display());
        if !available.is_empty() {
            msg.push_str("\navailable F-codes: ");
            msg.push_str(&available.join(", "));
        }
        return Err(RecoverError::usage(msg));
    }
    Ok(RecoverOutcome::ok())
}

/// Placeholder for the Receipt-emission contract. The scaffold prints
/// the contract a per-F-code implementation will satisfy.
///
/// Real Receipt emission lands with the per-F-code task that wires the
/// recovery action — emit `Receipt { kind: "recovery.action", scope: <F-code>, … }`
/// via the existing event-log path.
pub(crate) fn note_receipt_contract(class: &str, scope: &str) {
    eprintln!(
        "  [scaffold] recovery action would emit Receipt(kind=\"recovery.action\", \
         class=\"{class}\", scope=\"{scope}\") once the per-F-code handler lands"
    );
}

/// Placeholder for the Touch-ID gating contract. The scaffold prints
/// the contract; the real gate calls `PresenceProof::require(…)` from
/// the per-F-code handler. Only authority-modifying recovery requires
/// the gate; informational or restart-only recovery does not.
pub(crate) fn note_presence_contract(class: &str, scope: &str) {
    eprintln!(
        "  [scaffold] authority-modifying recovery would call PresenceProof::require() \
         (class=\"{class}\", scope=\"{scope}\") before performing the action"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn fixture_runbook() -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tmp runbook");
        writeln!(
            f,
            "# Recovery Runbook\n\n## F-DAEMON-1 — Daemon crashed mid-session\n\
             - Symptom: daemon process exited\n\
             - Recovery: `ember recover daemon`\n\n\
             ## F-AUTHORITY-1 — Delegation grant expired\n\
             - Symptom: 403 mid-session\n\
             - Recovery: relogin"
        )
        .unwrap();
        f
    }

    #[test]
    fn explain_finds_section() {
        let runbook = fixture_runbook();
        let r = explain_f_code("F-DAEMON-1", Some(runbook.path().to_path_buf()));
        assert!(r.is_ok(), "expected Ok, got {r:?}");
    }

    #[test]
    fn explain_case_insensitive() {
        let runbook = fixture_runbook();
        let r = explain_f_code("f-authority-1", Some(runbook.path().to_path_buf()));
        assert!(r.is_ok(), "expected case-insensitive match, got {r:?}");
    }

    #[test]
    fn explain_unknown_lists_available() {
        let runbook = fixture_runbook();
        let r = explain_f_code("F-BOGUS-9", Some(runbook.path().to_path_buf()));
        let err = r.expect_err("expected error on unknown F-code");
        let err = err.to_string();
        assert!(
            err.contains("F-DAEMON-1"),
            "error should list available codes; got: {err}"
        );
        assert!(
            err.contains("F-AUTHORITY-1"),
            "error should list available codes; got: {err}"
        );
    }
}
