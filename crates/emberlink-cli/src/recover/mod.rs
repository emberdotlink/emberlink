//!
//! `ember recover {daemon, authority, broker, audit, install}` — operator
//! recovery surface per design §Component 1.
//!
//! Each class entry point routes to a sub-module (`daemon`, `authority`,
//! `broker`, `audit`, `install`) that is incrementally populated as
//! per-F-code implementations land. Today the scaffold exposes the verb
//! surface and the `--explain F-CODE` runbook bridge; per-F-code recovery
//! work is tracked as `implementation-note-455-*` tasks shipping progressively.
//!
//! Each recovery action emits a Receipt of kind `recovery.action` once the
//! per-F-code implementation lands. Authority-modifying recovery is gated
//! by the existing `PresenceProof` primitive (Touch ID on macOS). The
//! scaffold-level handlers print the Receipt-emission contract and the
//! Touch-ID-gating contract without doing the work — the per-F-code task
//! that wires the real action also wires the Receipt + presence-proof
//! call. See `project design notes`.
//!
//! ## Checkpoint for `target_state_anchor`
//!
//! `recover_cli_scaffold_landed` is anchored in this module's docstring.

use std::fs;
use std::path::PathBuf;

use clap::Subcommand;

pub mod audit;
pub mod authority;
pub mod broker;
pub mod daemon;
pub mod install;

/// Top-level CLI subcommand surface for `ember recover`.
///
/// Each variant routes to its class sub-module via [`dispatch`]. The
/// `--explain F-CODE` flag is a peer dispatch that prints a runbook
/// excerpt instead of routing to a class.
#[derive(Subcommand, Debug)]
pub enum RecoverCmd {
    /// Recover daemon-side state (process, socket, db, pid).
    ///
    /// See `F-DAEMON-*` in `docs/runbook/recovery.md`.
    Daemon(daemon::RecoverDaemonArgs),

    /// Recover authority (workflow grants, identity root, keychain).
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

/// Result of a recover-subcommand handler call.
///
/// The scaffold returns Ok or a stable error string the bin wrapper
/// surfaces to stderr. Once per-F-code work lands the handler may
/// upgrade to a richer error type.
pub type RecoverResult = Result<(), String>;

/// Dispatch a `RecoverCmd` to its class sub-module (or runbook bridge).
///
/// `runbook_path` defaults to `docs/runbook/recovery.md` relative to the
/// repository root. Override for tests via the `--runbook` plumbing once
/// the per-F-code handlers begin to need it.
pub fn dispatch(cmd: RecoverCmd, runbook_path: Option<PathBuf>) -> RecoverResult {
    match cmd {
        RecoverCmd::Daemon(args) => daemon::handle(args),
        RecoverCmd::Authority(args) => authority::handle(args),
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
    let body = fs::read_to_string(&path)
        .map_err(|e| format!("could not read runbook at {}: {}", path.display(), e))?;
    let needle = f_code.to_ascii_uppercase();

    let mut lines = body.lines().peekable();
    let mut in_section = false;
    let mut printed = false;
    let mut available: Vec<&str> = Vec::new();
    while let Some(line) = lines.next() {
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
        return Err(msg);
    }
    Ok(())
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
    use tempfile::NamedTempFile;
    use std::io::Write;

    fn fixture_runbook() -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tmp runbook");
        writeln!(
            f,
            "# Recovery Runbook\n\n## F-DAEMON-1 — Daemon crashed mid-session\n\
             - Symptom: daemon process exited\n\
             - Recovery: `ember recover daemon`\n\n\
             ## F-AUTHORITY-1 — Workflow grant expired\n\
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
        assert!(err.contains("F-DAEMON-1"), "error should list available codes; got: {err}");
        assert!(err.contains("F-AUTHORITY-1"), "error should list available codes; got: {err}");
    }
}
