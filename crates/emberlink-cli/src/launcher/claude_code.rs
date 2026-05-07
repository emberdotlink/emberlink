//! `ember claude-code` launcher.
//!
//! Per design §2 / implementation-note-109:
//!
//! 1. Register a new session with the daemon (stub today; real RPC lands
//!    in implementation-note-63 / implementation-note-89 — `register_session(persona) → {session_id,
//!    grant_id, proxy_url}`).
//! 2. Set `EMBER_GRANT_ID` / `EMBER_PROXY_URL` / `HTTPS_PROXY` /
//!    `EMBER_SESSION_ID` in the child env. **Only the child** — the
//!    parent shell's `HTTPS_PROXY` (if any) is preserved on launcher exit.
//! 3. Spawn `claude` (or `$EMBER_CLAUDE_BIN` override) with the augmented
//!    env, inheriting stdin/stdout/stderr.
//! 4. On child exit (signal forwarded by the terminal, or natural
//!    termination), close the session (stub today; implementation-note-89).
//! 5. Exit with the child's status code.
//!
//! The launcher uses `std::process::Command::status` (parent-and-child
//! model) rather than `execve`. Terminal SIGINT/SIGTERM go to the
//! foreground process group, so the child gets the signal at the same
//! time the launcher does. The `status()` call returns the child's
//! disposition; `close_session_stub` runs after it returns regardless of
//! exit code, giving us a single exit-trap point.
//!
//! Env-injection scope (cohort A acceptance): the child inherits the
//! parent env via `Command`'s default behavior, then we layer the four
//! ember vars on top. **We never write to `std::env::set_var`** — the
//! parent shell's environment is unchanged after the launcher returns.

use std::io;
use std::process::{Command, Stdio};

/// Outcome of the (today stubbed) daemon `register_session` RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRegistration {
    pub session_id: String,
    pub grant_id: String,
    pub proxy_url: String,
    /// Path to the daemon-managed ssh-agent socket for this session
    /// (implementation-note-22). When `Some`, the child process
    /// receives `SSH_AUTH_SOCK=<path>` so git/ssh in the child tree find
    /// the daemon socket. `None` when the daemon did not allocate an
    /// ssh-agent for this session (e.g. pre-design daemon).
    pub ssh_auth_sock: Option<String>,
}

/// Stub: register a new claude-code session with the daemon.
///
/// Real RPC lands in implementation-note-63 (daemon socket wiring) + implementation-note-89
/// (session lifecycle). The synthetic IDs are timestamp-suffixed so
/// repeated launches in the same second still produce distinct values
/// at the millisecond resolution.
pub fn register_session_stub() -> SessionRegistration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    SessionRegistration {
        session_id: format!("sess_stub_{nanos:032}"),
        grant_id: format!("grt_stub_{nanos:032}"),
        proxy_url: "http://127.0.0.1:8484".to_string(),
        // stub: no ssh-agent socket allocated yet (implementation-note-22
        // wires real path when daemon supports broker_exec ssh_agent=true).
        ssh_auth_sock: None,
    }
}

/// Stub: close a claude-code session. Real call lands in implementation-note-89.
///
/// Stderr-only output so the child's stdout (which the user is actually
/// reading) stays clean.
pub fn close_session_stub(session_id: &str) {
    eprintln!(
        "ember claude-code: closing session {session_id} (stub — implementation-note-89 wires real call)"
    );
}

/// Resolve the child binary. `$EMBER_CLAUDE_BIN` overrides the default
/// `claude` lookup so test harnesses can substitute `/usr/bin/true` etc.
pub fn resolve_claude_bin() -> String {
    std::env::var("EMBER_CLAUDE_BIN").unwrap_or_else(|_| "claude".to_string())
}

/// Run `claude` (or `$EMBER_CLAUDE_BIN`) with cohort A env vars layered on
/// top of the inherited parent environment. Returns the child's exit code
/// (or `1` if the child was killed by a signal with no exit code).
///
/// Pure function over the registration so unit tests can drive it with
/// fixture values; the real CLI entry point fills in the registration via
/// `register_session_stub` (or — post implementation-note-63 — the real RPC).
pub fn run_with_registration(
    bin: &str,
    extra_args: &[String],
    registration: &SessionRegistration,
) -> io::Result<i32> {
    eprintln!(
        "ember claude-code: launching {bin} (session={}, grant={}, proxy={})",
        registration.session_id, registration.grant_id, registration.proxy_url,
    );

    let mut cmd = Command::new(bin);
    cmd.args(extra_args)
        .env("EMBER_GRANT_ID", &registration.grant_id)
        .env("EMBER_PROXY_URL", &registration.proxy_url)
        .env("HTTPS_PROXY", &registration.proxy_url)
        .env("EMBER_SESSION_ID", &registration.session_id)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // Inject daemon-managed ssh-agent socket when the broker provided one
    // (implementation-note-22). git/ssh in the child tree pick this up
    // automatically without any additional configuration.
    if let Some(ref sock) = registration.ssh_auth_sock {
        cmd.env("SSH_AUTH_SOCK", sock);
    }
    let status = cmd
        .status()
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("ember claude-code: failed to spawn {bin}: {e}"),
            )
        })?;

    close_session_stub(&registration.session_id);

    Ok(status.code().unwrap_or(1))
}

/// `ember claude-code [extra_args...]` entry point.
///
/// Defers to `register_session_stub` + `run_with_registration`; intended
/// to be the only call site from `bin/ember.rs` so the dispatch path is
/// uniform across the friendly-dev launcher family.
pub fn launch_claude_code(extra_args: &[String]) -> io::Result<i32> {
    let bin = resolve_claude_bin();
    let registration = register_session_stub();
    run_with_registration(&bin, extra_args, &registration)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> SessionRegistration {
        SessionRegistration {
            session_id: "sess_fixture".to_string(),
            grant_id: "grt_fixture".to_string(),
            proxy_url: "http://127.0.0.1:9999".to_string(),
            ssh_auth_sock: None,
        }
    }

    #[test]
    fn register_session_stub_emits_distinct_ids() {
        let a = register_session_stub();
        // Sleep is unreliable across CI; nanos resolution + the 32-pad
        // gives us enough entropy that the second call will differ.
        let b = register_session_stub();
        assert_ne!(
            (a.session_id, a.grant_id),
            (b.session_id, b.grant_id),
            "stub registrations must produce distinct ids per call"
        );
    }

    #[test]
    fn run_with_registration_propagates_zero_exit() {
        // /usr/bin/true exits 0 on every Unix; cohort A targets macOS first.
        let code = run_with_registration("/usr/bin/true", &[], &fixture()).expect("spawn /usr/bin/true");
        assert_eq!(code, 0);
    }

    #[test]
    fn run_with_registration_propagates_nonzero_exit() {
        let code = run_with_registration("/usr/bin/false", &[], &fixture()).expect("spawn /usr/bin/false");
        assert_eq!(code, 1);
    }

    #[test]
    fn run_with_registration_does_not_pollute_parent_env() {
        // Anchor: ensure the parent process's environment doesn't
        // gain EMBER_GRANT_ID after we run a child that should only
        // see it in the child env. The launcher writes only via
        // `Command::env(...)`; an accidental `std::env::set_var` in
        // `run_with_registration` would leak `grt_fixture` to the
        // parent, which we'd see here.
        let _ = run_with_registration("/usr/bin/true", &[], &fixture()).expect("spawn /usr/bin/true");
        let leaked = std::env::var("EMBER_GRANT_ID")
            .map(|v| v.contains("grt_fixture"))
            .unwrap_or(false);
        assert!(
            !leaked,
            "launcher must not write EMBER_GRANT_ID into parent env"
        );
    }

    #[test]
    fn run_with_registration_reports_spawn_failure() {
        let result = run_with_registration("/no/such/binary-that-must-not-exist", &[], &fixture());
        assert!(
            result.is_err(),
            "missing binary must surface as Err, not silent zero exit"
        );
    }

    #[test]
    fn resolve_claude_bin_honors_override() {
        // SAFETY: Rust 2024 marks env mutation `unsafe` because it can
        // race other threads reading env. This test is single-threaded;
        // we set a value, observe it, and clear it before exit. The
        // racy global is the price of dependency injection on env.
        unsafe {
            std::env::set_var("EMBER_CLAUDE_BIN", "/usr/local/bin/claude-test");
        }
        assert_eq!(resolve_claude_bin(), "/usr/local/bin/claude-test");
        unsafe {
            std::env::remove_var("EMBER_CLAUDE_BIN");
        }
        assert_eq!(resolve_claude_bin(), "claude");
    }
}
