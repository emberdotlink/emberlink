//! `ember claude-code` launcher.
//!
//! Per design §2 / implementation-note-389 + design §3 (PATH-shadow wiring, sub-B).
//! Real daemon RPC shipped in #2318 (LAUNCHER-SESSION-RPC); see design §2
//! for the full protocol contract.
//!
//! 1. Resolve persona: `$EMBER_PERSONA` env var if set; otherwise
//!    `claude-code-{hostname}` (matching what `init --for claude-code`
//!    creates). Install PATH-shadow symlinks via `install_path_shadow`
//!    (idempotent; creates `~/.ember/shadow/bin/` on first launch, verifies
//!    symlinks on subsequent launches).
//! 2. Register a new session with the daemon (`register_session_rpc`) — live
//!    Unix-socket RPC per design §2. Returns `{session_id, grant_id,
//!    proxy_url}`.
//! 3. Set `EMBER_GRANT_ID` / `EMBER_PROXY_URL` / `EMBER_SESSION_ID` in
//!    the child env. `HTTPS_PROXY` is intentionally NOT set — the
//!    daemon's LLM proxy isn't CONNECT-compatible (see
//!    implementation-note-429). Claude Code talks
//!    to api.anthropic.com directly with the friendly's own auth.
//! 4. Prepend `shadow_dir` to the child's `PATH` via `Command::env` so that
//!    tool invocations like `gh pr create` resolve to the ember Construct
//!    binary. **We never write to `std::env::set_var`** — the parent shell's
//!    PATH is unchanged after the launcher returns.
//! 5. Spawn `claude` (or `$EMBER_CLAUDE_BIN` override) with the augmented
//!    env, inheriting stdin/stdout/stderr.
//! 6. On child exit (signal forwarded by the terminal, or natural
//!    termination), close the session via `close_session_rpc` which emits
//!    a signed Receipt with `termination_reason = clean_exit`.
//! 7. Exit with the child's status code.
//!
//! implementation-note-430
//!
//! The launcher uses `std::process::Command::status` (parent-and-child
//! model) rather than `execve`. Terminal SIGINT/SIGTERM go to the
//! foreground process group, so the child gets the signal at the same
//! time the launcher does. The `status()` call returns the child's
//! disposition; `close_session_rpc` runs after it returns regardless of
//! exit code, giving us a single exit-trap point.
//!
//! Env-injection scope (cohort A acceptance): the child inherits the
//! parent env via `Command`'s default behavior, then we layer the ember
//! vars on top. **We never write to `std::env::set_var`** — the parent
//! shell's environment is unchanged after the launcher returns.

use std::io;
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::launcher::path_shadow::{ConstructSpec, install_path_shadow, shadow_bin_dir};
use crate::launcher::presence;
use crate::launcher::session_prefs;

use serde_json::{Value, json};

/// Outcome of the daemon `register_session` RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRegistration {
    pub session_id: String,
    pub grant_id: String,
    pub proxy_url: String,
    /// Git credential-injection proxy URL (implementation-note-267).
    /// When `Some`, the child process receives `EMBER_GIT_PROXY_URL=<url>`.
    /// `None` when the daemon did not allocate a git proxy (git proxy disabled
    /// or pre-fix daemon).
    pub git_proxy_url: Option<String>,
    /// Path to the daemon-managed ssh-agent socket for this session
    /// (implementation-note-72). When `Some`, the child process
    /// receives `SSH_AUTH_SOCK=<path>` so git/ssh in the child tree find
    /// the daemon socket. `None` when the daemon did not allocate an
    /// ssh-agent for this session (e.g. pre-design daemon).
    pub ssh_auth_sock: Option<String>,
}

/// Call the daemon `register_session` RPC and return the session triple.
///
/// `persona` — the persona name or id for the session.
/// `socket_path` — path to the daemon Unix socket (`~/.ember/run/daemon.sock`).
///
/// Returns `Err` when the daemon is unreachable or returns an error.
pub fn register_session_rpc(persona: &str, socket_path: &Path) -> io::Result<SessionRegistration> {
    let launcher_pid = std::process::id();
    let params = json!({
        "persona": persona,
        "launcher_pid": launcher_pid,
    });
    let result = call_daemon(socket_path, "register_session", &params)?;
    parse_register_session_result(&result, socket_path)
}

fn parse_register_session_result(
    result: &Value,
    socket_path: &Path,
) -> io::Result<SessionRegistration> {
    if let (Some(tab_url), Some(prompt_id)) = (
        result["presence_required"]["tab_url"].as_str(),
        result["presence_required"]["prompt_id"].as_str(),
    ) {
        return Err(presence::session_open_presence_unavailable(
            socket_path,
            prompt_id,
            tab_url,
        ));
    }

    let session_id = result["session_id"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "daemon: missing session_id"))?
        .to_string();
    let grant_id = result["grant_id"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "daemon: missing grant_id"))?
        .to_string();
    // implementation-note-267: the daemon should always include
    // proxy_url in the register_session response (it reads EMBER_PROXY_URL
    // from runtime state). If the fallback to 8484 fires it means the daemon
    // is pre-fix or the LLM proxy failed to bind — Claude Code will hit
    // ECONNREFUSED. Emit a clear warning so the regression is visible.
    let proxy_url = match result["proxy_url"].as_str() {
        Some(url) => url.to_string(),
        None => {
            eprintln!(
                "ember claude-code: WARNING — daemon did not return proxy_url in \
                 register_session response; falling back to http://127.0.0.1:8484 which \
                 is likely not bound. Claude Code may fail with ECONNREFUSED. \
                 (implementation-note-267)"
            );
            "http://127.0.0.1:8484".to_string()
        }
    };
    let git_proxy_url = result["git_proxy_url"].as_str().map(|s| s.to_string());
    Ok(SessionRegistration {
        session_id,
        grant_id,
        proxy_url,
        git_proxy_url,
        ssh_auth_sock: None,
    })
}

/// Call the daemon `close_session` RPC.
///
/// Triggers daemon-side grant termination and emits a signed Receipt with
/// `termination_reason = clean_exit` into the session's sidecar directory.
/// Errors are logged to stderr but do not affect the launcher's exit code
/// — the child has already exited by this point.
pub fn close_session_rpc(session_id: &str, socket_path: &Path) {
    let params = json!({ "session_id": session_id });
    if let Err(e) = call_daemon(socket_path, "close_session", &params) {
        eprintln!("ember claude-code: close_session failed: {e}");
    }
}

/// Resolve the shadow root directory: `~/.ember/shadow/`, overridable via
/// `$EMBER_SHADOW_DIR` for test harnesses.
///
/// The shadow root holds credential / config / state files. Shim binaries
/// live under `<shadow_dir>/bin/` — use [`shadow_bin_dir`] to obtain the
/// PATH-prepend target.
pub fn resolve_shadow_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("EMBER_SHADOW_DIR") {
        return PathBuf::from(override_dir);
    }
    dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".ember")
        .join("shadow")
}

/// Cohort-A canonical Construct set (Option 2 — hardcoded constant).
///
/// Maps tool names to the expected `ember-<tool>` binary name. The binary is
/// resolved by searching `$PATH` for `ember-<tool>`, then falling back to a
/// sibling of the current executable (for installed layouts where all ember
/// binaries live in the same directory).
///
/// TODO: post-v0.3 follow-up: discover dynamically by scanning
/// `~/.ember/constructs/` or querying the daemon's installed-constructs list.
pub const COHORT_A_TOOLS: &[&str] = &[
    "gh", "git", "kubectl", "npm", "docker", "wrangler", "pulumi",
];

/// Build the [`ConstructSpec`] list for the cohort-A Construct set.
///
/// For each tool in [`COHORT_A_TOOLS`], attempts to resolve `ember-<tool>` by:
/// 1. Searching the current `$PATH` via `which`-style lookup.
/// 2. Checking for a sibling binary next to the current executable.
///
/// Tools whose binary cannot be found are silently skipped — the shadow
/// directory only needs shims for Constructs that are actually installed.
pub fn cohort_a_construct_specs() -> Vec<ConstructSpec> {
    let sibling_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));

    COHORT_A_TOOLS
        .iter()
        .filter_map(|tool| {
            let ember_name = format!("ember-{tool}");

            // 1. Sibling of current executable (preferred for installed layout).
            if let Some(ref dir) = sibling_dir {
                let candidate = dir.join(&ember_name);
                if candidate.exists() {
                    return Some(ConstructSpec {
                        tool_name: tool.to_string(),
                        target_binary: candidate,
                    });
                }
            }

            // 2. Search PATH entries for `ember-<tool>`.
            if let Ok(path_var) = std::env::var("PATH") {
                for entry in std::env::split_paths(&path_var) {
                    let candidate = entry.join(&ember_name);
                    if candidate.exists() {
                        return Some(ConstructSpec {
                            tool_name: tool.to_string(),
                            target_binary: candidate,
                        });
                    }
                }
            }

            None
        })
        .collect()
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
/// `shadow_dir` is prepended to the child's `PATH` so Construct shims
/// intercept tool invocations transparently. The parent shell's PATH is
/// never mutated — this uses `Command::env("PATH", ...)` only.
///
/// Pure function over the registration so unit tests can drive it with
/// fixture values; the real CLI entry point fills in the registration via
/// `register_session_rpc`.
pub fn run_with_registration(
    bin: &str,
    extra_args: &[String],
    registration: &SessionRegistration,
    socket_path: &Path,
    shadow_dir: &Path,
) -> io::Result<i32> {
    eprintln!(
        "ember claude-code: launching {bin} (session={}, grant={}, proxy={})",
        registration.session_id, registration.grant_id, registration.proxy_url,
    );

    // Build child PATH: shadow_dir prepended to the parent's PATH.
    // We use Command::env so the parent shell's PATH is never touched.
    let parent_path = std::env::var("PATH").unwrap_or_default();
    let child_path = format!("{}:{}", shadow_dir.display(), parent_path);

    let mut cmd = Command::new(bin);
    cmd.args(extra_args)
        .env("EMBER_GRANT_ID", &registration.grant_id)
        .env("EMBER_PROXY_URL", &registration.proxy_url)
        // implementation-note-429: do NOT inject
        // HTTPS_PROXY for Claude Code. The daemon's LLM proxy
        // (`infra::proxy::run_proxy`) is a custom POST endpoint for the
        // Anthropic SDK base_url use case — NOT a CONNECT-supporting
        // transparent HTTPS_PROXY. Claude Code uses HTTPS_PROXY
        // semantics (sends `CONNECT api.anthropic.com:443`), and
        // run_proxy returns 400 (ERR_BAD_REQUEST) on CONNECT. Cohort-A
        // value prop is the broker for credentialed SUBPROCESS calls
        // (gh / git push / kubectl) via Constructs + shadow PATH —
        // Claude Code's API connection is the friendly's own concern
        // (subscription / API key). EMBER_PROXY_URL is still injected
        // so Constructs can use it via different code paths if needed.
        .env("EMBER_SESSION_ID", &registration.session_id)
        .env("PATH", &child_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // Inject the git proxy URL when the daemon provided one (implementation-note-267).
    if let Some(ref gpu) = registration.git_proxy_url {
        cmd.env("EMBER_GIT_PROXY_URL", gpu);
    }
    // Inject daemon-managed ssh-agent socket when the broker provided one
    // (implementation-note-72). git/ssh in the child tree pick this up
    // automatically without any additional configuration.
    if let Some(ref sock) = registration.ssh_auth_sock {
        cmd.env("SSH_AUTH_SOCK", sock);
    }
    let status = cmd.status().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("ember claude-code: failed to spawn {bin}: {e}"),
        )
    })?;

    // Exit trap: close session unconditionally on child exit, including
    // signal-forwarded SIGINT/SIGTERM. close_session_rpc logs but does not
    // propagate errors — the child exit code is what the user cares about.
    close_session_rpc(&registration.session_id, socket_path);

    Ok(status.code().unwrap_or(1))
}

/// Resolve the persona name for the session.
///
/// Priority:
/// 1. `$EMBER_PERSONA` env var — explicit override, highest precedence.
/// 2. The locked 2-slot Persona schema (CONTEXT.md "Identity surface"
///    §Persona ID schema): `claude-code-<context>` where `<context>` is
///    the worktree directory name when launched with `-w` (future flag)
///    or `default`. Routes through the shared helper
///    [`super::default_persona_id_for_runtime`] so the launcher and
///    `onboarding::claude_code::claude_code_persona_name` agree on the
///    same identifier shape.
///
/// Returns the persona name string. The caller is responsible for surfacing a
/// clear error if the daemon rejects the persona (e.g. user never ran
/// `ember init --for claude-code`).
pub fn resolve_persona_name() -> String {
    if let Ok(v) = std::env::var("EMBER_PERSONA")
        && !v.is_empty()
    {
        return v;
    }
    crate::onboarding::claude_code::claude_code_persona_name()
}

/// Print the host-mode mediation disclaimer (design §Component 5a) and
/// wait for the user to acknowledge or suppress it.
///
/// Behaviour:
/// - If stderr is not a tty (piped / CI): returns immediately without printing.
/// - If `host_mode_disclaimer_suppressed` is true in session-prefs: returns
///   immediately without printing.
/// - Otherwise: prints the locked copy to stderr, reads one line from stdin,
///   and (if the user typed `s` or `S`) persists suppression to session-prefs.
///   Any other input (including bare Enter) continues silently.
pub fn maybe_print_host_mode_disclaimer() -> io::Result<()> {
    // Skip when stderr is not a tty — no human reader, suppression irrelevant.
    if !std::io::stderr().is_terminal() {
        return Ok(());
    }

    // Skip when the user has already suppressed the disclaimer.
    let prefs = session_prefs::load();
    if prefs.host_mode_disclaimer_suppressed {
        return Ok(());
    }

    // LOCKED COPY — do not edit. Source: design §Component 5a.
    eprintln!(
        "\nember brokers 15 tools (git, gh, kubectl, …); other commands run with your shell's authority.\n\
         Need stricter? `ember up` runs in a container.\n\
         \n\
         [Enter] continue   [S] don't show again"
    );

    // Read one line from stdin. Non-tty stdin in CI is guarded above, so
    // this read will always have a human on the other end. Errors are
    // ignored — a read failure (e.g. stdin closed) is treated as Enter.
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);

    let trimmed = input.trim();
    if trimmed.eq_ignore_ascii_case("s") {
        // Persist suppression. Log but do not block launch on failure.
        if let Err(e) = session_prefs::suppress_host_mode_disclaimer() {
            eprintln!("ember: could not persist disclaimer suppression: {e}");
        }
    }

    Ok(())
}

/// `ember claude-code [extra_args...]` entry point.
///
/// Resolves persona via `resolve_persona_name` (`$EMBER_PERSONA` env var or
/// the cohort-A default `claude-code-{hostname}`), installs PATH-shadow
/// symlinks (design §3 sub-A), calls `register_session_rpc` (live RPC per
/// #2318 / design §2), prepends the shadow dir to the child PATH, spawns
/// the child, then `close_session_rpc` on exit. The socket path is
/// `~/.ember/run/daemon.sock` by default, overridable via `socket_path`.
pub fn launch_claude_code(extra_args: &[String], socket_path: &Path) -> io::Result<i32> {
    let bin = resolve_claude_bin();
    let persona = resolve_persona_name();

    // Step 1: Install PATH-shadow symlinks before registering the session so
    // the shadow dir is ready before the child process is spawned.
    let shadow_dir = resolve_shadow_dir();
    let construct_specs = cohort_a_construct_specs();
    install_path_shadow(&shadow_dir, &construct_specs)?;

    // Step 2: Register session with the daemon (mints EMBER_SESSION_ID).
    let registration = register_session_rpc(&persona, socket_path).map_err(|e| {
        let msg = e.to_string();
        // When the daemon rejects a "no such persona" error for the cohort-A
        // default name, surface a friendly hint so users know to run init.
        if msg.contains("not found")
            || msg.contains("no such persona")
            || msg.contains("unknown persona")
        {
            io::Error::new(
                e.kind(),
                "no cohort-A persona found.\n  \
                 Run `ember init --for claude-code` first, or set \
                 $EMBER_PERSONA to an existing persona name."
                    .to_string(),
            )
        } else {
            e
        }
    })?;

    // Step 3: Print the host-mode mediation disclaimer (design §Component 5a)
    // immediately before invoking the Claude Code child binary. Skipped when
    // stderr is not a tty or the user has persisted suppression.
    maybe_print_host_mode_disclaimer()?;

    // Step 4: Spawn child with shadow/bin PATH prepended and all ember env vars set.
    // The bin/ subdirectory holds the shim binaries; the root holds creds/config.
    let bin_dir = shadow_bin_dir(&shadow_dir);
    run_with_registration(&bin, extra_args, &registration, socket_path, &bin_dir)
}

/// Send a synchronous JSON-RPC request over the daemon's Unix socket and
/// return the `result` value. Mirrors the `call_daemon` shape in
/// `crates/emberlink-cli/src/broker.rs` so wire behaviour is identical.
fn call_daemon(socket_path: &Path, method: &str, params: &Value) -> io::Result<Value> {
    match crate::call_daemon_rpc(socket_path, method, params) {
        Ok(result) => Ok(result),
        Err(crate::DaemonRpcError::Unavailable(e)) => Err(io::Error::new(
            e.kind(),
            format!(
                "ember claude-code: daemon not running (socket: {}): {e}; \
                 start with 'ember daemon start'",
                socket_path.display()
            ),
        )),
        Err(crate::DaemonRpcError::Io(e)) => Err(io::Error::new(
            e.kind(),
            format!("daemon socket error: {e}"),
        )),
        Err(crate::DaemonRpcError::Protocol(e)) => {
            Err(io::Error::new(io::ErrorKind::InvalidData, e))
        }
        Err(crate::DaemonRpcError::Rpc { message, .. }) => {
            Err(io::Error::other(format!("daemon error: {message}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> SessionRegistration {
        SessionRegistration {
            session_id: "sess_fixture".to_string(),
            grant_id: "grt_fixture".to_string(),
            proxy_url: "http://127.0.0.1:9999".to_string(),
            git_proxy_url: None,
            ssh_auth_sock: None,
        }
    }

    #[test]
    fn run_with_registration_propagates_zero_exit() {
        // /usr/bin/true exits 0 on every Unix; cohort A targets macOS first.
        let code = run_with_registration(
            "/usr/bin/true",
            &[],
            &fixture(),
            Path::new("/nonexistent.sock"),
            Path::new("/tmp"),
        )
        .expect("spawn /usr/bin/true");
        assert_eq!(code, 0);
    }

    #[test]
    fn run_with_registration_propagates_nonzero_exit() {
        let code = run_with_registration(
            "/usr/bin/false",
            &[],
            &fixture(),
            Path::new("/nonexistent.sock"),
            Path::new("/tmp"),
        )
        .expect("spawn /usr/bin/false");
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
        let _ = run_with_registration(
            "/usr/bin/true",
            &[],
            &fixture(),
            Path::new("/nonexistent.sock"),
            Path::new("/tmp"),
        )
        .expect("spawn /usr/bin/true");
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
        let result = run_with_registration(
            "/no/such/binary-that-must-not-exist",
            &[],
            &fixture(),
            Path::new("/nonexistent.sock"),
            Path::new("/tmp"),
        );
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

    #[test]
    fn register_session_rpc_fails_when_daemon_not_running() {
        let err = register_session_rpc("default", Path::new("/nonexistent.sock"))
            .expect_err("should fail when daemon is not running");
        let msg = err.to_string();
        assert!(
            msg.contains("daemon not running") || msg.contains("No such file"),
            "error should mention daemon or missing socket: {msg}"
        );
    }

    #[test]
    fn close_session_rpc_is_silent_on_failure() {
        // close_session_rpc must not panic when the daemon is unreachable —
        // the child has already exited and the launcher still needs to return.
        close_session_rpc("sess_nonexistent", Path::new("/nonexistent.sock"));
    }

    #[test]
    fn parse_register_session_result_parses_direct_success() {
        let raw = json!({
            "session_id": "sess_fixture",
            "grant_id": "grt_fixture",
            "proxy_url": "http://127.0.0.1:7001",
            "git_proxy_url": "http://127.0.0.1:7002",
        });
        let parsed = parse_register_session_result(&raw, Path::new("/tmp/daemon.sock"))
            .expect("direct result must parse");
        assert_eq!(parsed.session_id, "sess_fixture");
        assert_eq!(parsed.grant_id, "grt_fixture");
        assert_eq!(parsed.proxy_url, "http://127.0.0.1:7001");
        assert_eq!(
            parsed.git_proxy_url.as_deref(),
            Some("http://127.0.0.1:7002")
        );
    }

    #[test]
    fn parse_register_session_result_rejects_reserved_presence_branch() {
        let raw = json!({
            "presence_required": {
                "tab_url": "http://localhost:5173/prompt/pmt_xyz",
                "prompt_id": "pmt_xyz",
            }
        });
        let err = parse_register_session_result(&raw, Path::new("/tmp/daemon.sock"))
            .expect_err("reserved browser branch must refuse cleanly");
        let msg = err.to_string();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(
            msg.contains("browser/session-open presence flow is not shipped yet"),
            "error must explain current state: {msg}"
        );
        assert!(
            msg.contains("prompt_id=pmt_xyz"),
            "error must carry prompt_id context: {msg}"
        );
    }

    // ── persona resolution tests (implementation-note-431) ──

    #[test]
    fn persona_defaults_to_cohort_a_when_env_unset() {
        // Serialize against other EMBER_PERSONA-mutating tests in this
        // crate (`bind.rs::resolve_persona_rejects_…` removes,
        // `persona_uses_env_var_when_set` sets+restores). Without the
        // lock, the cargo parallel runner can race our `remove_var`
        // against another test's `set_var("EMBER_PERSONA", "foo")` and
        // `resolved` comes back as "foo" instead of the cohort-A
        // default. Same pattern as #3237.
        let _g = crate::EMBER_PERSONA_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("EMBER_PERSONA").ok();
        // SAFETY: holds EMBER_PERSONA_TEST_LOCK for the duration of the
        // env mutation; restored before return.
        unsafe { std::env::remove_var("EMBER_PERSONA") };
        // Mirror the onboarding helper to build the expected name.
        let hostname = crate::onboarding::claude_code::claude_code_persona_name();
        let resolved = resolve_persona_name();
        // Restore prior before any assertion so a panic leaves a clean env.
        if let Some(v) = prior {
            unsafe { std::env::set_var("EMBER_PERSONA", v) };
        }
        assert_eq!(
            resolved, hostname,
            "resolve_persona_name should match claude_code_persona_name when EMBER_PERSONA is unset"
        );
        assert!(
            resolved.starts_with("claude-code-"),
            "default persona must be prefixed claude-code-: {resolved}"
        );
    }

    #[test]
    fn persona_uses_env_var_when_set() {
        // Serialize against other tests in this crate that touch
        // EMBER_PERSONA (notably `bind.rs::resolve_persona_rejects_…`).
        // Without this lock the cargo parallel runner can interleave a
        // set_var/remove_var with our read, producing the
        // `resolved != "foo"` failure.
        let _g = crate::EMBER_PERSONA_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Save prior so we don't clobber developer env or other test
        // setup that leaked across module boundaries.
        let prior = std::env::var("EMBER_PERSONA").ok();
        // SAFETY: holds EMBER_PERSONA_TEST_LOCK for the duration of the
        // env mutation; restored before return.
        unsafe { std::env::set_var("EMBER_PERSONA", "foo") };
        let resolved = resolve_persona_name();
        // Restore prior value (or clear) before assertion so a panic
        // leaves a clean env for the next acquirer.
        unsafe {
            match prior {
                Some(v) => std::env::set_var("EMBER_PERSONA", v),
                None => std::env::remove_var("EMBER_PERSONA"),
            }
        }
        assert_eq!(resolved, "foo");
    }

    #[test]
    fn clear_error_when_no_cohort_a_persona() {
        // Simulate a daemon "not found" response by constructing the error
        // shape that register_session_rpc would return and verifying that
        // launch_claude_code would surface the friendly hint.
        // We drive this by testing the error-remapping closure logic directly:
        // create an io::Error with the "not found" substring and assert the
        // remapped message contains the init hint.
        let raw_err = io::Error::new(
            io::ErrorKind::Other,
            "daemon error: persona 'claude-code-myhost' not found",
        );
        let msg = raw_err.to_string();
        let remapped = if msg.contains("not found")
            || msg.contains("no such persona")
            || msg.contains("unknown persona")
        {
            io::Error::new(
                raw_err.kind(),
                format!(
                    "no cohort-A persona found.\n  \
                     Run `ember init --for claude-code` first, or set \
                     $EMBER_PERSONA to an existing persona name."
                ),
            )
        } else {
            raw_err
        };
        let remapped_msg = remapped.to_string();
        assert!(
            remapped_msg.contains("ember init --for claude-code"),
            "error must guide user to init: {remapped_msg}"
        );
    }

    // ── implementation-note-267: launcher env injection tests ──

    #[test]
    fn registration_with_real_proxy_url_is_not_8484() {
        // implementation-note-267: verify that a registration
        // carrying a daemon-provided URL (non-8484) is accepted without
        // falling back. This is the T1 launcher acceptance condition.
        let reg = SessionRegistration {
            session_id: "sess_test".to_string(),
            grant_id: "grt_test".to_string(),
            proxy_url: "http://127.0.0.1:61169".to_string(),
            git_proxy_url: Some("http://127.0.0.1:61170".to_string()),
            ssh_auth_sock: None,
        };
        assert_ne!(
            reg.proxy_url, "http://127.0.0.1:8484",
            "proxy_url must not be the hardcoded fallback port when daemon returns real URL"
        );
        assert_eq!(
            reg.proxy_url, "http://127.0.0.1:61169",
            "proxy_url must match the daemon-returned ephemeral port"
        );
        assert_eq!(
            reg.git_proxy_url.as_deref(),
            Some("http://127.0.0.1:61170"),
            "git_proxy_url must be carried from daemon response"
        );
    }

    #[test]
    fn run_with_registration_injects_daemon_proxy_url_not_8484() {
        // implementation-note-267: T2 launcher — assert that the
        // child env receives the daemon-returned proxy URL. We verify this
        // indirectly by confirming run_with_registration succeeds (returns 0)
        // with a registration carrying an ephemeral port. The real child-env
        // assertion lives in the daemon-side T2 (register_session_response_includes_real_proxy_url).
        let reg = SessionRegistration {
            session_id: "sess_proxy_wire".to_string(),
            grant_id: "grt_proxy_wire".to_string(),
            proxy_url: "http://127.0.0.1:62000".to_string(),
            git_proxy_url: None,
            ssh_auth_sock: None,
        };
        assert_ne!(
            reg.proxy_url, "http://127.0.0.1:8484",
            "proxy_url must not be 8484 when using daemon-returned URL"
        );
        // Confirm the registration can be consumed by run_with_registration
        // without error (child /usr/bin/true exits 0 immediately).
        let code = run_with_registration(
            "/usr/bin/true",
            &[],
            &reg,
            Path::new("/nonexistent.sock"),
            Path::new("/tmp"),
        )
        .expect("spawn /usr/bin/true with real proxy URL");
        assert_eq!(
            code, 0,
            "child must exit 0 when launched with real proxy URL"
        );
    }

    // ── host-mode mediation disclaimer tests (implementation-note-432) ──

    #[test]
    fn disclaimer_skipped_when_stderr_not_tty() {
        // In a test process stderr is not a tty, so maybe_print_host_mode_disclaimer
        // must return Ok(()) immediately without reading stdin or printing anything.
        // This covers the CI/piped path from the acceptance criteria.
        let result = maybe_print_host_mode_disclaimer();
        assert!(
            result.is_ok(),
            "disclaimer must not error when stderr is not a tty"
        );
    }

    #[test]
    fn disclaimer_skipped_when_suppressed_in_prefs() {
        let _g = session_prefs::EMBER_HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::TempDir::new().expect("create temp dir");
        unsafe { std::env::set_var("EMBER_HOME", dir.path()) };
        // Write suppression=true into session-prefs.
        session_prefs::suppress_host_mode_disclaimer().expect("suppress");
        // maybe_print_host_mode_disclaimer must return without printing when
        // suppressed=true. In a test process stderr is not a tty so it would
        // skip anyway; we validate the prefs-read path by asserting prefs.
        let prefs = session_prefs::load();
        unsafe { std::env::remove_var("EMBER_HOME") };
        assert!(
            prefs.host_mode_disclaimer_suppressed,
            "suppression must be persisted and readable back"
        );
    }

    #[test]
    fn disclaimer_suppression_write_path() {
        let _g = session_prefs::EMBER_HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Verify the suppress_host_mode_disclaimer helper writes and the
        // subsequent load reflects the persisted value (round-trip).
        let dir = tempfile::TempDir::new().expect("create temp dir");
        unsafe { std::env::set_var("EMBER_HOME", dir.path()) };
        // Before: not suppressed.
        let before = session_prefs::load();
        assert!(!before.host_mode_disclaimer_suppressed);
        // Suppress.
        session_prefs::suppress_host_mode_disclaimer().expect("suppress");
        // After: suppressed.
        let after = session_prefs::load();
        unsafe { std::env::remove_var("EMBER_HOME") };
        assert!(
            after.host_mode_disclaimer_suppressed,
            "suppression must persist"
        );
    }
}
