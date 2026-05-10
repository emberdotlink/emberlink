//! Per-Construct runtime: env-detect → classify → broker.resolve → broker.exec.
//!
//! Two entry points:
//!
//! - [`run_construct`] — stub lifecycle used by tests and future stub-mode
//!   callers. Takes a [`ConstructSpec`] value; steps 3–4 are not yet wired.
//! - [`run_construct_full`] — full PTY lifecycle (env-detect → classify →
//!   broker_exec RPC → PTY bridge → exit). Takes a [`ConstructConfig`] impl.
//!   This is the entry point used by production Construct shims (ember-gh etc.).

use std::io::IsTerminal;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::json;

use crate::{ClassifyArgv, ConstructConfig};

// ---------------------------------------------------------------------------
// TTY detection helper
// ---------------------------------------------------------------------------

/// Detect whether the parent process attached a TTY to any of the standard
/// streams. Per T-CONSTRUCT-RUNTIME-NON-TTY-DETECTION, when none of stdin /
/// stdout / stderr have a TTY parent (headless, CI, headless cron, `docker
/// run` without `-t`), the shim must skip PTY allocation and let the daemon
/// run the child with `Stdio::piped()` so the bridge thread doesn't die on
/// stdin EOF and SIGTERM-cascade the spawned tool.
fn parent_has_tty() -> bool {
    std::io::stdin().is_terminal()
        || std::io::stdout().is_terminal()
        || std::io::stderr().is_terminal()
}

/// Build the `broker_exec` JSON-RPC params object.
///
/// Factored out so the non-TTY path is observable in unit tests: when
/// `pty_socket_path` is `None`, the resulting JSON does not contain a
/// `pty_socket_path` key, which the daemon's `handle_broker_exec` reads as
/// "take the piped-stderr branch" (per `crates/ember-daemon/src/broker/handler.rs`
/// ~1699-1740: `if let Some(ref socket_path) = req.pty_socket_path { … } else { … }`).
fn build_broker_exec_params(
    binary: &str,
    argv: &[String],
    env_passthrough: &[&'static str],
    pty_socket_path: Option<&std::path::Path>,
) -> serde_json::Value {
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/tmp".to_string());

    match pty_socket_path {
        Some(p) => json!({
            "binary": binary,
            "argv": argv,
            "cwd": cwd,
            "env_passthrough": env_passthrough,
            "pty_socket_path": p.to_string_lossy(),
        }),
        None => json!({
            "binary": binary,
            "argv": argv,
            "cwd": cwd,
            "env_passthrough": env_passthrough,
        }),
    }
}

// ---------------------------------------------------------------------------
// Stub lifecycle (run_construct + ConstructSpec)
// ---------------------------------------------------------------------------

/// Inputs for one [`run_construct`] invocation (stub lifecycle).
///
/// Each Construct binary builds one of these in `main()` and hands it to
/// [`run_construct`]. The fields capture the construct-specific bits
/// (classifier, manifest bytes, wrapped binary path) while the runtime
/// owns the lifecycle (env detect, broker calls, exit handling).
pub struct ConstructSpec<'a, C: ClassifyArgv> {
    /// Argv passed to this Construct (already stripped of argv[0]).
    pub argv: &'a [String],
    /// Construct-specific classifier (turns argv into an ActionKey).
    pub classifier: &'a C,
    /// Embedded `Construct.toml` bytes (for future broker.resolve payload).
    pub construct_toml_bytes: &'static [u8],
    /// Env var that signals we're inside an ember session — typically
    /// `"EMBER_SESSION_ID"`. If absent, we exec the wrapped binary directly.
    pub session_id_env: &'static str,
    /// Absolute path to the real tool, e.g. `"/usr/bin/gh"`.
    pub wrapped_binary: &'static str,
}

/// Stub entry point for Construct shims (steps 1–2 only; broker stubbed).
///
/// Returns the `ExitCode` to surface from `main`. See module docs for the
/// lifecycle stages and exit codes.
pub fn run_construct<C: ClassifyArgv>(spec: ConstructSpec<C>) -> ExitCode {
    // 1. env-detect: no session → passthrough exec the real tool.
    if std::env::var_os(spec.session_id_env).is_none() {
        let err = Command::new(spec.wrapped_binary).args(spec.argv).exec();
        // exec only returns on failure.
        eprintln!(
            "core-construct-runtime: failed to exec passthrough binary {:?}: {err}",
            spec.wrapped_binary
        );
        return ExitCode::from(126);
    }

    // 2. classify argv → ActionKey.
    let action_key = match spec.classifier.classify(spec.argv) {
        Some(k) => k,
        None => {
            eprintln!(
                "core-construct-runtime: classify failed for argv {:?}",
                spec.argv
            );
            return ExitCode::from(2);
        }
    };

    // 3. broker.resolve — STUB. Mirrors daemon's `-32001 NotSupported`
    //    in `crates/ember-daemon/src/broker_handler.rs::resolve_with_registry`.
    //    TODO: wire to daemon broker.resolve RPC,
    //    pass `spec.construct_toml_bytes` + `action_key` in the request.
    let _ = spec.construct_toml_bytes;
    eprintln!(
        "core-construct-runtime: broker.resolve not yet implemented \
         (implementation-note-11); action_key={action_key}"
    );

    // 4. broker.exec — STUB, unreachable while step 3 short-circuits.
    //    TODO: once broker.resolve returns a lease,
    //    spawn `spec.wrapped_binary` with the lease envelope and forward
    //    its exit status. Until then, step 3's `64` is what callers see.

    ExitCode::from(64)
}

// ---------------------------------------------------------------------------
// Full PTY lifecycle (run_construct_full + ConstructConfig)
// ---------------------------------------------------------------------------

/// Full lifecycle entry point for production Construct shims.
///
/// Drives env-detect → classify → broker_exec RPC → PTY bridge → exit.
/// The `config` parameter supplies all construct-specific details via the
/// [`ConstructConfig`] trait. `argv` is the process argv with argv[0] stripped.
pub fn run_construct_full<C: ConstructConfig>(argv: &[String], config: &C) -> ExitCode {
    // 1. env-detect: no session → passthrough exec.
    if std::env::var_os(config.session_id_env()).is_none() {
        let binary = config.resolve_binary();
        let err = Command::new(&binary).args(argv).exec();
        eprintln!("ember-construct: failed to exec {binary}: {err}");
        return ExitCode::from(126u8);
    }

    // 2. classify argv → action_key.
    //
    // The per-shim classifier returns `None` for read-only and safe-write
    // verbs that don't need broker mediation (per ember-git/src/classify.rs
    // docs: "Returns `None` for read-only and safe-write verbs (passthrough
    // — no broker mediation)"). Honour that intent: fall through to direct
    // exec instead of aborting, mirroring the env-detect passthrough above.
    //
    // Trade-off: passthrough exec skips the daemon's
    // `session.construct_invocation` receipt for these verbs. Acceptable
    // because they're local-only / read-only and the daemon's per-action
    // policy gate doesn't have anything to enforce on them. If uniform
    // observability becomes load-bearing, the per-shim classifier should
    // return `Some(git.<verb>)` for read-only verbs (mirroring the
    // daemon-side `ember_construct::GitClassifier`'s "always
    // classify" behaviour) so they round-trip through broker_exec.
    let classified = match config.classify(argv) {
        Some(k) => k,
        None => {
            tracing::debug!(
                argv = ?argv,
                "ember-construct: classify=None; passthrough exec (no broker mediation)"
            );
            let binary = config.resolve_binary();
            let err = Command::new(&binary).args(argv).exec();
            eprintln!("ember-construct: failed to exec {binary}: {err}");
            return ExitCode::from(126u8);
        }
    };

    tracing::info!(
        action_key = %classified,
        "ember-construct: dispatching via broker.exec"
    );

    let grant_id = std::env::var("EMBER_GRANT_ID").ok();
    tracing::info!(
        action_key = %classified,
        grant_id = ?grant_id,
        "ember-construct: broker.resolve+exec"
    );

    // 3. Resolve daemon socket and binary.
    let socket_path = crate::rpc::daemon_socket_path();
    let binary = config.resolve_binary();

    // 4. Decide whether to allocate a PTY.
    //
    // T-CONSTRUCT-RUNTIME-NON-TTY-DETECTION: when the parent has NO TTY on
    // any of stdin/stdout/stderr (headless, CI, headless cron, `docker run`
    // without `-t`, non-interactive `nohup`), skip the PTY socket entirely
    // and send `pty_socket_path: None` so the daemon takes its piped-stderr
    // path. The PTY bridge thread would otherwise die on stdin EOF and the
    // daemon's shim-EOF policy would SIGTERM-cascade the child.
    //
    // When at least one stream has a TTY, keep the existing PTY allocation
    // path verbatim so interactive `ember-git status`, `ember-gh pr view`
    // etc. continue to work.
    let pty_socket_path: Option<PathBuf> = if parent_has_tty() {
        Some(PathBuf::from(format!(
            "/tmp/ember-construct-pty-{}.sock",
            std::process::id()
        )))
    } else {
        tracing::debug!(
            "ember-construct: parent has no TTY; skipping PTY allocation"
        );
        None
    };

    // 5. Bind the PTY listener and spawn the bridge thread (TTY path only).
    //    The daemon connects to this path immediately after forkpty, so we
    //    must bind before sending the RPC.
    let bridge_handle = if let Some(ref pty_sock_path) = pty_socket_path {
        let _ = std::fs::remove_file(pty_sock_path);

        let listener = match UnixListener::bind(pty_sock_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!(
                    "ember-construct: failed to bind PTY socket {}: {e}",
                    pty_sock_path.display()
                );
                return ExitCode::from(1u8);
            }
        };
        let _ = std::fs::set_permissions(
            pty_sock_path,
            std::fs::Permissions::from_mode(0o600),
        );

        // Install signal handlers.
        #[cfg(unix)]
        crate::pty_bridge::install_signal_handlers();

        // Spawn the PTY bridge thread.
        let done = Arc::new(Mutex::new(false));
        let done_clone = Arc::clone(&done);
        let bridge_thread = thread::spawn(move || {
            crate::pty_bridge::pty_bridge_client(listener, done_clone);
        });

        // Set stdin non-blocking for the bridge pump loop.
        unsafe {
            let flags = libc::fcntl(0 /* stdin fd */, libc::F_GETFL, 0);
            if flags >= 0 {
                libc::fcntl(0, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }

        Some((bridge_thread, done))
    } else {
        None
    };

    // 6. Send broker_exec RPC to the daemon. On the non-TTY path, omit
    //    `pty_socket_path` so the daemon's `handle_broker_exec` takes its
    //    piped-stderr branch and returns the captured tail in `stderr_tail`.
    let params = build_broker_exec_params(
        &binary,
        argv,
        config.env_passthrough(),
        pty_socket_path.as_deref(),
    );

    let result = crate::rpc::call_daemon_rpc(&socket_path, "broker_exec", &params);

    // 7. Signal the bridge thread that the child has exited (TTY path only).
    if let Some((bridge_thread, done)) = bridge_handle {
        if let Ok(mut d) = done.lock() {
            *d = true;
        }
        let _ = bridge_thread.join();
    }

    // Cleanup temp socket (no-op when non-TTY path skipped the bind).
    if let Some(ref pty_sock_path) = pty_socket_path {
        let _ = std::fs::remove_file(pty_sock_path);
    }

    // 8. Propagate exit code from child.
    match result {
        Ok(resp) => {
            let stderr_tail = resp
                .get("stderr_tail")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !stderr_tail.is_empty() {
                eprint!("{stderr_tail}");
            }

            let exit_code = resp
                .get("exit_code")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);

            tracing::info!(
                exit_code = exit_code,
                action_key = %classified,
                "ember-construct: child exited"
            );

            if exit_code < 0 {
                ExitCode::from(1u8)
            } else {
                ExitCode::from(exit_code.min(255) as u8)
            }
        }
        Err(crate::rpc::RpcError::DaemonUnavailable(msg)) => {
            eprintln!("ember-construct: daemon unavailable — {msg}");
            eprintln!("ember-construct: start emberd with 'ember daemon start'");
            ExitCode::from(2u8)
        }
        Err(crate::rpc::RpcError::DaemonRpc { code, message }) => {
            eprintln!("ember-construct: broker_exec rejected (code={code}): {message}");
            ExitCode::from(1u8)
        }
        Err(e) => {
            eprintln!("ember-construct: broker_exec error: {e}");
            ExitCode::from(1u8)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (stub lifecycle)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ActionKey;

    struct MockClassifier {
        result: Option<ActionKey>,
    }

    impl ClassifyArgv for MockClassifier {
        fn classify(&self, _argv: &[String]) -> Option<ActionKey> {
            self.result.clone()
        }
    }

    // These tests mutate process-global env vars, so they must run on the
    // same thread to avoid stomping each other. Cargo runs tests in parallel
    // by default; we serialize via a mutex.
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const TEST_ENV: &str = "EMBER_SESSION_ID_CCR_TEST";

    #[test]
    fn env_absent_attempts_passthrough_exec() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: tests are serialized via ENV_LOCK; remove_var is sound here.
        unsafe {
            std::env::remove_var(TEST_ENV);
        }

        let classifier = MockClassifier {
            result: Some(ActionKey("test.action".to_string())),
        };
        let argv: Vec<String> = vec!["--help".to_string()];
        let spec = ConstructSpec {
            argv: &argv,
            classifier: &classifier,
            construct_toml_bytes: b"",
            session_id_env: TEST_ENV,
            // A path that definitely does not exist → exec fails → 126.
            wrapped_binary: "/usr/bin/false-fake-ccr-test-nonexistent",
        };

        let code = run_construct(spec);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(126)));
    }

    #[test]
    fn env_present_classify_some_returns_stub_64() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(TEST_ENV, "session-abc");
        }

        let classifier = MockClassifier {
            result: Some(ActionKey("test.action".to_string())),
        };
        let argv: Vec<String> = vec!["pr".to_string(), "create".to_string()];
        let spec = ConstructSpec {
            argv: &argv,
            classifier: &classifier,
            construct_toml_bytes: b"",
            session_id_env: TEST_ENV,
            wrapped_binary: "/usr/bin/false-fake-ccr-test-nonexistent",
        };

        let code = run_construct(spec);

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(TEST_ENV);
        }

        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(64)));
    }

    #[test]
    fn env_present_classify_none_returns_2() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(TEST_ENV, "session-abc");
        }

        let classifier = MockClassifier { result: None };
        let argv: Vec<String> = vec!["weird".to_string()];
        let spec = ConstructSpec {
            argv: &argv,
            classifier: &classifier,
            construct_toml_bytes: b"",
            session_id_env: TEST_ENV,
            wrapped_binary: "/usr/bin/false-fake-ccr-test-nonexistent",
        };

        let code = run_construct(spec);

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(TEST_ENV);
        }

        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(2)));
    }

    // -----------------------------------------------------------------------
    // Non-TTY detection (T-CONSTRUCT-RUNTIME-NON-TTY-DETECTION)
    // -----------------------------------------------------------------------

    /// `build_broker_exec_params` MUST omit `pty_socket_path` when the caller
    /// passes `None`. The daemon's `handle_broker_exec` reads
    /// `req.pty_socket_path.is_some()` to choose between the forkpty bridge
    /// path and the piped-stderr path (per
    /// `crates/ember-daemon/src/broker/handler.rs` ~1699). If we leak a
    /// `pty_socket_path: ""` (or a stale path) into the JSON, the daemon
    /// takes the wrong branch and the bridge-EOF cascade still fires.
    #[test]
    fn build_broker_exec_params_no_pty_omits_key() {
        let argv = vec!["push".to_string(), "origin".to_string()];
        let env_pt: &[&'static str] = &["GIT_TOKEN"];
        let params = build_broker_exec_params("/usr/bin/git", &argv, env_pt, None);

        let obj = params.as_object().expect("params should be a JSON object");
        assert!(
            !obj.contains_key("pty_socket_path"),
            "non-TTY path must omit pty_socket_path; got {params:?}"
        );
        // Sanity: the rest of the contract is preserved.
        assert_eq!(obj["binary"], "/usr/bin/git");
        assert_eq!(obj["argv"], json!(["push", "origin"]));
        assert_eq!(obj["env_passthrough"], json!(["GIT_TOKEN"]));
    }

    /// TTY path (caller passes `Some(path)`) MUST include `pty_socket_path`
    /// verbatim — this is the existing interactive contract that ember-git /
    /// ember-gh rely on for terminal-attached operator use.
    #[test]
    fn build_broker_exec_params_with_pty_includes_key() {
        let argv = vec!["status".to_string()];
        let env_pt: &[&'static str] = &[];
        let p = std::path::PathBuf::from("/tmp/ember-construct-pty-test.sock");
        let params = build_broker_exec_params("/usr/bin/git", &argv, env_pt, Some(&p));

        let obj = params.as_object().expect("params should be a JSON object");
        assert_eq!(
            obj.get("pty_socket_path").and_then(|v| v.as_str()),
            Some("/tmp/ember-construct-pty-test.sock"),
        );
    }

    /// Stub `ConstructConfig` for `run_construct_full` exercise. The wrapped
    /// binary is intentionally a path that does not exist; we never execute
    /// it because the env-detect branch fires (or, when EMBER_SESSION_ID is
    /// set, the broker_exec RPC fails with DaemonUnavailable).
    struct StubConfig {
        env: &'static str,
    }

    impl ClassifyArgv for StubConfig {
        fn classify(&self, _argv: &[String]) -> Option<ActionKey> {
            Some(ActionKey("git.push".to_string()))
        }
    }

    impl ConstructConfig for StubConfig {
        fn session_id_env(&self) -> &'static str {
            self.env
        }
        fn construct_toml_bytes(&self) -> &'static [u8] {
            b""
        }
        fn resolve_binary(&self) -> String {
            // Doesn't matter — daemon RPC fails before we'd exec anything.
            "/usr/bin/false-fake-ccr-test-nonexistent".to_string()
        }
        fn env_passthrough(&self) -> &'static [&'static str] {
            &[]
        }
    }

    /// When the parent has no TTY, `run_construct_full` MUST NOT bind a UDS
    /// at `/tmp/ember-construct-pty-<pid>.sock`. We exercise the function
    /// against a daemon socket that doesn't exist; the call returns
    /// DaemonUnavailable and we verify the side effects on the filesystem.
    ///
    /// This test relies on `cargo test` running with stdin/stdout/stderr
    /// detached from a TTY (the normal case for CI and `cargo test`
    /// invocations from non-interactive shells). If a developer runs the
    /// test from an interactive terminal that gives the test process a TTY,
    /// the test is skipped — see the early `parent_has_tty()` check.
    #[test]
    fn run_construct_full_no_tty_skips_pty_bind() {
        if parent_has_tty() {
            // Interactive runner — non-TTY behaviour is impossible to assert
            // here without redirecting stdio, which is fragile inside cargo
            // test. The test is meaningful in CI / non-interactive runs and
            // serves as a regression checkpoint there.
            eprintln!(
                "run_construct_full_no_tty_skips_pty_bind: skipped (parent has TTY)"
            );
            return;
        }

        let _guard = ENV_LOCK.lock().unwrap();

        // Force run_construct_full past env-detect and classify, into the
        // broker_exec RPC. Use a unique env var so we don't collide with
        // other tests' EMBER_SESSION_ID setup.
        let env_var = "EMBER_SESSION_ID_NON_TTY_TEST";
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(env_var, "session-non-tty");
            // Point the daemon-socket resolver at a path that doesn't exist
            // so `call_daemon_rpc` returns DaemonUnavailable instead of
            // hanging on a real daemon.
            std::env::set_var(
                "EMBER_SOCKET_PATH",
                "/tmp/ember-construct-runtime-non-tty-test-NONEXISTENT.sock",
            );
        }

        let pty_path = std::path::PathBuf::from(format!(
            "/tmp/ember-construct-pty-{}.sock",
            std::process::id()
        ));
        // Pre-clean — if a stale file exists from a prior aborted run, drop
        // it so the assertion is meaningful.
        let _ = std::fs::remove_file(&pty_path);

        let config = StubConfig { env: env_var };
        let argv: Vec<String> = vec!["push".to_string(), "origin".to_string()];
        let _exit = run_construct_full(&argv, &config);

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(env_var);
            std::env::remove_var("EMBER_SOCKET_PATH");
        }

        assert!(
            !pty_path.exists(),
            "non-TTY run_construct_full must not bind {} (file present after call)",
            pty_path.display(),
        );
    }
}
