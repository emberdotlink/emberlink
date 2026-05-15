//! Per-Construct runtime: env-detect → classify → broker.resolve → broker.exec.
//!
//! Two entry points:
//!
//! - [`run_construct`] — stub lifecycle used by tests and future stub-mode
//!   callers. Takes a [`ConstructSpec`] value; steps 3–4 are wired via
//!   [`resolve_via_broker`] + [`exec_via_broker`] against a pluggable
//!   [`BrokerTransport`] (production: [`DaemonRpcTransport`]; tests:
//!   in-memory mocks).
//! - [`run_construct_full`] — full PTY lifecycle (env-detect → classify →
//!   broker_exec RPC → PTY bridge → exit). Takes a [`ConstructConfig`] impl.
//!   This is the entry point used by production Construct shims (ember-gh etc.).
//!
//! ## Resolve → exec two-phase invariant (implementation-note-20)
//!
//! Per design §9, the construct shim MUST call `broker.resolve` BEFORE
//! `broker.exec`. Resolve returns a [`SpawnHandle`] binding the four
//! authority dimensions: `binary_path`, `env_allowlist`, `materialization_id`
//! (credential held in daemon memory; never plaintext over the shim wire),
//! and `target_uid` (the uid the daemon will drop privilege to before
//! `execve`). Exec consumes the handle. Daemon-side `credential_provisioned`
//! Receipt emits ONLY after resolve+exec succeed as a two-phase transaction.
//!
//! When resolve succeeds but exec is skipped or fails, the shim emits a
//! `credential_resolve_aborted` indicator (via [`BrokerTransport::abort_resolve`]),
//! so the daemon's audit chain shows the abort path instead of a false-
//! positive `credential_provisioned` (HIGH-E remediation).

use std::io::IsTerminal;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::json;

use crate::{ActionKey, ClassifyArgv, ConstructConfig};

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
// Two-phase resolve → exec (implementation-note-20)
// ---------------------------------------------------------------------------

/// Opaque spawn handle returned by [`resolve_via_broker`].
///
/// Binds the four authority dimensions per design §9: the absolute binary
/// path the daemon will `execve`, the env-var allowlist forwarded into the
/// child env, the `materialization_id` (the daemon's in-memory credential
/// reference — plaintext NEVER leaves the daemon over the shim wire), and
/// the `target_uid` the daemon drops privilege to before exec.
///
/// `exec_via_broker` consumes the handle by value so callers can't
/// double-spend a resolved lease across multiple exec calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnHandle {
    /// Absolute path to the wrapped binary (e.g. `/usr/bin/gh`). Echoed
    /// back to the shim so the daemon's resolve gate is the single
    /// authority on which binary the exec phase will run.
    pub binary: String,
    /// Env-var names the daemon will forward into the child env at exec
    /// time. Sourced from `construct.toml`'s per-action allowlist.
    pub env_allowlist: Vec<String>,
    /// Daemon-side credential reference. The plaintext credential stays
    /// in daemon memory; the shim only sees this opaque id. Surfaces as
    /// `secret_ref` on the broker_exec RPC so the daemon can re-look-up
    /// the credential without round-tripping plaintext.
    pub materialization_id: String,
    /// Uid the daemon drops privilege to before `execve`. `0` means
    /// "no privilege drop" (legacy / single-user surface); production
    /// SCION callers pass the agent-tier uid.
    pub target_uid: u32,
}

/// Errors surfaced by [`resolve_via_broker`] and [`exec_via_broker`].
#[derive(Debug)]
pub enum BrokerTransactionError {
    /// Daemon socket unreachable. Maps to `RpcError::DaemonUnavailable`.
    DaemonUnavailable(String),
    /// Daemon returned a JSON-RPC error from the resolve/exec method.
    DaemonRpc { code: i32, message: String },
    /// Wire / protocol corruption (malformed JSON, missing fields).
    Protocol(String),
    /// Local IO error before the request reached the daemon.
    Io(String),
}

impl std::fmt::Display for BrokerTransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DaemonUnavailable(s) => write!(f, "daemon unavailable: {s}"),
            Self::DaemonRpc { code, message } => {
                write!(f, "daemon rpc error {code}: {message}")
            }
            Self::Protocol(s) => write!(f, "protocol: {s}"),
            Self::Io(s) => write!(f, "io: {s}"),
        }
    }
}

impl From<crate::rpc::RpcError> for BrokerTransactionError {
    fn from(e: crate::rpc::RpcError) -> Self {
        match e {
            crate::rpc::RpcError::DaemonUnavailable(s) => Self::DaemonUnavailable(s),
            crate::rpc::RpcError::DaemonRpc { code, message } => {
                Self::DaemonRpc { code, message }
            }
            crate::rpc::RpcError::Protocol(s) => Self::Protocol(s),
            crate::rpc::RpcError::Io(s) => Self::Io(s),
        }
    }
}

/// Outcome of [`exec_via_broker`] — the exit code from the wrapped binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutcome {
    /// Process exit code. Negative when the child was killed by signal
    /// before exit; callers should map negative codes to `1` per the
    /// existing `run_construct_full` convention.
    pub exit_code: i64,
    /// Captured stderr tail from the daemon's piped-stderr branch.
    /// Empty on the PTY path. Forwarded to the shim's stderr before
    /// return so daemon-side error messages reach the operator.
    pub stderr_tail: String,
}

/// Audit indicator emitted by the shim after the resolve+exec transaction
/// completes (or aborts). Mirrors the daemon-side Receipt-kind catalog
/// (per design) so the construct shim's local observability and the
/// daemon's audit chain stay in lock-step.
///
/// - `CredentialProvisioned` — emitted ONLY when [`resolve_via_broker`]
///   AND [`exec_via_broker`] both succeed. False positives here would
///   poison the audit chain (HIGH-E in the design §9 review).
/// - `CredentialResolveAborted` — emitted when resolve succeeds but exec
///   is skipped or fails. The daemon-side counterpart is a follow-up
///   `broker_resolve_release` RPC that releases the in-memory credential
///   without ever marking it provisioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialAuditKind {
    /// Resolve + exec both succeeded — credential was actually used.
    CredentialProvisioned,
    /// Resolve succeeded but exec did not run to completion — credential
    /// is being torn down without a use record.
    CredentialResolveAborted,
}

impl CredentialAuditKind {
    /// Wire-format payload kind name. Matches the daemon's Receipt-kind
    /// catalog entries (design).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CredentialProvisioned => "credential_provisioned",
            Self::CredentialResolveAborted => "credential_resolve_aborted",
        }
    }
}

/// Transport contract for the construct shim's resolve → exec exchange.
///
/// Production callers use [`DaemonRpcTransport`] which dispatches over the
/// daemon UDS via `crate::rpc::call_daemon_rpc`. Tests inject in-memory
/// mocks to verify the resolve-before-exec ordering, the spawn-handle
/// binding shape, and the audit-kind emission discipline without standing
/// up a real daemon.
pub trait BrokerTransport {
    /// Phase 1 — resolve. Send the lease request to the daemon and
    /// receive a [`SpawnHandle`] bound to (binary, env_allowlist,
    /// materialization_id, target_uid). MUST be called before
    /// [`exec_via_broker`].
    fn resolve(
        &self,
        action_key: &ActionKey,
        binary: &str,
        env_passthrough: &[String],
        construct_toml_bytes: &[u8],
    ) -> Result<SpawnHandle, BrokerTransactionError>;

    /// Phase 2 — exec. Consume the spawn handle and run the wrapped
    /// binary under the daemon's supervision. Returns the child's
    /// [`ExecOutcome`] on success.
    fn exec(
        &self,
        handle: SpawnHandle,
        argv: &[String],
    ) -> Result<ExecOutcome, BrokerTransactionError>;

    /// Phase 1.5 — abort. Called by the shim when resolve succeeded but
    /// the exec phase did not run (or failed before completing). Releases
    /// the in-memory credential daemon-side and emits a
    /// `credential_resolve_aborted` Receipt instead of
    /// `credential_provisioned`. Best-effort: a transport error here is
    /// logged via tracing but does not propagate.
    fn abort_resolve(&self, handle: &SpawnHandle);
}

/// Phase 1: resolve via the daemon's `broker_resolve` RPC.
///
/// Sends a lease-request shape (action_key + binary + env_passthrough +
/// construct_toml_bytes) and receives a [`SpawnHandle`] binding
/// (binary, env_allowlist, materialization_id, target_uid). The
/// `materialization_id` carries the daemon's credential reference;
/// plaintext is NEVER returned over this RPC (per implementation-note-21-
/// SECRETREF-CONTRACT — only `handle_broker_resolve`'s legacy
/// secret-ref → plaintext path returns raw credentials, and that path
/// is gated to trust-boundary callers).
pub fn resolve_via_broker<T: BrokerTransport>(
    transport: &T,
    action_key: &ActionKey,
    binary: &str,
    env_passthrough: &[String],
    construct_toml_bytes: &[u8],
) -> Result<SpawnHandle, BrokerTransactionError> {
    transport.resolve(action_key, binary, env_passthrough, construct_toml_bytes)
}

/// Phase 2: exec via the daemon's `broker_exec` RPC.
///
/// Consumes the [`SpawnHandle`] returned by [`resolve_via_broker`].
/// Taking the handle by value enforces "handle is single-use" at the
/// type level — callers cannot double-spend a resolved lease across
/// multiple exec attempts.
pub fn exec_via_broker<T: BrokerTransport>(
    transport: &T,
    handle: SpawnHandle,
    argv: &[String],
) -> Result<ExecOutcome, BrokerTransactionError> {
    transport.exec(handle, argv)
}

/// Production [`BrokerTransport`] that dispatches to the daemon over UDS.
///
/// `resolve` sends a `broker_resolve` JSON-RPC with the lease-request
/// shape; `exec` sends a `broker_exec` JSON-RPC carrying the spawn
/// handle's `materialization_id` as `secret_ref` so the daemon
/// correlates the two phases. `abort_resolve` sends a follow-up
/// `broker_resolve_release` RPC; failures here are best-effort.
pub struct DaemonRpcTransport {
    pub socket_path: PathBuf,
}

impl DaemonRpcTransport {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }
}

impl BrokerTransport for DaemonRpcTransport {
    fn resolve(
        &self,
        action_key: &ActionKey,
        binary: &str,
        env_passthrough: &[String],
        construct_toml_bytes: &[u8],
    ) -> Result<SpawnHandle, BrokerTransactionError> {
        // Lease-request shape. The daemon's `resolve_with_registry`
        // recognises an absent `secret_ref` paired with a non-null
        // `lease_request` object as the construct-shim resolve path
        // (vs. the legacy secret_ref → plaintext path used by ember-
        // proxy / ember-tools, which is preserved verbatim).
        let params = json!({
            "lease_request": {
                "action_key": action_key.0,
                "binary": binary,
                "env_passthrough": env_passthrough,
                "construct_toml_hash_input_len": construct_toml_bytes.len(),
            }
        });
        let resp = crate::rpc::call_daemon_rpc(&self.socket_path, "broker_resolve", &params)?;

        let materialization_id = resp
            .get("materialization_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BrokerTransactionError::Protocol(
                    "broker_resolve response missing materialization_id".to_string(),
                )
            })?
            .to_string();

        // The daemon echoes the binary path so the shim cannot tamper
        // with it between resolve and exec (the daemon is the single
        // authority on which binary the exec phase actually runs).
        let resolved_binary = resp
            .get("binary")
            .and_then(|v| v.as_str())
            .unwrap_or(binary)
            .to_string();

        // Env-allowlist may be narrowed by the daemon (per-action
        // allowlist from construct.toml). When absent in the response,
        // fall back to what the shim requested.
        let env_allowlist: Vec<String> = resp
            .get("env_allowlist")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_else(|| env_passthrough.to_vec());

        let target_uid = resp
            .get("target_uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        Ok(SpawnHandle {
            binary: resolved_binary,
            env_allowlist,
            materialization_id,
            target_uid,
        })
    }

    fn exec(
        &self,
        handle: SpawnHandle,
        argv: &[String],
    ) -> Result<ExecOutcome, BrokerTransactionError> {
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/tmp".to_string());
        let params = json!({
            "binary": handle.binary,
            "argv": argv,
            "cwd": cwd,
            "env_passthrough": handle.env_allowlist,
            "secret_ref": handle.materialization_id,
            "target_uid": handle.target_uid,
        });
        let resp = crate::rpc::call_daemon_rpc(&self.socket_path, "broker_exec", &params)?;
        let exit_code = resp.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(0);
        let stderr_tail = resp
            .get("stderr_tail")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Ok(ExecOutcome {
            exit_code,
            stderr_tail,
        })
    }

    fn abort_resolve(&self, handle: &SpawnHandle) {
        let params = json!({
            "materialization_id": handle.materialization_id,
            "reason": "shim_aborted_before_exec",
        });
        match crate::rpc::call_daemon_rpc(
            &self.socket_path,
            "broker_resolve_release",
            &params,
        ) {
            Ok(_) => {
                tracing::debug!(
                    materialization_id = %handle.materialization_id,
                    "ember-construct: broker_resolve_release acknowledged"
                );
            }
            Err(e) => {
                // Best-effort: log and continue. The daemon's resolve-
                // pending state expires on its own watchdog timeout if
                // the shim disappears entirely.
                tracing::warn!(
                    materialization_id = %handle.materialization_id,
                    error = %e,
                    "ember-construct: broker_resolve_release failed (best-effort; daemon watchdog will reclaim)"
                );
            }
        }
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

/// Stub entry point for Construct shims, parameterised over the broker
/// transport. Production callers should prefer [`run_construct_full`];
/// this entry point exists for tests and stub-mode shims that don't need
/// the PTY bridge.
///
/// Drives env-detect → classify → resolve → exec. The resolve+exec pair
/// runs as a two-phase transaction:
///
/// 1. `resolve_via_broker` returns a [`SpawnHandle`] binding
///    (binary, env_allowlist, materialization_id, target_uid).
/// 2. `exec_via_broker` consumes the handle by value.
///
/// If resolve fails the shim exits before exec is touched.
/// If resolve succeeds but exec fails (or this function returns before
/// invoking exec for any reason), the shim calls
/// [`BrokerTransport::abort_resolve`] which signals the daemon to emit a
/// `credential_resolve_aborted` Receipt instead of
/// `credential_provisioned`. This is the HIGH-E remediation from the
/// design §9 review.
pub fn run_construct_with_transport<C: ClassifyArgv, T: BrokerTransport>(
    spec: ConstructSpec<C>,
    transport: &T,
) -> ExitCode {
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

    // 3. broker.resolve — phase 1. Receives a SpawnHandle binding
    //    (binary, env_allowlist, materialization_id, target_uid).
    let handle = match resolve_via_broker(
        transport,
        &action_key,
        spec.wrapped_binary,
        &[],
        spec.construct_toml_bytes,
    ) {
        Ok(h) => h,
        Err(BrokerTransactionError::DaemonUnavailable(msg)) => {
            eprintln!("core-construct-runtime: daemon unavailable — {msg}");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!(
                "core-construct-runtime: broker_resolve failed (action_key={action_key}): {e}"
            );
            return ExitCode::from(1);
        }
    };

    // 4. broker.exec — phase 2. Consumes the spawn handle. The handle
    //    is cloned before being moved into exec so we still hold the
    //    materialization_id for the abort path below.
    let abort_handle = handle.clone();
    let exec_result = exec_via_broker(transport, handle, spec.argv);
    let outcome = match exec_result {
        Ok(o) => o,
        Err(e) => {
            // Resolve succeeded, exec did not. Emit credential_resolve_
            // aborted instead of credential_provisioned.
            transport.abort_resolve(&abort_handle);
            eprintln!(
                "core-construct-runtime: broker_exec failed (action_key={action_key}): {e}"
            );
            return ExitCode::from(1);
        }
    };

    // 5. Propagate child exit code. The daemon emits
    //    credential_provisioned only after BOTH phases reach this point
    //    (its `broker_exec` handler holds the resolve→exec transaction).
    if !outcome.stderr_tail.is_empty() {
        eprint!("{}", outcome.stderr_tail);
    }
    if outcome.exit_code < 0 {
        ExitCode::from(1u8)
    } else {
        ExitCode::from(outcome.exit_code.min(255) as u8)
    }
}

/// Stub entry point for Construct shims using the production
/// [`DaemonRpcTransport`]. Wraps [`run_construct_with_transport`].
///
/// Returns the `ExitCode` to surface from `main`. See module docs for the
/// lifecycle stages and exit codes.
pub fn run_construct<C: ClassifyArgv>(spec: ConstructSpec<C>) -> ExitCode {
    let socket_path = crate::rpc::daemon_socket_path();
    let transport = DaemonRpcTransport::new(socket_path);
    run_construct_with_transport(spec, &transport)
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

    // 6. Translate emberlink-shaped argv to wrapped-tool-native argv
    //    (implementation-note-22 / Q5 grill-pair LOCK):
    //    `ConstructConfig::translate_argv` strips/renames emberlink-specific
    //    flags the upstream binary doesn't understand. Default is identity;
    //    scion strips `--persona`/`--max-depth`/`--brief`, renames
    //    `--template` → `--type`, injects `--non-interactive` for `start`.
    //
    //    Invariant: classify ran above on the EMBERLINK argv (so the action
    //    key reflects the originally-intended semantics); broker_exec runs
    //    below on the TRANSLATED argv (so the upstream binary sees only its
    //    own native vocabulary).
    //
    //    Anchor: construct_config_translate_argv_hook_landed.
    let translated_argv = config.translate_argv(argv);

    // 7. Send broker_exec RPC to the daemon. On the non-TTY path, omit
    //    `pty_socket_path` so the daemon's `handle_broker_exec` takes its
    //    piped-stderr branch and returns the captured tail in `stderr_tail`.
    let params = build_broker_exec_params(
        &binary,
        &translated_argv,
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

    // -----------------------------------------------------------------------
    // BrokerTransport mocks for the resolve→exec two-phase tests.
    // -----------------------------------------------------------------------

    /// In-memory transport that records the audit kind the shim would
    /// emit on the daemon side. The mock decides resolve / exec outcomes
    /// based on flags set by each test.
    struct MockTransport {
        resolve_outcome: std::sync::Mutex<ResolveOutcome>,
        exec_outcome: std::sync::Mutex<ExecOutcomeMock>,
        recorded: std::sync::Mutex<Vec<MockEvent>>,
    }

    #[derive(Clone)]
    enum ResolveOutcome {
        Ok(SpawnHandle),
        Err(BrokerTransactionError),
    }

    #[derive(Clone)]
    enum ExecOutcomeMock {
        Ok(ExecOutcome),
        Err(BrokerTransactionError),
    }

    /// Tagged trace of what the transport saw — used to assert the
    /// resolve-before-exec ordering and the abort-vs-provisioned
    /// audit-kind invariants.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[allow(clippy::enum_variant_names)]
    enum MockEvent {
        ResolveCalled { action_key: String, binary: String },
        ExecCalled { materialization_id: String },
        AbortCalled { materialization_id: String },
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                resolve_outcome: std::sync::Mutex::new(ResolveOutcome::Ok(SpawnHandle {
                    binary: "/usr/bin/mock-tool".to_string(),
                    env_allowlist: vec!["PATH".to_string()],
                    materialization_id: "mat-abc-123".to_string(),
                    target_uid: 1000,
                })),
                exec_outcome: std::sync::Mutex::new(ExecOutcomeMock::Ok(ExecOutcome {
                    exit_code: 0,
                    stderr_tail: String::new(),
                })),
                recorded: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn with_resolve(self, outcome: ResolveOutcome) -> Self {
            *self.resolve_outcome.lock().unwrap() = outcome;
            self
        }

        fn with_exec(self, outcome: ExecOutcomeMock) -> Self {
            *self.exec_outcome.lock().unwrap() = outcome;
            self
        }

        fn events(&self) -> Vec<MockEvent> {
            self.recorded.lock().unwrap().clone()
        }

        /// Derive the audit kind that should be emitted given the
        /// recorded events. Mirrors the daemon's transaction logic:
        /// resolve + exec both observed → `credential_provisioned`;
        /// resolve + abort observed → `credential_resolve_aborted`;
        /// neither → no audit.
        fn audit_kind(&self) -> Option<CredentialAuditKind> {
            let events = self.events();
            let resolved = events
                .iter()
                .any(|e| matches!(e, MockEvent::ResolveCalled { .. }));
            let executed = events
                .iter()
                .any(|e| matches!(e, MockEvent::ExecCalled { .. }));
            let aborted = events
                .iter()
                .any(|e| matches!(e, MockEvent::AbortCalled { .. }));
            if resolved && executed && !aborted {
                Some(CredentialAuditKind::CredentialProvisioned)
            } else if resolved && aborted {
                Some(CredentialAuditKind::CredentialResolveAborted)
            } else {
                None
            }
        }
    }

    impl BrokerTransport for MockTransport {
        fn resolve(
            &self,
            action_key: &ActionKey,
            binary: &str,
            _env_passthrough: &[String],
            _construct_toml_bytes: &[u8],
        ) -> Result<SpawnHandle, BrokerTransactionError> {
            self.recorded.lock().unwrap().push(MockEvent::ResolveCalled {
                action_key: action_key.0.clone(),
                binary: binary.to_string(),
            });
            match self.resolve_outcome.lock().unwrap().clone() {
                ResolveOutcome::Ok(h) => Ok(h),
                ResolveOutcome::Err(e) => Err(e),
            }
        }

        fn exec(
            &self,
            handle: SpawnHandle,
            _argv: &[String],
        ) -> Result<ExecOutcome, BrokerTransactionError> {
            self.recorded.lock().unwrap().push(MockEvent::ExecCalled {
                materialization_id: handle.materialization_id.clone(),
            });
            match self.exec_outcome.lock().unwrap().clone() {
                ExecOutcomeMock::Ok(o) => Ok(o),
                ExecOutcomeMock::Err(e) => Err(e),
            }
        }

        fn abort_resolve(&self, handle: &SpawnHandle) {
            self.recorded.lock().unwrap().push(MockEvent::AbortCalled {
                materialization_id: handle.materialization_id.clone(),
            });
        }
    }

    impl Clone for BrokerTransactionError {
        fn clone(&self) -> Self {
            match self {
                Self::DaemonUnavailable(s) => Self::DaemonUnavailable(s.clone()),
                Self::DaemonRpc { code, message } => Self::DaemonRpc {
                    code: *code,
                    message: message.clone(),
                },
                Self::Protocol(s) => Self::Protocol(s.clone()),
                Self::Io(s) => Self::Io(s.clone()),
            }
        }
    }

    /// implementation-note-20 acceptance 1+2:
    /// run_construct calls resolve_via_broker before exec_via_broker.
    /// The mock transport records the call order and the spawn handle
    /// must bind binary + env + credential + target_uid.
    #[test]
    fn run_construct_calls_resolve_before_exec() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(TEST_ENV, "session-abc");
        }

        let classifier = MockClassifier {
            result: Some(ActionKey("git.push".to_string())),
        };
        let argv: Vec<String> = vec!["push".to_string(), "origin".to_string()];
        let spec = ConstructSpec {
            argv: &argv,
            classifier: &classifier,
            construct_toml_bytes: b"",
            session_id_env: TEST_ENV,
            wrapped_binary: "/usr/bin/git",
        };

        let transport = MockTransport::new();
        let code = run_construct_with_transport(spec, &transport);

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(TEST_ENV);
        }

        // Exit code 0 — both phases succeeded.
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(0)));

        // Resolve must come first, exec must follow.
        let events = transport.events();
        assert_eq!(events.len(), 2, "expected resolve+exec only, got {events:?}");
        match &events[0] {
            MockEvent::ResolveCalled { action_key, binary } => {
                assert_eq!(action_key, "git.push");
                assert_eq!(binary, "/usr/bin/git");
            }
            other => panic!("first event should be ResolveCalled, got {other:?}"),
        }
        match &events[1] {
            MockEvent::ExecCalled { materialization_id } => {
                assert_eq!(materialization_id, "mat-abc-123");
            }
            other => panic!("second event should be ExecCalled, got {other:?}"),
        }

        // The transaction succeeded → credential_provisioned.
        assert_eq!(
            transport.audit_kind(),
            Some(CredentialAuditKind::CredentialProvisioned)
        );
    }

    /// implementation-note-20 acceptance 3:
    /// Receipt emitted only on resolve+exec succeeding as a transaction.
    /// When exec fails after a successful resolve, the audit kind is
    /// `credential_resolve_aborted`, never `credential_provisioned`.
    #[test]
    fn resolve_without_exec_triggers_credential_resolve_aborted() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(TEST_ENV, "session-abc");
        }

        let classifier = MockClassifier {
            result: Some(ActionKey("git.push".to_string())),
        };
        let argv: Vec<String> = vec!["push".to_string()];
        let spec = ConstructSpec {
            argv: &argv,
            classifier: &classifier,
            construct_toml_bytes: b"",
            session_id_env: TEST_ENV,
            wrapped_binary: "/usr/bin/git",
        };

        let transport = MockTransport::new().with_exec(ExecOutcomeMock::Err(
            BrokerTransactionError::DaemonRpc {
                code: -32003,
                message: "argv_classification_mismatch".to_string(),
            },
        ));
        let code = run_construct_with_transport(spec, &transport);

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(TEST_ENV);
        }

        // Exit code 1 — broker_exec failed.
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));

        // The audit kind is `credential_resolve_aborted`, NOT
        // `credential_provisioned`. This is the HIGH-E remediation:
        // a credential whose exec phase never completes is never
        // recorded as provisioned.
        let kind = transport.audit_kind();
        assert_eq!(
            kind,
            Some(CredentialAuditKind::CredentialResolveAborted),
            "resolve-without-exec must trigger credential_resolve_aborted, got {kind:?}"
        );
        assert_ne!(
            kind,
            Some(CredentialAuditKind::CredentialProvisioned),
            "resolve-without-exec must NEVER trigger credential_provisioned"
        );
        assert_eq!(kind.map(|k| k.as_str()), Some("credential_resolve_aborted"));
    }

    /// implementation-note-20 acceptance 2:
    /// spawn_handle binds binary + env + credential + target_uid.
    /// Constructs a handle directly and asserts the four fields exist
    /// with the expected types — guards against accidental field drops
    /// during refactor.
    #[test]
    fn spawn_handle_binds_four_authority_dimensions() {
        let handle = SpawnHandle {
            binary: "/usr/bin/gh".to_string(),
            env_allowlist: vec!["GH_TOKEN".to_string(), "GITHUB_TOKEN".to_string()],
            materialization_id: "mat-xyz-789".to_string(),
            target_uid: 1500,
        };

        assert_eq!(handle.binary, "/usr/bin/gh");
        assert_eq!(handle.env_allowlist.len(), 2);
        assert!(handle.env_allowlist.contains(&"GH_TOKEN".to_string()));
        assert_eq!(handle.materialization_id, "mat-xyz-789");
        assert_eq!(handle.target_uid, 1500);
    }

    /// implementation-note-20: resolve failure short-
    /// circuits before exec is reached. No audit kind is emitted
    /// because resolve never produced a credential to begin with.
    #[test]
    fn resolve_failure_short_circuits_before_exec() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(TEST_ENV, "session-abc");
        }

        let classifier = MockClassifier {
            result: Some(ActionKey("git.push".to_string())),
        };
        let argv: Vec<String> = vec!["push".to_string()];
        let spec = ConstructSpec {
            argv: &argv,
            classifier: &classifier,
            construct_toml_bytes: b"",
            session_id_env: TEST_ENV,
            wrapped_binary: "/usr/bin/git",
        };

        let transport = MockTransport::new().with_resolve(ResolveOutcome::Err(
            BrokerTransactionError::DaemonRpc {
                code: -32003,
                message: "policy_denied".to_string(),
            },
        ));
        let code = run_construct_with_transport(spec, &transport);

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(TEST_ENV);
        }

        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));

        // Only resolve was attempted; no exec; no abort needed because
        // resolve never produced a handle to release.
        let events = transport.events();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], MockEvent::ResolveCalled { .. }));
        assert_eq!(transport.audit_kind(), None);
    }

    #[test]
    fn credential_audit_kind_wire_names_are_stable() {
        // The wire-format strings are read by the daemon's Receipt-kind
        // catalog (design). Changing them silently would break the
        // audit chain — pin them here so a refactor surfaces the break.
        assert_eq!(
            CredentialAuditKind::CredentialProvisioned.as_str(),
            "credential_provisioned"
        );
        assert_eq!(
            CredentialAuditKind::CredentialResolveAborted.as_str(),
            "credential_resolve_aborted"
        );
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
