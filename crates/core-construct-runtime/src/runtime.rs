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
//! ## Resolve → exec two-phase invariant
//!
//! Per ADR 124 §9, the construct shim MUST call `broker.resolve` BEFORE
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
use std::time::{Duration, Instant};

use core_event_types::{ActionRef, ExecutionContract};
use core_events::construct_toml::TerminalMode;
use serde_json::{Value, json};

use crate::factory::FactoryDisposition;
use crate::{ActionKey, ClassifyArgv, ConstructConfig};

const EMBER_PERSONA_ID_ENV: &str = "EMBER_PERSONA_ID";
const EMBER_ATTACHMENT_ID_ENV: &str = "EMBER_ATTACHMENT_ID";
const EMBER_ATTACHMENT_ENDPOINT_TOKEN_ENV: &str = "EMBER_ATTACHMENT_ENDPOINT_TOKEN";
const EMBER_WORKSPACE_REF_ENV: &str = "EMBER_WORKSPACE_REF";
const EMBER_DEV_RUNTIME_ID_ENV: &str = "EMBER_DEV_RUNTIME_ID";
const EMBER_SUBJECT_REF_ENV: &str = "EMBER_SUBJECT_REF";
const EMBER_FORGE_SUBJECT_REF_ENV: &str = "EMBER_FORGE_SUBJECT_REF";
const EMBER_COORDINATION_REF_ENV: &str = "EMBER_COORDINATION_REF";
const EMBER_FORGE_COORDINATION_REF_ENV: &str = "EMBER_FORGE_COORDINATION_REF";
const BROKER_EXEC_POOL_EXHAUSTED_CODE: i32 = -32020;
const BROKER_EXEC_POOL_EXHAUSTED_BACKOFF_MS: [u64; 3] = [100, 300, 1000];

// ---------------------------------------------------------------------------
// TTY detection helper
// ---------------------------------------------------------------------------

/// Detect whether the parent process attached a TTY to any of the standard
/// streams. When none of stdin /
/// stdout / stderr have a TTY parent (autopilot, CI, headless cron, `docker
/// run` without `-t`), the shim must skip PTY allocation and let the daemon
/// run the child with `Stdio::piped()` so the bridge thread doesn't die on
/// stdin EOF and SIGTERM-cascade the spawned tool.
fn parent_has_tty() -> bool {
    std::io::stdin().is_terminal()
        || std::io::stdout().is_terminal()
        || std::io::stderr().is_terminal()
}

// ---------------------------------------------------------------------------
// Unsessioned subprocess audit log (Tier 1) — best-effort logging from
// the passthrough branches.
// ---------------------------------------------------------------------------

/// Outcome tag for [`log_unsessioned_subprocess`]. Mirrors the daemon's
/// `subprocess_audit_log` `outcome` enum.
#[derive(Debug, Clone, Copy)]
pub enum UnsessionedOutcome {
    /// Env-detect branch: `EMBER_SESSION_ID` was unset and the action was
    /// classified as credential-bearing. The shim refused before exec so the
    /// audit row carries `outcome = "denied_no_session"`.
    DeniedNoSession,
    /// Env-detect branch: `EMBER_SESSION_ID` was unset and the wrapped
    /// binary will inherit whatever credentials the parent process already
    /// has, so the audit row carries `outcome = "ambient_credential_used"`
    /// as a defensive label even when no credential was actually present.
    AmbientCredentialUsed,
    /// Classify-None branch: session active, but the shim's argv classifier
    /// returned `None` (read-only / safe-write verb that does not need
    /// broker mediation). The audit row carries
    /// `outcome = "passthrough_no_classify"`.
    PassthroughNoClassify,
}

impl UnsessionedOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::DeniedNoSession => "denied_no_session",
            Self::AmbientCredentialUsed => "ambient_credential_used",
            Self::PassthroughNoClassify => "passthrough_no_classify",
        }
    }
}

/// Best-effort, fire-and-forget RPC that records an unsessioned subprocess
/// invocation in the daemon's tamper-evident audit chain.
///
/// Called from `run_construct_full`'s no-session branches before the shim
/// either execs the wrapped binary or fails closed. Acceptance:
///
/// * Daemon up + reachable → one new row in `audit_log` with action
///   `subprocess.<vendor>.invoke_no_session`, before exec or deny returns.
/// * Daemon unreachable / timeout / RPC error → silently swallowed; the
///   shim continues to exec. Logging a subprocess invocation must NEVER
///   block the underlying tool.
///
/// The 50 ms per-syscall timeout matches the Tier 1 spec: <100 ms total
/// added latency in the daemon-up case, immediate failure in the down
/// case (UDS `connect` returns `ECONNREFUSED` / `ENOENT` synchronously).
pub fn log_unsessioned_subprocess<C: ConstructConfig>(
    config: &C,
    argv: &[String],
    outcome: UnsessionedOutcome,
) {
    let vendor = config.vendor();
    // "unknown" is the default the trait returns when a config impl forgot
    // to override `vendor()`. The daemon's whitelist would reject it; skip
    // the RPC entirely so we don't burn a connect+timeout per invocation.
    if vendor == "unknown" {
        return;
    }

    let verb = config
        .classify(argv)
        .map(|k| k.0)
        .or_else(|| argv.first().cloned())
        .unwrap_or_else(|| "unclassified".to_string());

    let mut argv_summary: String = argv.iter().take(3).cloned().collect::<Vec<_>>().join(" ");
    if argv_summary.len() > 256 {
        // char_indices() so we don't slice mid-UTF-8.
        if let Some((cut, _)) = argv_summary.char_indices().nth(255) {
            argv_summary.truncate(cut);
        }
    }

    let params = json!({
        "vendor": vendor,
        "verb": verb,
        "outcome": outcome.as_str(),
        "argv_summary": argv_summary,
    });

    let timeout = Duration::from_millis(50);
    if let Err(e) = crate::rpc::call_daemon_rpc_current_env_with_timeout(
        "subprocess_audit_log",
        &params,
        timeout,
    ) {
        tracing::debug!(
            vendor = %vendor,
            verb = %verb,
            error = %e,
            "subprocess_audit_log: best-effort failure (continuing to passthrough exec)"
        );
    }
}

/// Build the `broker_exec` JSON-RPC params object.
///
/// Factored out so the non-TTY path is observable in unit tests: when
/// `pty_socket_path` is `None`, the resulting JSON does not contain a
/// `pty_socket_path` key, which the daemon's `handle_broker_exec` reads as
/// "take the piped-stderr branch" (per `crates/ember-daemon/src/broker/handler.rs`
/// ~1699-1740: `if let Some(ref socket_path) = req.pty_socket_path { … } else { … }`).
fn build_broker_exec_params(
    argv: &[String],
    env_passthrough: &[&'static str],
    execution_contract: &ExecutionContract,
    construct_toml_bytes: &[u8],
    session_id: Option<&str>,
    pty_socket_path: Option<&std::path::Path>,
) -> serde_json::Value {
    use base64::Engine as _;

    let construct_toml_bytes =
        base64::engine::general_purpose::STANDARD.encode(construct_toml_bytes);
    let mut params = match pty_socket_path {
        Some(p) => json!({
            "execution_contract": execution_contract,
            "argv": argv,
            "env_passthrough": env_passthrough,
            "pty_socket_path": p.to_string_lossy(),
            "construct_toml_bytes": construct_toml_bytes,
        }),
        None => json!({
            "execution_contract": execution_contract,
            "argv": argv,
            "env_passthrough": env_passthrough,
            "construct_toml_bytes": construct_toml_bytes,
        }),
    };

    if execution_contract.workspace_ref.is_none()
        && let Some(cwd) = broker_exec_compat_cwd()
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert("cwd".to_string(), Value::String(cwd));
    }

    if let Some(session_id) = session_id.filter(|s| !s.is_empty())
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert(
            "session_id".to_string(),
            Value::String(session_id.to_string()),
        );
    }
    if let Some(persona_id) = session_persona_id_from_env()
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert("caller_persona".to_string(), Value::String(persona_id));
    }
    if let Some((attachment_id, endpoint_token)) = attachment_endpoint_from_env()
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert("attachment_id".to_string(), Value::String(attachment_id));
        obj.insert(
            "attachment_endpoint_token".to_string(),
            Value::String(endpoint_token),
        );
    }

    params
}

fn broker_exec_compat_cwd() -> Option<String> {
    std::env::var_os("EMBER_BROKER_CWD")
        .filter(|cwd| !cwd.is_empty())
        .map(|cwd| std::path::PathBuf::from(cwd).to_string_lossy().into_owned())
}

fn build_broker_resolve_params(
    execution_contract: &ExecutionContract,
    env_passthrough: &[String],
    construct_toml_bytes: &[u8],
    session_id: Option<&str>,
) -> serde_json::Value {
    let mut params = json!({
        "execution_contract": execution_contract,
        "lease_request": {
            "action_ref": execution_contract.action_ref.clone(),
            "env_passthrough": env_passthrough,
            "construct_toml_hash_input_len": construct_toml_bytes.len(),
        }
    });
    if let Some(session_id) = session_id.filter(|s| !s.is_empty())
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert(
            "session_id".to_string(),
            Value::String(session_id.to_string()),
        );
    }
    if let Some(persona_id) = session_persona_id_from_env()
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert("persona_id".to_string(), Value::String(persona_id));
    }
    if let Some((attachment_id, endpoint_token)) = attachment_endpoint_from_env()
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert("attachment_id".to_string(), Value::String(attachment_id));
        obj.insert(
            "attachment_endpoint_token".to_string(),
            Value::String(endpoint_token),
        );
    }
    params
}

fn build_spawn_handle_broker_exec_params(
    handle: &SpawnHandle,
    argv: &[String],
    session_id: Option<&str>,
) -> serde_json::Value {
    let execution_contract = handle.execution_contract.clone();
    let mut params = json!({
        "execution_contract": &execution_contract,
        "argv": argv,
        "env_passthrough": &handle.env_allowlist,
        "secret_ref": &handle.materialization_id,
        "target_uid": handle.target_uid,
    });
    if execution_contract.workspace_ref.is_none()
        && let Some(cwd) = broker_exec_compat_cwd()
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert("cwd".to_string(), Value::String(cwd));
    }
    if let Some(session_id) = session_id.filter(|s| !s.is_empty())
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert(
            "session_id".to_string(),
            Value::String(session_id.to_string()),
        );
    }
    if let Some((attachment_id, endpoint_token)) = attachment_endpoint_from_env()
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert("attachment_id".to_string(), Value::String(attachment_id));
        obj.insert(
            "attachment_endpoint_token".to_string(),
            Value::String(endpoint_token),
        );
    }
    params
}

fn session_persona_id_from_env() -> Option<String> {
    std::env::var(EMBER_PERSONA_ID_ENV)
        .ok()
        .filter(|s| !s.is_empty())
}

fn workspace_ref_from_env() -> Option<String> {
    std::env::var(EMBER_WORKSPACE_REF_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(legacy_workspace_ref_from_runtime_id_env)
}

fn legacy_workspace_ref_from_runtime_id_env() -> Option<String> {
    std::env::var(EMBER_DEV_RUNTIME_ID_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|runtime_id| format!("managed_worktree:{runtime_id}"))
}

fn ref_from_env(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        std::env::var(*name)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn subject_ref_from_env() -> Option<String> {
    ref_from_env(&[EMBER_SUBJECT_REF_ENV, EMBER_FORGE_SUBJECT_REF_ENV])
}

fn coordination_ref_from_env() -> Option<String> {
    ref_from_env(&[EMBER_COORDINATION_REF_ENV, EMBER_FORGE_COORDINATION_REF_ENV])
}

fn caller_ref_from_env(session_id: Option<&str>) -> Option<String> {
    session_persona_id_from_env()
        .map(|persona_id| format!("persona:{persona_id}"))
        .or_else(|| {
            session_id
                .filter(|value| !value.is_empty())
                .map(|value| format!("session:{value}"))
        })
}

fn attachment_endpoint_from_env() -> Option<(String, String)> {
    let attachment_id = std::env::var(EMBER_ATTACHMENT_ID_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    let endpoint_token = std::env::var(EMBER_ATTACHMENT_ENDPOINT_TOKEN_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    Some((attachment_id, endpoint_token))
}

const APPROVAL_POLL_INTERVAL: Duration = Duration::from_millis(500);
const APPROVAL_POLL_TIMEOUT: Duration = Duration::from_secs(300);

fn wait_for_approval_request(
    transport: &crate::rpc::DaemonTransport,
    approval_request_id: &str,
    persona_id: Option<&str>,
) -> Result<(), BrokerTransactionError> {
    eprintln!("ember-construct: waiting for approval {approval_request_id}");
    let deadline = Instant::now() + APPROVAL_POLL_TIMEOUT;
    loop {
        let mut params = json!({ "id": approval_request_id });
        if let Some(persona_id) = persona_id
            && let Some(obj) = params.as_object_mut()
        {
            obj.insert(
                "persona_id".to_string(),
                Value::String(persona_id.to_string()),
            );
        }
        let status = crate::rpc::call_daemon_rpc_transport(transport, "grant_status", &params)?;
        let kind = status
            .get("kind")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if kind != "approval" {
            return Err(BrokerTransactionError::Protocol(format!(
                "grant_status for approval {approval_request_id} returned unexpected kind {kind:?}"
            )));
        }
        let approval_status = status
            .get("status")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        match approval_status {
            "pending" => {
                if Instant::now() >= deadline {
                    return Err(BrokerTransactionError::Protocol(format!(
                        "approval {approval_request_id} did not resolve within {}s",
                        APPROVAL_POLL_TIMEOUT.as_secs()
                    )));
                }
                thread::sleep(APPROVAL_POLL_INTERVAL);
            }
            "approved" => return Ok(()),
            other => {
                return Err(BrokerTransactionError::Protocol(format!(
                    "approval {approval_request_id} resolved as {other}"
                )));
            }
        }
    }
}

fn broker_exec_until_ready(
    transport: &crate::rpc::DaemonTransport,
    params: &Value,
    persona_id: Option<&str>,
) -> Result<Value, BrokerTransactionError> {
    let mut pool_exhausted_attempt = 0usize;
    loop {
        let resp = match crate::rpc::call_daemon_rpc_transport(transport, "broker_exec", params) {
            Ok(resp) => resp,
            Err(err) => {
                let err: BrokerTransactionError = err.into();
                if let Some(retry_after_ms) = pool_exhausted_retry_after_ms(&err)
                    && let Some(backoff_ms) =
                        BROKER_EXEC_POOL_EXHAUSTED_BACKOFF_MS.get(pool_exhausted_attempt)
                {
                    tracing::warn!(
                        attempt = pool_exhausted_attempt + 1,
                        retry_after_ms,
                        backoff_ms,
                        "broker_exec pool exhausted; retrying with bounded backoff"
                    );
                    pool_exhausted_attempt += 1;
                    thread::sleep(Duration::from_millis(*backoff_ms));
                    continue;
                }
                return Err(err);
            }
        };
        let approval_required = resp
            .get("approval_required")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        if !approval_required {
            return Ok(resp);
        }
        let approval_request_id = resp
            .get("approval_request_id")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                BrokerTransactionError::Protocol(
                    "broker_exec approval_required response missing approval_request_id"
                        .to_string(),
                )
            })?;
        wait_for_approval_request(transport, approval_request_id, persona_id)?;
    }
}

fn pool_exhausted_retry_after_ms(err: &BrokerTransactionError) -> Option<u64> {
    match err {
        BrokerTransactionError::DaemonRpc {
            code,
            data: Some(data),
            ..
        } if *code == BROKER_EXEC_POOL_EXHAUSTED_CODE => {
            data.get("retry_after_ms").and_then(Value::as_u64)
        }
        _ => None,
    }
}

fn response_execution_contract(
    resp: &Value,
    rpc_method: &str,
) -> Result<ExecutionContract, BrokerTransactionError> {
    let execution_contract = resp.get("execution_contract").ok_or_else(|| {
        BrokerTransactionError::Protocol(format!(
            "{rpc_method} response missing execution_contract"
        ))
    })?;
    serde_json::from_value::<ExecutionContract>(execution_contract.clone()).map_err(|e| {
        BrokerTransactionError::Protocol(format!(
            "{rpc_method} response carried invalid execution_contract: {e}"
        ))
    })
}

fn execution_contract_for_action(
    action_ref: ActionRef,
    session_id: Option<&str>,
) -> ExecutionContract {
    let mut execution_contract = ExecutionContract::new(action_ref);
    execution_contract.workspace_ref = workspace_ref_from_env();
    execution_contract.subject_ref = subject_ref_from_env();
    execution_contract.coordination_ref = coordination_ref_from_env();
    execution_contract.caller_ref = caller_ref_from_env(session_id);
    execution_contract
}

fn action_ref_from_manifest_bytes(
    construct_toml_bytes: &[u8],
    action_key: &ActionKey,
) -> Result<ActionRef, BrokerTransactionError> {
    let text = std::str::from_utf8(construct_toml_bytes).map_err(|e| {
        BrokerTransactionError::Protocol(format!("construct_toml_bytes is not valid UTF-8: {e}"))
    })?;
    core_events::construct_toml::resolve_action_ref(text, &action_key.0).map_err(|e| {
        BrokerTransactionError::Protocol(format!(
            "resolve structured action_ref for {action_key}: {e}"
        ))
    })
}

fn terminal_mode_from_manifest_bytes(
    construct_toml_bytes: &[u8],
    action_key: &ActionKey,
) -> Result<TerminalMode, BrokerTransactionError> {
    let text = std::str::from_utf8(construct_toml_bytes).map_err(|e| {
        BrokerTransactionError::Protocol(format!("construct_toml_bytes is not valid UTF-8: {e}"))
    })?;
    core_events::construct_toml::resolve_action_terminal_mode(text, &action_key.0).map_err(|e| {
        BrokerTransactionError::Protocol(format!("failed to resolve terminal_mode: {e}"))
    })
}

fn pty_socket_path_for_terminal_mode(mode: TerminalMode) -> Option<PathBuf> {
    match mode {
        TerminalMode::Piped => None,
        TerminalMode::Pty => Some(PathBuf::from(format!(
            "/tmp/ember-construct-pty-{}.sock",
            std::process::id()
        ))),
        TerminalMode::Auto => parent_has_tty().then(|| {
            PathBuf::from(format!(
                "/tmp/ember-construct-pty-{}.sock",
                std::process::id()
            ))
        }),
    }
}

fn build_credentialless_command(
    binary: &str,
    argv: &[String],
    scrubbed_env: &[&'static str],
    pinned_env: &[(&'static str, &'static str)],
) -> Command {
    let mut command = Command::new(binary);
    command.args(argv);
    for key in scrubbed_env {
        command.env_remove(key);
    }
    for (key, value) in pinned_env {
        command.env(key, value);
    }
    command
}

fn exec_factory_credentialless<C: ConstructConfig>(argv: &[String], config: &C) -> ExitCode {
    log_unsessioned_subprocess(config, argv, UnsessionedOutcome::PassthroughNoClassify);
    let binary = config.resolve_binary();
    tracing::debug!(
        vendor = %config.vendor(),
        scrubbed_env = ?config.credentialless_env_scrub(),
        pinned_env = ?config.credentialless_env_set(),
        "ember-construct: factory credentialless direct exec with provider material scrubbed"
    );
    let err = build_credentialless_command(
        &binary,
        argv,
        config.credentialless_env_scrub(),
        config.credentialless_env_set(),
    )
    .exec();
    eprintln!("ember-construct: failed to exec credentialless {binary}: {err}");
    ExitCode::from(126u8)
}

fn factory_refusal_exit(disposition: FactoryDisposition, argv: &[String]) -> ExitCode {
    eprintln!(
        "ember-construct: factory disposition {disposition} refuses argv {:?}",
        argv
    );
    match disposition {
        FactoryDisposition::ResolverRequired => eprintln!(
            "ember-construct: trusted resolver evidence is required before this argv can run"
        ),
        FactoryDisposition::PayloadAnalysisRequired => {
            eprintln!("ember-construct: payload analysis is required before this argv can run")
        }
        FactoryDisposition::UnsupportedFailClosed => {
            eprintln!("ember-construct: argv is outside the declared construct factory contract")
        }
        FactoryDisposition::Mediated | FactoryDisposition::Credentialless => {}
    }
    ExitCode::from(1u8)
}

fn factory_refusal_disposition(
    disposition: Option<FactoryDisposition>,
) -> Option<FactoryDisposition> {
    match disposition {
        Some(
            FactoryDisposition::ResolverRequired
            | FactoryDisposition::PayloadAnalysisRequired
            | FactoryDisposition::UnsupportedFailClosed,
        ) => disposition,
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Two-phase resolve → exec
// ---------------------------------------------------------------------------

/// Opaque spawn handle returned by [`resolve_via_broker`].
///
/// Binds the four authority dimensions per ADR 124 §9: the absolute binary
/// path the daemon will `execve`, the env-var allowlist forwarded into the
/// child env, the `materialization_id` (the daemon's in-memory credential
/// reference — plaintext NEVER leaves the daemon over the shim wire), and
/// the `target_uid` the daemon drops privilege to before exec.
///
/// `exec_via_broker` consumes the handle by value so callers can't
/// double-spend a resolved lease across multiple exec calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnHandle {
    /// Authority-approved execution contract for this resolve → exec
    /// transaction. The runner-local fields below remain transitional and are
    /// deliberately separate from this authority-facing envelope.
    pub execution_contract: ExecutionContract,
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
    DaemonRpc {
        code: i32,
        message: String,
        data: Option<Value>,
    },
    /// Wire / protocol corruption (malformed JSON, missing fields).
    Protocol(String),
    /// Local IO error before the request reached the daemon.
    Io(String),
}

impl std::fmt::Display for BrokerTransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DaemonUnavailable(s) => write!(f, "daemon unavailable: {s}"),
            Self::DaemonRpc { code, message, .. } => {
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
            crate::rpc::RpcError::DaemonRpc {
                code,
                message,
                data,
            } => Self::DaemonRpc {
                code,
                message,
                data,
            },
            crate::rpc::RpcError::Protocol(s) => Self::Protocol(s),
            crate::rpc::RpcError::Io(s) => Self::Io(s),
        }
    }
}

/// Outcome of [`exec_via_broker`] — the exit code from the wrapped binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutcome {
    /// Authority-side execution-contract identifier associated with the run.
    pub contract_id: Option<String>,
    /// Process exit code. Negative when the child was killed by signal
    /// before exit; callers should map negative codes to `1` per the
    /// existing `run_construct_full` convention.
    pub exit_code: i64,
    /// Captured stdout tail from the daemon's non-PTY branch. Empty on PTY
    /// and passthrough paths.
    pub stdout_tail: String,
    /// Captured stderr tail from the daemon's piped-stderr branch.
    /// Empty on the PTY path. Forwarded to the shim's stderr before
    /// return so daemon-side error messages reach the operator.
    pub stderr_tail: String,
}

/// Audit indicator emitted by the shim after the resolve+exec transaction
/// completes (or aborts). Mirrors the daemon-side Receipt-kind catalog
/// (per ADR 133) so the construct shim's local observability and the
/// daemon's audit chain stay in lock-step.
///
/// - `CredentialProvisioned` — emitted ONLY when [`resolve_via_broker`]
///   AND [`exec_via_broker`] both succeed. False positives here would
///   poison the audit chain (HIGH-E in the ADR 140 §9 review).
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
    /// catalog entries (ADR 133).
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
/// current daemon transport (`UDS` locally, bridge mTLS when configured).
/// Tests inject in-memory
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
        action_ref: &ActionRef,
        env_passthrough: &[String],
        construct_toml_bytes: &[u8],
        session_id: Option<&str>,
    ) -> Result<SpawnHandle, BrokerTransactionError>;

    /// Phase 2 — exec. Consume the spawn handle and run the wrapped
    /// binary under the daemon's supervision. Returns the child's
    /// [`ExecOutcome`] on success.
    fn exec(
        &self,
        handle: SpawnHandle,
        argv: &[String],
        session_id: Option<&str>,
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
/// plaintext is NEVER returned over this RPC — only `handle_broker_resolve`'s
/// legacy secret-ref → plaintext path returns raw credentials, and that path
/// is gated to trust-boundary callers.
pub fn resolve_via_broker<T: BrokerTransport>(
    transport: &T,
    action_ref: &ActionRef,
    env_passthrough: &[String],
    construct_toml_bytes: &[u8],
    session_id: Option<&str>,
) -> Result<SpawnHandle, BrokerTransactionError> {
    transport.resolve(
        action_ref,
        env_passthrough,
        construct_toml_bytes,
        session_id,
    )
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
    session_id: Option<&str>,
) -> Result<ExecOutcome, BrokerTransactionError> {
    transport.exec(handle, argv, session_id)
}

/// Production [`BrokerTransport`] that dispatches to the daemon over the
/// current runtime transport.
///
/// `resolve` sends a `broker_resolve` JSON-RPC with the lease-request
/// shape; `exec` sends a `broker_exec` JSON-RPC carrying the spawn
/// handle's `materialization_id` as `secret_ref` so the daemon
/// correlates the two phases. `abort_resolve` sends a follow-up
/// `broker_resolve_release` RPC; failures here are best-effort.
pub struct DaemonRpcTransport {
    pub transport: crate::rpc::DaemonTransport,
}

impl DaemonRpcTransport {
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            transport: crate::rpc::DaemonTransport::Uds(socket_path),
        }
    }

    pub fn from_current_env() -> Self {
        Self {
            transport: crate::rpc::decide_transport(),
        }
    }
}

impl BrokerTransport for DaemonRpcTransport {
    fn resolve(
        &self,
        action_ref: &ActionRef,
        env_passthrough: &[String],
        construct_toml_bytes: &[u8],
        session_id: Option<&str>,
    ) -> Result<SpawnHandle, BrokerTransactionError> {
        // Lease-request shape. The daemon's `resolve_with_registry`
        // recognises an absent `secret_ref` paired with a non-null
        // `lease_request` object as the construct-shim resolve path
        // (vs. the legacy secret_ref → plaintext path used by ember-
        // proxy / ember-tools, which is preserved verbatim).
        let execution_contract = execution_contract_for_action(action_ref.clone(), session_id);
        let params = build_broker_resolve_params(
            &execution_contract,
            env_passthrough,
            construct_toml_bytes,
            session_id,
        );
        let resp =
            crate::rpc::call_daemon_rpc_transport(&self.transport, "broker_resolve", &params)?;

        let execution_contract = response_execution_contract(&resp, "broker_resolve")?;
        let materialization_id = resp
            .get("materialization_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BrokerTransactionError::Protocol(
                    "broker_resolve response missing materialization_id".to_string(),
                )
            })?
            .to_string();

        if execution_contract.action_ref != *action_ref {
            return Err(BrokerTransactionError::Protocol(format!(
                "broker_resolve response action_ref drifted from request: {} != {}",
                execution_contract.action_ref, action_ref
            )));
        }

        // The daemon echoes the binary path so the shim cannot tamper
        // with it between resolve and exec (the daemon is the single
        // authority on which binary the exec phase actually runs).
        let resolved_binary = resp
            .get("binary")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BrokerTransactionError::Protocol(
                    "broker_resolve response missing binary".to_string(),
                )
            })?
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

        let target_uid = resp.get("target_uid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        Ok(SpawnHandle {
            execution_contract,
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
        session_id: Option<&str>,
    ) -> Result<ExecOutcome, BrokerTransactionError> {
        let params = build_spawn_handle_broker_exec_params(&handle, argv, session_id);
        let persona_id = session_persona_id_from_env();
        let resp = broker_exec_until_ready(&self.transport, &params, persona_id.as_deref())?;
        let execution_contract = response_execution_contract(&resp, "broker_exec")?;
        if execution_contract.action_ref != handle.execution_contract.action_ref {
            return Err(BrokerTransactionError::Protocol(format!(
                "broker_exec response action_ref drifted from request: {} != {}",
                execution_contract.action_ref, handle.execution_contract.action_ref
            )));
        }
        let contract_id = execution_contract.contract_id.clone();
        let exit_code = resp.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(0);
        let stdout_tail = resp
            .get("stdout_tail")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let stderr_tail = resp
            .get("stderr_tail")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Ok(ExecOutcome {
            contract_id,
            exit_code,
            stdout_tail,
            stderr_tail,
        })
    }

    fn abort_resolve(&self, handle: &SpawnHandle) {
        let params = json!({
            "materialization_id": handle.materialization_id,
            "reason": "shim_aborted_before_exec",
        });
        match crate::rpc::call_daemon_rpc_transport(
            &self.transport,
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
/// ADR 140 §9 review.
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
    let session_id = std::env::var(spec.session_id_env).ok();
    let action_ref = match action_ref_from_manifest_bytes(spec.construct_toml_bytes, &action_key) {
        Ok(action_ref) => action_ref,
        Err(e) => {
            eprintln!("core-construct-runtime: failed to resolve structured action_ref: {e}");
            return ExitCode::from(2);
        }
    };

    // 3. broker.resolve — phase 1. Receives a SpawnHandle binding
    //    (binary, env_allowlist, materialization_id, target_uid).
    let handle = match resolve_via_broker(
        transport,
        &action_ref,
        &[],
        spec.construct_toml_bytes,
        session_id.as_deref(),
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
    let exec_result = exec_via_broker(transport, handle, spec.argv, session_id.as_deref());
    let outcome = match exec_result {
        Ok(o) => o,
        Err(e) => {
            // Resolve succeeded, exec did not. Emit credential_resolve_
            // aborted instead of credential_provisioned.
            transport.abort_resolve(&abort_handle);
            eprintln!("core-construct-runtime: broker_exec failed (action_key={action_key}): {e}");
            return ExitCode::from(1);
        }
    };

    // 5. Propagate child exit code. The daemon emits
    //    credential_provisioned only after BOTH phases reach this point
    //    (its `broker_exec` handler holds the resolve→exec transaction).
    if !outcome.stdout_tail.is_empty() {
        print!("{}", outcome.stdout_tail);
    }
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
    let transport = DaemonRpcTransport::from_current_env();
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
    // 1. Pre-classify so the no-session branch can distinguish brokered,
    //    credential-bearing actions from read-only passthrough verbs.
    let classified = config.classify(argv);
    let factory_disposition = config.factory_disposition(classified.as_ref(), argv);

    // Trusted-resolver hook (anchor: factory_resolver_framework_landed).
    //
    // When the disposition is ResolverRequired, give the construct's
    // env-derivation hook a chance to derive a target from cwd state (git
    // remote, kubeconfig context, package.json, env vars) before the shim
    // refuses pre-RPC. The hook returns a synthesized argv with the
    // derived target injected as an explicit flag the existing classifier
    // and broker pipeline already recognise (e.g. `gh pr list` becomes
    // `gh pr list --repo acme/widgets`). The daemon re-classifies the
    // synthesized argv server-side and applies its existing
    // `target ⊆ grant.resource` clamp — the resolver supplies a target
    // candidate, the daemon decides authority. Per operator 2026-06-11:
    // the grant clamp is the security gate, argv ceremony is UX.
    //
    // Hook is silent for non-ResolverRequired dispositions (Mediated /
    // PayloadAnalysisRequired / UnsupportedFailClosed) — those stay on
    // their existing paths.
    let resolved_argv_owned: Option<Vec<String>> =
        if factory_disposition == Some(FactoryDisposition::ResolverRequired) {
            let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
            config.resolve_target_from_environment(classified.as_ref(), argv, &cwd)
        } else {
            None
        };
    let (argv, classified, factory_disposition): (&[String], _, _) = match resolved_argv_owned
        .as_deref()
    {
        Some(synthesized) => {
            let new_classified = config.classify(synthesized);
            let new_disposition = config.factory_disposition(new_classified.as_ref(), synthesized);
            tracing::info!(
                original_argv = ?argv,
                synthesized_argv = ?synthesized,
                new_disposition = ?new_disposition,
                "ember-construct: trusted resolver derived target from cwd; re-running disposition"
            );
            (synthesized, new_classified, new_disposition)
        }
        None => (argv, classified, factory_disposition),
    };

    if factory_disposition == Some(FactoryDisposition::Credentialless) {
        return exec_factory_credentialless(argv, config);
    }

    if let Some(disposition) = factory_refusal_disposition(factory_disposition) {
        return factory_refusal_exit(disposition, argv);
    }

    // 2. env-detect:
    //    - no session + classified action → fail closed
    //    - no session + classify=None → passthrough exec
    if std::env::var_os(config.session_id_env()).is_none() {
        match classified.as_ref() {
            Some(action_key) => {
                log_unsessioned_subprocess(config, argv, UnsessionedOutcome::DeniedNoSession);
                eprintln!(
                    "ember-construct: {} requires a brokered ember session",
                    action_key
                );
                eprintln!(
                    "ember-construct: launch the canonical brokered session with `ember claude`"
                );
                eprintln!(
                    "ember-construct: outside a session, only unclassified read-only passthrough verbs are allowed"
                );
                return ExitCode::from(1u8);
            }
            None => {
                log_unsessioned_subprocess(config, argv, UnsessionedOutcome::PassthroughNoClassify);
                let binary = config.resolve_binary();
                let err = Command::new(&binary).args(argv).exec();
                eprintln!("ember-construct: failed to exec {binary}: {err}");
                return ExitCode::from(126u8);
            }
        }
    }

    // v0.3.0 friendly truth gate: a shell that only carries the session id
    // is not the same thing as the canonical launcher posture. The launcher
    // also injects attachment-scoped endpoint coordinates, and construct
    // shims without them fall into a partial host/session shape that
    // produces confusing daemon authority failures. Refuse early and point
    // the operator back to the supported launcher path.
    if attachment_endpoint_from_env().is_none() {
        eprintln!(
            "ember-construct: partial ember session detected ({} is set, but attachment endpoint env is missing)",
            config.session_id_env()
        );
        eprintln!(
            "ember-construct: for v0.3.0, launch the canonical brokered session with `ember claude`"
        );
        eprintln!(
            "ember-construct: host/headless shells are not yet a full substitute for the launcher path"
        );
        return ExitCode::from(1u8);
    }

    // 3. classify argv → action_key.
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
    let classified = match classified {
        Some(k) => k,
        None => {
            tracing::debug!(
                argv = ?argv,
                "ember-construct: classify=None; passthrough exec (no broker mediation)"
            );
            // Tier 1: log
            // the classify=None passthrough so read-only / safe-write verbs
            // still appear in the chain (verb name from argv[0]).
            log_unsessioned_subprocess(config, argv, UnsessionedOutcome::PassthroughNoClassify);
            let binary = config.resolve_binary();
            let err = Command::new(&binary).args(argv).exec();
            eprintln!("ember-construct: failed to exec {binary}: {err}");
            return ExitCode::from(126u8);
        }
    };

    tracing::info!(
        action_ref = %classified,
        "ember-construct: dispatching via broker.exec"
    );

    tracing::info!(
        action_ref = %classified,
        attachment_id = ?std::env::var(EMBER_ATTACHMENT_ID_ENV).ok(),
        "ember-construct: broker.resolve+exec"
    );
    let session_id = std::env::var(config.session_id_env()).ok();
    let action_ref =
        match action_ref_from_manifest_bytes(config.construct_toml_bytes(), &classified) {
            Ok(action_ref) => action_ref,
            Err(e) => {
                eprintln!("ember-construct: failed to resolve structured action_ref: {e}");
                return ExitCode::from(2u8);
            }
        };
    let terminal_mode =
        match terminal_mode_from_manifest_bytes(config.construct_toml_bytes(), &classified) {
            Ok(mode) => mode,
            Err(e) => {
                eprintln!("ember-construct: failed to resolve terminal_mode: {e}");
                return ExitCode::from(2u8);
            }
        };
    let execution_contract =
        execution_contract_for_action(action_ref.clone(), session_id.as_deref());

    // 3. Resolve the daemon transport.
    let daemon_transport = crate::rpc::decide_transport();

    // 4. Decide whether to allocate a PTY.
    //
    // When the parent has NO TTY on
    // any of stdin/stdout/stderr (autopilot, CI, headless cron, `docker run`
    // without `-t`, non-interactive `nohup`), skip the PTY socket entirely
    // and send `pty_socket_path: None` so the daemon takes its piped-stderr
    // path. The PTY bridge thread would otherwise die on stdin EOF and the
    // daemon's shim-EOF policy would SIGTERM-cascade the child.
    //
    // When terminal_mode=auto and at least one stream has a TTY, keep the
    // existing PTY allocation path so interactive `ember-git status`,
    // `ember-gh pr view`, etc. continue to work. Actions that declare
    // terminal_mode=piped are structured command executions and must avoid
    // the daemon's forkpty path even when the parent harness has a terminal.
    let pty_socket_path: Option<PathBuf> = pty_socket_path_for_terminal_mode(terminal_mode);
    if pty_socket_path.is_none() {
        tracing::debug!(
            terminal_mode = ?terminal_mode,
            parent_has_tty = parent_has_tty(),
            "ember-construct: skipping PTY allocation"
        );
    }

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
        let _ = std::fs::set_permissions(pty_sock_path, std::fs::Permissions::from_mode(0o600));

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

    // 6. Translate emberlink-shaped argv to wrapped-tool-native argv:
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
        &translated_argv,
        config.env_passthrough(),
        &execution_contract,
        config.construct_toml_bytes(),
        session_id.as_deref(),
        pty_socket_path.as_deref(),
    );

    let persona_id = session_persona_id_from_env();
    let result = broker_exec_until_ready(&daemon_transport, &params, persona_id.as_deref());

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
            let execution_contract = match response_execution_contract(&resp, "broker_exec") {
                Ok(contract) => contract,
                Err(e) => {
                    eprintln!("ember-construct: broker_exec error: {e}");
                    return ExitCode::from(1u8);
                }
            };
            let stdout_tail = resp
                .get("stdout_tail")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !stdout_tail.is_empty() {
                print!("{stdout_tail}");
            }
            let stderr_tail = resp
                .get("stderr_tail")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !stderr_tail.is_empty() {
                eprint!("{stderr_tail}");
            }

            let exit_code = resp.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(0);

            tracing::info!(
                exit_code = exit_code,
                action_key = %classified,
                contract_id = ?execution_contract.contract_id,
                "ember-construct: child exited"
            );

            if exit_code < 0 {
                ExitCode::from(1u8)
            } else {
                ExitCode::from(exit_code.min(255) as u8)
            }
        }
        Err(BrokerTransactionError::DaemonUnavailable(msg)) => {
            eprintln!("ember-construct: daemon unavailable — {msg}");
            eprintln!(
                "ember-construct: inspect posture with 'ember status' or repair with 'sudo ember daemon install'"
            );
            ExitCode::from(2u8)
        }
        Err(BrokerTransactionError::DaemonRpc {
            code,
            message,
            data,
        }) => {
            if code == -32020
                && let Some(retry_after_ms) = data
                    .as_ref()
                    .and_then(|d| d.get("retry_after_ms"))
                    .and_then(Value::as_u64)
            {
                eprintln!(
                    "ember-construct: broker_exec pool exhausted; retry_after_ms={retry_after_ms}"
                );
                ExitCode::from(78u8)
            } else {
                eprintln!("ember-construct: broker_exec rejected (code={code}): {message}");
                ExitCode::from(1u8)
            }
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
    use serde_json::json;

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
    use std::io::Write as _;
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const TEST_ENV: &str = "EMBER_SESSION_ID_CCR_TEST";
    // Full v2 manifests: the carrier-load seam is fail-closed (ADR 196), so
    // identity-only stubs no longer resolve.
    const TEST_CONSTRUCT_TOML_BYTES: &[u8] = br#"
schema_version = "2"

[meta]
name = "ember-git"
plugin_address = "registry.ember.systems/ember-systems/ember-git"
plugin_version = "0.1.0"
publisher = "did:emberlink"
provider_kind = "cli"
summary = "Git CLI Construct"
description = "Mediates git invocations through ember."

[defaults]
materialization_class = "brokered_credential"
material_classes = [{ kind = "broker", authority_ref = "github" }]
default_runner_classes = ["local_trusted"]

[runtime.cli]
wrapped_binary = "git"

[[actions]]
key = "git.push"
action_version = "v1"
summary = "Push commits to a remote"
input_schema = { kind = "argv", classifier = "push *" }
risk_tier = "medium"
idempotency = "non_idempotent"
interaction_class = "inline_interactive"
audit_fields = ["action_ref", "terminal_outcome"]
handler_ref = "cli:git.push"
"#;

    const TEST_GH_CONSTRUCT_TOML_BYTES: &[u8] = br#"
schema_version = "2"

[meta]
name = "ember-gh"
plugin_address = "registry.ember.systems/ember-systems/ember-gh"
plugin_version = "0.1.0"
publisher = "did:emberlink"
provider_kind = "cli"
summary = "GitHub CLI Construct"
description = "Mediates gh invocations through ember."

[defaults]
materialization_class = "brokered_credential"
material_classes = [{ kind = "broker", authority_ref = "github" }]
default_runner_classes = ["local_trusted"]

[runtime.cli]
wrapped_binary = "gh"

[[actions]]
key = "pr_list"
action_version = "v1"
summary = "List pull requests"
input_schema = { kind = "argv", classifier = "pr list *" }
risk_tier = "low"
idempotency = "idempotent"
interaction_class = "inline_interactive"
terminal_mode = "piped"
audit_fields = ["action_ref", "terminal_outcome"]
handler_ref = "cli:gh.pr_list"
"#;

    fn test_action_ref() -> ActionRef {
        ActionRef::new(
            "registry.ember.systems/ember-systems/ember-git",
            "git.push",
            "v1",
        )
    }

    fn test_gh_action_ref() -> ActionRef {
        ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_list",
            "v1",
        )
    }

    fn test_execution_contract() -> ExecutionContract {
        let mut execution_contract = ExecutionContract::new(test_action_ref());
        execution_contract.contract_id = Some("contract-test-123".to_string());
        execution_contract.workspace_ref = Some("managed_worktree:test".to_string());
        execution_contract.caller_ref = Some("session:test".to_string());
        execution_contract.authority_ref = Some("grant:test".to_string());
        execution_contract
    }

    fn test_execution_contract_without_workspace_ref() -> ExecutionContract {
        let mut execution_contract = test_execution_contract();
        execution_contract.workspace_ref = None;
        execution_contract
    }

    fn assert_no_top_level_execution_contract_mirrors(params: &serde_json::Value) {
        let obj = params.as_object().expect("params should be a JSON object");
        for field in [
            "contract_id",
            "action_ref",
            "workspace_ref",
            "subject_ref",
            "coordination_ref",
            "caller_ref",
            "authority_ref",
        ] {
            assert!(
                !obj.contains_key(field),
                "params must not dual-emit top-level execution_contract mirror {field}; got {params:?}"
            );
        }
    }

    fn test_spawn_handle() -> SpawnHandle {
        SpawnHandle {
            execution_contract: test_execution_contract(),
            binary: "/usr/bin/mock-tool".to_string(),
            env_allowlist: vec!["PATH".to_string()],
            materialization_id: "mat-abc-123".to_string(),
            target_uid: 1000,
        }
    }

    fn spawn_mock_daemon_once(
        result: serde_json::Value,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::thread::JoinHandle<serde_json::Value>,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("daemon.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).expect("bind daemon");
        let join = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept daemon client");
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone daemon client"));
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).expect("read daemon request");
            let request: serde_json::Value =
                serde_json::from_str(&line).expect("parse daemon request");
            let response = json!({
                "jsonrpc": "2.0",
                "id": request.get("id").cloned().unwrap_or_else(|| json!("1")),
                "result": result,
            });
            let mut writer = stream;
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&response).expect("serialize daemon response")
            )
            .expect("write daemon response");
            request
        });
        (dir, socket_path, join)
    }

    fn protocol_error_message(err: BrokerTransactionError) -> String {
        match err {
            BrokerTransactionError::Protocol(message) => message,
            other => panic!("expected protocol error, got {other:?}"),
        }
    }

    #[test]
    fn pool_exhausted_retry_hint_reads_structured_data_only() {
        let err = BrokerTransactionError::DaemonRpc {
            code: BROKER_EXEC_POOL_EXHAUSTED_CODE,
            message: "pool_exhausted retry_after_ms=100".to_string(),
            data: Some(json!({ "retry_after_ms": 300 })),
        };
        assert_eq!(pool_exhausted_retry_after_ms(&err), Some(300));

        let message_only = BrokerTransactionError::DaemonRpc {
            code: BROKER_EXEC_POOL_EXHAUSTED_CODE,
            message: "pool_exhausted retry_after_ms=100".to_string(),
            data: None,
        };
        assert_eq!(pool_exhausted_retry_after_ms(&message_only), None);

        let wrong_code = BrokerTransactionError::DaemonRpc {
            code: -32003,
            message: "pool_exhausted retry_after_ms=100".to_string(),
            data: Some(json!({ "retry_after_ms": 100 })),
        };
        assert_eq!(pool_exhausted_retry_after_ms(&wrong_code), None);
    }

    #[test]
    fn daemon_rpc_resolve_requires_response_execution_contract() {
        let response = json!({
            "contract_id": "legacy-top-level-contract",
            "materialization_id": "mat-from-resolve",
            "binary": "/usr/bin/git",
            "env_allowlist": ["PATH"],
            "target_uid": 1000,
        });
        let (_dir, socket_path, join) = spawn_mock_daemon_once(response);
        let transport = DaemonRpcTransport::new(socket_path);

        let err = transport
            .resolve(
                &test_action_ref(),
                &["PATH".to_string()],
                TEST_CONSTRUCT_TOML_BYTES,
                Some("session-resolve"),
            )
            .expect_err("broker_resolve responses must carry nested execution_contract");

        let request = join.join().expect("mock daemon thread");
        assert_eq!(request["method"], "broker_resolve");
        assert!(request["params"]["execution_contract"].is_object());
        assert_eq!(
            protocol_error_message(err),
            "broker_resolve response missing execution_contract"
        );
    }

    #[test]
    fn daemon_rpc_exec_requires_response_execution_contract() {
        let response = json!({
            "contract_id": "legacy-top-level-contract",
            "exit_code": 0,
            "stdout_tail": "",
            "stderr_tail": "",
        });
        let (_dir, socket_path, join) = spawn_mock_daemon_once(response);
        let transport = DaemonRpcTransport::new(socket_path);

        let err = transport
            .exec(
                test_spawn_handle(),
                &["status".to_string()],
                Some("session-exec"),
            )
            .expect_err("broker_exec responses must carry nested execution_contract");

        let request = join.join().expect("mock daemon thread");
        assert_eq!(request["method"], "broker_exec");
        assert!(request["params"]["execution_contract"].is_object());
        assert_eq!(
            protocol_error_message(err),
            "broker_exec response missing execution_contract"
        );
    }

    #[test]
    fn daemon_rpc_exec_uses_nested_execution_contract_contract_id() {
        let mut execution_contract = test_execution_contract();
        execution_contract.contract_id = Some("nested-contract-id".to_string());
        let response = json!({
            "contract_id": "legacy-top-level-contract",
            "execution_contract": execution_contract,
            "exit_code": 7,
            "stdout_tail": "out",
            "stderr_tail": "err",
        });
        let (_dir, socket_path, join) = spawn_mock_daemon_once(response);
        let transport = DaemonRpcTransport::new(socket_path);

        let outcome = transport
            .exec(
                test_spawn_handle(),
                &["status".to_string()],
                Some("session-exec"),
            )
            .expect("broker_exec response with nested execution_contract should parse");

        let request = join.join().expect("mock daemon thread");
        assert_eq!(request["method"], "broker_exec");
        assert_eq!(outcome.contract_id.as_deref(), Some("nested-contract-id"));
        assert_eq!(outcome.exit_code, 7);
        assert_eq!(outcome.stdout_tail, "out");
        assert_eq!(outcome.stderr_tail, "err");
    }

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
        ResolveCalled {
            action_ref: String,
            session_id: Option<String>,
        },
        ExecCalled {
            materialization_id: String,
            session_id: Option<String>,
        },
        AbortCalled {
            materialization_id: String,
        },
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                resolve_outcome: std::sync::Mutex::new(ResolveOutcome::Ok(test_spawn_handle())),
                exec_outcome: std::sync::Mutex::new(ExecOutcomeMock::Ok(ExecOutcome {
                    contract_id: Some("contract-test-123".to_string()),
                    exit_code: 0,
                    stdout_tail: String::new(),
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
            action_ref: &ActionRef,
            _env_passthrough: &[String],
            _construct_toml_bytes: &[u8],
            session_id: Option<&str>,
        ) -> Result<SpawnHandle, BrokerTransactionError> {
            self.recorded
                .lock()
                .unwrap()
                .push(MockEvent::ResolveCalled {
                    action_ref: action_ref.to_string(),
                    session_id: session_id.map(str::to_string),
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
            session_id: Option<&str>,
        ) -> Result<ExecOutcome, BrokerTransactionError> {
            self.recorded.lock().unwrap().push(MockEvent::ExecCalled {
                materialization_id: handle.materialization_id.clone(),
                session_id: session_id.map(str::to_string),
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
                Self::DaemonRpc {
                    code,
                    message,
                    data,
                } => Self::DaemonRpc {
                    code: *code,
                    message: message.clone(),
                    data: data.clone(),
                },
                Self::Protocol(s) => Self::Protocol(s.clone()),
                Self::Io(s) => Self::Io(s.clone()),
            }
        }
    }

    /// Two-phase resolve acceptance 1+2:
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
            construct_toml_bytes: TEST_CONSTRUCT_TOML_BYTES,
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
        assert_eq!(
            events.len(),
            2,
            "expected resolve+exec only, got {events:?}"
        );
        match &events[0] {
            MockEvent::ResolveCalled {
                action_ref,
                session_id,
            } => {
                assert_eq!(action_ref, &test_action_ref().to_string());
                assert_eq!(session_id.as_deref(), Some("session-abc"));
            }
            other => panic!("first event should be ResolveCalled, got {other:?}"),
        }
        match &events[1] {
            MockEvent::ExecCalled {
                materialization_id,
                session_id,
            } => {
                assert_eq!(materialization_id, "mat-abc-123");
                assert_eq!(session_id.as_deref(), Some("session-abc"));
            }
            other => panic!("second event should be ExecCalled, got {other:?}"),
        }

        // The transaction succeeded → credential_provisioned.
        assert_eq!(
            transport.audit_kind(),
            Some(CredentialAuditKind::CredentialProvisioned)
        );
    }

    /// Two-phase resolve acceptance 3:
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
            construct_toml_bytes: TEST_CONSTRUCT_TOML_BYTES,
            session_id_env: TEST_ENV,
            wrapped_binary: "/usr/bin/git",
        };

        let transport = MockTransport::new().with_exec(ExecOutcomeMock::Err(
            BrokerTransactionError::DaemonRpc {
                code: -32003,
                message: "argv_classification_mismatch".to_string(),
                data: None,
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

    /// Two-phase resolve acceptance 2:
    /// spawn_handle binds binary + env + credential + target_uid.
    /// Constructs a handle directly and asserts the four fields exist
    /// with the expected types — guards against accidental field drops
    /// during refactor.
    #[test]
    fn spawn_handle_binds_authority_refs_and_runner_internals() {
        let handle = SpawnHandle {
            execution_contract: ExecutionContract::new(ActionRef::new(
                "registry.ember.systems/ember-systems/ember-gh",
                "pr_create",
                "v1",
            ))
            .with_contract_id("contract-xyz-789"),
            binary: "/usr/bin/gh".to_string(),
            env_allowlist: vec!["GH_TOKEN".to_string(), "GITHUB_TOKEN".to_string()],
            materialization_id: "mat-xyz-789".to_string(),
            target_uid: 1500,
        };

        assert_eq!(
            handle.execution_contract.contract_id.as_deref(),
            Some("contract-xyz-789")
        );
        assert_eq!(
            handle.execution_contract.action_ref,
            ActionRef::new(
                "registry.ember.systems/ember-systems/ember-gh",
                "pr_create",
                "v1",
            )
        );
        assert_eq!(handle.binary, "/usr/bin/gh");
        assert_eq!(handle.env_allowlist.len(), 2);
        assert!(handle.env_allowlist.contains(&"GH_TOKEN".to_string()));
        assert_eq!(handle.materialization_id, "mat-xyz-789");
        assert_eq!(handle.target_uid, 1500);
    }

    #[test]
    fn action_ref_from_manifest_bytes_accepts_legacy_dotted_gh_key() {
        let action_ref = action_ref_from_manifest_bytes(
            TEST_GH_CONSTRUCT_TOML_BYTES,
            &ActionKey("gh.pr_list".to_string()),
        )
        .expect("legacy gh action key should resolve");
        assert_eq!(action_ref, test_gh_action_ref());
    }

    #[test]
    fn terminal_mode_from_manifest_bytes_accepts_legacy_dotted_gh_key() {
        let terminal_mode = terminal_mode_from_manifest_bytes(
            TEST_GH_CONSTRUCT_TOML_BYTES,
            &ActionKey("gh.pr_list".to_string()),
        )
        .expect("legacy gh action key should resolve terminal mode");

        assert_eq!(terminal_mode, TerminalMode::Piped);
    }

    #[test]
    fn pty_socket_path_for_piped_omits_socket() {
        assert!(pty_socket_path_for_terminal_mode(TerminalMode::Piped).is_none());
    }

    #[test]
    fn pty_socket_path_for_pty_forces_socket() {
        assert!(pty_socket_path_for_terminal_mode(TerminalMode::Pty).is_some());
    }

    /// Resolve failure short-
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
            construct_toml_bytes: TEST_CONSTRUCT_TOML_BYTES,
            session_id_env: TEST_ENV,
            wrapped_binary: "/usr/bin/git",
        };

        let transport = MockTransport::new().with_resolve(ResolveOutcome::Err(
            BrokerTransactionError::DaemonRpc {
                code: -32003,
                message: "policy_denied".to_string(),
                data: None,
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
        // catalog (ADR 133). Changing them silently would break the
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
    // Non-TTY detection
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
        let execution_contract = test_execution_contract();
        let params = build_broker_exec_params(&argv, env_pt, &execution_contract, b"", None, None);

        let obj = params.as_object().expect("params should be a JSON object");
        assert!(
            !obj.contains_key("pty_socket_path"),
            "non-TTY path must omit pty_socket_path; got {params:?}"
        );
        assert!(
            !obj.contains_key("binary"),
            "preferred broker_exec params must omit raw binary; got {params:?}"
        );
        assert!(
            !obj.contains_key("cwd"),
            "workspace_ref-backed broker_exec params must omit raw cwd; got {params:?}"
        );
        assert_no_top_level_execution_contract_mirrors(&params);
        // Sanity: the rest of the contract is preserved.
        assert_eq!(obj["argv"], json!(["push", "origin"]));
        assert_eq!(obj["env_passthrough"], json!(["GIT_TOKEN"]));
        assert_eq!(
            obj["execution_contract"]["contract_id"],
            json!("contract-test-123")
        );
        assert_eq!(
            obj["execution_contract"]["action_ref"]["action_key"],
            "git.push"
        );
    }

    /// TTY path (caller passes `Some(path)`) MUST include `pty_socket_path`
    /// verbatim — this is the existing interactive contract that ember-git /
    /// ember-gh rely on for terminal-attached operator use.
    #[test]
    fn build_broker_exec_params_with_pty_includes_key() {
        let argv = vec!["status".to_string()];
        let env_pt: &[&'static str] = &[];
        let p = std::path::PathBuf::from("/tmp/ember-construct-pty-test.sock");
        let execution_contract = test_execution_contract();
        let params =
            build_broker_exec_params(&argv, env_pt, &execution_contract, b"", None, Some(&p));

        let obj = params.as_object().expect("params should be a JSON object");
        assert_no_top_level_execution_contract_mirrors(&params);
        assert_eq!(
            obj.get("pty_socket_path").and_then(|v| v.as_str()),
            Some("/tmp/ember-construct-pty-test.sock"),
        );
    }

    #[test]
    fn build_broker_exec_params_includes_session_id_when_present() {
        let argv = vec!["status".to_string()];
        let env_pt: &[&'static str] = &[];
        let execution_contract = test_execution_contract();
        let params = build_broker_exec_params(
            &argv,
            env_pt,
            &execution_contract,
            b"",
            Some("sess_runtime_fixture"),
            None,
        );

        let obj = params.as_object().expect("params should be a JSON object");
        assert_no_top_level_execution_contract_mirrors(&params);
        assert_eq!(
            obj.get("session_id").and_then(|v| v.as_str()),
            Some("sess_runtime_fixture"),
        );
    }

    #[test]
    fn build_broker_exec_params_prefers_broker_cwd_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::set_var("EMBER_BROKER_CWD", "/home/test/worktree");
        }

        let argv = vec!["status".to_string()];
        let env_pt: &[&'static str] = &[];
        let execution_contract = test_execution_contract_without_workspace_ref();
        let params = build_broker_exec_params(&argv, env_pt, &execution_contract, b"", None, None);

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var("EMBER_BROKER_CWD");
        }

        let obj = params.as_object().expect("params should be a JSON object");
        assert_eq!(
            obj.get("cwd").and_then(|v| v.as_str()),
            Some("/home/test/worktree"),
        );
        assert!(
            !obj.contains_key("binary"),
            "compatibility cwd fallback should still omit raw binary; got {params:?}"
        );
        assert_no_top_level_execution_contract_mirrors(&params);
    }

    #[test]
    fn build_broker_exec_params_without_workspace_ref_omits_cwd_without_explicit_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var("EMBER_BROKER_CWD");
        }

        let argv = vec!["status".to_string()];
        let env_pt: &[&'static str] = &[];
        let execution_contract = test_execution_contract_without_workspace_ref();
        let params = build_broker_exec_params(&argv, env_pt, &execution_contract, b"", None, None);

        let obj = params.as_object().expect("params should be a JSON object");
        assert_no_top_level_execution_contract_mirrors(&params);
        assert!(
            !obj.contains_key("cwd"),
            "missing workspace_ref must not silently fall back to ambient cwd; got {params:?}"
        );
    }

    #[test]
    fn execution_contract_prefers_canonical_workspace_ref_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        let prior_workspace_ref = std::env::var_os(EMBER_WORKSPACE_REF_ENV);
        let prior_dev_runtime_id = std::env::var_os(EMBER_DEV_RUNTIME_ID_ENV);
        // SAFETY: tests that mutate process env are serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(EMBER_WORKSPACE_REF_ENV, "managed_worktree:rt-yankee");
            std::env::set_var(EMBER_DEV_RUNTIME_ID_ENV, "rt-legacy");
        }

        let execution_contract =
            execution_contract_for_action(test_gh_action_ref(), Some("sess_runtime_fixture"));

        // SAFETY: tests that mutate process env are serialized via ENV_LOCK.
        unsafe {
            match prior_workspace_ref {
                Some(value) => std::env::set_var(EMBER_WORKSPACE_REF_ENV, value),
                None => std::env::remove_var(EMBER_WORKSPACE_REF_ENV),
            }
            match prior_dev_runtime_id {
                Some(value) => std::env::set_var(EMBER_DEV_RUNTIME_ID_ENV, value),
                None => std::env::remove_var(EMBER_DEV_RUNTIME_ID_ENV),
            }
        }

        assert_eq!(
            execution_contract.workspace_ref.as_deref(),
            Some("managed_worktree:rt-yankee"),
            "construct runtime must prefer the canonical workspace ref over the legacy runtime id"
        );
    }

    #[test]
    fn execution_contract_keeps_legacy_runtime_id_workspace_ref_fallback() {
        let _guard = ENV_LOCK.lock().unwrap();
        let prior_workspace_ref = std::env::var_os(EMBER_WORKSPACE_REF_ENV);
        let prior_dev_runtime_id = std::env::var_os(EMBER_DEV_RUNTIME_ID_ENV);
        // SAFETY: tests that mutate process env are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(EMBER_WORKSPACE_REF_ENV);
            std::env::set_var(EMBER_DEV_RUNTIME_ID_ENV, "rt-yankee");
        }

        let execution_contract =
            execution_contract_for_action(test_gh_action_ref(), Some("sess_runtime_fixture"));

        // SAFETY: tests that mutate process env are serialized via ENV_LOCK.
        unsafe {
            match prior_workspace_ref {
                Some(value) => std::env::set_var(EMBER_WORKSPACE_REF_ENV, value),
                None => std::env::remove_var(EMBER_WORKSPACE_REF_ENV),
            }
            match prior_dev_runtime_id {
                Some(value) => std::env::set_var(EMBER_DEV_RUNTIME_ID_ENV, value),
                None => std::env::remove_var(EMBER_DEV_RUNTIME_ID_ENV),
            }
        }

        assert_eq!(
            execution_contract.workspace_ref.as_deref(),
            Some("managed_worktree:rt-yankee"),
            "legacy EMBER_DEV_RUNTIME_ID remains a compatibility carrier for v0.3.0 shims"
        );
    }

    #[test]
    fn execution_contract_reads_subject_and_coordination_refs_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        let prior_subject_ref = std::env::var_os(EMBER_SUBJECT_REF_ENV);
        let prior_forge_subject_ref = std::env::var_os(EMBER_FORGE_SUBJECT_REF_ENV);
        let prior_coordination_ref = std::env::var_os(EMBER_COORDINATION_REF_ENV);
        let prior_forge_coordination_ref = std::env::var_os(EMBER_FORGE_COORDINATION_REF_ENV);
        // SAFETY: tests that mutate process env are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(EMBER_SUBJECT_REF_ENV);
            std::env::set_var(EMBER_FORGE_SUBJECT_REF_ENV, " forge:run:run-123 ");
            std::env::set_var(EMBER_COORDINATION_REF_ENV, "forge:workflow_event:event-123");
            std::env::set_var(
                EMBER_FORGE_COORDINATION_REF_ENV,
                "forge:workflow_event:legacy",
            );
        }

        let execution_contract =
            execution_contract_for_action(test_gh_action_ref(), Some("sess_runtime_fixture"));

        // SAFETY: tests that mutate process env are serialized via ENV_LOCK.
        unsafe {
            match prior_subject_ref {
                Some(value) => std::env::set_var(EMBER_SUBJECT_REF_ENV, value),
                None => std::env::remove_var(EMBER_SUBJECT_REF_ENV),
            }
            match prior_forge_subject_ref {
                Some(value) => std::env::set_var(EMBER_FORGE_SUBJECT_REF_ENV, value),
                None => std::env::remove_var(EMBER_FORGE_SUBJECT_REF_ENV),
            }
            match prior_coordination_ref {
                Some(value) => std::env::set_var(EMBER_COORDINATION_REF_ENV, value),
                None => std::env::remove_var(EMBER_COORDINATION_REF_ENV),
            }
            match prior_forge_coordination_ref {
                Some(value) => std::env::set_var(EMBER_FORGE_COORDINATION_REF_ENV, value),
                None => std::env::remove_var(EMBER_FORGE_COORDINATION_REF_ENV),
            }
        }

        assert_eq!(
            execution_contract.subject_ref.as_deref(),
            Some("forge:run:run-123")
        );
        assert_eq!(
            execution_contract.coordination_ref.as_deref(),
            Some("forge:workflow_event:event-123"),
            "canonical EMBER_COORDINATION_REF must win over the Forge compatibility alias"
        );
    }

    #[test]
    fn build_broker_exec_params_includes_caller_persona_when_present() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var(EMBER_PERSONA_ID_ENV, "persona-fixture-id");
        }

        let argv = vec!["status".to_string()];
        let env_pt: &[&'static str] = &[];
        let execution_contract = test_execution_contract();
        let params = build_broker_exec_params(
            &argv,
            env_pt,
            &execution_contract,
            b"",
            Some("sess_runtime_fixture"),
            None,
        );

        unsafe {
            std::env::remove_var(EMBER_PERSONA_ID_ENV);
        }

        let obj = params.as_object().expect("params should be a JSON object");
        assert_no_top_level_execution_contract_mirrors(&params);
        assert_eq!(
            obj.get("caller_persona").and_then(|v| v.as_str()),
            Some("persona-fixture-id"),
        );
    }

    #[test]
    fn spawn_handle_broker_exec_params_omit_top_level_mirrors() {
        let argv = vec!["push".to_string(), "origin".to_string()];
        let handle = test_spawn_handle();
        let params =
            build_spawn_handle_broker_exec_params(&handle, &argv, Some("sess_runtime_fixture"));

        let obj = params.as_object().expect("params should be a JSON object");
        assert_no_top_level_execution_contract_mirrors(&params);
        assert_eq!(
            obj["execution_contract"]["contract_id"],
            json!("contract-test-123")
        );
        assert_eq!(
            obj["execution_contract"]["action_ref"]["action_key"],
            "git.push"
        );
        assert_eq!(obj["argv"], json!(["push", "origin"]));
        assert_eq!(obj["env_passthrough"], json!(["PATH"]));
        assert_eq!(obj["secret_ref"], json!("mat-abc-123"));
        assert_eq!(obj["target_uid"], json!(1000));
        assert_eq!(
            obj.get("session_id").and_then(|v| v.as_str()),
            Some("sess_runtime_fixture")
        );
    }

    #[test]
    fn build_broker_resolve_params_includes_persona_id_when_present() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var(EMBER_PERSONA_ID_ENV, "persona-fixture-id");
        }

        let execution_contract = test_execution_contract();
        let params = build_broker_resolve_params(
            &execution_contract,
            &["GIT_TOKEN".to_string()],
            TEST_CONSTRUCT_TOML_BYTES,
            Some("sess_runtime_fixture"),
        );

        unsafe {
            std::env::remove_var(EMBER_PERSONA_ID_ENV);
        }

        let obj = params.as_object().expect("params should be a JSON object");
        assert_eq!(
            obj.get("persona_id").and_then(|v| v.as_str()),
            Some("persona-fixture-id"),
        );
        assert!(
            obj["lease_request"].get("binary").is_none(),
            "preferred broker_resolve params must omit raw binary; got {params:?}"
        );
        assert_no_top_level_execution_contract_mirrors(&params);
        assert_eq!(obj["lease_request"]["action_ref"]["action_key"], "git.push");
        assert_eq!(
            obj["execution_contract"]["contract_id"],
            json!("contract-test-123")
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

    struct StubConfigClassifyNone {
        env: &'static str,
    }

    impl ClassifyArgv for StubConfigClassifyNone {
        fn classify(&self, _argv: &[String]) -> Option<ActionKey> {
            None
        }
    }

    impl ConstructConfig for StubConfigClassifyNone {
        fn session_id_env(&self) -> &'static str {
            self.env
        }
        fn construct_toml_bytes(&self) -> &'static [u8] {
            b""
        }
        fn resolve_binary(&self) -> String {
            "/usr/bin/false-fake-ccr-test-nonexistent".to_string()
        }
        fn env_passthrough(&self) -> &'static [&'static str] {
            &[]
        }
    }

    struct StubConfigForAction {
        env: &'static str,
        action: Option<&'static str>,
        factory_disposition: Option<FactoryDisposition>,
        scrubbed_env: &'static [&'static str],
    }

    impl ClassifyArgv for StubConfigForAction {
        fn classify(&self, _argv: &[String]) -> Option<ActionKey> {
            self.action.map(|action| ActionKey(action.to_string()))
        }
    }

    impl ConstructConfig for StubConfigForAction {
        fn session_id_env(&self) -> &'static str {
            self.env
        }
        fn construct_toml_bytes(&self) -> &'static [u8] {
            b""
        }
        fn resolve_binary(&self) -> String {
            "/usr/bin/false-fake-ccr-test-nonexistent".to_string()
        }
        fn env_passthrough(&self) -> &'static [&'static str] {
            &[]
        }
        fn factory_disposition(
            &self,
            _action_key: Option<&ActionKey>,
            _argv: &[String],
        ) -> Option<FactoryDisposition> {
            self.factory_disposition
        }
        fn credentialless_env_scrub(&self) -> &'static [&'static str] {
            self.scrubbed_env
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
            eprintln!("run_construct_full_no_tty_skips_pty_bind: skipped (parent has TTY)");
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

    #[test]
    fn run_construct_full_partial_session_env_fails_fast_before_rpc() {
        let _guard = ENV_LOCK.lock().unwrap();

        let env_var = "EMBER_SESSION_ID_PARTIAL_TEST";
        let pty_path = std::path::PathBuf::from(format!(
            "/tmp/ember-construct-pty-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&pty_path);

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(env_var, "session-partial");
            std::env::remove_var(EMBER_ATTACHMENT_ID_ENV);
            std::env::remove_var(EMBER_ATTACHMENT_ENDPOINT_TOKEN_ENV);
            std::env::set_var(
                "EMBER_SOCKET_PATH",
                "/tmp/ember-construct-runtime-partial-env-NONEXISTENT.sock",
            );
        }

        let config = StubConfig { env: env_var };
        let argv: Vec<String> = vec!["push".to_string(), "origin".to_string()];
        let exit = run_construct_full(&argv, &config);

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(env_var);
            std::env::remove_var("EMBER_SOCKET_PATH");
        }

        assert_eq!(
            exit,
            ExitCode::from(1u8),
            "partial session env must fail fast"
        );
        assert!(
            !pty_path.exists(),
            "partial session env must fail before any PTY socket bind"
        );
    }

    #[test]
    fn run_construct_full_env_absent_classified_action_fails_closed() {
        let _guard = ENV_LOCK.lock().unwrap();

        let env_var = "EMBER_SESSION_ID_ENV_ABSENT_CLASSIFIED_TEST";
        let pty_path = std::path::PathBuf::from(format!(
            "/tmp/ember-construct-pty-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&pty_path);

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(env_var);
            std::env::remove_var(EMBER_ATTACHMENT_ID_ENV);
            std::env::remove_var(EMBER_ATTACHMENT_ENDPOINT_TOKEN_ENV);
        }

        let config = StubConfig { env: env_var };
        let argv: Vec<String> = vec!["push".to_string(), "origin".to_string()];
        let exit = run_construct_full(&argv, &config);

        assert_eq!(
            exit,
            ExitCode::from(1u8),
            "classified no-session action must fail closed"
        );
        assert!(
            !pty_path.exists(),
            "classified no-session action must fail before any PTY socket bind"
        );
    }

    #[test]
    fn h2_construct_gate_denies_credentialed_verbs_without_session() {
        let _guard = ENV_LOCK.lock().unwrap();

        for (label, env_var, action, argv) in [
            (
                "git_push",
                "EMBER_SESSION_ID_H2_GIT_PUSH",
                "git.push",
                vec!["push", "origin"],
            ),
            (
                "gh_pr_create",
                "EMBER_SESSION_ID_H2_GH_PR_CREATE",
                "gh.pr_create",
                vec!["pr", "create"],
            ),
            (
                "kubectl_apply",
                "EMBER_SESSION_ID_H2_KUBECTL_APPLY",
                "kubectl.apply",
                vec!["apply", "-f", "k8s.yaml"],
            ),
        ] {
            let pty_path = std::path::PathBuf::from(format!(
                "/tmp/ember-construct-pty-{}.sock",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&pty_path);

            unsafe {
                std::env::remove_var(&env_var);
                std::env::remove_var(EMBER_ATTACHMENT_ID_ENV);
                std::env::remove_var(EMBER_ATTACHMENT_ENDPOINT_TOKEN_ENV);
            }

            let config = StubConfigForAction {
                env: env_var,
                action: Some(action),
                factory_disposition: None,
                scrubbed_env: &[],
            };
            let argv: Vec<String> = argv.into_iter().map(str::to_string).collect();
            let exit = run_construct_full(&argv, &config);

            unsafe {
                std::env::remove_var(&env_var);
            }

            assert_eq!(
                exit,
                ExitCode::from(1u8),
                "{label}: credential-bearing no-session action must fail closed"
            );
            assert!(
                !pty_path.exists(),
                "{label}: no-session credential gate must fail before PTY/broker setup"
            );
        }
    }

    #[test]
    fn run_construct_full_env_absent_classify_none_passthrough_execs() {
        let _guard = ENV_LOCK.lock().unwrap();

        let env_var = "EMBER_SESSION_ID_ENV_ABSENT_NONE_TEST";

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(env_var);
            std::env::remove_var(EMBER_ATTACHMENT_ID_ENV);
            std::env::remove_var(EMBER_ATTACHMENT_ENDPOINT_TOKEN_ENV);
        }

        let config = StubConfigClassifyNone { env: env_var };
        let argv: Vec<String> = vec!["status".to_string()];
        let exit = run_construct_full(&argv, &config);

        assert_eq!(
            exit,
            ExitCode::from(126u8),
            "classify=None no-session path should still passthrough-exec"
        );
    }

    #[test]
    fn run_construct_full_sessioned_classify_none_skips_broker_rpc() {
        let _guard = ENV_LOCK.lock().unwrap();

        let env_var = "EMBER_SESSION_ID_CLASSIFY_NONE_TEST";
        let pty_path = std::path::PathBuf::from(format!(
            "/tmp/ember-construct-pty-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&pty_path);

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(env_var, "session-classify-none");
            std::env::set_var(EMBER_ATTACHMENT_ID_ENV, "att-classify-none");
            std::env::set_var(EMBER_ATTACHMENT_ENDPOINT_TOKEN_ENV, "ep-classify-none");
            std::env::set_var(
                "EMBER_SOCKET_PATH",
                "/tmp/ember-construct-runtime-classify-none-NONEXISTENT.sock",
            );
        }

        let config = StubConfigClassifyNone { env: env_var };
        let argv: Vec<String> = vec!["status".to_string()];
        let exit = run_construct_full(&argv, &config);

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(env_var);
            std::env::remove_var(EMBER_ATTACHMENT_ID_ENV);
            std::env::remove_var(EMBER_ATTACHMENT_ENDPOINT_TOKEN_ENV);
            std::env::remove_var("EMBER_SOCKET_PATH");
        }

        assert_eq!(
            exit,
            ExitCode::from(126u8),
            "sessioned classify=None path must passthrough-exec, not hit broker RPC"
        );
        assert!(
            !pty_path.exists(),
            "classify=None passthrough must return before any PTY socket bind"
        );
    }

    #[test]
    fn h7_read_only_passthrough_skips_broker_for_named_verbs() {
        let _guard = ENV_LOCK.lock().unwrap();

        for (label, env_var, argv) in [
            (
                "git_status",
                "EMBER_SESSION_ID_H7_GIT_STATUS",
                vec!["status"],
            ),
            (
                "kubectl_get",
                "EMBER_SESSION_ID_H7_KUBECTL_GET",
                vec!["get", "pods"],
            ),
        ] {
            let pty_path = std::path::PathBuf::from(format!(
                "/tmp/ember-construct-pty-{}.sock",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&pty_path);

            unsafe {
                std::env::set_var(&env_var, "session-read-only");
                std::env::set_var(EMBER_ATTACHMENT_ID_ENV, "att-read-only");
                std::env::set_var(EMBER_ATTACHMENT_ENDPOINT_TOKEN_ENV, "ep-read-only");
                std::env::set_var(
                    "EMBER_SOCKET_PATH",
                    format!("/tmp/ember-construct-runtime-h7-{label}-NONEXISTENT.sock"),
                );
            }

            let config = StubConfigForAction {
                env: env_var,
                action: None,
                factory_disposition: None,
                scrubbed_env: &[],
            };
            let argv: Vec<String> = argv.into_iter().map(str::to_string).collect();
            let exit = run_construct_full(&argv, &config);

            unsafe {
                std::env::remove_var(&env_var);
                std::env::remove_var(EMBER_ATTACHMENT_ID_ENV);
                std::env::remove_var(EMBER_ATTACHMENT_ENDPOINT_TOKEN_ENV);
                std::env::remove_var("EMBER_SOCKET_PATH");
            }

            assert_eq!(
                exit,
                ExitCode::from(126u8),
                "{label}: read-only classify=None path should attempt direct passthrough exec"
            );
            assert!(
                !pty_path.exists(),
                "{label}: read-only passthrough must not enter broker/PTY setup"
            );
        }
    }

    #[test]
    fn credentialless_command_removes_provider_env_from_child() {
        let argv = vec!["s3".to_string(), "ls".to_string()];
        let command = build_credentialless_command(
            "/usr/bin/aws",
            &argv,
            &["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"],
            &[
                ("AWS_SHARED_CREDENTIALS_FILE", "/dev/null"),
                ("AWS_CONFIG_FILE", "/dev/null"),
                ("AWS_EC2_METADATA_DISABLED", "true"),
            ],
        );
        let envs: Vec<_> = command
            .get_envs()
            .map(|(key, value)| (key.to_os_string(), value.map(|v| v.to_os_string())))
            .collect();

        for key in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"] {
            assert!(
                envs.iter()
                    .any(|(env_key, value)| env_key == key && value.is_none()),
                "credentialless command must remove {key}"
            );
        }

        for (key, expected) in [
            ("AWS_SHARED_CREDENTIALS_FILE", "/dev/null"),
            ("AWS_CONFIG_FILE", "/dev/null"),
            ("AWS_EC2_METADATA_DISABLED", "true"),
        ] {
            assert!(
                envs.iter().any(|(env_key, value)| env_key == key
                    && value.as_deref() == Some(std::ffi::OsStr::new(expected))),
                "credentialless command must pin {key}={expected}"
            );
        }
    }

    #[test]
    fn run_construct_full_factory_credentialless_skips_broker_and_scrubs() {
        let _guard = ENV_LOCK.lock().unwrap();

        let env_var = "EMBER_SESSION_ID_FACTORY_CREDENTIALLESS_TEST";
        let pty_path = std::path::PathBuf::from(format!(
            "/tmp/ember-construct-pty-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&pty_path);

        unsafe {
            std::env::set_var(env_var, "session-factory-credentialless");
            std::env::set_var(EMBER_ATTACHMENT_ID_ENV, "att-factory-credentialless");
            std::env::set_var(
                EMBER_ATTACHMENT_ENDPOINT_TOKEN_ENV,
                "ep-factory-credentialless",
            );
            std::env::set_var(
                "EMBER_SOCKET_PATH",
                "/tmp/ember-construct-runtime-factory-credentialless-NONEXISTENT.sock",
            );
            std::env::set_var("AWS_ACCESS_KEY_ID", "must-not-reach-child");
        }

        let config = StubConfigForAction {
            env: env_var,
            action: None,
            factory_disposition: Some(FactoryDisposition::Credentialless),
            scrubbed_env: &["AWS_ACCESS_KEY_ID"],
        };
        let argv: Vec<String> = vec!["s3".to_string(), "ls".to_string()];
        let exit = run_construct_full(&argv, &config);

        unsafe {
            std::env::remove_var(env_var);
            std::env::remove_var(EMBER_ATTACHMENT_ID_ENV);
            std::env::remove_var(EMBER_ATTACHMENT_ENDPOINT_TOKEN_ENV);
            std::env::remove_var("EMBER_SOCKET_PATH");
            std::env::remove_var("AWS_ACCESS_KEY_ID");
        }

        assert_eq!(
            exit,
            ExitCode::from(126u8),
            "factory credentialless path should direct-exec the wrapped binary"
        );
        assert!(
            !pty_path.exists(),
            "factory credentialless path must not enter broker/PTY setup"
        );
    }

    #[test]
    fn run_construct_full_factory_refusal_fails_before_legacy_passthrough() {
        let _guard = ENV_LOCK.lock().unwrap();

        let env_var = "EMBER_SESSION_ID_FACTORY_REFUSAL_TEST";
        let pty_path = std::path::PathBuf::from(format!(
            "/tmp/ember-construct-pty-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&pty_path);

        unsafe {
            std::env::set_var(env_var, "session-factory-refusal");
            std::env::set_var(EMBER_ATTACHMENT_ID_ENV, "att-factory-refusal");
            std::env::set_var(EMBER_ATTACHMENT_ENDPOINT_TOKEN_ENV, "ep-factory-refusal");
            std::env::set_var(
                "EMBER_SOCKET_PATH",
                "/tmp/ember-construct-runtime-factory-refusal-NONEXISTENT.sock",
            );
        }

        let config = StubConfigForAction {
            env: env_var,
            action: None,
            factory_disposition: Some(FactoryDisposition::PayloadAnalysisRequired),
            scrubbed_env: &[],
        };
        let argv: Vec<String> = vec!["deploy".to_string(), "--template".to_string()];
        let exit = run_construct_full(&argv, &config);

        unsafe {
            std::env::remove_var(env_var);
            std::env::remove_var(EMBER_ATTACHMENT_ID_ENV);
            std::env::remove_var(EMBER_ATTACHMENT_ENDPOINT_TOKEN_ENV);
            std::env::remove_var("EMBER_SOCKET_PATH");
        }

        assert_eq!(
            exit,
            ExitCode::from(1u8),
            "factory refusal must fail closed instead of legacy passthrough"
        );
        assert!(
            !pty_path.exists(),
            "factory refusal must return before broker/PTY setup"
        );
    }

    // -----------------------------------------------------------------------
    // Tier 1 tests for
    // log_unsessioned_subprocess. The daemon-up happy-path is exercised by
    // ember-daemon's handle_subprocess_audit_log tests; here we pin the
    // best-effort failure modes — vendor=="unknown" short-circuit, and
    // daemon-unreachable returning without panic.
    // -----------------------------------------------------------------------

    struct StubConfigWithVendor {
        env: &'static str,
        vendor: &'static str,
    }
    impl ClassifyArgv for StubConfigWithVendor {
        fn classify(&self, _argv: &[String]) -> Option<ActionKey> {
            Some(ActionKey("git.push".to_string()))
        }
    }
    impl ConstructConfig for StubConfigWithVendor {
        fn vendor(&self) -> &'static str {
            self.vendor
        }
        fn session_id_env(&self) -> &'static str {
            self.env
        }
        fn construct_toml_bytes(&self) -> &'static [u8] {
            b""
        }
        fn resolve_binary(&self) -> String {
            "/usr/bin/false-fake-ccr-test-nonexistent".to_string()
        }
        fn env_passthrough(&self) -> &'static [&'static str] {
            &[]
        }
    }

    #[test]
    fn log_unsessioned_subprocess_skips_when_vendor_unknown() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            // Even with a never-existent socket path, an "unknown" vendor
            // must not even attempt the RPC — it would otherwise burn a
            // connect+timeout on every invocation.
            std::env::set_var(
                "EMBER_SOCKET_PATH",
                "/tmp/ember-construct-runtime-unknown-vendor-NONEXISTENT.sock",
            );
        }
        let config = StubConfigWithVendor {
            env: "EMBER_SESSION_ID_VENDOR_UNKNOWN_TEST",
            vendor: "unknown",
        };
        let argv: Vec<String> = vec!["push".to_string()];
        // Must return without panic. We can't easily prove "no connect
        // attempt" from outside, but the test will hang past the 50ms
        // timeout if the short-circuit broke.
        let start = std::time::Instant::now();
        log_unsessioned_subprocess(&config, &argv, UnsessionedOutcome::AmbientCredentialUsed);
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(20),
            "vendor=unknown must short-circuit before the RPC timeout; took {elapsed:?}"
        );
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var("EMBER_SOCKET_PATH");
        }
    }

    #[test]
    fn log_unsessioned_subprocess_swallows_daemon_unreachable() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(
                "EMBER_SOCKET_PATH",
                "/tmp/ember-construct-runtime-daemon-down-NONEXISTENT.sock",
            );
        }
        let config = StubConfigWithVendor {
            env: "EMBER_SESSION_ID_DAEMON_DOWN_TEST",
            vendor: "git",
        };
        let argv: Vec<String> = vec!["push".to_string(), "origin".to_string()];
        // Returns without panic / propagation. UDS connect returns
        // ECONNREFUSED / ENOENT synchronously — no timeout needed.
        log_unsessioned_subprocess(&config, &argv, UnsessionedOutcome::AmbientCredentialUsed);
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var("EMBER_SOCKET_PATH");
        }
    }

    // -----------------------------------------------------------------------
    // Trusted-resolver hook (factory_resolver_framework_landed).
    //
    // These tests prove the runtime calls
    // `ConstructConfig::resolve_target_from_environment` for ResolverRequired
    // dispositions before the refusal exit, re-runs classify+disposition on
    // the synthesized argv, and stays silent on non-ResolverRequired
    // dispositions.
    // -----------------------------------------------------------------------

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test config whose `resolve_target_from_environment` and
    /// `factory_disposition` calls are observable from the test via shared
    /// `Arc<AtomicUsize>` counters.
    struct ResolverHookStub {
        env: &'static str,
        resolver_calls: Arc<AtomicUsize>,
        disposition_calls: Arc<AtomicUsize>,
        synthesized_argv: Option<Vec<String>>,
        first_disposition: Option<FactoryDisposition>,
        synthesized_disposition: Option<FactoryDisposition>,
    }

    impl ClassifyArgv for ResolverHookStub {
        fn classify(&self, _argv: &[String]) -> Option<ActionKey> {
            Some(ActionKey("gh.pr_list".to_string()))
        }
    }

    impl ConstructConfig for ResolverHookStub {
        fn session_id_env(&self) -> &'static str {
            self.env
        }
        fn construct_toml_bytes(&self) -> &'static [u8] {
            b""
        }
        fn resolve_binary(&self) -> String {
            "/usr/bin/false-fake-ccr-test-nonexistent".to_string()
        }
        fn env_passthrough(&self) -> &'static [&'static str] {
            &[]
        }
        fn factory_disposition(
            &self,
            _action_key: Option<&ActionKey>,
            argv: &[String],
        ) -> Option<FactoryDisposition> {
            let call = self.disposition_calls.fetch_add(1, Ordering::SeqCst);
            // First call sees the raw argv. After the resolver-hook
            // synthesizes argv, the runtime re-calls disposition on the new
            // argv — distinguish by content rather than call-count, since
            // call-count order isn't load-bearing.
            match &self.synthesized_argv {
                Some(synth) if argv == synth.as_slice() => self.synthesized_disposition,
                _ if call == 0 => self.first_disposition,
                _ => self.first_disposition,
            }
        }
        fn resolve_target_from_environment(
            &self,
            _action_key: Option<&ActionKey>,
            _argv: &[String],
            _cwd: &std::path::Path,
        ) -> Option<Vec<String>> {
            self.resolver_calls.fetch_add(1, Ordering::SeqCst);
            self.synthesized_argv.clone()
        }
    }

    /// AC: when disposition is `ResolverRequired`, the runtime invokes
    /// `resolve_target_from_environment` BEFORE `factory_refusal_exit`.
    /// A `None` return falls through to the legacy refusal (exit 1).
    #[test]
    fn factory_resolver_hook_called_when_resolver_required_and_none_falls_through() {
        let _guard = ENV_LOCK.lock().unwrap();
        let env_var = "EMBER_SESSION_ID_RESOLVER_HOOK_FALLTHROUGH";
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(env_var);
            std::env::set_var(
                "EMBER_SOCKET_PATH",
                "/tmp/ember-construct-runtime-resolver-hook-falls-through-NONEXISTENT.sock",
            );
        }

        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let disposition_calls = Arc::new(AtomicUsize::new(0));
        let config = ResolverHookStub {
            env: env_var,
            resolver_calls: Arc::clone(&resolver_calls),
            disposition_calls: Arc::clone(&disposition_calls),
            synthesized_argv: None, // resolver fails to derive
            first_disposition: Some(FactoryDisposition::ResolverRequired),
            synthesized_disposition: None,
        };
        let argv: Vec<String> = vec!["pr".into(), "list".into()];
        let exit = run_construct_full(&argv, &config);

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var("EMBER_SOCKET_PATH");
        }

        assert_eq!(
            resolver_calls.load(Ordering::SeqCst),
            1,
            "runtime MUST call resolve_target_from_environment once when disposition is ResolverRequired"
        );
        assert_eq!(
            exit,
            ExitCode::from(1u8),
            "resolver None falls through to factory_refusal_exit (ResolverRequired)"
        );
    }

    /// AC: when the resolver returns `Some(synthesized)` and the synthesized
    /// argv re-disposes to a non-refusal class (Credentialless here), the
    /// runtime advances PAST the refusal exit instead of refusing. Proven by
    /// reaching `exec_factory_credentialless` whose failed exec returns 126
    /// (distinct from the refusal's exit 1).
    #[test]
    fn factory_resolver_hook_synthesized_argv_re_runs_disposition_past_refusal() {
        let _guard = ENV_LOCK.lock().unwrap();
        let env_var = "EMBER_SESSION_ID_RESOLVER_HOOK_SYNTHESIZED";
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(env_var);
            std::env::set_var(
                "EMBER_SOCKET_PATH",
                "/tmp/ember-construct-runtime-resolver-hook-synthesized-NONEXISTENT.sock",
            );
        }

        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let disposition_calls = Arc::new(AtomicUsize::new(0));
        let synthesized = vec![
            "pr".to_string(),
            "list".to_string(),
            "--repo".to_string(),
            "acme/widgets".to_string(),
        ];
        let config = ResolverHookStub {
            env: env_var,
            resolver_calls: Arc::clone(&resolver_calls),
            disposition_calls: Arc::clone(&disposition_calls),
            synthesized_argv: Some(synthesized.clone()),
            first_disposition: Some(FactoryDisposition::ResolverRequired),
            // After synthesis, this would normally become `Mediated`. Use
            // `Credentialless` here so we exit at the credentialless-exec
            // path (126) instead of running through RPC plumbing — the only
            // load-bearing assertion is "advanced past the refusal arm."
            synthesized_disposition: Some(FactoryDisposition::Credentialless),
        };
        let argv: Vec<String> = vec!["pr".into(), "list".into()];
        let exit = run_construct_full(&argv, &config);

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var("EMBER_SOCKET_PATH");
        }

        assert_eq!(
            resolver_calls.load(Ordering::SeqCst),
            1,
            "runtime MUST call resolve_target_from_environment once"
        );
        assert!(
            disposition_calls.load(Ordering::SeqCst) >= 2,
            "runtime MUST re-run factory_disposition on the synthesized argv (got {} calls)",
            disposition_calls.load(Ordering::SeqCst)
        );
        // Credentialless path execs /nonexistent → exit 126; would have
        // been 1 if the refusal arm fired.
        assert_eq!(
            exit,
            ExitCode::from(126u8),
            "synthesized argv must reach Credentialless exec path (126), not refusal (1)"
        );
    }

    /// AC: hook is silent for non-ResolverRequired dispositions. Mediated
    /// stays on the broker path; the resolver is never asked.
    #[test]
    fn factory_resolver_hook_not_called_for_mediated_disposition() {
        let _guard = ENV_LOCK.lock().unwrap();
        let env_var = "EMBER_SESSION_ID_RESOLVER_HOOK_MEDIATED";
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(env_var);
            std::env::set_var(
                "EMBER_SOCKET_PATH",
                "/tmp/ember-construct-runtime-resolver-hook-mediated-NONEXISTENT.sock",
            );
        }

        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let disposition_calls = Arc::new(AtomicUsize::new(0));
        let config = ResolverHookStub {
            env: env_var,
            resolver_calls: Arc::clone(&resolver_calls),
            disposition_calls: Arc::clone(&disposition_calls),
            synthesized_argv: Some(vec!["unused".to_string()]),
            first_disposition: Some(FactoryDisposition::Mediated),
            synthesized_disposition: None,
        };
        let argv: Vec<String> = vec!["pr".into(), "list".into(), "--repo".into(), "x/y".into()];
        // env not set → no-session + classified Some → DeniedNoSession arm → exit 1.
        let _ = run_construct_full(&argv, &config);

        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var("EMBER_SOCKET_PATH");
        }

        assert_eq!(
            resolver_calls.load(Ordering::SeqCst),
            0,
            "Mediated disposition MUST NOT consult the resolver hook"
        );
    }
}
