use std::cell::RefCell;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use core_broker::BrokerProvider;
use thiserror::Error;
use tokio::signal;
use tokio::sync::{oneshot, watch};
use tracing::info;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use libc;

use crate::infra::config::DaemonConfig;
use crate::infra::dashboard::run_dashboard;
use crate::infra::pid::{PidError, PidFile};
use crate::infra::rate_limit::RateLimiter;
use crate::infra::socket::{SocketError, SocketListener, new_shared_policy_engine};
use crate::infra::store::DaemonStore;
use crate::infra::vault::{Vault, log_vault_identity};
use crate::trust::bridge_ca::{BridgeCa, BridgeCaLoadError};
use crate::trust::policy::{PolicyEngine, PolicyError};

fn daemon_socket_path_with(
    config: &DaemonConfig,
    env_override: Option<std::ffi::OsString>,
) -> PathBuf {
    env_override
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| config.socket_dir.join("daemon.sock"))
}

fn daemon_socket_path(config: &DaemonConfig) -> PathBuf {
    daemon_socket_path_with(config, std::env::var_os("EMBER_DAEMON_SOCKET"))
}

const STARTUP_BINARY_MANIFEST_ENV: &str = "EMBER_MANIFEST_PATH";

fn startup_binary_manifest_candidates(explicit_manifest: Option<PathBuf>) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = explicit_manifest.filter(|path| !path.as_os_str().is_empty()) {
        candidates.push(path);
    }
    candidates.push(crate::binary_manifest::bundled_install_dir().join("manifest.toml"));
    candidates
}

fn resolve_startup_binary_manifest_path<F>(
    explicit_manifest: Option<PathBuf>,
    exists: F,
) -> Option<PathBuf>
where
    F: Fn(&Path) -> bool,
{
    startup_binary_manifest_candidates(explicit_manifest)
        .into_iter()
        .find(|path| exists(path))
}

fn reload_policy_slot_from_file(
    policy_slot: &crate::infra::socket::SharedPolicyEngine,
    policy_file: &std::path::Path,
) -> Result<(), PolicyError> {
    let engine = PolicyEngine::from_file(policy_file)?;
    *policy_slot.borrow_mut() = Rc::new(engine);
    Ok(())
}

/// Path to the dedicated `0700` rpc-forward UDS the daemon binds for the
/// OS-supervised `ember-rpc` sibling (ADR 155 priv-sep SLICE 2a). Distinct from
/// the shared `0660 daemon.sock` — `0700 ember:ember` so only the `ember`-uid
/// sibling can dial it. Kept in lockstep with `ember_rpc::Config::default()
/// .forward_uds`; once the sibling is OS-supervised (a later sub-slice) its unit
/// pins `EMBER_RPC_FORWARD_UDS` to this path when `socket_dir` is not the
/// default `/var/run/emberd`.
fn daemon_rpc_socket_path(config: &DaemonConfig) -> PathBuf {
    config.socket_dir.join("rpc.sock")
}

/// P22-S2 PR-E: parse the `EMBER_TRANSITIONAL_TCP_LLM_PROXY` opt-in. The
/// loopback-TCP LLM gateway is OFF by default (the per-session UDS lanes are
/// live); an operator re-enables it only with `1`/`true` (case-insensitive,
/// trimmed). Any other value — or absent — keeps it disabled (fail-closed:
/// the squattable no-peer-auth listener stays down unless explicitly asked for).
fn parse_transitional_tcp_flag(value: Option<&str>) -> bool {
    match value {
        Some(v) => {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        }
        None => false,
    }
}

/// ADR 207: container sessions cannot use the host peercred UDS lane, so a
/// daemon with the mTLS container bridge configured must also expose the TCP
/// Anthropic data-plane proxy. The explicit transitional flag remains the
/// host-only compatibility escape hatch.
fn should_bind_llm_proxy(value: Option<&str>, bridge_configured: bool) -> bool {
    parse_transitional_tcp_flag(value) || bridge_configured
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("config error: {0}")]
    Config(#[from] crate::infra::config::ConfigError),
    #[error("pid error: {0}")]
    Pid(#[from] PidError),
    #[error("socket error: {0}")]
    Socket(#[from] SocketError),
    #[error("store error: {0}")]
    Store(#[from] crate::infra::store::StoreError),
    #[error("vault error: {0}")]
    Vault(String),
    #[error("policy error: {0}")]
    Policy(#[from] PolicyError),
    #[error("daemon is not running")]
    NotRunning,
    #[error("signal error: {0}")]
    Signal(std::io::Error),
    /// Audit-chain startup wiring (D): startup sampling verify
    /// detected a chain break. The daemon refused normal-serve and
    /// entered quarantine. Recovery requires operator intervention.
    #[error("audit chain break detected at startup: {0}")]
    AuditChainBreak(String),
    /// Audit-chain startup wiring (E): the
    /// daemon's long-lived identity key could not be initialised, so
    /// the daemon refuses startup (fail-closed). Receipts are
    /// load-bearing for the audit chain and the broker; running
    /// without a signing identity would silently produce unverifiable
    /// state.
    #[error("identity init failed: {0}")]
    IdentityInitFailed(String),
    /// Bridge CA startup bootstrap: the explicit bridge
    /// bootstrap path (ADR 154 component 3) could not load or mint the
    /// Bridge CA. When the bridge lane is enabled, fail closed rather than
    /// starting with a missing CA or unreadable sibling cert.
    #[error("bridge CA init failed: {0}")]
    BridgeCaInit(String),
}

/// Internal status of the vault auto-unseal step at daemon startup. Used to
/// Startup action for providers that are optional on the operator/dev0 lane.
/// GitHub stays load-bearing; every other provider may be:
/// - registered as real when configured
/// - registered as Mock when explicitly allow-listed
/// - skipped when absent or currently malformed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OptionalBrokerStartupAction {
    RegisterReal,
    RegisterMock,
    Skip,
}

fn optional_broker_startup_action(
    configured: &Result<bool, crate::broker::authority::BrokerAuthorityError>,
    mock_opted_in: bool,
) -> OptionalBrokerStartupAction {
    match configured {
        Ok(true) => OptionalBrokerStartupAction::RegisterReal,
        Ok(false) | Err(_) => {
            if mock_opted_in {
                OptionalBrokerStartupAction::RegisterMock
            } else {
                OptionalBrokerStartupAction::Skip
            }
        }
    }
}

fn broker_startup_config_path(provider: BrokerProvider) -> Option<&'static str> {
    match provider {
        BrokerProvider::Github => Some("~/.config/emberlink/ember-engine.env"),
        BrokerProvider::AwsSts => Some("~/.config/emberlink/aws-sts.env"),
        BrokerProvider::Gcp => Some("~/.config/emberlink/gcp.env"),
        BrokerProvider::AzureCli => Some("~/.config/emberlink/azure.env"),
        BrokerProvider::FlyIo => Some("~/.config/emberlink/fly.env"),
        BrokerProvider::HashiVault => Some("~/.config/emberlink/hashivault.env"),
        BrokerProvider::Okta => Some("~/.config/emberlink/okta.env"),
        BrokerProvider::Vercel => Some("~/.config/emberlink/vercel.env"),
        BrokerProvider::Cloudflare | BrokerProvider::Anthropic | BrokerProvider::Tailscale => None,
    }
}

fn warn_mock_broker_registration(
    provider: &'static str,
    config_path: Option<&'static str>,
    reason: &'static str,
    error: Option<&str>,
) {
    match (config_path, error) {
        (Some(path), Some(err)) => tracing::warn!(
            provider,
            config_path = path,
            error = err,
            "mock broker registered: {provider} ({reason})"
        ),
        (Some(path), None) => tracing::warn!(
            provider,
            config_path = path,
            "mock broker registered: {provider} ({reason})"
        ),
        (None, Some(err)) => tracing::warn!(
            provider,
            error = err,
            "mock broker registered: {provider} ({reason})"
        ),
        (None, None) => tracing::warn!(provider, "mock broker registered: {provider} ({reason})"),
    }
}

fn should_bootstrap_vault_at_startup(bridge_bind: Option<SocketAddr>) -> bool {
    bridge_bind.is_some()
}

/// The outcome of a dashboard TCP bind attempt. Sent to `run()`'s `start_notify`
/// callback after the bind (or timeout) so the CLI can print the correct banner line.
#[derive(Debug, Clone)]
pub enum DashboardBind {
    /// Dashboard bound successfully. Contains the address it is listening on.
    Bound(SocketAddr),
    /// Dashboard failed to bind. Contains the attempted address and the OS error message.
    Failed { addr: SocketAddr, error: String },
    /// No dashboard configured (dashboard_addr is None in DaemonConfig).
    Disabled,
    /// The bind task did not respond within the startup timeout.
    Timeout,
}

/// Outcome of the git-echo credential-injection proxy bind.
/// Mirrors `DashboardBind` semantics. Sent to `run()`'s `start_notify`
/// callback so the CLI can print `EMBER_PROXY_URL=…` for qember.sh +
/// ember-git.sh consumers.
#[derive(Debug, Clone)]
pub enum GitProxyBind {
    /// Proxy bound successfully. Contains the address it is listening on.
    Bound(SocketAddr),
    /// Proxy failed to bind. Contains the attempted address and the OS error message.
    Failed { addr: SocketAddr, error: String },
    /// No proxy configured (`git_proxy_addr` is `None` in `DaemonConfig`).
    Disabled,
    /// The bind task did not respond within the startup timeout.
    Timeout,
}

/// Outcome of the general LLM/HTTP credential-
/// injection proxy bind. Mirrors `GitProxyBind` semantics. The LLM proxy
/// (`run_proxy` / `handle_request`) is what the Anthropic SDK demo path
/// posts to; its bound URL is exposed via `EMBER_PROXY_URL` and the
/// `proxy.url` sidecar.
#[derive(Debug, Clone)]
pub enum LlmProxyBind {
    /// Proxy bound successfully. Contains the address it is listening on.
    Bound(SocketAddr),
    /// Proxy failed to bind. Contains the attempted address and the OS error message.
    Failed { addr: SocketAddr, error: String },
    /// No proxy configured (`llm_proxy_addr` is `None` in `DaemonConfig`).
    Disabled,
    /// The bind task did not respond within the startup timeout.
    Timeout,
}

const LOCAL_PROXY_RESTART_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

#[cfg(any(target_os = "macos", test))]
async fn start_local_startup_component_on_local<T, F, Fut>(
    local: &tokio::task::LocalSet,
    component: &'static str,
    start: F,
) -> Option<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    local
        .run_until(async {
            match start().await {
                Ok(value) => Some(value),
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        component,
                        "local startup component unavailable"
                    );
                    None
                }
            }
        })
        .await
}

async fn supervise_local_proxy<F, Fut>(
    label: &'static str,
    configured_addr: SocketAddr,
    shutdown: watch::Receiver<bool>,
    startup_bind_tx: oneshot::Sender<Result<SocketAddr, std::io::Error>>,
    mut run_once: F,
) where
    F: FnMut(
            SocketAddr,
            watch::Receiver<bool>,
            oneshot::Sender<Result<SocketAddr, std::io::Error>>,
        ) -> Fut
        + 'static,
    Fut: std::future::Future<Output = Result<(), crate::infra::proxy::ProxyError>> + 'static,
{
    let mut next_bind_addr = configured_addr;
    let mut startup_bind_tx = Some(startup_bind_tx);

    loop {
        let (attempt_bind_tx, attempt_bind_rx) = oneshot::channel();
        let handle =
            tokio::task::spawn_local(run_once(next_bind_addr, shutdown.clone(), attempt_bind_tx));

        let bind_outcome = attempt_bind_rx.await;
        match &bind_outcome {
            Ok(Ok(bound)) => {
                next_bind_addr = *bound;
                if let Some(tx) = startup_bind_tx.take() {
                    let _ = tx.send(Ok(*bound));
                }
            }
            Ok(Err(error)) => {
                if let Some(tx) = startup_bind_tx.take() {
                    let _ = tx.send(Err(std::io::Error::new(error.kind(), error.to_string())));
                }
            }
            Err(_) => {
                if let Some(tx) = startup_bind_tx.take() {
                    let _ = tx.send(Err(std::io::Error::other(format!(
                        "{label} exited before reporting bind result"
                    ))));
                }
            }
        }

        let join_outcome = handle.await;
        if *shutdown.borrow() {
            break;
        }

        match bind_outcome {
            Ok(Ok(_)) => match join_outcome {
                Ok(Ok(())) => {
                    tracing::warn!(
                        addr = %next_bind_addr,
                        "{label} exited without shutdown; restarting on the same port"
                    );
                }
                Ok(Err(error)) => {
                    tracing::warn!(
                        addr = %next_bind_addr,
                        error = %error,
                        "{label} exited with error; restarting on the same port"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        addr = %next_bind_addr,
                        error = %error,
                        "{label} panicked; restarting on the same port"
                    );
                }
            },
            Ok(Err(error)) => {
                tracing::warn!(
                    addr = %next_bind_addr,
                    error = %error,
                    "{label} failed to bind; retrying"
                );
            }
            Err(_) => match join_outcome {
                Ok(Err(error)) => {
                    tracing::warn!(
                        addr = %next_bind_addr,
                        error = %error,
                        "{label} exited before reporting bind result; restarting"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        addr = %next_bind_addr,
                        error = %error,
                        "{label} panicked before reporting bind result; restarting"
                    );
                }
                Ok(Ok(())) => {
                    tracing::warn!(
                        addr = %next_bind_addr,
                        "{label} exited before reporting bind result; restarting"
                    );
                }
            },
        }

        tokio::time::sleep(LOCAL_PROXY_RESTART_DELAY).await;
    }
}

/// Aggregate bind report passed to `run()`'s `start_notify` callback. Carries
/// every listener that may have raced to bind during startup so the CLI can
/// render a consolidated banner. New listeners get a new field here rather
/// than a parallel callback.
#[derive(Debug, Clone)]
pub struct StartupBinds {
    pub dashboard: DashboardBind,
    pub git_proxy: GitProxyBind,
    /// Bind outcome for the LLM proxy.
    pub llm_proxy: LlmProxyBind,
    /// Daemon's Ed25519 signing-identity pubkey (64-hex). Empty string if
    /// identity initialisation failed at startup. Used by the CLI to render
    /// the camera-clean Identity line in the foreground startup banner.
    pub identity_pubkey: String,
}

/// Host sandbox startup probe.
///
/// Verifies the daemon is actually running under a kernel-level sandbox
/// (seccomp on Linux, sandbox-exec on macOS) at startup. Designed to
/// catch the silent-passthrough failure mode where the systemd unit
/// (slice B) or LaunchDaemon plist (slice D) wiring is missing or
/// misconfigured, leaving the daemon running un-sandboxed despite the
/// profile JSON shipping (slice A) and `.sb` file (slice C) being
/// present.
///
/// Detection paths:
/// - Linux: read `/proc/self/status`, check the `Seccomp:` field.
///   Value 2 = filter mode (the expected state under SystemCallFilter=),
///   value 1 = strict mode, value 0 = no filter installed.
/// - macOS: invoke `sandbox_check(getpid(), "default", 0)` via FFI to
///   libsandbox.dylib (private but stable since macOS 10.7). Returns
///   non-zero when the process is sandboxed.
///
/// Failure mode: emit a loud `WARN` log + best-effort one-shot startup
/// event (audit-log path). Don't refuse to start by default — too risky
/// on dev workstations where systemd/launchd aren't configured.
/// Optional strict mode via env var `EMBER_REQUIRE_SANDBOX=1` refuses
/// to start on detection failure (returns `Err(SandboxProbeFailure)`).
///
/// Returns:
/// - `Ok(SandboxState::SeccompFilter)` — Linux daemon running under
///   seccomp filter mode (expected state for production)
/// - `Ok(SandboxState::SeccompStrict)` — Linux daemon under strict-mode
///   seccomp (rare; not the SystemCallFilter= path but still sandboxed)
/// - `Ok(SandboxState::MacosSandbox)` — macOS daemon running under
///   sandbox-exec (expected state for production)
/// - `Ok(SandboxState::Unsandboxed)` — no kernel sandbox active; logs
///   a WARN with operator guidance
/// - `Err(SandboxProbeFailure)` — strict mode enabled and not sandboxed
pub fn check_sandbox_at_startup() -> Result<SandboxState, SandboxProbeFailure> {
    let state = probe_sandbox_state();
    if matches!(state, SandboxState::Unsandboxed) {
        tracing::warn!(
            "daemon is NOT running under a kernel sandbox; ensure systemd \
             SystemCallFilter= (Linux) or LaunchDaemon sandbox-exec (macOS) \
             is wired. Set EMBER_REQUIRE_SANDBOX=1 to refuse-on-detect. \
             Per META-DAEMON-SECCOMP-PROFILE-HOST."
        );
        if std::env::var("EMBER_REQUIRE_SANDBOX").is_ok_and(|v| v == "1") {
            return Err(SandboxProbeFailure::StrictModeUnsandboxed);
        }
    } else {
        tracing::info!(state = ?state, "sandbox startup probe — daemon is sandboxed");
    }
    Ok(state)
}

/// Outcome of the kernel-sandbox startup probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxState {
    /// Linux: seccomp filter mode active (SystemCallFilter= or BPF program installed).
    SeccompFilter,
    /// Linux: strict-mode seccomp (only read/write/_exit/sigreturn allowed). Rare.
    SeccompStrict,
    /// macOS: sandbox-exec profile active.
    MacosSandbox,
    /// Neither sandbox primitive detected — daemon runs un-sandboxed.
    Unsandboxed,
}

/// Returned when `EMBER_REQUIRE_SANDBOX=1` is set and the probe finds
/// no kernel-level sandbox.
#[derive(Debug, Error)]
pub enum SandboxProbeFailure {
    #[error(
        "EMBER_REQUIRE_SANDBOX=1 set but no kernel sandbox detected at startup; \
         wire systemd SystemCallFilter= (Linux) or LaunchDaemon sandbox-exec (macOS)"
    )]
    StrictModeUnsandboxed,
}

#[cfg(target_os = "linux")]
fn probe_sandbox_state() -> SandboxState {
    // /proc/self/status carries a `Seccomp:` line; value is 0/1/2 per
    // <linux/seccomp.h>. Filter mode (2) is what SystemCallFilter= installs.
    match std::fs::read_to_string("/proc/self/status") {
        Ok(status) => {
            for line in status.lines() {
                if let Some(value) = line.strip_prefix("Seccomp:") {
                    let trimmed = value.trim();
                    return match trimmed {
                        "2" => SandboxState::SeccompFilter,
                        "1" => SandboxState::SeccompStrict,
                        _ => SandboxState::Unsandboxed,
                    };
                }
            }
            SandboxState::Unsandboxed
        }
        Err(_) => SandboxState::Unsandboxed,
    }
}

#[cfg(target_os = "macos")]
fn probe_sandbox_state() -> SandboxState {
    // sandbox_check() from libsandbox.dylib. Private API but stable since
    // macOS 10.7 and used by Apple's own daemons. Returns non-zero when
    // the process is sandboxed; we use the "default" operation as a
    // generic probe.
    unsafe extern "C" {
        fn sandbox_check(pid: libc::pid_t, operation: *const libc::c_char, flags: u32) -> i32;
    }
    let op = c"default".as_ptr();
    let pid = unsafe { libc::getpid() };
    let rc = unsafe { sandbox_check(pid, op, 0) };
    if rc != 0 {
        SandboxState::MacosSandbox
    } else {
        SandboxState::Unsandboxed
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn probe_sandbox_state() -> SandboxState {
    // No kernel-sandbox primitive on this platform (e.g. Windows targets).
    // Return Unsandboxed so the WARN fires; strict mode then refuses.
    SandboxState::Unsandboxed
}

/// Render a 64-hex Ed25519 pubkey as a
/// short SSH-style fingerprint (`4a5d:a587:dd36:53b2`) using the first
/// 8 bytes / 16 hex chars. The dashboard, the receipt detail page, and
/// the demo teardown printout all use the same shape so a viewer can
/// match it across surfaces. Returns `—` for placeholder / empty input
/// so log lines never carry a half-formed string.
pub fn daemon_identity_fingerprint(pubkey_hex: &str) -> String {
    let trimmed = pubkey_hex.trim();
    if trimmed.len() < 16 || trimmed.chars().all(|c| c == '0') {
        return "—".to_string();
    }
    let head = &trimmed[..16];
    let mut out = String::with_capacity(19);
    for (i, ch) in head.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push(':');
        }
        out.push(ch);
    }
    out
}

/// Read `SO_PEERCRED` (Linux) or `LOCAL_PEERCRED` (macOS) from an accepted
/// `UnixStream` and enforce the group-membership gate.
///
/// Returns `Ok(PeerCreds)` when the peer is authorised:
/// - **development mode**: peer uid matches the daemon's effective uid, OR
/// - **install-shaped mode**: the peer has already passed the
///   `ember:ember-clients` UDS filesystem ACL and surfaced kernel peer creds.
///
/// Returns `Err` (with a structured `tracing::warn!`) when the peer is
/// not authorised or when the kernel credential read fails. The `Err` path
/// is fail-closed — callers should drop the connection immediately.
///
/// Target-OS gate: only Linux and macOS are audited; other platforms are
/// rejected at compile time by the `compile_error!` in `socket.rs`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn authenticate_peer_creds(
    stream: &tokio::net::UnixStream,
) -> std::io::Result<crate::infra::socket::PeerCreds> {
    authenticate_peer_creds_with(
        || {
            stream
                .peer_cred()
                .map(|cred| crate::infra::socket::PeerCreds {
                    uid: cred.uid(),
                    gid: cred.gid(),
                    pid: cred.pid(),
                })
        },
        daemon_euid_runtime(),
        ember_clients_gid_runtime(),
    )
}

/// Non-Linux/macOS stub — never reachable because the `compile_error!` in
/// `socket.rs` prevents building on other targets.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn authenticate_peer_creds(
    _stream: &tokio::net::UnixStream,
) -> std::io::Result<crate::infra::socket::PeerCreds> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "peer credential auth is only supported on Linux and macOS",
    ))
}

// ---------------------------------------------------------------------------
// PeerCredPrincipal — kernel-attested per-call identity
// (peercred principal binding, ADR 094 + ADR 136 §"Decision §2")
// ---------------------------------------------------------------------------

/// Kernel-attested identity of the caller on the other end of a Unix
/// domain socket. Extracted at connection accept time from
/// `UnixStream::peer_cred()` and carried through the dispatcher to
/// every broker handler so authorization decisions are bound to a
/// kernel-supplied identity rather than the attacker-controlled
/// `caller_persona` field in the request payload.
///
/// The principal triple `(uid, pid, socket_path)`:
///
/// - `uid`         — peer's effective uid. The primary check for
///   broker handlers: a caller whose kernel uid does not match the
///   persona's bound uid is refused with `-32004`.
/// - `pid`         — pid-namespace-scoped peer pid. Diagnostics only:
///   the bare PID is reuse-prone (see the sibling pidfd binding
///   for the pidfd-based reuse-immune surface).
/// - `socket_path` — per-agent UDS path the connection accepted on.
///   Each agent gets its own per-agent UDS socket;
///   the path is the cohesive identity binding the OS uid to a
///   specific persona. For Phase 1 (this task) the daemon's single
///   socket path is used uniformly.
/// Linux-only RAII wrapper around a pidfd. Closes the fd on drop.
///
/// Wrapping the fd in its own struct + holding it as `Arc<PidFdOwner>` on
/// `PeerCredPrincipal` lets the principal be `Clone`able (it is cloned per
/// dispatch in `socket::handle_connection`) while keeping single-owner
/// `close(2)` semantics: the kernel only sees one close, on the last clone
/// drop. Using `Arc` rather than `dup(2)`-on-clone keeps the fd count
/// constant and avoids leaking fds across the per-RPC clone path.
///
/// Pidfd binding.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct PidFdOwner {
    fd: std::os::unix::io::RawFd,
}

#[cfg(target_os = "linux")]
impl PidFdOwner {
    /// Borrow the underlying raw fd. The fd remains owned by this
    /// `PidFdOwner` — callers MUST NOT close it.
    pub fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.fd
    }
}

#[cfg(target_os = "linux")]
impl Drop for PidFdOwner {
    fn drop(&mut self) {
        // SAFETY: `self.fd` was obtained from `pidfd_open` (a real
        // kernel-issued descriptor) and is owned by this struct. After
        // close, no other reference to it exists because the `PidFdOwner`
        // is being dropped here.
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// `pidfd_open(pid, 0)` — open a process file descriptor for `pid`.
/// Returns `Some(fd)` when the syscall succeeds; `None` when it fails
/// (most commonly `ENOSYS` on pre-5.3 kernels, or `ESRCH` if the pid
/// is already reaped between accept() and pidfd_open()).
///
/// The returned fd is reuse-immune: even if the kernel later reaps the
/// process and reassigns its PID, the pidfd continues to refer to the
/// original process. A subsequent `poll(POLLIN)` will report POLLIN |
/// POLLHUP once the original process exits.
#[cfg(target_os = "linux")]
fn pidfd_open(pid: i32) -> Option<std::os::unix::io::RawFd> {
    // SAFETY: `SYS_pidfd_open` takes (pid, flags). We pass flags=0
    // (PIDFD_NONBLOCK is not required — `poll()` with timeout 0 is
    // already non-blocking). The return value is a new fd (>= 0) or
    // -1 on error; we check for the error case.
    let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        tracing::debug!(
            pid,
            error = %err,
            "pidfd_open failed — principal proceeds without reuse-immune binding"
        );
        None
    } else {
        Some(ret as std::os::unix::io::RawFd)
    }
}

/// macOS process **start time** in microseconds since the epoch, read via
/// `proc_pidinfo(PROC_PIDTBSDINFO)`. `None` when the process does not exist
/// (already reaped) or the call fails.
///
/// macOS start-time binding — the start time is the reuse-immune
/// anchor on macOS (which has no `pidfd`): a PID-reuse collision is detected
/// because the replacement process has a different start time. The kernel
/// records `pbi_start_tvsec`/`pbi_start_tvusec` at process creation and never
/// mutates them, so re-reading and comparing is sufficient to defeat the
/// accept→use TOCTOU.
#[cfg(target_os = "macos")]
fn proc_pid_start_time_usec(pid: i32) -> Option<u64> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: `proc_pidinfo` writes at most `size` bytes into `info` for the
    // `PROC_PIDTBSDINFO` flavor; we pass the exact size of the struct we
    // allocated and a valid mutable pointer to it. A successful call returns
    // `size`; any other return (0, negative, short read) is treated as
    // failure.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut libc::proc_bsdinfo as *mut libc::c_void,
            size,
        )
    };
    if n != size {
        return None;
    }
    Some(info.pbi_start_tvsec.wrapping_mul(1_000_000) + info.pbi_start_tvusec)
}

#[derive(Debug, Clone)]
pub struct PeerCredPrincipal {
    pub uid: u32,
    /// Pid-namespace-scoped peer pid. On Linux, prefer `is_alive()` (which
    /// consults the bound pidfd) over inspecting this field directly — the
    /// bare PID is reuse-prone, and the pidfd is the reuse-immune anchor.
    pub pid: i32,
    /// Per-agent UDS socket path. Each
    /// agent gets its own per-agent socket; for Phase 1 the daemon's single
    /// socket path is used uniformly.
    pub socket_path: PathBuf,
    /// Pidfd opened at accept time against the
    /// peer's PID. `Some(_)` when `pidfd_open(2)` succeeded; `None` when
    /// the syscall is unavailable (pre-5.3 kernel) or the process exited
    /// between `accept()` and `pidfd_open()`. `Arc`-wrapped so the
    /// principal can be cloned per-dispatch without re-issuing `dup(2)`
    /// or risking double-close: `Drop` only fires on the last clone.
    ///
    /// Not on the wire — local kernel resource only. Skipped in
    /// `PartialEq` because two clones share the same Arc but the
    /// abstract identity of the principal is uid + pid + socket_path.
    #[cfg(target_os = "linux")]
    pub pidfd: Option<std::sync::Arc<PidFdOwner>>,
    /// macOS start-time binding (P22-S2) — macOS has no pidfd,
    /// so the bare PID is reuse-prone: the peer could exit and the kernel
    /// reassign its PID to an attacker process between `accept()` and a
    /// later `is_alive()` / binary-attestation read. We close that TOCTOU
    /// the way polkit does — bind the PID to the process **start time**
    /// (`proc_pidinfo(PROC_PIDTBSDINFO)` `pbi_start_tvsec`/`pbi_start_tvusec`,
    /// microseconds since epoch). A PID-reuse collision is detectable
    /// because the new process has a different start time. `Some(_)` when
    /// `proc_pidinfo` succeeded at accept; `None` for principals built via
    /// `new()` (tests / Internal dispatch) — treated as legacy-equivalent
    /// (`is_alive()` returns `true`), mirroring `pidfd: None` on Linux.
    ///
    /// Skipped in `PartialEq` for the same reason as `pidfd` — it is a
    /// liveness anchor, not part of the abstract `(uid, pid, socket_path)`
    /// identity.
    #[cfg(target_os = "macos")]
    pub start_time_usec: Option<u64>,
}

impl PartialEq for PeerCredPrincipal {
    fn eq(&self, other: &Self) -> bool {
        // pidfd is a local kernel resource — two principals describing
        // the same peer share identity even when one was constructed
        // with a pidfd (production) and the other without (tests, or
        // pre-5.3 kernels).
        self.uid == other.uid && self.pid == other.pid && self.socket_path == other.socket_path
    }
}

impl Eq for PeerCredPrincipal {}

impl PeerCredPrincipal {
    /// Construct a `PeerCredPrincipal` from an accepted `UnixStream` and
    /// the per-agent socket path the connection landed on.
    ///
    /// `socket_path` is the listener path the connection accepted on
    /// (the per-agent UDS path) — passed in so the constructor
    /// is independent of the listener's address API which is not always
    /// usable on a connected stream.
    ///
    /// On Linux this also issues `pidfd_open(pid, 0)` to bind a
    /// reuse-immune handle to the peer process (the pidfd
    /// binding). The pidfd is `None` on legacy kernels — broker handlers
    /// fall back to the bare-PID surface in that case.
    ///
    /// Returns `Err` when the kernel does not surface peer credentials
    /// (a fail-closed posture mirroring `authenticate_peer_creds`).
    #[cfg(target_os = "linux")]
    pub fn from_stream(
        stream: &tokio::net::UnixStream,
        socket_path: PathBuf,
    ) -> std::io::Result<Self> {
        let cred = stream.peer_cred()?;
        let pid = cred.pid().ok_or_else(|| {
            std::io::Error::other(
                "peer pid unavailable — fail-closed (no kernel-attested principal)",
            )
        })?;
        let pidfd = pidfd_open(pid).map(|fd| std::sync::Arc::new(PidFdOwner { fd }));
        Ok(Self {
            uid: cred.uid(),
            pid,
            socket_path,
            pidfd,
        })
    }

    /// macOS path — pidfd is a Linux-only surface. The principal is
    /// still constructed (so the peercred-binding gate runs), but
    /// `is_alive()` cannot consult a pidfd; it returns `true`
    /// unconditionally.
    #[cfg(target_os = "macos")]
    pub fn from_stream(
        stream: &tokio::net::UnixStream,
        socket_path: PathBuf,
    ) -> std::io::Result<Self> {
        let cred = stream.peer_cred()?;
        let pid = cred.pid().ok_or_else(|| {
            std::io::Error::other(
                "peer pid unavailable — fail-closed (no kernel-attested principal)",
            )
        })?;
        // macOS start-time binding — capture the peer's process
        // start time at accept so a later PID-reuse collision is detectable.
        // `None` is logged (the process may already be gone, or the syscall
        // is unavailable); `is_alive()` then falls back to the bare-PID
        // posture for this principal rather than failing the accept outright.
        let start_time_usec = proc_pid_start_time_usec(pid);
        if start_time_usec.is_none() {
            tracing::warn!(
                pid,
                "PeerCredPrincipal::from_stream: proc_pidinfo start-time unavailable — principal proceeds without reuse-immune binding"
            );
        }
        Ok(Self {
            uid: cred.uid(),
            pid,
            socket_path,
            start_time_usec,
        })
    }

    /// Non-Linux/macOS stub — peer-cred binding is unsupported.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub fn from_stream(
        _stream: &tokio::net::UnixStream,
        _socket_path: PathBuf,
    ) -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "PeerCredPrincipal::from_stream is only supported on Linux and macOS",
        ))
    }

    /// Construct a `PeerCredPrincipal` directly from raw fields. Used by
    /// tests and by the daemon-internal `Internal` dispatch path that
    /// needs to thread a synthetic principal through the broker
    /// handlers without a real Unix socket. No pidfd is opened — the
    /// resulting principal is treated as legacy-kernel-equivalent
    /// (`is_alive()` returns `true`).
    pub fn new(uid: u32, pid: i32, socket_path: PathBuf) -> Self {
        Self {
            uid,
            pid,
            socket_path,
            #[cfg(target_os = "linux")]
            pidfd: None,
            #[cfg(target_os = "macos")]
            start_time_usec: None,
        }
    }

    /// Test-only constructor: build a principal with a synthetic pidfd
    /// for the given pid. Performs an actual `pidfd_open(pid, 0)` —
    /// the caller is responsible for ensuring the pid refers to a
    /// process whose lifecycle they control.
    ///
    /// Returns `None` when `pidfd_open` fails (pre-5.3 kernel, ESRCH,
    /// etc.). Tests that depend on pidfd behaviour should skip on a
    /// `None` return rather than panic.
    ///
    /// Pidfd binding — test seam so the dead-pid rejection
    /// test can build a principal with a real pidfd against an already-
    /// exited child.
    #[cfg(target_os = "linux")]
    pub fn new_with_pidfd_for_test(uid: u32, pid: i32, socket_path: PathBuf) -> Option<Self> {
        let fd = pidfd_open(pid)?;
        Some(Self {
            uid,
            pid,
            socket_path,
            pidfd: Some(std::sync::Arc::new(PidFdOwner { fd })),
        })
    }

    /// Verify the peer process bound to this principal is still alive.
    ///
    /// On Linux: when a pidfd was successfully opened at accept time,
    /// `poll(pidfd, POLLIN, 0)` is consulted. POLLIN on a pidfd fires
    /// once the kernel has reaped the process, so a `revents` with
    /// `POLLIN` set is the signal that the bound process is dead. A
    /// dead-or-reaped principal returns `false` — broker handlers refuse
    /// the call with the dedicated error code.
    ///
    /// Falls back to `true` when no pidfd is bound (pre-5.3 kernel,
    /// pidfd_open failed at accept time, or this principal was built
    /// via `new()` for tests / Internal dispatch). In that case the
    /// daemon retains only the bare-PID guarantee — reuse-immunity is
    /// not available, matching the legacy posture.
    ///
    /// On macOS and other non-Linux targets: always returns `true`. The
    /// peercred-binding gate (uid match) still runs; the pidfd-backed
    /// reuse-immunity surface is Linux-only.
    #[cfg(target_os = "linux")]
    pub fn is_alive(&self) -> bool {
        let Some(owner) = self.pidfd.as_ref() else {
            // No pidfd bound — caller gets only the bare-PID guarantee.
            return true;
        };
        let mut pfd = libc::pollfd {
            fd: owner.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `poll` reads/writes the single pollfd we pass in;
        // `nfds = 1` matches the slice we provide; `timeout = 0` makes
        // the call non-blocking. The fd is owned by `self` for the
        // duration of the call.
        let n = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, 0) };
        if n < 0 {
            // poll() itself failed — fail-closed: treat the principal
            // as not-alive so the broker refuses the call rather than
            // honoring a request whose liveness we cannot verify.
            let err = std::io::Error::last_os_error();
            tracing::warn!(
                pid = self.pid,
                error = %err,
                "PeerCredPrincipal::is_alive: poll() failed — treating principal as dead"
            );
            return false;
        }
        if n == 0 {
            // Timeout (with 0ms): no events ready, process still alive.
            return true;
        }
        // n > 0 — some event fired. POLLIN on a pidfd is the
        // "process has exited" signal; POLLHUP / POLLERR also indicate
        // a dead pidfd. Any revents bit on a pidfd means the bound
        // process is no longer live.
        let dead =
            pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0;
        if dead {
            tracing::warn!(
                pid = self.pid,
                uid = self.uid,
                revents = pfd.revents,
                "PeerCredPrincipal::is_alive: pidfd signals reaped/dead process — refusing"
            );
        }
        !dead
    }

    /// macOS liveness + reuse-immunity via the start-time binding.
    ///
    /// macOS start-time binding — re-reads the current start time
    /// for `self.pid` and compares it to the value captured at accept:
    /// - start time unchanged → the bound process is still alive: `true`.
    /// - process gone (`proc_pidinfo` fails) → the bound process exited:
    ///   `false`.
    /// - start time **differs** → the PID was reused by a different process
    ///   (the original exited and the kernel reassigned its PID): `false`.
    ///   This is the macOS analogue of the Linux pidfd reaped-process signal.
    ///
    /// Falls back to `true` only when no start time was captured at accept
    /// (`start_time_usec == None` — principal built via `new()` for
    /// tests / Internal dispatch, or `proc_pidinfo` was unavailable at
    /// accept), retaining the bare-PID posture exactly like Linux does when
    /// no pidfd is bound.
    #[cfg(target_os = "macos")]
    pub fn is_alive(&self) -> bool {
        let Some(captured) = self.start_time_usec else {
            // No start time bound — caller gets only the bare-PID guarantee.
            return true;
        };
        match proc_pid_start_time_usec(self.pid) {
            Some(current) if current == captured => true,
            Some(current) => {
                tracing::warn!(
                    pid = self.pid,
                    uid = self.uid,
                    captured,
                    current,
                    "PeerCredPrincipal::is_alive: macOS start-time mismatch — PID reused by a different process; refusing"
                );
                false
            }
            None => {
                tracing::warn!(
                    pid = self.pid,
                    uid = self.uid,
                    "PeerCredPrincipal::is_alive: macOS process gone (proc_pidinfo failed) — refusing"
                );
                false
            }
        }
    }

    /// Non-Linux/macOS stub — no reuse protection available.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub fn is_alive(&self) -> bool {
        true
    }
}

/// Return the daemon's effective uid. Separate from `socket::daemon_euid`
/// to keep runtime.rs self-contained. `pub(crate)` so the ssh-agent-over-bridge
/// bind path can stamp the bridge's expected peer uid (the issuee — daemon/
/// operator uid for the host & container-forwarder topologies).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn daemon_euid_runtime() -> u32 {
    // SAFETY: `geteuid` is a simple syscall wrapper with no preconditions.
    unsafe { libc::geteuid() }
}

/// Non-Linux/macOS stub. The brokered ssh-agent bridge is a Unix-socket feature;
/// this keeps the crate compiling on other targets where it is never bound.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn daemon_euid_runtime() -> u32 {
    0
}

/// Look up the gid of the `ember-clients` group. Returns `None` when the
/// group does not exist (development mode / CI), in which case the
/// `authenticate_peer_creds` function falls back to uid-equality check.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn ember_clients_gid_runtime() -> Option<u32> {
    use std::ffi::CString;
    let name = CString::new("ember-clients").ok()?;
    // SAFETY: `getgrnam` is a standard POSIX function. We read `gr_gid`
    // immediately and do not retain the pointer past this block.
    let gr = unsafe { libc::getgrnam(name.as_ptr()) };
    if gr.is_null() {
        None
    } else {
        Some(unsafe { (*gr).gr_gid })
    }
}

/// Pure authenticate function: injectable for unit testing without a real
/// socket pair or a second uid/gid on the test host.
///
/// `get_peer` — callable that returns the kernel peer creds (or an error).
/// `daemon_uid` — the daemon's effective uid (fallback for dev mode).
/// `clients_gid` — the `ember-clients` gid, or `None` in dev mode.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn authenticate_peer_creds_with<F>(
    get_peer: F,
    daemon_uid: u32,
    clients_gid: Option<u32>,
) -> std::io::Result<crate::infra::socket::PeerCreds>
where
    F: FnOnce() -> std::io::Result<crate::infra::socket::PeerCreds>,
{
    let peer = get_peer().map_err(|e| {
        tracing::warn!(
            error = %e,
            daemon_uid,
            "authenticate_peer_creds: failed to read peer credentials — rejecting connection"
        );
        e
    })?;

    // Development mode: no ember-clients group configured → accept any
    // peer whose uid matches the daemon's own euid. This preserves the
    // existing C39-HANDLER-C1 behaviour on developer workstations.
    let authorised = match clients_gid {
        None => {
            let ok = peer.uid == daemon_uid;
            if !ok {
                tracing::warn!(
                    peer_uid = peer.uid,
                    peer_gid = peer.gid,
                    pid = ?peer.pid,
                    daemon_uid,
                    "authenticate_peer_creds: dev-mode uid mismatch — rejecting connection"
                );
            }
            ok
        }
        Some(gid) => {
            // Install-shaped mode: the UDS filesystem ACL is the actual
            // connect gate (`daemon.sock` is created 0660 ember:ember-clients
            // inside a 0750 ember:ember-clients directory). Supplementary-group
            // membership is what the installer provisions for the operator, and
            // SO_PEERCRED / LOCAL_PEERCRED do not reliably surface that as the
            // peer's primary gid. Once the process has connected and surfaced
            // peer creds successfully, accept the connection and use the peer
            // uid/pid only for downstream auditing / principal binding.
            tracing::debug!(
                peer_uid = peer.uid,
                peer_gid = peer.gid,
                pid = ?peer.pid,
                expected_clients_gid = gid,
                daemon_uid,
                "authenticate_peer_creds: install-mode peer accepted via socket ACL"
            );
            true
        }
    };

    if authorised {
        tracing::info!(
            peer_uid = peer.uid,
            peer_gid = peer.gid,
            pid = ?peer.pid,
            "authenticate_peer_creds: connection authorised"
        );
        Ok(peer)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "peer not authorised",
        ))
    }
}

/// The daemon runtime — owns config, PID file, and socket listener.
pub struct DaemonRuntime {
    config: DaemonConfig,
    pid_file: PidFile,
    /// Path the config was loaded from — used for the vault identity warning in `run()`.
    /// `None` when config came from defaults (no file on disk).
    config_path: Option<std::path::PathBuf>,
    /// Actual address the dashboard
    /// listener bound to (`Some(addr)`) or absent when the dashboard is
    /// disabled / failed to bind / timed out (`None`). Populated from inside
    /// `run()` after the bind result arrives. `Mutex` (not `RefCell`)
    /// because `DaemonRuntime` is held across await points in `run()` and
    /// the test harness reads it from a different thread than the one
    /// driving the daemon.
    pub dashboard_actual_addr: Mutex<Option<SocketAddr>>,
    /// The SE-sealed Bridge
    /// CA (ADR 154 component 3). `None` until an explicit bridge bootstrap
    /// path opens the vault and loads-or-mints the CA via
    /// [`load_or_mint_bridge_ca`]. Startup on the default local path now
    /// keeps this empty and relies on the cached `bridge_ca.pub` fingerprint
    /// instead. `Mutex<Option<Arc<…>>>` matches the `dashboard_actual_addr`
    /// pattern above — the value is populated inside `run()`, but the field
    /// declaration lives on `DaemonRuntime::new`.
    pub bridge_ca: Mutex<Option<Arc<BridgeCa>>>,
}

impl DaemonRuntime {
    pub fn new(config: DaemonConfig) -> Self {
        let pid_file = PidFile::new(config.pid_file.clone());
        Self {
            config,
            pid_file,
            config_path: None,
            dashboard_actual_addr: Mutex::new(None),
            bridge_ca: Mutex::new(None),
        }
    }

    /// Like `new`, but records the path the config was loaded from.
    /// Used to emit the production-keyring-with-custom-config warning at startup.
    pub fn new_with_config_path(config: DaemonConfig, config_path: std::path::PathBuf) -> Self {
        let pid_file = PidFile::new(config.pid_file.clone());
        Self {
            config,
            pid_file,
            config_path: Some(config_path),
            dashboard_actual_addr: Mutex::new(None),
            bridge_ca: Mutex::new(None),
        }
    }

    pub fn record_dashboard_bind(&self, dashboard_bind: &DashboardBind) {
        // Persist the resolved bind
        // address on the runtime so out-of-band readers (tests, future
        // introspection helpers) see the same truth as `/api/status`. Only
        // the `Bound` variant maps to `Some`; `Failed`/`Disabled`/`Timeout`
        // all map to `None` so callers can distinguish "bound" from
        // "configured" without re-deriving from the bind report.
        let actual_dashboard_addr = match dashboard_bind {
            DashboardBind::Bound(addr) => Some(*addr),
            DashboardBind::Failed { .. } | DashboardBind::Disabled | DashboardBind::Timeout => None,
        };
        if let Ok(mut slot) = self.dashboard_actual_addr.lock() {
            *slot = actual_dashboard_addr;
        }
    }

    pub fn bootstrap_vault_for_startup(&self, store: &DaemonStore) -> Result<(), DaemonError> {
        if should_bootstrap_vault_at_startup(self.config.bridge_bind) {
            // ADR 216 — provision the DWK at startup. The vault itself stays
            // locked until the CLI relay provides a double-envelope unlock
            // (the operator's first `ember` command after boot). The DWK is
            // the inner envelope; it never leaves uid=450.
            store
                .provision_dwk()
                .map_err(|e| DaemonError::Vault(format!("DWK provision: {e}")))?;

            // Check if a double-envelope outer blob exists. If so, the vault
            // is provisioned but locked — the CLI relay will unlock it. If not,
            // this is a clean boot and provisioning happens via the
            // vault.de_provision_begin/outer RPC pair.
            let has_de_outer = store
                .read_double_envelope_outer()
                .map_err(|e| DaemonError::Vault(format!("read double-envelope: {e}")))?
                .is_some();

            if has_de_outer {
                tracing::info!(
                    "vault: double-envelope outer blob found — vault locked, awaiting \
                     CLI relay unlock (ADR 216)"
                );
            } else {
                tracing::info!(
                    "vault: no double-envelope outer blob — vault unprovisioned, awaiting \
                     CLI relay provisioning (ADR 216)"
                );
            }

            log_vault_identity(&self.config, self.config_path.as_deref());

            // ADR 216: canary verification, bridge CA loading, and audit
            // events are DEFERRED to the vault.de_unlock_complete RPC handler.
            // The vault stays locked at startup; the CLI relay triggers these
            // on the operator's first `ember` command (double-envelope unlock).
        } else {
            tracing::info!("startup bootstrap skipped because bridge_bind is not configured");
        }

        Ok(())
    }

    /// Start the daemon: write PID, open store, bind socket, run until shutdown signal.
    ///
    /// `start_notify` is called exactly once, as soon as every startup listener's
    /// bind result is known (or the 2-second startup timeout expires), with a
    /// `StartupBinds` aggregate. Pass `None` to skip the notification (e.g., in
    /// background mode or tests).
    pub async fn run(
        &self,
        start_notify: Option<Box<dyn FnOnce(StartupBinds)>>,
    ) -> Result<(), DaemonError> {
        // keyring-core 1.0 split — the macOS Keychain backend lives in a
        // separate crate (`apple-native-keyring-store`) and must be
        // registered as the default store before any `keyring_core::Entry`
        // call. The legacy `keyring` v3 crate auto-registered via its
        // `apple-native` feature at link time; v1+ requires explicit
        // registration. Idempotent: re-registering replaces the previous
        // store. Failures are logged + warn; subsequent Entry::new() calls
        // outside the EMBER_VAULT_MOCK three-axis gate will return
        // NoDefaultStore.
        #[cfg(target_os = "macos")]
        {
            match apple_native_keyring_store::keychain::Store::new() {
                Ok(store) => keyring_core::set_default_store(store),
                Err(e) => tracing::warn!(
                    error = ?e,
                    "keyring-core: failed to register apple-native-keyring-store at daemon startup"
                ),
            }
        }

        self.config.ensure_dirs()?;
        self.pid_file.write()?;

        // LLM proxy wire-up fix: install the rustls process-wide
        // CryptoProvider once at daemon startup. Both the LLM proxy
        // (`run_proxy`) and the git-echo proxy (`run_git_echo_proxy`) call
        // `HttpsConnectorBuilder::with_webpki_roots()` which panics on the
        // first request when no provider is installed. Tests do this via
        // `ensure_rustls_provider()`; production previously had no install
        // site at all — the bug surfaced when the LLM proxy started seeing
        // real Anthropic POSTs (the git-echo path would have hit the same
        // panic on its first real github.com push). Idempotent: returns
        // Err if already installed, which we ignore.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let socket_path = daemon_socket_path(&self.config);
        info!(pid = std::process::id(), socket = %socket_path.display(), "ember daemon starting");
        // CLI-VERSION-FLAG: log the binary's compile-time version + git SHA +
        // build timestamp at INFO so a stale binary running against a newer
        // codebase (the vault AEAD decrypt-failure root cause) is
        // identifiable in seconds via `tail daemon.log`. Also surfaces the
        // `(no-git)` fallback if the build script ran without a working repo.
        info!(
            version = env!("CARGO_PKG_VERSION"),
            git_sha = env!("EMBERLINK_GIT_SHA"),
            build_timestamp = env!("EMBERLINK_BUILD_TIMESTAMP"),
            "ember daemon binary version"
        );

        // ADR212-TELEMETRY-EXPORTER — install the process-global telemetry
        // registry before any broker materialization or `/metrics` scrape can
        // land. The instance discriminator is the daemon socket path (bounded,
        // non-sensitive, never a per-principal id); the build SHA is the
        // compiled-in commit. Idempotent (`OnceCell`): the dashboard's
        // `/metrics` route and the broker hot-path recorder read this surface.
        crate::infra::telemetry::init(socket_path.display().to_string(), env!("EMBERLINK_GIT_SHA"));

        // ADR 212 increment 2 — wire the in-process proxy-forward path's
        // telemetry sink so its host-authorization outcomes + forward latency
        // land on emberd's existing `/metrics`. (The proxy's OWN per-process
        // endpoint is gated on ADR 197's separate `ember-proxy` process, not yet
        // shipped; today the forward path runs inside emberd.)
        crate::infra::telemetry::install_forward_sink();

        // Deployment-tier announce. The tier-defaults principle
        // (`.claude/rules/agent-discipline.md` §"dev0/team0/ent0") makes the
        // tier load-bearing for several auth invariants. Surface it in the
        // log so operators reading `tail daemon.log` see immediately whether
        // they're running the dev0 friction-first posture or the team0+
        // security-first posture.
        info!(tier = self.config.tier.as_str(), "deployment tier");
        crate::infra::handler::set_dispatch_deployment_tier(self.config.tier);

        // ADR 207 runtime backend selection. Resolve once at startup so
        // config spelling errors refuse boot through `DaemonConfig::load`,
        // and the selected execution-space adapter is visible in logs.
        // The current resolver is intentionally side-effect-free until a
        // concrete daemon-side container adapter consumes the Box.
        {
            let _container_runtime = crate::spawn::runtime::RuntimeBackend::resolve_from_config(
                &self.config,
            )
            .map_err(|e| {
                DaemonError::Config(crate::infra::config::ConfigError::Validation(e.to_string()))
            })?;
            info!(
                runtime_backend = self.config.runtime_backend.as_str(),
                "container runtime backend selected"
            );
        }

        // Load the per-op user-presence config from
        // [presence] in config.toml into the process-global gate. Done
        // BEFORE the vault unlock so the very first `mark_unlocked` call
        // applies the right idle-timeout window.
        {
            use std::time::Duration;
            let cfg = crate::trust::presence::PresenceConfig {
                idle_timeout: self
                    .config
                    .presence
                    .idle_timeout_secs
                    .map(Duration::from_secs)
                    .unwrap_or(crate::trust::presence::DEFAULT_IDLE_TIMEOUT),
                quiet_hours_start: self.config.presence.quiet_hours_start,
                quiet_hours_end: self.config.presence.quiet_hours_end,
            };
            crate::trust::presence::configure(cfg);
        }
        crate::infra::interactive_unlock::configure_grace_window(
            self.config.tier.interactive_grace_window(),
        );

        // cordon_phase1_receipt_mint_retrofitted — load the daemon
        // identity BEFORE opening the store so the cordon migration
        // (which runs inside `DaemonStore::open` → `migrate` →
        // `cordon_migration_phase1_if_needed`) has access to
        // `current_identity()` for signing the Phase 1 bridge receipt.
        // Per ADR 174 v2 §5 + ADR 176 §4: the bridge row INSERT and the
        // `audit.chain_v1_segment_bridge_unattested` Receipt v2 append
        // are atomic across the cordon's BEGIN IMMEDIATE boundary; the
        // identity must already exist at that point. The identity init
        // is itself idempotent (process-singleton `OnceCell`), so the
        // reorder is benign for non-cordon paths.
        //
        // Failure is fail-closed (was already the case at the
        // previously-later call site): receipts are load-bearing for
        // the audit chain (signed evidence) and the broker (credential
        // -access proof); refuse normal-serve rather than silently
        // produce state nothing downstream can verify.
        #[allow(unused_assignments)]
        let mut identity_pubkey_hex = String::new();
        match crate::infra::receipt::init_identity(&self.config.data_dir) {
            Ok(pubkey) => {
                let fingerprint = daemon_identity_fingerprint(&pubkey);
                identity_pubkey_hex = pubkey.clone();
                info!(
                    signer_pubkey = %pubkey,
                    fingerprint = %fingerprint,
                    "daemon identity key loaded (pre-store-open for cordon receipt mint)"
                );
                info!(
                    signer_pubkey = %pubkey,
                    fingerprint = %fingerprint,
                    canonical_version = %crate::infra::receipt::CANONICAL_VERSION,
                    "daemon-identity-anchor: pass --pubkey to `ember receipt verify` to verify offline"
                );
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "SEC-S5-V030-AUDIT-CHAIN-C-WIRES (F-S5-013): daemon identity key \
                     unavailable; refusing startup (fail-closed)"
                );
                return Err(DaemonError::IdentityInitFailed(e.to_string()));
            }
        }

        // ADR 200 §2/§5 — stand up the event-sourced identity substrate and
        // ensure the daemon's own identity (self-root + Daemon Persona) is
        // event-sourced. Idempotent: genesis runs once, then this is a no-op.
        // Fail-closed, mirroring the identity-key init above — if the daemon
        // cannot establish its own self-root, an external verifier could not
        // distinguish daemon-attributable from operator-authorized actions
        // (§2), so we refuse startup rather than limp past.
        {
            use crate::infra::identity_substrate::{ensure_daemon_identity, open_identity_store};
            // Reuse the DaemonPersona that `init_identity` just loaded into the
            // process singleton — avoids a second key-file read + mode re-check
            // (and the attendant race window).
            let persona = crate::infra::receipt::current_identity().ok_or_else(|| {
                DaemonError::IdentityInitFailed(
                    "daemon identity not initialized before substrate genesis".to_string(),
                )
            })?;
            let mut identity_store = open_identity_store(&self.config.data_dir)
                .map_err(|e| DaemonError::IdentityInitFailed(e.to_string()))?;
            match ensure_daemon_identity(&mut identity_store, persona) {
                Ok(ids) => info!(
                    daemon_root_id = %ids.root_id,
                    daemon_persona_id = %ids.persona_id,
                    "ADR 200 identity substrate: daemon self-root + Daemon Persona ready"
                ),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "ADR 200 identity substrate genesis failed; refusing startup (fail-closed)"
                    );
                    return Err(DaemonError::IdentityInitFailed(e.to_string()));
                }
            }
            // The on-disk log is the source of truth; later S3 PRs reopen the
            // store on demand (the daemon idiom for !Send rusqlite handles).
        }

        // Open the store and vault. DaemonStore holds a rusqlite Connection which
        // is !Send + !Sync, so we wrap in Rc and run everything on a LocalSet.
        let db_path = self.config.data_dir.join("daemon.db");
        let store = Rc::new(DaemonStore::open(&db_path)?);

        // audit_chain_v2_schema_landed — the pre-verifier `recover_audit_
        // chain_tail` call was DELETED per R4 / pass-2 finding #3. The
        // CHECK constraint on `audit_log` (`segment_id = 0 OR action =
        // genesis OR (row_hash IS NOT NULL AND prev_hash IS NOT NULL)`)
        // structurally precludes the half-write input that primitive was
        // designed to clean up. Keeping it around shipped dead-code-with-
        // live-tests; the v2 redesign removes it cleanly.

        // Audit-chain startup verify + audit_verifier_outcome_v2:
        // walk the last 1000 rows of the audit chain (the
        // verifier-startup-cadence work
        // will upgrade this to full-walk-if-N<100k in Phase B).
        // On Break / TopologyViolation / IncompleteRepair*, flip the
        // process-global quarantine latch under a distinct authority
        // class so the operator-facing diagnostic can branch on cause.
        // LegacyRowsPresent is NOT a quarantine — it's the post-cordon
        // expected state (segment 0 carries the legacy NULL block).
        match crate::infra::audit::run_audit_verify(store.conn(), Some(1000), store.data_dir()) {
            Ok(crate::infra::audit::VerifyOutcome::Ok {
                rows_walked,
                segments_walked,
                ..
            }) => {
                tracing::info!(
                    rows_walked,
                    segments_walked,
                    "SEC-S5-V030-AUDIT-CHAIN-C-WIRES: audit chain startup sample verify ok"
                );
            }
            Ok(crate::infra::audit::VerifyOutcome::LegacyRowsPresent {
                count,
                max_legacy_id,
                chain_resumes_at_id,
            }) => {
                // Phase-2 attestation pending — NOT a quarantine. The
                // operator can clear this by running `ember audit
                // migrate-chain --acknowledge` to mint the Phase 2
                // attested receipt (the cordon migration's
                // `_attested` companion to `_unattested`).
                tracing::warn!(
                    legacy_rows = count,
                    max_legacy_id,
                    chain_resumes_at_id,
                    "SEC-S5-V030-AUDIT-CHAIN-C-WIRES: legacy NULL-hash block present \
                     in segment 0 (post-cordon expected state); Phase 2 attestation pending"
                );
            }
            Ok(crate::infra::audit::VerifyOutcome::Break { kind }) => {
                let reason = match &kind {
                    crate::infra::audit::BreakKind::RowHashMismatch {
                        at_row_id,
                        expected_hash,
                        stored_hash,
                        rows_walked_before,
                    } => format!(
                        "audit chain RowHashMismatch at row {at_row_id} \
                         (walked {rows_walked_before} before): expected {expected_hash}, stored {stored_hash}"
                    ),
                    crate::infra::audit::BreakKind::ForwardLinkMismatch {
                        at_row_id,
                        predecessor_row_id,
                        expected_prev_hash,
                        stored_prev_hash,
                        rows_walked_before,
                    } => format!(
                        "audit chain ForwardLinkMismatch at row {at_row_id} \
                         (predecessor row {predecessor_row_id}, walked {rows_walked_before} before): \
                         expected prev_hash {expected_prev_hash}, stored {stored_prev_hash:?}"
                    ),
                };
                tracing::error!(
                    reason = %reason,
                    "SEC-S5-V030-AUDIT-CHAIN-C-WIRES: audit-chain TAMPER DETECTED at startup; \
                     entering quarantine, binding socket, and refusing non-read-class methods"
                );
                crate::infra::handler::enter_quarantine(
                    crate::infra::handler::QuarantineAuthority::StartupAuditChainBreak,
                    reason,
                );
            }
            Ok(crate::infra::audit::VerifyOutcome::ChainTopologyInvariantViolation {
                kind,
                at_row_id,
                rows_walked_before,
            }) => {
                let reason = format!(
                    "audit chain topology violation {kind:?} at row {at_row_id} \
                     (walked {rows_walked_before} before)"
                );
                tracing::error!(
                    ?kind,
                    at_row_id,
                    rows_walked_before,
                    "SEC-S5-V030-AUDIT-CHAIN-C-WIRES: audit-chain TOPOLOGY VIOLATION at startup"
                );
                crate::infra::handler::enter_quarantine(
                    crate::infra::handler::QuarantineAuthority::TopologyViolation,
                    reason,
                );
            }
            Ok(crate::infra::audit::VerifyOutcome::IncompleteRepair { receipt_id_orphan }) => {
                let reason = format!(
                    "audit chain IncompleteRepair: receipt {receipt_id_orphan} \
                     was minted but the tombstone row never committed"
                );
                tracing::error!(
                    %receipt_id_orphan,
                    "SEC-S5-V030-AUDIT-CHAIN-C-WIRES: audit-chain INCOMPLETE REPAIR at startup"
                );
                crate::infra::handler::enter_quarantine(
                    crate::infra::handler::QuarantineAuthority::IncompleteRepair,
                    reason,
                );
            }
            Ok(crate::infra::audit::VerifyOutcome::IncompleteRepairReceipt {
                tombstone_row_id,
            }) => {
                let reason = format!(
                    "audit chain IncompleteRepairReceipt: tombstone row {tombstone_row_id} \
                     committed but the repair receipt was never minted"
                );
                tracing::error!(
                    tombstone_row_id,
                    "SEC-S5-V030-AUDIT-CHAIN-C-WIRES: audit-chain INCOMPLETE REPAIR RECEIPT at startup"
                );
                crate::infra::handler::enter_quarantine(
                    crate::infra::handler::QuarantineAuthority::IncompleteRepairReceipt,
                    reason,
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "SEC-S5-V030-AUDIT-CHAIN-C-WIRES: audit chain startup verify could not \
                     run (pre-migration DB or SQL failure); skipping (NOT entering quarantine)"
                );
            }
        }

        // ADR 211 Phase 4 / AC-6 — provision the daemon's headless lease-KEK and
        // rehydrate any SE-wrapped, restart-surviving lease blobs BEFORE the
        // socket listener accepts requests, so leases minted in a prior run are
        // live (not silently dropped) on the first post-restart request. Mirrors
        // the audit-chain startup verify above: run against the just-opened store.
        //
        // ADR 216 S3: lease-KEK is now a symmetric key held in double-envelope
        // custody. The CLI unlocks it via de_unlock_begin/complete with
        // purpose=lease_kek after vault MEK unlock. At this point in startup,
        // the lease-KEK is not yet available — it arrives when the CLI relays
        // the DE unlock flow. Lease rehydration happens inside de_unlock_complete.
        //
        // The old SE-based provision_lease_kek() call is removed; the daemon
        // runs with in-memory-only leases until the CLI completes DE unlock.

        // PATH-PINNING-STARTUP-VERIFY: daemon refuses startup on manifest sig mismatch.
        // Shim content-hash verify-on-connect: the loaded
        // manifest is also installed into the process-global
        // `broker::handler::MANIFEST` so every per-connection broker
        // handler can verify the peer binary against it without
        // re-reading the TOML.
        {
            let explicit_manifest = std::env::var_os(STARTUP_BINARY_MANIFEST_ENV)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from);
            let manifest_candidates = startup_binary_manifest_candidates(explicit_manifest.clone());
            if let Some(manifest_path) =
                resolve_startup_binary_manifest_path(explicit_manifest, |path| path.exists())
            {
                // ADR 157 §Component 1 — trust-root SET verification.
                //
                // Replaces the previous `dev_mode_enabled()` bypass branch
                // (the dev-manifest bypass, commit 6e63351b).
                // The verifier ALWAYS runs; what differs between dev and
                // prod daemons is the SET of acceptable signers,
                // parameterized via `EMBER_TRUST_ROOTS` (parsed in
                // `infra/config.rs` and threaded through `DaemonConfig`).
                //
                // Trust set = [compiled-in release IdentityRoot]
                //             UNION parse_trust_roots(self.config.trust_roots).
                //
                // Prod plist sets `EMBER_TRUST_ROOTS=""` (or omits the
                // var); trust set = [release-only] and a dev-signed
                // manifest is rejected. Dev plist sets
                // `EMBER_TRUST_ROOTS=<dev-fingerprint>`; trust set
                // includes the dev root, so a dev-signed manifest verifies
                // under the SAME code path as prod. No branch.
                //
                // This is the structural difference between "dev mode
                // skips the check" (the trap) and "dev mode trusts an
                // additional root" (the cure). See ADR 157 for full
                // doctrine.
                let mut trust_roots: Vec<ed25519_dalek::VerifyingKey> = Vec::new();
                // 1. Always include the compiled-in release root if it
                //    parses cleanly. The all-zero placeholder fails to
                //    parse, which is intentional — see trust_graph.rs.
                if let Ok(release_pk) = ed25519_dalek::VerifyingKey::from_bytes(
                    &crate::trust_graph::EMBER_SYSTEMS_PUBKEY_BYTES,
                ) {
                    trust_roots.push(release_pk);
                }
                // 2. Add any operator-supplied roots from
                //    `EMBER_TRUST_ROOTS` / `[daemon].trust_roots`.
                let user_roots =
                    match crate::binary_manifest::parse_trust_roots(&self.config.trust_roots) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                raw = %self.config.trust_roots,
                                "PATH-PINNING-STARTUP-VERIFY: refusing to start — \
                                 EMBER_TRUST_ROOTS parse failed"
                            );
                            std::process::exit(2);
                        }
                    };
                let n_user_roots = crate::binary_manifest::append_unique_operator_trust_roots(
                    &mut trust_roots,
                    user_roots,
                );

                if trust_roots.is_empty() {
                    // Neither the compiled-in release root nor any
                    // operator-supplied root resolved. Refuse to start —
                    // there is no signer the daemon would accept.
                    tracing::error!(
                        manifest = %manifest_path.display(),
                        "PATH-PINNING-STARTUP-VERIFY: refusing to start — \
                         no valid trust roots (release placeholder invalid \
                         and EMBER_TRUST_ROOTS empty)"
                    );
                    std::process::exit(2);
                }

                // ADR 157 §Component 1 — emit the single startup INFO line
                // listing the trust-set composition so operators / auditors
                // can confirm posture without grepping the codebase.
                tracing::info!(
                    manifest = %manifest_path.display(),
                    n_total_roots = trust_roots.len(),
                    n_user_supplied = n_user_roots,
                    dev_mode_active = (n_user_roots > 0),
                    "PATH-PINNING-STARTUP-VERIFY: trust roots = \
                     release-bundled + {} additional",
                    n_user_roots
                );

                if let Err(e) = crate::binary_manifest::verify_manifest_signature_with_trust_roots(
                    &manifest_path,
                    &trust_roots,
                ) {
                    tracing::error!(
                        manifest = %manifest_path.display(),
                        error = %e,
                        "PATH-PINNING-STARTUP-VERIFY: refusing to start — \
                         manifest signature failed against trust-root set"
                    );
                    std::process::exit(2);
                }

                // ADR 157 §Component 5 — Receipt-stamping signal. Stash
                // the dev/prod posture in the process-global flag so
                // every Receipt emitted this daemon-run can stamp
                // `dev_mode_active: <bool>`. The flag is "true" iff any
                // non-release root is in the trust set (i.e. the
                // operator added an additional signer via
                // `EMBER_TRUST_ROOTS`). The Receipt-body wiring lives in
                // the dev-mode receipt stamp path; this call site
                // is the canonical input.
                crate::binary_manifest::set_dev_mode_active(n_user_roots > 0);

                // ADR 162 §Component 2 — trust-list show/explain.
                // Capture the trust-root set as a structured snapshot
                // so `trust.list` (and future `trust.show` /
                // `trust.explain`) can answer "what is this daemon
                // prepared to verify against?" without re-reading
                // `EMBER_TRUST_ROOTS` or the manifest at query time.
                // Convention: the assembly above prepends the release
                // root, then extends with operator roots. Pass
                // `n_user_roots` so labelling is unambiguous.
                crate::binary_manifest::set_trust_roots_snapshot(
                    crate::binary_manifest::build_trust_root_records(&trust_roots, n_user_roots),
                );

                // ADR 157 §Component 7 — deprecation warnings for the
                // legacy bypass env vars. Behavior is preserved in v0.3
                // (the bypass was never on this code path again — we
                // already removed it above — so setting the env vars has
                // NO effect, but the WARN gives operators a clear
                // migration signal before v0.4 removes the parsers).
                if matches!(std::env::var("EMBER_VAULT_DEV_MODE").as_deref(), Ok("1")) {
                    tracing::warn!(
                        "deprecated: EMBER_VAULT_DEV_MODE is replaced by \
                         EMBER_TRUST_ROOTS (see ADR 157); will be removed in v0.4"
                    );
                }
                if std::env::var("EMBER_VAULT_MOCK").is_ok() {
                    tracing::warn!(
                        "deprecated: EMBER_VAULT_MOCK is replaced by \
                         EMBER_TRUST_ROOTS / EMBER_ALLOW_MOCK_BROKERS \
                         (see ADR 157); will be removed in v0.4"
                    );
                }

                // Signature verified — load + install the manifest so the
                // broker handlers' peer-binary pin gate
                // (`check_peer_binary_pinned`) can consult it. A parse
                // failure here is non-fatal: the signature gate above
                // already proved authenticity, and an empty manifest
                // simply leaves pin verification "disabled" (Ok(()) for
                // every peer) for the rest of this daemon run.
                match crate::binary_manifest::load_manifest(&manifest_path) {
                    Ok(manifest) => {
                        let entry_count = manifest.entries.len();
                        crate::broker::handler::install_manifest(manifest);
                        tracing::info!(
                            manifest = %manifest_path.display(),
                            entries = entry_count,
                            "binary manifest installed — peer-binary pin gate active"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            manifest = %manifest_path.display(),
                            error = %e,
                            "binary manifest: load failed after signature verify — peer-binary pin gate disabled"
                        );
                    }
                }
            } else {
                tracing::debug!(
                    candidates = ?manifest_candidates,
                    "binary manifest: not present on disk — peer-binary pin gate disabled"
                );
            }
        }

        // Keep the daemon's shared live-vault slot empty during startup.
        // The default path now reaches serve without opening the vault at all;
        // explicit bridge bootstrap below is the remaining startup-only
        // consumer of a direct bootstrap handle.
        let live_vault_slot = store.vault_slot();
        let live_lease_kek_slot = store.lease_kek_slot();

        // Vault MEK hardening C2: register the store with the
        // presence module so an explicit `vault_lock` RPC clears the
        // shared live-vault slot (hard-lock semantics — main local
        // helper lanes lose live vault access). Idle auto-lock keeps the
        // slot populated as observability (`presence_gate_soft_lock_distinction_landed`).
        crate::trust::presence::register_store(Rc::clone(&store));
        crate::infra::interactive_unlock::register_config(self.config.clone());

        // cordon_phase1_receipt_mint_retrofitted — daemon identity is now
        // initialised BEFORE `DaemonStore::open` (search the earlier call
        // site in this function) so the cordon migration's Phase 1 bridge
        // receipt can be signed by the singleton. The variable below was
        // populated by that earlier call; it is consumed downstream
        // (snapshot watcher, dashboard, etc.) without re-initialising the
        // OnceCell.

        // Bridge CA public-key cache: if a previous explicit bridge bootstrap
        // published `bridge_ca.pub`, startup can keep embedding the same
        // fingerprint in spawn receipts without opening the MEK. Missing or
        // malformed cache is non-fatal; the receipt path already treats
        // `[0u8; 32]` as "fingerprint not asserted".
        match load_cached_bridge_ca_fingerprint(&self.config.data_dir) {
            Ok(Some(fingerprint)) => {
                store.set_bridge_ca_fingerprint(fingerprint);
                tracing::info!(
                    fingerprint = %hex::encode(fingerprint),
                    "bridge CA fingerprint loaded from cached pubkey without opening vault"
                );
            }
            Ok(None) => {
                tracing::info!(
                    "bridge CA pubkey absent at startup; spawn receipts will omit bridge fingerprint until explicit bridge bootstrap occurs"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "bridge CA pubkey cache unreadable; startup continues without cached bridge fingerprint"
                );
            }
        }

        self.bootstrap_vault_for_startup(&store)?;

        // Credential-store wiring (ADR 137 sub-piece D): construct the
        // pluggable `CredentialStore` trait object from the
        // `[credential_store]` config section. Defaults to the
        // `LocalEncryptedStore` (which adapts the existing Vault) when
        // the section is absent or `backend = "local"`. The trait
        // object is shared across the broker-registration loop below
        // so each provider's `<provider>_config_from_store` sibling can
        // pull credentials from whatever backend the operator selected.
        let cred_store: Arc<dyn crate::infra::credential_store::CredentialStore> = match &self
            .config
            .credential_store
        {
            None => Arc::new(
                crate::infra::credential_store::LocalEncryptedStore::with_runtime_authority(
                    Rc::clone(&store),
                    &self.config.data_dir,
                ),
            ),
            Some(cs) if cs.backend == "local" => Arc::new(
                crate::infra::credential_store::LocalEncryptedStore::with_runtime_authority(
                    Rc::clone(&store),
                    &self.config.data_dir,
                ),
            ),
            Some(cs) if cs.backend == "hashicorp-vault" => {
                use crate::infra::config::resolve_at_ref;
                use crate::infra::credential_store::HashiVaultStore;
                use crate::infra::credential_store::hashicorp_vault::{
                    HashiVaultAuth, ReqwestHttpClient, UnavailablePolicy,
                };

                let addr = cs.addr.clone().ok_or_else(|| {
                    DaemonError::Vault(
                        "credential_store backend=hashicorp-vault requires `addr`".to_string(),
                    )
                })?;
                let mount = cs.mount.clone();
                let auth = match cs.auth.as_deref().unwrap_or("token") {
                    "token" => {
                        let raw = cs.token.as_deref().ok_or_else(|| {
                            DaemonError::Vault(
                                "credential_store auth=token requires `token`".to_string(),
                            )
                        })?;
                        let resolved = resolve_at_ref(raw).map_err(|e| {
                            DaemonError::Vault(format!(
                                "credential_store: failed to resolve token: {}",
                                e
                            ))
                        })?;
                        HashiVaultAuth::Token {
                            token: secrecy::SecretString::from(resolved),
                        }
                    }
                    "approle" => {
                        let role_id = cs.role_id.clone().ok_or_else(|| {
                            DaemonError::Vault(
                                "credential_store auth=approle requires `role_id`".to_string(),
                            )
                        })?;
                        let raw_secret = cs.secret_id.as_deref().ok_or_else(|| {
                            DaemonError::Vault(
                                "credential_store auth=approle requires `secret_id`".to_string(),
                            )
                        })?;
                        let resolved = resolve_at_ref(raw_secret).map_err(|e| {
                            DaemonError::Vault(format!(
                                "credential_store: failed to resolve secret_id: {}",
                                e
                            ))
                        })?;
                        HashiVaultAuth::AppRole {
                            role_id,
                            secret_id: secrecy::SecretString::from(resolved),
                        }
                    }
                    "aws" => {
                        // AWS IAM auth.
                        // Daemon proves its surrounding AWS IAM
                        // identity (env vars / instance metadata
                        // / IRSA / ECS task role / Fargate) via a
                        // SigV4-signed sts:GetCallerIdentity
                        // request that Vault re-plays server-side.
                        // The `role` field names the Vault
                        // AWS-auth role (`vault auth/aws/role/<role>`).
                        let role = cs.role.clone().ok_or_else(|| {
                            DaemonError::Vault(
                                "credential_store auth=aws requires `role`".to_string(),
                            )
                        })?;
                        HashiVaultAuth::Aws { role }
                    }
                    "hcp-service-principal" => {
                        // HashiCorp Cloud
                        // Platform service-principal auth. Exchange
                        // (client_id, client_secret) at HCP IdP's
                        // OAuth2 client_credentials endpoint for an
                        // access_token; submit that as
                        // `Authorization: Bearer` against the
                        // HCP-hosted Vault cluster's `addr`.
                        let client_id = cs.client_id.clone().ok_or_else(|| {
                            DaemonError::Vault(
                                "credential_store auth=hcp-service-principal requires `client_id`"
                                    .to_string(),
                            )
                        })?;
                        let raw_secret = cs.client_secret.as_deref().ok_or_else(|| {
                                DaemonError::Vault(
                                    "credential_store auth=hcp-service-principal requires `client_secret`"
                                        .to_string(),
                                )
                            })?;
                        let resolved = resolve_at_ref(raw_secret).map_err(|e| {
                            DaemonError::Vault(format!(
                                "credential_store: failed to resolve client_secret: {}",
                                e
                            ))
                        })?;
                        HashiVaultAuth::HcpServicePrincipal {
                            client_id,
                            client_secret: secrecy::SecretString::from(resolved),
                        }
                    }
                    other => {
                        return Err(DaemonError::Vault(format!(
                            "credential_store: unknown auth method '{}'",
                            other
                        )));
                    }
                };
                let policy = match cs.unavailable_policy.as_str() {
                    "fail-hard" => UnavailablePolicy::FailHard,
                    "fall-back-to-cache" => UnavailablePolicy::FallBackToCache,
                    other => {
                        return Err(DaemonError::Vault(format!(
                            "credential_store: unknown unavailable_policy '{}'",
                            other
                        )));
                    }
                };
                let http = ReqwestHttpClient::new().map_err(|e| {
                    DaemonError::Vault(format!(
                        "credential_store: reqwest client construction failed: {}",
                        e
                    ))
                })?;
                let mut s = HashiVaultStore::new(
                    Arc::new(http),
                    addr,
                    mount,
                    auth,
                    policy,
                    cs.cache_ttl_secs.map(std::time::Duration::from_secs),
                );
                s.login().await.map_err(|e| {
                    DaemonError::Vault(format!("credential_store: vault login failed: {}", e))
                })?;
                Arc::new(s)
            }
            Some(cs) => {
                return Err(DaemonError::Vault(format!(
                    "credential_store: unknown backend '{}'",
                    cs.backend
                )));
            }
        };

        let backend_name = self
            .config
            .credential_store
            .as_ref()
            .map(|c| c.backend.as_str())
            .unwrap_or("local");
        let backend_addr = self
            .config
            .credential_store
            .as_ref()
            .and_then(|c| c.addr.clone())
            .unwrap_or_else(|| "<local-vault>".to_string());
        info!(
            backend = backend_name,
            addr = %backend_addr,
            "credential store ready: backend={}",
            backend_name
        );

        // ADR 139 follow-up: the live broker registry always reloads authority
        // from the real runtime seam. On the local backend startup now uses
        // metadata-only "is this configured?" probes rather than a bootstrap
        // plaintext read, while runtime reloads prefer the shared interactive
        // live-vault slot and fall back to the active headless enrollment for
        // read-class provider-authority resolution only.
        let runtime_cred_store: Arc<dyn crate::infra::credential_store::CredentialStore> =
            Arc::clone(&cred_store);

        // Broker daemon RPC (ADR 094 Phase 2): install the credential
        // broker registry. Real provider implementations replace
        // `MockBroker` as their downstream tasks ship — currently the
        // GitHub App broker is wired;
        // Anthropic and Cloudflare follow. Calling `install_registry`
        // multiple times is a no-op after the first call (`OnceCell`).
        //
        // Dev/prod parity for mock brokers (ADR 157 §Component 2):
        // MockBroker registration is now an explicit opt-in via
        // `EMBER_ALLOW_MOCK_BROKERS`.
        //
        // Startup policy (ADR 202 §Decision 3, operator decision 2026-05-29):
        // - ALL providers, including GitHub, are optional at boot: register the
        //   real broker when configured, register Mock only when explicitly
        //   allow-listed, otherwise skip the provider without killing the
        //   daemon. A skipped provider's actions fail closed when attempted
        //   (no silent Mock — ADR 157 §Component 2 intact); skipping is NOT
        //   mocking.
        // - GitHub was previously load-bearing (failed startup when absent).
        //   The signed-`.pkg` product install boots the daemon BEFORE the
        //   operator provisions a GitHub App (provisioning is a
        //   first-interactive-use concern per ADR 202), so a fresh host must
        //   get a serving daemon — trust vault, audit, and configured
        //   providers fully live — with GitHub simply unregistered until
        //   first-use. Refusing to boot here is what left every fresh product
        //   install dead (VM-confirmed 2026-05-29).
        //
        // This keeps the no-silent-Mock invariant honest while avoiding
        // provider absence taking down the managed daemon on a host that has
        // not finished onboarding that provider.
        // Anchor: `dev_prod_parity_mock_broker_explicit_landed`.
        {
            use crate::broker::authority::{
                BrokerAuthorityResolver, CredentialPrecedence, ReloadingBroker, StartupProbeMode,
            };
            use core_broker::{BrokerProvider, MockBroker};
            let mut registry = crate::broker::handler::BrokerRegistry::new();

            // Read the
            // opt-in allowlist once at the top of the registration
            // block so every per-provider gate uses the same parsed
            // set. Unknown tokens get surfaced as a structured WARN
            // but do not halt startup (typo tolerance).
            let (mock_allow, mock_allow_unknown) =
                crate::broker::mock_allowlist::read_allow_mock_brokers_from_env();
            if !mock_allow_unknown.is_empty() {
                tracing::warn!(
                    env = crate::broker::mock_allowlist::ALLOW_MOCK_BROKERS_ENV,
                    unknown = ?mock_allow_unknown,
                    "EMBER_ALLOW_MOCK_BROKERS contains unrecognized provider name(s); \
                     each named provider has no Mock registered and missing real creds \
                     will fail startup"
                );
            }
            if !mock_allow.is_empty() {
                let names: Vec<&'static str> = mock_allow.iter().map(|p| p.as_str()).collect();
                info!(
                    env = crate::broker::mock_allowlist::ALLOW_MOCK_BROKERS_ENV,
                    providers = ?names,
                    "broker: mock-broker opt-in set declared ({} provider(s))",
                    mock_allow.len()
                );
            }

            // Broker vault cutover: precedence-flag for the
            // file/vault lookup order in each provider block below.
            //
            // - `EMBER_VAULT_FIRST=1` → vault-first (try the
            //   credential store first, fall back to the env-file
            //   loader on store-miss / store-error). This is the
            //   eventual steady-state.
            // - default (unset or any other value) → file-first
            //   during Phase 1 of the cutover. Operators who have
            //   not migrated their env files into the vault keep
            //   working without surprise; the vault still serves as
            //   the fallback when the env file is absent so the
            //   migration-in-progress posture is preserved.
            //
            // File-fallback (and its inverse, vault-fallback) stays
            // load-bearing in both orderings — the flag only swaps
            // which lane gets first attempt.
            let precedence = CredentialPrecedence::from_env();
            let vault_first = matches!(precedence, CredentialPrecedence::VaultFirst);
            let runtime_resolver = Arc::new(BrokerAuthorityResolver::new(
                Arc::clone(&runtime_cred_store),
                precedence,
            ));
            BrokerAuthorityResolver::install_current(Arc::clone(&runtime_resolver));
            let startup_probe_mode = match &self.config.credential_store {
                None => StartupProbeMode::MetadataOnly,
                Some(cs) if cs.backend == "local" => StartupProbeMode::MetadataOnly,
                Some(_) => StartupProbeMode::Plaintext,
            };
            info!(
                vault_first = vault_first,
                "credential precedence: {} (EMBER_VAULT_FIRST={})",
                if vault_first {
                    "vault-first"
                } else {
                    "file-first"
                },
                if vault_first { "1" } else { "unset/0" },
            );

            // GitHub: real broker when ~/.config/emberlink/ember-engine.{env,pem}
            // exist; Mock only when explicitly allow-listed; otherwise SKIP —
            // boot without the GitHub broker so a freshly-installed host whose
            // operator has not yet provisioned a GitHub App still gets a
            // serving daemon. GitHub actions fail closed (broker not registered)
            // until first-use provisioning wires the real broker. No silent
            // Mock (ADR 157 §Component 2). GitHub is now an optional-at-boot
            // provider like the others (ADR 202 §Decision 3; operator 2026-05-29)
            // — it was previously load-bearing and refused startup when absent,
            // which left every fresh product install dead.
            //
            // Credential-store wiring + broker vault cutover:
            // `startup_configured` honors the higher-priority lane first (per
            // `vault_first`), falling back to the other lane.
            let github_probe = runtime_resolver
                .startup_configured(BrokerProvider::Github, startup_probe_mode)
                .await;
            match optional_broker_startup_action(
                &github_probe,
                mock_allow.contains(&BrokerProvider::Github),
            ) {
                OptionalBrokerStartupAction::RegisterReal => {
                    registry.register(Box::new(ReloadingBroker::new(
                        BrokerProvider::Github,
                        Arc::clone(&runtime_resolver),
                    )));
                    info!(
                        provider = "github",
                        "broker registered: ReloadingBroker (GH App config detected at startup; reloads from runtime seam)"
                    );
                }
                OptionalBrokerStartupAction::RegisterMock => {
                    registry.register_mock(Box::new(MockBroker::new(BrokerProvider::Github)));
                    if let Err(e) = github_probe {
                        let error_detail = e.to_string();
                        warn_mock_broker_registration(
                            "github",
                            broker_startup_config_path(BrokerProvider::Github),
                            "opted in via EMBER_ALLOW_MOCK_BROKERS; GitHub App config is present but malformed",
                            Some(error_detail.as_str()),
                        );
                    } else {
                        warn_mock_broker_registration(
                            "github",
                            broker_startup_config_path(BrokerProvider::Github),
                            "opted in via EMBER_ALLOW_MOCK_BROKERS; GitHub App config is missing at startup",
                            None,
                        );
                    }
                }
                OptionalBrokerStartupAction::Skip => match github_probe {
                    Ok(false) => info!(
                        provider = "github",
                        "broker not configured at startup; skipping until first-use provisioning (GitHub actions fail closed until then)"
                    ),
                    Err(e) => tracing::warn!(
                        provider = "github",
                        error = %e,
                        "broker startup probe failed; skipping until config is repaired (GitHub actions fail closed until then)"
                    ),
                    Ok(true) => unreachable!("real provider handled above"),
                },
            }

            // AWS STS: real broker when ~/.config/emberlink/aws-sts.env
            // exists with the required AWS_LONG_LIVED_KEY_ID /
            // AWS_LONG_LIVED_KEY_SECRET / AWS_LONG_LIVED_REGION keys;
            // MockBroker fallback otherwise so dev hosts without AWS
            // config still answer broker_issue without a panic.
            //
            // Credential-store wiring + broker vault cutover:
            // honor `vault_first` precedence.
            let aws_sts_probe = runtime_resolver
                .startup_configured(BrokerProvider::AwsSts, startup_probe_mode)
                .await;
            match optional_broker_startup_action(
                &aws_sts_probe,
                mock_allow.contains(&BrokerProvider::AwsSts),
            ) {
                OptionalBrokerStartupAction::RegisterReal => {
                    registry.register(Box::new(ReloadingBroker::new(
                        BrokerProvider::AwsSts,
                        Arc::clone(&runtime_resolver),
                    )));
                    info!(
                        provider = "aws_sts",
                        "broker registered: ReloadingBroker (AWS STS config detected at startup; reloads from runtime seam)"
                    );
                }
                OptionalBrokerStartupAction::RegisterMock => {
                    registry.register_mock(Box::new(MockBroker::new(BrokerProvider::AwsSts)));
                    if let Err(e) = aws_sts_probe {
                        let error_detail = e.to_string();
                        warn_mock_broker_registration(
                            "aws_sts",
                            broker_startup_config_path(BrokerProvider::AwsSts),
                            "opted in via EMBER_ALLOW_MOCK_BROKERS; startup config probe failed",
                            Some(error_detail.as_str()),
                        );
                    } else {
                        warn_mock_broker_registration(
                            "aws_sts",
                            broker_startup_config_path(BrokerProvider::AwsSts),
                            "opted in via EMBER_ALLOW_MOCK_BROKERS; startup config is missing",
                            None,
                        );
                    }
                }
                OptionalBrokerStartupAction::Skip => match aws_sts_probe {
                    Ok(false) => info!(
                        provider = "aws_sts",
                        "broker not configured at startup; skipping optional provider"
                    ),
                    Err(e) => tracing::warn!(
                        provider = "aws_sts",
                        error = %e,
                        "broker startup probe failed; skipping optional provider until config is repaired"
                    ),
                    Ok(true) => unreachable!("real provider handled above"),
                },
            }

            // GCP: real broker when ~/.config/emberlink/gcp.env points
            // at a valid downloaded service-account JSON key file;
            // MockBroker fallback otherwise so dev hosts without GCP
            // config still answer broker_issue without a panic.
            //
            // Credential-store wiring + broker vault cutover:
            // honor `vault_first` precedence.
            let gcp_probe = runtime_resolver
                .startup_configured(BrokerProvider::Gcp, startup_probe_mode)
                .await;
            match optional_broker_startup_action(
                &gcp_probe,
                mock_allow.contains(&BrokerProvider::Gcp),
            ) {
                OptionalBrokerStartupAction::RegisterReal => {
                    registry.register(Box::new(ReloadingBroker::new(
                        BrokerProvider::Gcp,
                        Arc::clone(&runtime_resolver),
                    )));
                    info!(
                        provider = "gcp",
                        "broker registered: ReloadingBroker (GCP config detected at startup; reloads from runtime seam)"
                    );
                }
                OptionalBrokerStartupAction::RegisterMock => {
                    registry.register_mock(Box::new(MockBroker::new(BrokerProvider::Gcp)));
                    if let Err(e) = gcp_probe {
                        let error_detail = e.to_string();
                        warn_mock_broker_registration(
                            "gcp",
                            broker_startup_config_path(BrokerProvider::Gcp),
                            "opted in via EMBER_ALLOW_MOCK_BROKERS; startup config probe failed",
                            Some(error_detail.as_str()),
                        );
                    } else {
                        warn_mock_broker_registration(
                            "gcp",
                            broker_startup_config_path(BrokerProvider::Gcp),
                            "opted in via EMBER_ALLOW_MOCK_BROKERS; startup config is missing",
                            None,
                        );
                    }
                }
                OptionalBrokerStartupAction::Skip => match gcp_probe {
                    Ok(false) => info!(
                        provider = "gcp",
                        "broker not configured at startup; skipping optional provider"
                    ),
                    Err(e) => tracing::warn!(
                        provider = "gcp",
                        error = %e,
                        "broker startup probe failed; skipping optional provider until config is repaired"
                    ),
                    Ok(true) => unreachable!("real provider handled above"),
                },
            }

            // Azure: real broker when ~/.config/emberlink/azure.env
            // carries the AZURE_TENANT_ID + AZURE_CLIENT_ID +
            // AZURE_CLIENT_SECRET triple; MockBroker fallback otherwise
            // so dev hosts without Azure config still answer
            // broker_issue without a panic.
            //
            // Credential-store wiring + broker vault cutover:
            // honor `vault_first` precedence.
            let azure_probe = runtime_resolver
                .startup_configured(BrokerProvider::AzureCli, startup_probe_mode)
                .await;
            match optional_broker_startup_action(
                &azure_probe,
                mock_allow.contains(&BrokerProvider::AzureCli),
            ) {
                OptionalBrokerStartupAction::RegisterReal => {
                    registry.register(Box::new(ReloadingBroker::new(
                        BrokerProvider::AzureCli,
                        Arc::clone(&runtime_resolver),
                    )));
                    info!(
                        provider = "azure_cli",
                        "broker registered: ReloadingBroker (Azure config detected at startup; reloads from runtime seam)"
                    );
                }
                OptionalBrokerStartupAction::RegisterMock => {
                    registry.register_mock(Box::new(MockBroker::new(BrokerProvider::AzureCli)));
                    if let Err(e) = azure_probe {
                        let error_detail = e.to_string();
                        warn_mock_broker_registration(
                            "azure_cli",
                            broker_startup_config_path(BrokerProvider::AzureCli),
                            "opted in via EMBER_ALLOW_MOCK_BROKERS; startup config probe failed",
                            Some(error_detail.as_str()),
                        );
                    } else {
                        warn_mock_broker_registration(
                            "azure_cli",
                            broker_startup_config_path(BrokerProvider::AzureCli),
                            "opted in via EMBER_ALLOW_MOCK_BROKERS; startup config is missing",
                            None,
                        );
                    }
                }
                OptionalBrokerStartupAction::Skip => match azure_probe {
                    Ok(false) => info!(
                        provider = "azure_cli",
                        "broker not configured at startup; skipping optional provider"
                    ),
                    Err(e) => tracing::warn!(
                        provider = "azure_cli",
                        error = %e,
                        "broker startup probe failed; skipping optional provider until config is repaired"
                    ),
                    Ok(true) => unreachable!("real provider handled above"),
                },
            }

            // Fly.io: real broker when ~/.config/emberlink/fly.env
            // carries FLY_API_TOKEN; MockBroker fallback otherwise so
            // dev hosts without Fly config still answer broker_issue
            // without a panic.
            //
            // Credential-store wiring + broker vault cutover:
            // honor `vault_first` precedence.
            let fly_probe = runtime_resolver
                .startup_configured(BrokerProvider::FlyIo, startup_probe_mode)
                .await;
            match optional_broker_startup_action(
                &fly_probe,
                mock_allow.contains(&BrokerProvider::FlyIo),
            ) {
                OptionalBrokerStartupAction::RegisterReal => {
                    registry.register(Box::new(ReloadingBroker::new(
                        BrokerProvider::FlyIo,
                        Arc::clone(&runtime_resolver),
                    )));
                    info!(
                        provider = "fly_io",
                        "broker registered: ReloadingBroker (Fly config detected at startup; reloads from runtime seam)"
                    );
                }
                OptionalBrokerStartupAction::RegisterMock => {
                    registry.register_mock(Box::new(MockBroker::new(BrokerProvider::FlyIo)));
                    if let Err(e) = fly_probe {
                        let error_detail = e.to_string();
                        warn_mock_broker_registration(
                            "fly_io",
                            broker_startup_config_path(BrokerProvider::FlyIo),
                            "opted in via EMBER_ALLOW_MOCK_BROKERS; startup config probe failed",
                            Some(error_detail.as_str()),
                        );
                    } else {
                        warn_mock_broker_registration(
                            "fly_io",
                            broker_startup_config_path(BrokerProvider::FlyIo),
                            "opted in via EMBER_ALLOW_MOCK_BROKERS; startup config is missing",
                            None,
                        );
                    }
                }
                OptionalBrokerStartupAction::Skip => match fly_probe {
                    Ok(false) => info!(
                        provider = "fly_io",
                        "broker not configured at startup; skipping optional provider"
                    ),
                    Err(e) => tracing::warn!(
                        provider = "fly_io",
                        error = %e,
                        "broker startup probe failed; skipping optional provider until config is repaired"
                    ),
                    Ok(true) => unreachable!("real provider handled above"),
                },
            }

            // HashiCorp Vault: real broker when
            // ~/.config/emberlink/hashivault.env carries VAULT_TOKEN +
            // VAULT_ADDR; MockBroker fallback otherwise so dev hosts
            // without Vault config still answer broker_issue without a
            // panic.
            //
            // Credential-store wiring + broker vault cutover:
            // honor `vault_first` precedence.
            let hashi_probe = runtime_resolver
                .startup_configured(BrokerProvider::HashiVault, startup_probe_mode)
                .await;
            match optional_broker_startup_action(
                &hashi_probe,
                mock_allow.contains(&BrokerProvider::HashiVault),
            ) {
                OptionalBrokerStartupAction::RegisterReal => {
                    registry.register(Box::new(ReloadingBroker::new(
                        BrokerProvider::HashiVault,
                        Arc::clone(&runtime_resolver),
                    )));
                    info!(
                        provider = "hashi_vault",
                        "broker registered: ReloadingBroker (HashiVault config detected at startup; reloads from runtime seam)"
                    );
                }
                OptionalBrokerStartupAction::RegisterMock => {
                    registry.register_mock(Box::new(MockBroker::new(BrokerProvider::HashiVault)));
                    if let Err(e) = hashi_probe {
                        let error_detail = e.to_string();
                        warn_mock_broker_registration(
                            "hashi_vault",
                            broker_startup_config_path(BrokerProvider::HashiVault),
                            "opted in via EMBER_ALLOW_MOCK_BROKERS; startup config probe failed",
                            Some(error_detail.as_str()),
                        );
                    } else {
                        warn_mock_broker_registration(
                            "hashi_vault",
                            broker_startup_config_path(BrokerProvider::HashiVault),
                            "opted in via EMBER_ALLOW_MOCK_BROKERS; startup config is missing",
                            None,
                        );
                    }
                }
                OptionalBrokerStartupAction::Skip => match hashi_probe {
                    Ok(false) => info!(
                        provider = "hashi_vault",
                        "broker not configured at startup; skipping optional provider"
                    ),
                    Err(e) => tracing::warn!(
                        provider = "hashi_vault",
                        error = %e,
                        "broker startup probe failed; skipping optional provider until config is repaired"
                    ),
                    Ok(true) => unreachable!("real provider handled above"),
                },
            }

            // Okta: real broker when ~/.config/emberlink/okta.env
            // carries OKTA_ORG_URL + OKTA_CLIENT_ID +
            // OKTA_PRIVATE_KEY_PATH + OKTA_KEY_ID and the referenced
            // PEM file is readable; MockBroker fallback otherwise so
            // dev hosts without Okta config still answer broker_issue
            // without a panic.
            //
            // Credential-store wiring + broker vault cutover:
            // honor `vault_first` precedence.
            let okta_probe = runtime_resolver
                .startup_configured(BrokerProvider::Okta, startup_probe_mode)
                .await;
            match optional_broker_startup_action(
                &okta_probe,
                mock_allow.contains(&BrokerProvider::Okta),
            ) {
                OptionalBrokerStartupAction::RegisterReal => {
                    registry.register(Box::new(ReloadingBroker::new(
                        BrokerProvider::Okta,
                        Arc::clone(&runtime_resolver),
                    )));
                    info!(
                        provider = "okta",
                        "broker registered: ReloadingBroker (Okta config detected at startup; reloads from runtime seam)"
                    );
                }
                OptionalBrokerStartupAction::RegisterMock => {
                    registry.register_mock(Box::new(MockBroker::new(BrokerProvider::Okta)));
                    if let Err(e) = okta_probe {
                        let error_detail = e.to_string();
                        warn_mock_broker_registration(
                            "okta",
                            broker_startup_config_path(BrokerProvider::Okta),
                            "opted in via EMBER_ALLOW_MOCK_BROKERS; startup config probe failed",
                            Some(error_detail.as_str()),
                        );
                    } else {
                        warn_mock_broker_registration(
                            "okta",
                            broker_startup_config_path(BrokerProvider::Okta),
                            "opted in via EMBER_ALLOW_MOCK_BROKERS; startup config is missing",
                            None,
                        );
                    }
                }
                OptionalBrokerStartupAction::Skip => match okta_probe {
                    Ok(false) => info!(
                        provider = "okta",
                        "broker not configured at startup; skipping optional provider"
                    ),
                    Err(e) => tracing::warn!(
                        provider = "okta",
                        error = %e,
                        "broker startup probe failed; skipping optional provider until config is repaired"
                    ),
                    Ok(true) => unreachable!("real provider handled above"),
                },
            }

            // Vercel: real broker when ~/.config/emberlink/vercel.env
            // carries VERCEL_TOKEN; MockBroker fallback otherwise so
            // dev hosts without Vercel config still answer broker_issue
            // without a panic.
            //
            // Credential-store wiring + broker vault cutover:
            // honor `vault_first` precedence.
            let vercel_probe = runtime_resolver
                .startup_configured(BrokerProvider::Vercel, startup_probe_mode)
                .await;
            match optional_broker_startup_action(
                &vercel_probe,
                mock_allow.contains(&BrokerProvider::Vercel),
            ) {
                OptionalBrokerStartupAction::RegisterReal => {
                    registry.register(Box::new(ReloadingBroker::new(
                        BrokerProvider::Vercel,
                        Arc::clone(&runtime_resolver),
                    )));
                    info!(
                        provider = "vercel",
                        "broker registered: ReloadingBroker (Vercel config detected at startup; reloads from runtime seam)"
                    );
                }
                OptionalBrokerStartupAction::RegisterMock => {
                    registry.register_mock(Box::new(MockBroker::new(BrokerProvider::Vercel)));
                    if let Err(e) = vercel_probe {
                        let error_detail = e.to_string();
                        warn_mock_broker_registration(
                            "vercel",
                            broker_startup_config_path(BrokerProvider::Vercel),
                            "opted in via EMBER_ALLOW_MOCK_BROKERS; startup config probe failed",
                            Some(error_detail.as_str()),
                        );
                    } else {
                        warn_mock_broker_registration(
                            "vercel",
                            broker_startup_config_path(BrokerProvider::Vercel),
                            "opted in via EMBER_ALLOW_MOCK_BROKERS; startup config is missing",
                            None,
                        );
                    }
                }
                OptionalBrokerStartupAction::Skip => match vercel_probe {
                    Ok(false) => info!(
                        provider = "vercel",
                        "broker not configured at startup; skipping optional provider"
                    ),
                    Err(e) => tracing::warn!(
                        provider = "vercel",
                        error = %e,
                        "broker startup probe failed; skipping optional provider until config is repaired"
                    ),
                    Ok(true) => unreachable!("real provider handled above"),
                },
            }

            // All other providers still on MockBroker pending their
            // downstream wiring tasks. Keep this list explicit (not a
            // catch-all loop) so adding a real impl is a deliberate
            // edit, not a silent default.
            for (provider, name) in [
                (BrokerProvider::Cloudflare, "cloudflare"),
                (BrokerProvider::Anthropic, "anthropic"),
                (BrokerProvider::Tailscale, "tailscale"),
            ] {
                if mock_allow.contains(&provider) {
                    registry.register_mock(Box::new(MockBroker::new(provider)));
                    warn_mock_broker_registration(
                        name,
                        broker_startup_config_path(provider),
                        "opted in via EMBER_ALLOW_MOCK_BROKERS; no real broker exists yet",
                        None,
                    );
                } else {
                    info!(
                        provider = name,
                        "broker not configured at startup; skipping optional provider (no real broker yet)"
                    );
                }
            }
            crate::broker::handler::install_registry_with_authority(
                registry,
                crate::broker::handler::BrokerRegistryAuthority::InteractiveStartup,
            );
            info!(
                authority =
                    crate::broker::handler::BrokerRegistryAuthority::InteractiveStartup.as_str(),
                "broker registry installed (real + EMBER_ALLOW_MOCK_BROKERS opt-ins; see per-provider lines above)"
            );
        }

        // Broker startup no longer keeps a direct bootstrap vault handle on the
        // local backend. Drop the store bindings here so the serve loop begins
        // with only the shared runtime seam, not any bootstrap-only adapters.
        drop(cred_store);
        drop(runtime_cred_store);

        // Install the process-global
        // uid pool from `[spawn_pool]` in config.toml. Absent ⇒ pool
        // stays uninstalled and `handle_broker_exec` refuses with
        // `-32021` until the operator runs `ember daemon install`.
        // See `crates/ember-daemon/src/broker/uid_alloc.rs` and ADR
        // 166 (amendment to ADR 131).
        {
            let pool_cfg = self.config.spawn_pool.clone();
            match pool_cfg {
                Some(ref cfg) => {
                    info!(
                        uid_count = cfg.uids.len(),
                        gid = cfg.gid,
                        "spawn_pool: installing per-spawn uid pool ({} uids configured)",
                        cfg.uids.len()
                    );
                }
                None => {
                    tracing::warn!(
                        "spawn_pool: no [spawn_pool] section in config.toml — \
                         broker_exec will refuse with -32021 until operator runs \
                         `ember daemon install` (META-BROKER-EXEC-PER-SPAWN-UID)"
                    );
                }
            }
            crate::broker::uid_alloc::init_uid_pool(pool_cfg);
        }

        // NOTIF-2: sweep approval_requests that were left pending from a prior
        // session. Rows older than stale_approval_threshold_secs are marked
        // timed_out. Fires zero notifications — the user already saw the banner
        // when the request was first submitted.
        match store.expire_stale_pending_approvals(self.config.stale_approval_threshold_secs) {
            Ok(0) => {}
            Ok(n) => info!(
                count = n,
                "startup: auto-expired {n} stale pending approvals"
            ),
            Err(e) => tracing::warn!(error = %e, "startup stale-approval sweep failed"),
        }

        let policy = if self.config.policy_file.exists() {
            let engine = PolicyEngine::from_file(&self.config.policy_file)?;
            info!(path = %self.config.policy_file.display(), "loaded policy");
            engine
        } else {
            info!("no policy file found, using defaults");
            PolicyEngine::default()
        };
        let policy = new_shared_policy_engine(policy);
        let rate_limiter = Rc::new(RefCell::new(RateLimiter::default()));

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let sessions_dir = crate::session_watcher::sessions_dir_from_data(&self.config.data_dir);
        let listener = SocketListener::new(
            socket_path,
            shutdown_rx,
            store.clone(),
            Rc::clone(&policy),
            Rc::clone(&rate_limiter),
        )
        .with_sessions_dir(sessions_dir.clone());

        // Run socket listener and background tasks on a LocalSet (DaemonStore is !Send).
        let local = tokio::task::LocalSet::new();

        crate::trust::presence::startup_lock();
        #[cfg(target_os = "macos")]
        let _macos_invalidation_watcher = start_local_startup_component_on_local(
            &local,
            "macOS presence invalidation watcher",
            || async {
                crate::presence::invalidation_macos::MacosInvalidationWatcher::start().await
            },
        )
        .await;

        // Spawn the grant expiry sweep — runs every 60 seconds.
        // TTL-based expiry (column `expires_at`) and composite wall-clock
        // budget expiry (Statement-level `budget.wall_clock_secs`) both
        // run on the same cadence. The wall-clock sweep also emits
        // `budget.warning` at 80% elapsed — same pattern as TTL warnings.
        let expiry_store = Rc::clone(&store);
        local.spawn_local(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                match expiry_store.expire_stale_grants() {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(count = n, "expired stale grants"),
                    Err(e) => tracing::warn!(error = %e, "grant expiry sweep failed"),
                }
                match expiry_store.expire_grants_by_wall_clock() {
                    Ok((0, 0)) => {}
                    Ok((exhausted, warned)) => {
                        if exhausted > 0 {
                            tracing::info!(
                                count = exhausted,
                                "exhausted grants by wall-clock budget"
                            );
                        }
                        if warned > 0 {
                            tracing::info!(count = warned, "wall-clock 80% warnings emitted");
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "grant wall-clock sweep failed"),
                }
            }
        });

        // Stale-approval cleanup — background sweep marks pending
        // approvals older than `stale_approval_threshold_secs` as `timed_out`.
        // Runs every 60 seconds. Complements the startup sweep (line ~261) which
        // only catches requests left pending from prior sessions. This sweep
        // handles requests that arrive and time out within a running session.
        // Auto-swept rows fire zero desktop notifications (operator is not present).
        let stale_store = Rc::clone(&store);
        let stale_threshold = self.config.stale_approval_threshold_secs;
        local.spawn_local(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                match stale_store.expire_stale_pending_approvals(stale_threshold) {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(
                        count = n,
                        threshold_secs = stale_threshold,
                        "background: auto-expired stale pending approvals"
                    ),
                    Err(e) => tracing::warn!(error = %e, "background stale-approval sweep failed"),
                }
            }
        });

        // Image-revocations flow — 60-second revocation document poller.
        // Fetch path now wired.
        // Fetches signed `revocations/current.json` on each tick and evaluates
        // a severity-driven response (critical=IsolateDrainKill, high=DrainToTtl,
        // medium/low=Log). Unsigned/unverifiable, future-issued, and stale
        // documents (>30 min) fail closed. The runtime currently uses the default
        // no-signer poller until release-key pinning is wired, so fetched
        // documents cannot affect release posture unless a trusted signer is
        // explicitly supplied by owned code. Runs in a detached tokio::spawn
        // (not LocalSet) because the poller is Send and does not access !Send
        // daemon state.
        //
        // Configuration: `EMBER_REVOCATIONS_URL` env var. When unset, the
        // poller logs trace-level "no fetcher configured" each tick and
        // produces no decisions (implicit fail-closed posture). The host
        // operator opts in by setting the URL.
        //
        // TODO: decisions are logged but
        // not yet wired through to drain / kill / log actions on running
        // containers. The fetch wiring above is the prerequisite; action
        // application is a separate follow-up task.
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            let poller = ember_update::revocations::RevocationsPoller::new();
            let fetcher = match ember_update::revocations::RevocationsFetcher::from_env() {
                Some(Ok(f)) => {
                    tracing::info!(
                        url = %f.endpoint_url(),
                        timeout_secs = f.timeout_secs(),
                        "revocations fetcher configured"
                    );
                    Some(f)
                }
                Some(Err(e)) => {
                    tracing::warn!(
                        error = %e,
                        "revocations fetcher init failed; poller fail-closed"
                    );
                    None
                }
                None => {
                    tracing::info!(
                        "revocations endpoint not configured ({} unset); poller fail-closed",
                        ember_update::revocations::REVOCATIONS_URL_ENV
                    );
                    None
                }
            };
            loop {
                tick.tick().await;
                let Some(f) = fetcher.as_ref() else {
                    tracing::trace!("revocations poll tick — no fetcher configured (fail-closed)");
                    continue;
                };
                match f.fetch().await {
                    Ok(bytes) => match poller.poll(&bytes) {
                        Ok(decisions) if decisions.is_empty() => {
                            tracing::trace!("revocations poll tick — no decisions");
                        }
                        Ok(decisions) => {
                            tracing::info!(
                                count = decisions.len(),
                                "revocations poll tick — decisions produced"
                            );
                            for d in &decisions {
                                tracing::info!(
                                    digest = %d.entry.digest,
                                    action = ?d.action,
                                    "revocation decision"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "revocations poll: evaluate failed (fail-closed)");
                        }
                    },
                    Err(e) => {
                        tracing::warn!(error = %e, "revocations fetch failed (cycle skipped, fail-closed)");
                    }
                }
            }
        });
        tracing::info!("image revocations poller started (60s interval)");

        // Session heartbeat + TTL watcher.
        // Runs every 60 s. Closes orphaned sessions (launcher PID dead > 5 min)
        // and sessions whose grant is past the 24-hour TTL backstop.
        let session_store_clone = Rc::clone(&store);
        let sessions_dir_for_watcher = sessions_dir.clone();
        local.spawn_local(async move {
            crate::session_watcher::run(session_store_clone, sessions_dir_for_watcher).await;
        });
        tracing::info!("session heartbeat watcher started");

        // Presence-bridge launcher pidfd watch (Phase 1) —
        // fast-path launcher exit detector. Polls per-session pidfds every
        // 1 s on Linux (kqueue stub on macOS) so launcher exit fires the
        // revocation-cascade placeholder within ~1 s, complementing the
        // 60 s session_watcher above. Phase 2 wires the cascade itself.
        let launcher_watch_store = Rc::clone(&store);
        let sessions_dir_for_launcher_watch = sessions_dir.clone();
        local.spawn_local(async move {
            crate::launcher_watch::run(launcher_watch_store, sessions_dir_for_launcher_watch).await;
        });
        tracing::info!("launcher pidfd watcher started");

        // ADR 117 — periodic vault snapshot task.
        // Runs every `snapshot_interval_secs` (default 3600). Disabled when
        // `snapshot_interval_secs` is 0 or when the daemon identity is not
        // initialised (test harness or pre-startup paths).
        if self.config.snapshot_interval_secs > 0 {
            if let Some(identity) = crate::infra::receipt::current_identity() {
                let snapshot_store = Rc::clone(&store);
                let snapshot_data_dir = self.config.data_dir.clone();
                let snapshot_interval = self.config.snapshot_interval_secs;
                // SnapshotEmitter is Sync (wraps Mutex) so a shared ref from the
                // heap is stable across the closure captures.
                let emitter = Rc::new(crate::snapshot::SnapshotEmitter::new(snapshot_interval));
                local.spawn_local(async move {
                    // Tick at the configured interval. The emitter checks the
                    // wall-clock itself so spurious extra ticks are no-ops.
                    let tick_secs = snapshot_interval.min(60);
                    let mut interval =
                        tokio::time::interval(std::time::Duration::from_secs(tick_secs));
                    loop {
                        interval.tick().await;
                        match emitter.maybe_emit(
                            &snapshot_store,
                            identity,
                            &snapshot_data_dir,
                            0, // event_log_high_watermark: 0 until event-log wiring lands
                        ) {
                            Ok(Some(id)) => {
                                tracing::info!(snapshot_id = %id, "periodic vault snapshot emitted")
                            }
                            Ok(None) => {}
                            Err(e) => tracing::warn!(error = %e, "periodic vault snapshot failed"),
                        }
                    }
                });
                tracing::info!(
                    interval_secs = snapshot_interval,
                    "vault snapshot task started"
                );
            } else {
                tracing::warn!("snapshot task skipped — daemon identity not initialised");
            }
        }

        // Periodic cluster snapshot pull task.
        // Runs every `snapshot_pull_interval_secs` (default 600, i.e. 10 min).
        // Only active when both `snapshot_pull_endpoint` and
        // `snapshot_pull_cluster_id` are configured. On each tick it calls
        // the EIC's `/api/cluster-snapshot/latest`, validates the signed
        // manifest, and stores the encrypted blob in the local vault.
        if self.config.snapshot_pull_interval_secs > 0
            && let (Some(ref endpoint), Some(ref cluster_id)) = (
                self.config.snapshot_pull_endpoint.clone(),
                self.config.snapshot_pull_cluster_id.clone(),
            )
        {
            if let Some(identity) = crate::infra::receipt::current_identity() {
                let pull_endpoint = endpoint.clone();
                let pull_cluster_id = cluster_id.clone();
                let pull_interval = self.config.snapshot_pull_interval_secs;
                // EIC Daemon Persona pubkey — use this daemon's identity pubkey as
                // the trust anchor. In a real deployment the operator configures
                // the EIC's pubkey here; for the dev0 default we use the same
                // identity key since both daemons share the same IdentityRoot.
                let eic_pubkey_hex = identity.pubkey_hex();
                let pull_vault_slot = live_vault_slot.clone();
                let pull_store_path = self.config.data_dir.join("daemon.db");
                let puller = Rc::new(crate::snapshot::SnapshotPuller::new(pull_interval));
                local.spawn_local(async move {
                    let tick_secs = pull_interval.min(60);
                    let mut interval =
                        tokio::time::interval(std::time::Duration::from_secs(tick_secs));
                    loop {
                        interval.tick().await;
                        // SnapshotPuller::maybe_pull is async and opens its
                        // own store connection (rusqlite is !Send).
                        let pull_store =
                            match crate::infra::store::DaemonStore::open(&pull_store_path) {
                                Ok(s) => s,
                                Err(e) => {
                                    tracing::warn!(error = %e, "pull task: failed to open store");
                                    continue;
                                }
                            };
                        pull_store.replace_vault_slot(pull_vault_slot.clone());
                        let Some(pull_vault) = pull_store.vault() else {
                            tracing::warn!("pull task: vault unavailable");
                            continue;
                        };
                        match puller
                            .maybe_pull(
                                &pull_endpoint,
                                &pull_cluster_id,
                                &eic_pubkey_hex,
                                &pull_vault,
                                &pull_store,
                            )
                            .await
                        {
                            Ok(Some(id)) => {
                                tracing::info!(
                                    snapshot_id = %id,
                                    cluster_id = %pull_cluster_id,
                                    "cluster snapshot pulled"
                                );
                            }
                            Ok(None) => {}
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    cluster_id = %pull_cluster_id,
                                    "periodic cluster snapshot pull failed"
                                );
                            }
                        }
                    }
                });
                tracing::info!(
                    interval_secs = pull_interval,
                    endpoint = %endpoint,
                    cluster_id = %cluster_id,
                    "cluster snapshot pull task started"
                );
            } else {
                tracing::warn!("snapshot pull task skipped — daemon identity not initialised");
            }
        }

        // Spawn the dashboard HTTP listener if configured. The bind result is captured via
        // a oneshot channel and driven to completion inside `local.run_until(bind_rx)` below,
        // before the main accept loop starts. This ensures the LocalSet is polled so the
        // dashboard task can actually run and send on the channel.
        //
        // We retain the configured address alongside the receiver so a bind failure can
        // report which port was attempted.
        let dashboard_bind_info: Option<(
            SocketAddr,
            oneshot::Receiver<Result<SocketAddr, std::io::Error>>,
        )> = if let Some(dashboard_addr) = self.config.dashboard_addr {
            let db_path = self.config.data_dir.join("daemon.db");
            let version = env!("CARGO_PKG_VERSION").to_string();
            let dashboard_shutdown = shutdown_tx.subscribe();
            let (bind_tx, bind_rx) = oneshot::channel();
            local.spawn_local(run_dashboard(
                dashboard_addr,
                db_path,
                version,
                Some(live_vault_slot.clone()),
                dashboard_shutdown,
                Some(bind_tx),
            ));
            Some((dashboard_addr, bind_rx))
        } else {
            None
        };

        // Spawn the git-echo credential-injection proxy if
        // configured. Bind result is captured via a oneshot channel and
        // driven below alongside the dashboard's. Each proxy task gets its
        // own DaemonStore (rusqlite Connection is !Send) but shares the
        // daemon's live-vault slot so explicit lock cuts off proxy-side
        // secret access too.
        let git_proxy_bind_info: Option<(
            SocketAddr,
            oneshot::Receiver<Result<SocketAddr, std::io::Error>>,
        )> = if let Some(proxy_addr) = self.config.git_proxy_addr {
            let proxy_db_path = self.config.data_dir.join("daemon.db");
            let proxy_shutdown = shutdown_tx.subscribe();
            let (bind_tx, bind_rx) = oneshot::channel::<Result<SocketAddr, std::io::Error>>();
            let proxy_vault_slot = live_vault_slot.clone();
            let proxy_lease_kek_slot = live_lease_kek_slot.clone();
            let git_proxy_sessions_dir = sessions_dir.clone();
            // Git proxy spawn marker: spawn_local run_git_echo_proxy via this LocalSet.
            local.spawn_local(supervise_local_proxy(
                "git proxy",
                proxy_addr,
                proxy_shutdown,
                bind_tx,
                move |bind_addr, proxy_shutdown, bind_tx| {
                    let proxy_db_path = proxy_db_path.clone();
                    let proxy_vault_slot = proxy_vault_slot.clone();
                    let proxy_lease_kek_slot = proxy_lease_kek_slot.clone();
                    let sessions_dir = git_proxy_sessions_dir.clone();
                    async move {
                        let store = match crate::infra::store::DaemonStore::open(&proxy_db_path) {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "git proxy: failed to open store; proxy disabled"
                                );
                                let _ = bind_tx.send(Err(std::io::Error::other(format!(
                                    "git proxy store open: {e}"
                                ))));
                                return Ok(());
                            }
                        };
                        // ProxyState wraps a rusqlite Connection which is
                        // !Send + !Sync; the Arc is used only within this
                        // LocalSet (single-threaded runtime), mirroring
                        // run_proxy / run_git_echo_proxy themselves.
                        //
                        // Wedge meter wiring: attach the vault to this
                        // fresh store. Without this,
                        // increment_statement_usage's re-sign of block 0 calls
                        // persona_root_keypair → self.vault() → None → "no
                        // vault is attached", silently dropping every meter
                        // delta and breaking budget enforcement at the wire.
                        store.replace_vault_slot(proxy_vault_slot.clone());
                        store.replace_lease_kek_slot(proxy_lease_kek_slot.clone());
                        #[allow(clippy::arc_with_non_send_sync)]
                        let state = std::sync::Arc::new(crate::infra::proxy::ProxyState::new(
                            store,
                            Some(sessions_dir.clone()),
                        ));
                        // Install the
                        // `DaemonEventSink` immediately after construction.
                        // The git-echo proxy does not broadcast grant events
                        // (no SDK subscribers reach this listener), so the
                        // sink is created with `events_tx = None` — audit
                        // writes still route through the sink, broadcast is
                        // a no-op.
                        #[allow(clippy::arc_with_non_send_sync)]
                        let event_sink = std::sync::Arc::new(
                            crate::infra::proxy::DaemonEventSink::new(state.clone(), None),
                        );
                        let _ = state.event_sink.set(event_sink);
                        let cfg = crate::infra::proxy::GitEchoConfig {
                            bind_addr,
                            upstream_host: "github.com".to_string(),
                            state,
                            upstream_scheme: crate::infra::proxy::Scheme::Https,
                        };
                        crate::infra::proxy::run_git_echo_proxy(cfg, proxy_shutdown, Some(bind_tx))
                            .await
                    }
                },
            ));
            Some((proxy_addr, bind_rx))
        } else {
            None
        };

        // Spawn the general LLM/HTTP credential-
        // injection proxy (`run_proxy` — provider-aware auth, X-Ember-* header
        // protocol). This is the listener the Anthropic SDK demo posts to via
        // `base_url=$EMBER_PROXY_URL`; previously `run_proxy` was defined but
        // never spawned, so every Beat 4 call hit the git-echo proxy and 400'd.
        // Mirrors the git-proxy spawn block exactly: fresh DaemonStore
        // (rusqlite is !Send), shared live-vault slot, dedicated bind
        // channel.
        // P22-S2 PR-E (ADR 197 §1): the loopback-TCP LLM gateway is the
        // transitional path — no kernel peer identity, port-squattable, and the
        // only consumer of the replayable endpoint-token bearer. With the
        // per-session peercred-gated UDS lanes live (PR-C Claude, PR-D codex),
        // it is GUARDED OFF BY DEFAULT and only spawned when an operator
        // explicitly opts in via `EMBER_TRANSITIONAL_TCP_LLM_PROXY=1` (for a
        // non-UDS Anthropic client during cutover). Default-off removes the
        // CRIT-1 surface from the live system. The git-echo proxy and the
        // daemon socket are unaffected.
        let bridge_configured = self.config.bridge_bind.is_some();
        let transitional_tcp_enabled = std::env::var("EMBER_TRANSITIONAL_TCP_LLM_PROXY").ok();
        let bind_llm_proxy =
            should_bind_llm_proxy(transitional_tcp_enabled.as_deref(), bridge_configured);
        if !bind_llm_proxy {
            tracing::info!(
                "transitional TCP LLM proxy disabled by default (P22-S2 PR-E); per-session UDS is the live LLM gateway. Set EMBER_TRANSITIONAL_TCP_LLM_PROXY=1 to re-enable for non-UDS clients."
            );
        } else if bridge_configured
            && !parse_transitional_tcp_flag(transitional_tcp_enabled.as_deref())
        {
            tracing::info!(
                "TCP LLM proxy enabled because the ADR 207 container bridge is configured; container Anthropic sessions cannot use the host peercred UDS lane."
            );
        }
        let llm_proxy_bind_info: Option<(
            SocketAddr,
            oneshot::Receiver<Result<SocketAddr, std::io::Error>>,
        )> = if let Some(proxy_addr) = self.config.llm_proxy_addr.filter(|_| bind_llm_proxy) {
            let proxy_db_path = self.config.data_dir.join("daemon.db");
            let proxy_shutdown = shutdown_tx.subscribe();
            let (bind_tx, bind_rx) = oneshot::channel::<Result<SocketAddr, std::io::Error>>();
            let proxy_vault_slot = live_vault_slot.clone();
            let proxy_lease_kek_slot = live_lease_kek_slot.clone();
            let llm_proxy_sessions_dir = sessions_dir.clone();
            local.spawn_local(supervise_local_proxy(
                "llm proxy",
                proxy_addr,
                proxy_shutdown,
                bind_tx,
                move |bind_addr, proxy_shutdown, bind_tx| {
                    let proxy_db_path = proxy_db_path.clone();
                    let proxy_vault_slot = proxy_vault_slot.clone();
                    let proxy_lease_kek_slot = proxy_lease_kek_slot.clone();
                    let sessions_dir = llm_proxy_sessions_dir.clone();
                    async move {
                        let store = match crate::infra::store::DaemonStore::open(&proxy_db_path) {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "llm proxy: failed to open store; proxy disabled"
                                );
                                let _ = bind_tx.send(Err(std::io::Error::other(format!(
                                    "llm proxy store open: {e}"
                                ))));
                                return Ok(());
                            }
                        };
                        // Wedge meter wiring: attach vault to the
                        // fresh store so increment_statement_usage's block-0
                        // re-sign can read the issuing persona's root keypair
                        // (vault-sealed). Same fix as the git-echo proxy spawn
                        // block above.
                        store.replace_vault_slot(proxy_vault_slot.clone());
                        store.replace_lease_kek_slot(proxy_lease_kek_slot.clone());
                        #[allow(clippy::arc_with_non_send_sync)]
                        let state = std::sync::Arc::new(crate::infra::proxy::ProxyState::new(
                            store,
                            Some(sessions_dir.clone()),
                        ));
                        // Install the
                        // `DaemonEventSink` immediately after construction.
                        // The LLM proxy currently runs without a broadcast
                        // channel here (the SocketListener owns the
                        // `events_tx` and it is not yet plumbed into this
                        // spawn block — preserving the prior behaviour
                        // verbatim). Audit-log writes route through the sink
                        // shim; broadcast is a no-op until the channel is
                        // wired through.
                        #[allow(clippy::arc_with_non_send_sync)]
                        let event_sink = std::sync::Arc::new(
                            crate::infra::proxy::DaemonEventSink::new(state.clone(), None),
                        );
                        let _ = state.event_sink.set(event_sink);
                        let cfg = crate::infra::proxy::ProxyConfig { bind_addr };
                        crate::infra::proxy::run_proxy(cfg, state, proxy_shutdown, Some(bind_tx))
                            .await
                    }
                },
            ));
            Some((proxy_addr, bind_rx))
        } else {
            None
        };

        // P22-S2 (ADR 197 §1/§2) — per-session peercred-gated LLM-gateway Unix
        // sockets. This is the capability that supersedes the loopback TCP
        // listener's CRIT-1 surface (no peer identity, port-squattable,
        // replayable bearer). The registry owns one `0700` socket per session,
        // stood up at `register_session` and torn down at `close_session` via a
        // process-global command channel. PR-B builds the capability only — no
        // harness is pointed at these sockets yet (Claude/Codex stay on the
        // transitional TCP path until PR-C/PR-D), so this introduces no
        // live-behavior change; the gate is exercised by the integration tests.
        {
            let proxy_db_path = self.config.data_dir.join("daemon.db");
            let registry_vault_slot = live_vault_slot.clone();
            let registry_lease_kek_slot = live_lease_kek_slot.clone();
            let registry_sessions_dir = sessions_dir.clone();
            let registry_socket_dir = self.config.socket_dir.clone();
            let registry_shutdown = shutdown_tx.subscribe();
            let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<
                crate::infra::session_proxy::SessionProxyCommand,
            >();
            if !crate::infra::session_proxy::install_command_sender(cmd_tx) {
                tracing::warn!(
                    "session_proxy: command sender already installed — second daemon incarnation in-process; per-session sockets disabled for this run"
                );
            } else {
                local.spawn_local(async move {
                    let store = match crate::infra::store::DaemonStore::open(&proxy_db_path) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!(error = %e, "session_proxy: failed to open store; per-session sockets disabled");
                            return;
                        }
                    };
                    store.replace_vault_slot(registry_vault_slot.clone());
                    store.replace_lease_kek_slot(registry_lease_kek_slot.clone());
                    #[allow(clippy::arc_with_non_send_sync)]
                    let state = std::sync::Arc::new(crate::infra::proxy::ProxyState::new(
                        store,
                        Some(registry_sessions_dir.clone()),
                    ));
                    #[allow(clippy::arc_with_non_send_sync)]
                    let event_sink = std::sync::Arc::new(
                        crate::infra::proxy::DaemonEventSink::new(state.clone(), None),
                    );
                    let _ = state.event_sink.set(event_sink);
                    #[allow(clippy::arc_with_non_send_sync)]
                    let backend = std::sync::Arc::new(
                        crate::infra::proxy::DaemonPolicyBackend::new(state.clone()),
                    );
                    crate::infra::session_proxy::run_session_proxy_registry(
                        registry_socket_dir,
                        state,
                        backend,
                        cmd_rx,
                        registry_shutdown,
                    )
                    .await;
                });
            }
        }

        // P22-S2 (ADR 197 codex) / ADR 215 §2 — one per-session loopback-TCP
        // credential-injection registry shared by the codex GPT-plan responses
        // lane and the gemini Code Assist OAuth lane. Mirrors the session_proxy
        // registry above but binds loopback TCP (these harnesses dial a
        // `base_url`, not a UDS) and carries NO peer-attestation gate (a
        // non-root daemon cannot read a loopback-TCP peer's kernel identity).
        // Credential-safe by construction: each lane's projector pins a strict
        // endpoint gate, header strip, server-side credential injection + an
        // upstream-host pin. The launcher points the harness's config at the
        // per-session URL; each `Open` carries its own projector.
        {
            let loopback_proxy_db_path = self.config.data_dir.join("daemon.db");
            let loopback_registry_vault_slot = live_vault_slot.clone();
            let loopback_registry_lease_kek_slot = live_lease_kek_slot.clone();
            let loopback_registry_sessions_dir = sessions_dir.clone();
            let loopback_registry_shutdown = shutdown_tx.subscribe();
            let (loopback_cmd_tx, loopback_cmd_rx) = tokio::sync::mpsc::unbounded_channel::<
                crate::infra::loopback_proxy::LoopbackProxyCommand,
            >();
            if !crate::infra::loopback_proxy::install_loopback_command_sender(loopback_cmd_tx) {
                tracing::warn!(
                    "loopback_proxy: command sender already installed — second daemon incarnation in-process; per-session loopback listeners disabled for this run"
                );
            } else {
                local.spawn_local(async move {
                    let store = match crate::infra::store::DaemonStore::open(&loopback_proxy_db_path) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!(error = %e, "loopback_proxy: failed to open store; per-session loopback listeners disabled");
                            return;
                        }
                    };
                    store.replace_vault_slot(loopback_registry_vault_slot.clone());
                    store.replace_lease_kek_slot(loopback_registry_lease_kek_slot.clone());
                    #[allow(clippy::arc_with_non_send_sync)]
                    let state = std::sync::Arc::new(crate::infra::proxy::ProxyState::new(
                        store,
                        Some(loopback_registry_sessions_dir.clone()),
                    ));
                    #[allow(clippy::arc_with_non_send_sync)]
                    let event_sink = std::sync::Arc::new(
                        crate::infra::proxy::DaemonEventSink::new(state.clone(), None),
                    );
                    let _ = state.event_sink.set(event_sink);
                    #[allow(clippy::arc_with_non_send_sync)]
                    let backend = std::sync::Arc::new(
                        crate::infra::proxy::DaemonPolicyBackend::new(state.clone()),
                    );
                    crate::infra::loopback_proxy::run_loopback_proxy_registry(
                        backend,
                        loopback_cmd_rx,
                        loopback_registry_shutdown,
                    )
                    .await;
                });
            }
        }

        // Cursor HOST lane: per-session loopback HTTPS_PROXY endpoint for
        // egress allowlisting + audit only. Cursor's model auth remains
        // Cursor-owned client state; this registry intentionally does not use
        // the credential-injecting projector engine.
        {
            let cursor_egress_db_path = self.config.data_dir.join("daemon.db");
            let cursor_registry_shutdown = shutdown_tx.subscribe();
            let (cursor_cmd_tx, cursor_cmd_rx) = tokio::sync::mpsc::unbounded_channel::<
                crate::infra::cursor_egress_proxy::CursorEgressCommand,
            >();
            if !crate::infra::cursor_egress_proxy::install_cursor_egress_command_sender(
                cursor_cmd_tx,
            ) {
                tracing::warn!(
                    "cursor_egress_proxy: command sender already installed — second daemon incarnation in-process; per-session cursor egress listeners disabled for this run"
                );
            } else {
                local.spawn_local(async move {
                    let store = match crate::infra::store::DaemonStore::open(&cursor_egress_db_path)
                    {
                        Ok(s) => std::rc::Rc::new(s),
                        Err(e) => {
                            tracing::warn!(error = %e, "cursor_egress_proxy: failed to open store; per-session cursor egress listeners disabled");
                            return;
                        }
                    };
                    crate::infra::cursor_egress_proxy::run_cursor_egress_proxy_registry(
                        store,
                        cursor_cmd_rx,
                        cursor_registry_shutdown,
                    )
                    .await;
                });
            }
        }

        {
            let mut grace_zero_shutdown = shutdown_tx.subscribe();
            local.spawn_local(async move {
                let poll_interval = crate::infra::interactive_unlock::grace_window()
                    .min(std::time::Duration::from_secs(30))
                    .max(std::time::Duration::from_secs(1));
                let mut interval = tokio::time::interval(poll_interval);
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            let _ = crate::trust::presence::grace_lock_if_due();
                        }
                        changed = grace_zero_shutdown.changed() => {
                            if changed.is_err() || *grace_zero_shutdown.borrow() {
                                break;
                            }
                        }
                    }
                }
            });
        }

        // KMS edge phase 0: spawn the mTLS edge listener when the edge CA
        // has been provisioned by `kms init-edge`. The CA is stored at
        // `<data_dir>/kms/edge-ca/ca.seed` (32-byte raw Ed25519 seed).
        // When absent, log and degrade gracefully — the loopback path remains
        // fully operational. The listener binds on an OS-assigned port on the
        // tailnet interface; the exact bind address will be configurable once
        // the `kms init-edge` CLI command ships.
        {
            let edge_ca_seed_path = self
                .config
                .data_dir
                .join("kms")
                .join("edge-ca")
                .join("ca.seed");
            if edge_ca_seed_path.exists() {
                match std::fs::read(&edge_ca_seed_path) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut seed = [0u8; 32];
                        seed.copy_from_slice(&bytes);
                        match core_crypto::ca::generate_edge_ca(Some(seed)) {
                            Ok(edge_ca) => {
                                let edge_ca = std::sync::Arc::new(edge_ca);
                                // Bind on 0.0.0.0:0 for now (ephemeral port).
                                // Phase 1 will add a config-driven tailnet bind address.
                                let edge_bind: std::net::SocketAddr =
                                    "0.0.0.0:0".parse().expect("valid addr");
                                tokio::spawn(async move {
                                    match crate::infra::kms_edge::EdgeListener::spawn(
                                        edge_bind, edge_ca,
                                    )
                                    .await
                                    {
                                        Ok(handle) => {
                                            tracing::info!("edge listener spawned");
                                            let _ = handle.await;
                                        }
                                        Err(e) => {
                                            tracing::warn!(error = %e, "edge listener failed to start");
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "edge CA generation failed — edge listener skipped");
                            }
                        }
                    }
                    Ok(_) => {
                        tracing::warn!(
                            path = %edge_ca_seed_path.display(),
                            "edge CA seed file has unexpected length — edge listener skipped (no edge CA)"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            path = %edge_ca_seed_path.display(),
                            "failed to read edge CA seed — edge listener skipped (no edge CA)"
                        );
                    }
                }
            } else {
                tracing::debug!("edge listener skipped (no edge CA)");
            }
        }

        // ADR 155 priv-sep (SLICE 2a) — the in-process `ember_rpc::Listener`
        // collapse is REMOVED. The mTLS+JSON parser no longer runs inside the
        // vault-bearing daemon; it runs in the OS-supervised `emberd-rpc`
        // sibling (an independent launchd/systemd service, NOT a daemon child —
        // ADR 197 sibling-not-child resilience), which terminates mTLS and
        // forwards a typed frame to the daemon's dedicated `0700` rpc-forward
        // UDS (bound below, gated on `bridge_bind`). emberd attests the peer is
        // the real `emberd-rpc` binary (peercred + content-hash) before acting
        // on the frame. This reverses ADR 207 seam 5 + ADR 154 §Status
        // (in-process daemon-owned target) — the SLICE-3 docs lane records the
        // supersession. The sibling's bootstrap (install.rs launchd/systemd
        // load) is a follow-on sub-slice; until then the receiver binds and the
        // lane stays default-disabled.

        // Drive the LocalSet until every startup bind result arrives (or times
        // out). This polls spawned tasks so run_dashboard / run_git_echo_proxy /
        // run_proxy actually execute their TcpListener::bind. All three bind
        // futures share a 2-second deadline — if any races past the deadline
        // the CLI banner shows `Timeout` for that listener but the daemon
        // keeps running.
        let dashboard_attempt = dashboard_bind_info.as_ref().map(|(a, _)| *a);
        let proxy_attempt = git_proxy_bind_info.as_ref().map(|(a, _)| *a);
        let llm_attempt = llm_proxy_bind_info.as_ref().map(|(a, _)| *a);
        let dashboard_rx = dashboard_bind_info.map(|(_, rx)| rx);
        let proxy_rx = git_proxy_bind_info.map(|(_, rx)| rx);
        let llm_rx = llm_proxy_bind_info.map(|(_, rx)| rx);

        let (dashboard_outcome, proxy_outcome, llm_outcome) = local
            .run_until(async {
                let dashboard_fut = async {
                    match dashboard_rx {
                        None => None,
                        Some(rx) => {
                            Some(tokio::time::timeout(std::time::Duration::from_secs(2), rx).await)
                        }
                    }
                };
                let proxy_fut = async {
                    match proxy_rx {
                        None => None,
                        Some(rx) => {
                            Some(tokio::time::timeout(std::time::Duration::from_secs(2), rx).await)
                        }
                    }
                };
                let llm_fut = async {
                    match llm_rx {
                        None => None,
                        Some(rx) => {
                            Some(tokio::time::timeout(std::time::Duration::from_secs(2), rx).await)
                        }
                    }
                };
                tokio::join!(dashboard_fut, proxy_fut, llm_fut)
            })
            .await;

        let dashboard_bind: DashboardBind = match (dashboard_attempt, dashboard_outcome) {
            (None, _) => DashboardBind::Disabled,
            (Some(_), Some(Ok(Ok(Ok(bound))))) => DashboardBind::Bound(bound),
            (Some(addr), Some(Ok(Ok(Err(e))))) => DashboardBind::Failed {
                addr,
                error: e.to_string(),
            },
            (Some(_), Some(Ok(Err(_)))) => {
                tracing::warn!("dashboard bind channel closed before result was sent");
                DashboardBind::Timeout
            }
            (Some(_), Some(Err(_))) => {
                tracing::warn!("dashboard bind timed out after 2s");
                DashboardBind::Timeout
            }
            (Some(_), None) => DashboardBind::Disabled,
        };

        let git_proxy_bind: GitProxyBind = match (proxy_attempt, proxy_outcome) {
            (None, _) => GitProxyBind::Disabled,
            (Some(_), Some(Ok(Ok(Ok(bound))))) => {
                // Side-effects only on the success path: log + publish to env
                // + drop a sidecar file under data_dir so background-mode
                // launchers (qember.sh demo up) can pick the URL up after
                // forking the daemon and exiting the parent.
                //
                // This URL now lives at
                // `EMBER_GIT_PROXY_URL` + `<data_dir>/run/git-proxy.url`. The
                // bare `EMBER_PROXY_URL` and `proxy.url` names are claimed by
                // the LLM proxy below — that is the listener the Anthropic
                // SDK demo + `scripts/demo-smoke-anthropic.sh` post to,
                // and the previous overload caused every Beat 4 call to 400.
                let proxy_url = format!("http://{}", bound);
                info!(proxy_url = %proxy_url, "git proxy listening");
                // SAFETY: the daemon runtime is single-threaded at this point
                // (tokio current-thread + LocalSet; we have not entered the
                // accept loop), so a race-free env mutation is acceptable.
                unsafe {
                    std::env::set_var("EMBER_GIT_PROXY_URL", &proxy_url);
                }
                let url_path = self.config.data_dir.join("git-proxy.url");
                if let Err(e) = std::fs::write(&url_path, &proxy_url) {
                    tracing::warn!(
                        path = %url_path.display(),
                        error = %e,
                        "git proxy: failed to write git-proxy.url sidecar"
                    );
                }
                GitProxyBind::Bound(bound)
            }
            (Some(addr), Some(Ok(Ok(Err(e))))) => GitProxyBind::Failed {
                addr,
                error: e.to_string(),
            },
            (Some(_), Some(Ok(Err(_)))) => {
                tracing::warn!("git proxy bind channel closed before result was sent");
                GitProxyBind::Timeout
            }
            (Some(_), Some(Err(_))) => {
                tracing::warn!("git proxy bind timed out after 2s");
                GitProxyBind::Timeout
            }
            (Some(_), None) => GitProxyBind::Disabled,
        };

        // The LLM proxy claims `EMBER_PROXY_URL` and the
        // `<data_dir>/run/proxy.url` sidecar (matching the contract
        // documented in `scripts/demo-smoke-anthropic.sh` and consumed by
        // `scripts/demo-launch-runner.sh`). Anthropic SDK callers point
        // their `base_url` at this listener; the proxy injects `x-api-key`
        // from the vault per FINDING B in the brief.
        let llm_proxy_bind: LlmProxyBind = match (llm_attempt, llm_outcome) {
            (None, _) => LlmProxyBind::Disabled,
            (Some(_), Some(Ok(Ok(Ok(bound))))) => {
                let llm_url = format!("http://{}", bound);
                info!(url = %llm_url, "llm proxy listening");
                // SAFETY: same single-threaded-startup invariant as the
                // git-proxy block above.
                unsafe {
                    std::env::set_var("EMBER_PROXY_URL", &llm_url);
                }
                let url_path = self.config.data_dir.join("proxy.url");
                if let Err(e) = std::fs::write(&url_path, &llm_url) {
                    tracing::warn!(
                        path = %url_path.display(),
                        error = %e,
                        "llm proxy: failed to write proxy.url sidecar"
                    );
                }
                LlmProxyBind::Bound(bound)
            }
            (Some(addr), Some(Ok(Ok(Err(e))))) => LlmProxyBind::Failed {
                addr,
                error: e.to_string(),
            },
            (Some(_), Some(Ok(Err(_)))) => {
                tracing::warn!("llm proxy bind channel closed before result was sent");
                LlmProxyBind::Timeout
            }
            (Some(_), Some(Err(_))) => {
                tracing::warn!("llm proxy bind timed out after 2s");
                LlmProxyBind::Timeout
            }
            (Some(_), None) => LlmProxyBind::Disabled,
        };

        // Proxy URL via request context: extract the
        // bound proxy URLs from the bind results and wire them into the
        // SocketListener. This makes the URLs available in RequestContext for
        // every inbound RPC without relying on std::env::var across tokio
        // worker threads (Rust 2024 set_var cross-thread visibility hazard).
        // The env::set_var calls above are kept as belt-and-suspenders for
        // other consumers; RequestContext is now the primary path for
        // register_session.
        let resolved_llm_proxy_url: Option<String> = match &llm_proxy_bind {
            LlmProxyBind::Bound(addr) => Some(format!("http://{}", addr)),
            _ => None,
        };
        let resolved_git_proxy_url: Option<String> = match &git_proxy_bind {
            GitProxyBind::Bound(addr) => Some(format!("http://{}", addr)),
            _ => None,
        };
        let listener = listener
            .with_llm_proxy_url(resolved_llm_proxy_url)
            .with_git_proxy_url(resolved_git_proxy_url);

        self.record_dashboard_bind(&dashboard_bind);

        if let Some(notify) = start_notify {
            notify(StartupBinds {
                dashboard: dashboard_bind,
                git_proxy: git_proxy_bind,
                llm_proxy: llm_proxy_bind,
                identity_pubkey: identity_pubkey_hex.clone(),
            });
        }

        // Spawn a SIGHUP handler that reloads policy on signal.
        let policy_file = self.config.policy_file.clone();
        let policy_slot = Rc::clone(&policy);
        local.spawn_local(async move {
            #[cfg(unix)]
            {
                let mut sighup = tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::hangup(),
                )
                .expect("SIGHUP handler");
                loop {
                    sighup.recv().await;
                    match reload_policy_slot_from_file(&policy_slot, &policy_file) {
                        Ok(()) => {
                            tracing::info!(path = %policy_file.display(), "policy reloaded via SIGHUP");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to reload policy");
                        }
                    }
                }
            }
        });

        // ADR 155 priv-sep (SLICE 2a) — the daemon-side receiver for the
        // OS-supervised `ember-rpc` sibling: a dedicated `0700` rpc-forward UDS
        // that attests the peer (SO_PEERCRED uid==ember + emberd-rpc
        // content-hash + Linux TracerPid + PID-reuse recheck) and dispatches the
        // decoded typed frame as `DispatchSource::Bridge`. Gated on the bridge
        // lane being enabled (default-disabled: no `bridge_bind` → no receiver),
        // mirroring the retired in-process listener's gate. MUST be spawn_local —
        // it borrows the `!Send` `Rc<DaemonStore>` (unlike the old in-process
        // mTLS listener, which only forwarded over UDS and never touched the
        // store). The OS-supervised sibling that connects here is bootstrapped in
        // a later sub-slice; until then the socket binds and waits.
        if self.config.bridge_bind.is_some() {
            let rpc_listener = crate::infra::rpc_listener::RpcListener::new(
                daemon_rpc_socket_path(&self.config),
                shutdown_tx.subscribe(),
                Rc::clone(&store),
                Rc::clone(&policy),
                Rc::clone(&rate_limiter),
                listener.events_sender(),
                Some(sessions_dir.clone()),
            );
            local.spawn_local(rpc_listener.accept_loop());
        }

        // Run the socket accept loop and wait for SIGINT/SIGTERM.
        tokio::select! {
            result = local.run_until(listener.accept_loop()) => {
                result?;
            }
            _ = shutdown_signal() => {
                info!("shutdown signal received");
                let _ = shutdown_tx.send(true);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }

        info!("ember daemon stopped");
        Ok(())
    }

    /// Check if a daemon is running. Returns the PID if so.
    pub fn status(&self) -> Result<DaemonStatus, DaemonError> {
        match self.pid_file.read() {
            Ok(Some(pid)) if self.pid_file.is_running() => {
                let socket_path = daemon_socket_path(&self.config);
                Ok(DaemonStatus {
                    pid,
                    socket: socket_path,
                    running: true,
                })
            }
            Ok(Some(pid)) => Ok(DaemonStatus {
                pid,
                socket: daemon_socket_path(&self.config),
                running: false,
            }),
            Ok(None) => Err(DaemonError::NotRunning),
            Err(e) => Err(DaemonError::Pid(e)),
        }
    }

    /// Stop a running daemon by sending SIGTERM.
    pub fn stop(&self) -> Result<u32, DaemonError> {
        match self.pid_file.read() {
            Ok(Some(pid)) if self.pid_file.is_running() => {
                // Send SIGTERM
                let status = std::process::Command::new("kill")
                    .args([&pid.to_string()])
                    .status()
                    .map_err(DaemonError::Signal)?;
                if status.success() {
                    Ok(pid)
                } else {
                    Err(DaemonError::NotRunning)
                }
            }
            _ => Err(DaemonError::NotRunning),
        }
    }
}

pub struct DaemonStatus {
    pub pid: u32,
    pub socket: PathBuf,
    pub running: bool,
}

// ─── Bridge CA load-or-mint (SE-sealed startup bootstrap) ───
//
// On-disk layout under `<data_dir>`:
//
//   bridge_ca.wrap    — Vault-sealed 32-byte module wrapping key. Layout:
//                       `[24-byte XChaCha20 nonce | ciphertext]`. The
//                       wrapping key is minted once on first run and never
//                       rotated by this slice; rotation belongs to the ADR
//                       154 rotation slice.
//   bridge_ca.sealed  — `BridgeCa::seal_with_key` output:
//                       `[24-byte XChaCha20 nonce | ciphertext]` of the
//                       ed25519 signing key, sealed under the module
//                       wrapping key (NOT under the vault key directly —
//                       the indirection through `bridge_ca.wrap` keeps the
//                       vault boundary narrow and avoids exposing
//                       `Vault` internals).
//   bridge_ca.pub     — Raw 32-byte ed25519 verifying-key bytes, mode 0644
//                       on Unix. World-readable so external tooling and
//                       Slices C/D can compute the blake3 fingerprint
//                       without unsealing anything.
//   bridge_ca.pem     — PEM-encoded self-signed root cert, mode 0644 on
//                       Unix. World-readable so rustls clients can build a
//                       standard trust store without custom raw-key parsing.
//
// Why two sealed files instead of `Vault::seal`-ing the signing key
// directly: `BridgeCa` (Slice A) does not expose its private-key bytes by
// design (private-key escape would defeat its `ZeroizeOnDrop`). The
// only public seal/unseal surface takes a 32-byte wrapping key. Passing
// `Vault::vault_key` directly would require a `pub(crate)` accessor on
// `Vault` (CODEOWNERS-protected); minting a separate module key and
// sealing it via `Vault::seal/open` is identical security-wise and keeps
// the change scoped to `infra/runtime.rs`.

const BRIDGE_CA_PUBKEY_LEN: usize = 32;

/// Load the cached Bridge CA fingerprint from the published
/// `<data_dir>/bridge_ca.pub` file without opening the vault.
///
/// Returns:
/// - `Ok(Some(fp))` when the pubkey file exists and is structurally valid.
/// - `Ok(None)` when the pubkey file does not exist yet.
/// - `Err` when the file exists but is unreadable or malformed.
pub fn load_cached_bridge_ca_fingerprint(
    data_dir: &std::path::Path,
) -> Result<Option<[u8; 32]>, std::io::Error> {
    let pub_path = data_dir.join("bridge_ca.pub");
    let bytes = match std::fs::read(&pub_path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if bytes.len() != BRIDGE_CA_PUBKEY_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "bridge_ca.pub has {} bytes; expected {}",
                bytes.len(),
                BRIDGE_CA_PUBKEY_LEN
            ),
        ));
    }
    Ok(Some(*blake3::hash(&bytes).as_bytes()))
}

/// Load the SE-sealed Bridge CA from `<data_dir>` if present, otherwise
/// mint a fresh one. Always (re)writes the public root artifacts so external
/// tooling has the current fingerprint file and rustls clients have a PEM
/// trust root without unsealing anything.
///
/// **Pre:** `vault` is unlocked; `data_dir` exists and is writeable by
/// the daemon's effective uid.
/// **Post:** the returned `Arc<BridgeCa>` is wired into the runtime's
/// `bridge_ca` slot; `bridge_ca.wrap`, `bridge_ca.sealed`, `bridge_ca.pub`,
/// and `bridge_ca.pem` all exist on disk; the published public artifacts are
/// mode 0644 on Unix.
///
/// Factored out of `DaemonRuntime::run` so the integration tests at
/// `crates/ember-daemon/tests/bridge_ca_persistence.rs` can drive it
/// without spinning up the full daemon (PID file, socket binds, broker
/// registration, etc.).
pub fn load_or_mint_bridge_ca(
    data_dir: &std::path::Path,
    vault: &Vault,
) -> Result<Arc<BridgeCa>, BridgeCaLoadError> {
    Ok(Arc::new(BridgeCa::load_or_mint(data_dir, vault)?))
}

// ─── ember-rpc sibling server-cert mint (phase C sibling cert mint) ───
//
// Checkpoint mirror: `ember_rpc_sibling_server_cert_minted_at_startup` (also
// stamped on `crates/ember-daemon/src/trust/bridge_ca.rs`).
//
// On-disk layout under `<data_dir>/ember-rpc/`:
//
//   server.crt — PEM-encoded leaf cert, signed by BridgeCa, 30-day TTL.
//                Mode 0640 owner ember:ember-clients on Unix.
//   server.key — PEM-encoded ed25519 private key (PKCS#8 v1). Same mode +
//                ownership as the cert.
//
// The directory is created with mode 0750 owner ember:ember-clients so the
// sibling process (running as `ember`) can list it but no other operator
// can.

/// 30-day TTL for the ember-rpc sibling server cert.
///
/// Operator-friendly cadence: cert rotation shows up in logs at most once
/// per month under steady-state operation. Daemon restart (macOS update,
/// ember upgrade, MEK rotation) re-evaluates `not_after - now`; if
/// `<EMBER_RPC_CERT_ROTATION_SLACK`, mint fresh on next boot. Restarts
/// outside that slack window reuse the on-disk cert.
const EMBER_RPC_CERT_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 24 * 3600);

/// Rotation window: when `not_after - now < EMBER_RPC_CERT_ROTATION_SLACK`,
/// mint a fresh cert on the next daemon startup. 24h is large enough to
/// absorb typical clock skew + give operator-controlled restarts (cron'd
/// daily restart, etc.) the chance to land the rotation without forcing
/// it on every boot.
const EMBER_RPC_CERT_ROTATION_SLACK: std::time::Duration =
    std::time::Duration::from_secs(24 * 3600);

/// Mint or rotate the ember-rpc sibling's TLS server cert.
///
/// **Pre:** `data_dir` exists and is writeable by the daemon's effective
/// uid. `bridge_ca` is the in-memory `BridgeCa` from the same startup
/// path.
///
/// **Post:** `<data_dir>/ember-rpc/server.crt` and
/// `<data_dir>/ember-rpc/server.key` exist with mode 0640 owner
/// `ember:ember-clients` (best-effort chown — see ownership notes below).
/// The cert is signed by `bridge_ca` and has SAN entries covering
/// `host.docker.internal` + the resolved bind IP/hostname pair.
///
/// **Rotation:** if either file is missing, or the cert's `not_after`
/// minus the current wall-clock is less than `EMBER_RPC_CERT_ROTATION_SLACK`,
/// mint fresh. Otherwise reuse on-disk.
///
/// **Ownership notes:** chown to `ember:ember-clients` is best-effort.
/// When the daemon runs as root (typical launchd / systemd posture), the
/// chown succeeds. When the daemon runs as a non-privileged uid (dev
/// loops, tests), the chown is logged at WARN and skipped — the file
/// owner remains the daemon's effective uid, which is typically already
/// the correct sibling-readable uid in dev. The mode (0640) is always
/// applied; group-readability is the load-bearing invariant for the
/// sibling to read the key.
pub fn mint_or_rotate_ember_rpc_server_cert(
    data_dir: &std::path::Path,
    bridge_bind: Option<SocketAddr>,
    bridge_ca: &BridgeCa,
) -> Result<(), EmberRpcCertError> {
    let rpc_dir = data_dir.join("ember-rpc");
    let cert_path = rpc_dir.join("server.crt");
    let key_path = rpc_dir.join("server.key");

    std::fs::create_dir_all(&rpc_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 0750: ember (owner) + ember-clients (group) can list; world cannot.
        let _ = std::fs::set_permissions(&rpc_dir, std::fs::Permissions::from_mode(0o750));
    }

    // Decide: reuse on-disk, or mint fresh?
    let needs_mint = if cert_path.exists() && key_path.exists() {
        match read_cert_not_after(&cert_path) {
            Ok(not_after) => {
                let now = std::time::SystemTime::now();
                let within_rotation_slack = match not_after.duration_since(now) {
                    Ok(remaining) => remaining < EMBER_RPC_CERT_ROTATION_SLACK,
                    // not_after is in the past — already expired.
                    Err(_) => true,
                };
                if within_rotation_slack {
                    tracing::info!(
                        cert_path = %cert_path.display(),
                        "ember-rpc sibling server cert is within rotation slack — minting fresh"
                    );
                    true
                } else {
                    match server_cert_signed_by_bridge_ca(&cert_path, bridge_ca) {
                        Ok(true) => false,
                        Ok(false) => {
                            tracing::info!(
                                cert_path = %cert_path.display(),
                                "ember-rpc sibling server cert was not signed by the current Bridge CA — minting fresh"
                            );
                            true
                        }
                        Err(e) => {
                            tracing::warn!(
                                cert_path = %cert_path.display(),
                                error = %e,
                                "ember-rpc sibling server cert signature could not be verified — minting fresh"
                            );
                            true
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    cert_path = %cert_path.display(),
                    error = %e,
                    "ember-rpc sibling server cert unreadable — minting fresh"
                );
                true
            }
        }
    } else {
        true
    };

    if !needs_mint {
        tracing::info!(
            cert_path = %cert_path.display(),
            "ember-rpc sibling server cert reused (TTL > 24h rotation slack)"
        );
        return Ok(());
    }

    // Build SAN list. host.docker.internal covers macOS Docker Desktop +
    // Linux Docker installs configured with the `--add-host` flag; the
    // bridge_bind IP covers everything else.
    let sans = build_server_sans(bridge_bind);

    let (cert_pem, key_pem) = bridge_ca
        .sign_server_cert("ember-rpc", &sans, EMBER_RPC_CERT_TTL)
        .map_err(EmberRpcCertError::Sign)?;

    // Write cert. Mode 0640 owner ember:ember-clients (chown is
    // best-effort — see fn doc).
    write_with_mode_and_group(&cert_path, cert_pem.as_bytes(), 0o640)?;
    write_with_mode_and_group(&key_path, key_pem.as_bytes(), 0o640)?;

    tracing::info!(
        cert_path = %cert_path.display(),
        key_path = %key_path.display(),
        ttl_days = EMBER_RPC_CERT_TTL.as_secs() / 86400,
        san_count = sans.len(),
        "ember-rpc sibling server cert minted"
    );
    Ok(())
}

// ADR 155 priv-sep (SLICE 2a) — `bridge_listener_config` is DELETED along with
// the in-process listener collapse it fed. The OS-supervised `emberd-rpc`
// sibling reads its own `EMBER_RPC_*` config from its launchd/systemd unit (its
// mTLS listen addr, the server cert/key minted by
// `mint_or_rotate_ember_rpc_server_cert`, and the `EMBER_RPC_FORWARD_UDS`
// pinned to the daemon's `0700` `daemon_rpc_socket_path`); the daemon no longer
// derives an in-process `ember_rpc::ListenerConfig`.

/// Errors from [`mint_or_rotate_ember_rpc_server_cert`].
#[derive(Debug, thiserror::Error)]
pub enum EmberRpcCertError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sign: {0}")]
    Sign(crate::trust::bridge_ca::BridgeCaError),
}

/// Read a PEM cert from `path` and return its `not_after`.
///
/// Returns `Err` on PEM/DER parse failure or unreadable wall-clock
/// conversion. Callers treat any error as "rotate fresh" — the cert is
/// useless if we cannot read its expiry.
fn read_cert_not_after(path: &std::path::Path) -> Result<std::time::SystemTime, std::io::Error> {
    use x509_parser::prelude::FromDer;
    let pem_bytes = std::fs::read(path)?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("pem: {e}")))?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&pem.contents)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("der: {e}")))?;
    let not_after_secs = cert.validity().not_after.timestamp();
    if not_after_secs < 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not_after is before unix epoch",
        ));
    }
    let dur = std::time::Duration::from_secs(not_after_secs as u64);
    Ok(std::time::UNIX_EPOCH + dur)
}

/// Return whether `path` is signed by the currently loaded Bridge CA.
///
/// The sibling cert can outlive a Bridge CA rotation. TTL-only reuse would
/// preserve a still-unexpired cert whose issuer CN matches but whose Ed25519
/// signature no longer verifies under the daemon's current trust root, causing
/// isolated mTLS clients to fail with `BadSignature`.
fn server_cert_signed_by_bridge_ca(
    path: &std::path::Path,
    bridge_ca: &BridgeCa,
) -> Result<bool, std::io::Error> {
    use ed25519_dalek::Verifier as _;
    use x509_parser::prelude::FromDer;

    let pem_bytes = std::fs::read(path)?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("pem: {e}")))?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&pem.contents)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("der: {e}")))?;
    let signature =
        ed25519_dalek::Signature::try_from(cert.signature_value.as_ref()).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("signature: {e}"))
        })?;

    Ok(bridge_ca
        .verifying_key()
        .verify(cert.tbs_certificate.as_ref(), &signature)
        .is_ok())
}

/// Build the SAN list for the ember-rpc sibling cert from
/// `EMBER_BRIDGE_BIND`-derived addresses.
///
/// Always includes:
/// - `host.docker.internal` (macOS Docker Desktop + Linux with
///   `--add-host`)
/// - `localhost` (host-side clients on the loopback)
///
/// Conditionally includes the bridge IP when `bridge_bind` is set and
/// the IP is non-zero (Linux 0.0.0.0 default would be useless as a SAN).
fn build_server_sans(bridge_bind: Option<SocketAddr>) -> Vec<crate::trust::bridge_ca::ServerSan> {
    use crate::trust::bridge_ca::ServerSan;
    use std::net::IpAddr;

    let mut sans = vec![
        ServerSan::Dns("host.docker.internal".to_string()),
        ServerSan::Dns("localhost".to_string()),
        // Loopback IP literal for clients that connect to 127.0.0.1
        // directly rather than via "localhost".
        ServerSan::Ip("127.0.0.1".parse().expect("static IP parse")),
    ];

    if let Some(addr) = bridge_bind {
        let ip = addr.ip();
        let is_unspecified = match ip {
            IpAddr::V4(v4) => v4.is_unspecified(),
            IpAddr::V6(v6) => v6.is_unspecified(),
        };
        // 0.0.0.0 / :: are not useful as SAN entries — they mean "bind to
        // all interfaces", not "this is my hostname". Skip them.
        if !is_unspecified
            && !sans
                .iter()
                .any(|s| matches!(s, ServerSan::Ip(existing) if *existing == ip))
        {
            sans.push(ServerSan::Ip(ip));
        }
    }

    sans
}

/// Write `bytes` to `path` with mode `0640` and best-effort chown to
/// `ember:ember-clients`. The mode is always applied; chown is logged at
/// WARN and skipped when it fails (typical: daemon running as a
/// non-privileged uid in dev).
fn write_with_mode_and_group(
    path: &std::path::Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), std::io::Error> {
    // Remove first so a pre-existing 0400 file (from a previous run with
    // a more restrictive mode) doesn't fail the write.
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    std::fs::write(path, bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;

        // Best-effort chown via `chown` subprocess. Direct nix::unistd::
        // chown would require resolving ember + ember-clients to numeric
        // uid/gid — the subprocess form is what `install.rs` uses elsewhere
        // for the same pattern (see install.rs::install_pem_to_etc) and
        // keeps the error surface consistent.
        if let Err(e) = chown_ember_clients(path) {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "chown ember:ember-clients failed — file owner remains daemon's effective uid \
                 (mode 0640 still applied; sibling can read iff it's in ember-clients)"
            );
        }
    }
    Ok(())
}

/// Best-effort `chown ember:ember-clients <path>`. Returns Err on
/// subprocess failure; caller logs and continues.
#[cfg(unix)]
pub(crate) fn chown_ember_clients(path: &std::path::Path) -> Result<(), std::io::Error> {
    let path_str = path
        .to_str()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "non-utf8 path"))?;
    let output = std::process::Command::new("chown")
        .args(["ember:ember-clients", path_str])
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "chown exited {:?}; stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

#[cfg(test)]
mod ember_rpc_cert_tests {
    //! T2: runtime certificate minting tests use temporary data directories.
    //! Unit tests for the ember-rpc sibling server-cert mint path. The
    //! `BridgeCa::sign_server_cert` primitive is exercised in
    //! `crates/ember-daemon/src/trust/bridge_ca.rs::tests` — these tests
    //! cover the runtime wiring (file paths, mode, rotation decision).
    use super::*;
    use crate::trust::bridge_ca::BridgeCa;
    use tempfile::TempDir;

    /// Pre: empty data_dir, no bridge_bind, fresh BridgeCa.
    /// Post: ember-rpc/server.crt + server.key exist, mode 0640.
    #[test]
    fn mint_writes_pair_with_correct_mode() {
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path();
        let ca = BridgeCa::mint();

        mint_or_rotate_ember_rpc_server_cert(data_dir, None, &ca).expect("mint succeeds");

        let cert = data_dir.join("ember-rpc").join("server.crt");
        let key = data_dir.join("ember-rpc").join("server.key");
        assert!(cert.exists(), "server.crt exists");
        assert!(key.exists(), "server.key exists");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let cert_mode = std::fs::metadata(&cert)
                .expect("stat cert")
                .permissions()
                .mode()
                & 0o777;
            let key_mode = std::fs::metadata(&key)
                .expect("stat key")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(cert_mode, 0o640, "server.crt mode 0640");
            assert_eq!(key_mode, 0o640, "server.key mode 0640");
        }
    }

    /// Pre: cert minted moments ago (TTL=30d, slack=24h, so not within slack).
    /// Post: second mint call is a no-op — cert+key file mtimes don't change.
    #[test]
    fn second_mint_is_noop_when_outside_rotation_slack() {
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path();
        let ca = BridgeCa::mint();

        mint_or_rotate_ember_rpc_server_cert(data_dir, None, &ca).expect("first mint");
        let cert = data_dir.join("ember-rpc").join("server.crt");
        let first_contents = std::fs::read(&cert).expect("read cert");

        mint_or_rotate_ember_rpc_server_cert(data_dir, None, &ca).expect("second mint");
        let second_contents = std::fs::read(&cert).expect("read cert");

        assert_eq!(
            first_contents, second_contents,
            "second mint within the 30d TTL must reuse on-disk cert (no rotation)"
        );
    }

    /// Pre: cert minted moments ago under one BridgeCa, then daemon reloads a
    /// different BridgeCa while the old cert still has >24h TTL.
    /// Post: second call rotates because TTL-only reuse would break mTLS with
    /// a server cert signed by the old trust root.
    #[test]
    fn second_mint_rotates_when_bridge_ca_changed_even_outside_rotation_slack() {
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path();
        let old_ca = BridgeCa::mint();
        let current_ca = BridgeCa::mint();

        mint_or_rotate_ember_rpc_server_cert(data_dir, None, &old_ca).expect("first mint");
        let cert = data_dir.join("ember-rpc").join("server.crt");
        let first_contents = std::fs::read(&cert).expect("read cert");
        assert!(
            !server_cert_signed_by_bridge_ca(&cert, &current_ca)
                .expect("old cert parses for current CA check"),
            "old cert must not verify under unrelated current CA"
        );

        mint_or_rotate_ember_rpc_server_cert(data_dir, None, &current_ca).expect("second mint");
        let second_contents = std::fs::read(&cert).expect("read cert");

        assert_ne!(
            first_contents, second_contents,
            "cert must rotate when the Bridge CA changes despite healthy TTL"
        );
        assert!(
            server_cert_signed_by_bridge_ca(&cert, &current_ca)
                .expect("new cert parses for current CA check"),
            "rotated cert must verify under current CA"
        );
    }

    /// Pre: data_dir with a bridge_bind set to a specific IP.
    /// Post: minted cert's SAN list includes that IP.
    #[test]
    fn mint_includes_bridge_bind_ip_in_san() {
        use x509_parser::prelude::*;
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path();
        let ca = BridgeCa::mint();
        let bind: SocketAddr = "192.168.65.2:8443".parse().unwrap();

        mint_or_rotate_ember_rpc_server_cert(data_dir, Some(bind), &ca).expect("mint succeeds");

        let cert_pem = std::fs::read(data_dir.join("ember-rpc").join("server.crt")).expect("read");
        let (_, pem) = parse_x509_pem(&cert_pem).expect("pem");
        let (_, parsed) = X509Certificate::from_der(&pem.contents).expect("der");
        let san = parsed
            .subject_alternative_name()
            .expect("san parses")
            .expect("san present");
        let joined: String = san
            .value
            .general_names
            .iter()
            .map(|gn| format!("{:?}", gn))
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            joined.contains("[192, 168, 65, 2]"),
            "bridge_bind IP in SAN list (rendered as [192, 168, 65, 2]); got {joined}"
        );
    }

    /// Pre: bridge_bind set to 0.0.0.0 (the Linux default).
    /// Post: minted cert's SAN list does NOT include 0.0.0.0 (it's
    /// unspecified — useless as a hostname assertion). Should still have
    /// the canonical 3 entries.
    #[test]
    fn mint_skips_unspecified_bind_addr() {
        use x509_parser::prelude::*;
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path();
        let ca = BridgeCa::mint();
        let bind: SocketAddr = "0.0.0.0:8443".parse().unwrap();

        mint_or_rotate_ember_rpc_server_cert(data_dir, Some(bind), &ca).expect("mint succeeds");

        let cert_pem = std::fs::read(data_dir.join("ember-rpc").join("server.crt")).expect("read");
        let (_, pem) = parse_x509_pem(&cert_pem).expect("pem");
        let (_, parsed) = X509Certificate::from_der(&pem.contents).expect("der");
        let san = parsed
            .subject_alternative_name()
            .expect("san parses")
            .expect("san present");
        let joined: String = san
            .value
            .general_names
            .iter()
            .map(|gn| format!("{:?}", gn))
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            !joined.contains("[0, 0, 0, 0]"),
            "0.0.0.0 must NOT appear in SAN list; got {joined}"
        );
        // But the canonical DNS entries are still present.
        assert!(joined.contains("host.docker.internal"));
        assert!(joined.contains("localhost"));
    }

    /// ADR 155 priv-sep — the in-process `bridge_listener_config` is deleted,
    /// but the cert-mint writers the OS-supervised `emberd-rpc` sibling reads
    /// STAY. Pin the path contract: `load_or_mint_bridge_ca` +
    /// `mint_or_rotate_ember_rpc_server_cert` write `bridge_ca.pem` +
    /// `ember-rpc/{server.crt,server.key}` under `<data_dir>` — exactly the
    /// paths the sibling unit pins via `EMBER_RPC_{CA_CERT,SERVER_CERT,SERVER_KEY}`.
    #[test]
    fn ember_rpc_cert_mint_writes_expected_paths() {
        let tmp = TempDir::new().expect("tempdir");
        let mut config = DaemonConfig::for_test(tmp.path());
        let bind: SocketAddr = "127.0.0.1:4243".parse().expect("addr");
        config.bridge_bind = Some(bind);

        let vault = Vault::new([0x42u8; 32]);
        let ca = load_or_mint_bridge_ca(config.data_dir.as_path(), &vault)
            .expect("bridge CA mint writes bridge_ca.pem");
        mint_or_rotate_ember_rpc_server_cert(config.data_dir.as_path(), Some(bind), &ca)
            .expect("server cert mint");

        let rpc_dir = config.data_dir.join("ember-rpc");
        assert!(
            rpc_dir.join("server.crt").exists(),
            "server.crt under <data_dir>/ember-rpc/"
        );
        assert!(
            rpc_dir.join("server.key").exists(),
            "server.key under <data_dir>/ember-rpc/"
        );
        assert!(
            config.data_dir.join("bridge_ca.pem").exists(),
            "bridge_ca.pem under <data_dir>/"
        );
    }
}

#[cfg(test)]
mod bridge_ca_tests {
    //! T2: bridge CA persistence helper tests use temporary data directories.
    //! Unit tests for [`load_or_mint_bridge_ca`]. Lives alongside the
    //! helper so it compiles whenever the helper does; the T2 integration
    //! test at `tests/bridge_ca_persistence.rs` covers the persistence
    //! contract from a black-box angle.

    use super::*;
    use tempfile::TempDir;

    /// Stable deterministic vault key for unit tests. Matches the pattern
    /// used in `tests/budget_persistence.rs`.
    const TEST_VAULT_KEY: [u8; 32] = [0x42u8; 32];

    /// Pre: empty data_dir. Post: bridge_ca.wrap + bridge_ca.sealed +
    /// bridge_ca.pub + bridge_ca.pem all exist; pub file is 32 bytes;
    /// PEM root parses; helper returns `Arc<BridgeCa>` whose fingerprint
    /// matches blake3(pub bytes).
    #[test]
    fn first_run_mints_and_persists() {
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path();
        let vault = Vault::new(TEST_VAULT_KEY);

        let ca = load_or_mint_bridge_ca(data_dir, &vault).expect("first-run load_or_mint");

        assert!(data_dir.join("bridge_ca.wrap").exists(), "wrap blob");
        assert!(data_dir.join("bridge_ca.sealed").exists(), "sealed blob");
        assert!(data_dir.join("bridge_ca.pub").exists(), "pub bytes");
        assert!(data_dir.join("bridge_ca.pem").exists(), "PEM root");

        let pub_bytes = std::fs::read(data_dir.join("bridge_ca.pub")).expect("read pub");
        assert_eq!(pub_bytes.len(), 32, "ed25519 pub must be 32 bytes");
        let pem_bytes = std::fs::read(data_dir.join("bridge_ca.pem")).expect("read pem");
        let mut cursor = std::io::Cursor::new(pem_bytes);
        let certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<_, _>>()
            .expect("published PEM root parses");
        assert_eq!(certs.len(), 1, "exactly one CA cert published");

        let computed_fp = *blake3::hash(&pub_bytes).as_bytes();
        assert_eq!(
            ca.fingerprint(),
            computed_fp,
            "fingerprint matches blake3(pub bytes)"
        );
    }

    /// Pre: helper called twice with same data_dir + same vault.
    /// Post: second call returns the SAME fingerprint as the first
    /// (sealed blob round-trips). This is the load-bearing acceptance
    /// for "restart must NOT wipe outstanding per-agent client certs"
    /// (bridge_ca.rs module docstring).
    #[test]
    fn restart_preserves_fingerprint() {
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path();
        let vault = Vault::new(TEST_VAULT_KEY);

        let ca1 = load_or_mint_bridge_ca(data_dir, &vault).expect("first-run");
        let fp1 = ca1.fingerprint();
        // Drop the first instance so we're testing genuine load-from-disk,
        // not in-memory cache.
        drop(ca1);

        let ca2 = load_or_mint_bridge_ca(data_dir, &vault).expect("restart");
        assert_eq!(ca2.fingerprint(), fp1, "fingerprint stable across restart");
    }

    /// Pre: helper called once with vault A, then again with vault B
    /// (different key). Post: the second call fails — the wrapping key
    /// was sealed under vault A and can't be opened by vault B. This
    /// pins the "vault MEK rotation requires CA migration" invariant:
    /// the daemon refuses to silently re-mint and orphan the on-disk
    /// blob.
    #[test]
    fn vault_key_change_fails_unseal() {
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path();
        let vault_a = Vault::new(TEST_VAULT_KEY);
        let vault_b = Vault::new([0x99u8; 32]);

        let _ca1 = load_or_mint_bridge_ca(data_dir, &vault_a).expect("first-run with vault A");
        let result = load_or_mint_bridge_ca(data_dir, &vault_b);
        assert!(
            matches!(result, Err(BridgeCaLoadError::Vault(_))),
            "expected vault unseal error, got: {result:?}"
        );
    }

    /// Pre: bridge_ca.wrap exists but is truncated below the nonce length.
    /// Post: helper returns `MalformedBlob` rather than silently re-minting.
    #[test]
    fn truncated_wrap_blob_rejected() {
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path();
        let vault = Vault::new(TEST_VAULT_KEY);

        std::fs::write(data_dir.join("bridge_ca.wrap"), b"short").expect("write truncated");
        let result = load_or_mint_bridge_ca(data_dir, &vault);
        assert!(
            matches!(result, Err(BridgeCaLoadError::MalformedBlob { len: 5, .. })),
            "expected MalformedBlob with len=5, got: {result:?}"
        );
    }

    /// Pre: bridge_ca.{pub,pem} exist from a prior run. Post: helper still
    /// (re)writes both on the next call — the public artifacts are always
    /// freshly published, mode 0644 on Unix.
    #[test]
    #[cfg(unix)]
    fn published_bridge_ca_artifacts_are_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path();
        let vault = Vault::new(TEST_VAULT_KEY);

        let _ca = load_or_mint_bridge_ca(data_dir, &vault).expect("first-run");
        let pub_perms = std::fs::metadata(data_dir.join("bridge_ca.pub"))
            .expect("stat pub")
            .permissions();
        let pem_perms = std::fs::metadata(data_dir.join("bridge_ca.pem"))
            .expect("stat pem")
            .permissions();
        // Mask to the low 9 bits — file-type and setuid bits aren't
        // load-bearing for the "world-readable" assertion.
        assert_eq!(pub_perms.mode() & 0o777, 0o644, "pub bytes must be 0644");
        assert_eq!(pem_perms.mode() & 0o777, 0o644, "PEM root must be 0644");
    }

    #[test]
    fn cached_bridge_ca_fingerprint_loads_without_vault() {
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path();
        let vault = Vault::new(TEST_VAULT_KEY);

        let ca = load_or_mint_bridge_ca(data_dir, &vault).expect("first-run");
        let cached =
            load_cached_bridge_ca_fingerprint(data_dir).expect("cached fingerprint should load");
        assert_eq!(cached, Some(ca.fingerprint()));
    }

    #[test]
    fn cached_bridge_ca_fingerprint_rejects_malformed_pubkey() {
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path();
        std::fs::write(data_dir.join("bridge_ca.pub"), b"short").expect("write malformed pubkey");

        let err = load_cached_bridge_ca_fingerprint(data_dir).expect_err("malformed pubkey");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}

#[cfg(test)]
mod tests {
    //! T2: runtime startup unit tests use temporary dirs and loopback sockets.

    use super::{
        OptionalBrokerStartupAction, SandboxProbeFailure, SandboxState, check_sandbox_at_startup,
        daemon_socket_path_with, optional_broker_startup_action, probe_sandbox_state,
        reload_policy_slot_from_file, resolve_startup_binary_manifest_path,
        should_bootstrap_vault_at_startup, start_local_startup_component_on_local,
        startup_binary_manifest_candidates, supervise_local_proxy,
    };
    use super::{parse_transitional_tcp_flag, should_bind_llm_proxy};
    use crate::broker::authority::BrokerAuthorityError;
    use crate::infra::config::DaemonConfig;
    use crate::infra::socket::{new_shared_policy_engine, snapshot_policy_engine};
    use crate::trust::policy::{ApprovalRequirement, PolicyEngine};
    use std::io::Write as _;
    use std::path::PathBuf;

    // P22-S2 PR-E: the transitional TCP LLM proxy is OFF unless explicitly
    // opted in; fail-closed on absent / unrecognized values.
    #[test]
    fn transitional_tcp_flag_defaults_off_and_opts_in_explicitly() {
        assert!(!parse_transitional_tcp_flag(None));
        assert!(!parse_transitional_tcp_flag(Some("")));
        assert!(!parse_transitional_tcp_flag(Some("0")));
        assert!(!parse_transitional_tcp_flag(Some("no")));
        assert!(!parse_transitional_tcp_flag(Some("off")));
        assert!(parse_transitional_tcp_flag(Some("1")));
        assert!(parse_transitional_tcp_flag(Some("true")));
        assert!(parse_transitional_tcp_flag(Some("  TRUE  ")));
    }

    #[test]
    fn llm_proxy_binds_for_container_bridge_or_explicit_legacy_opt_in() {
        assert!(!should_bind_llm_proxy(None, false));
        assert!(!should_bind_llm_proxy(Some("0"), false));
        assert!(should_bind_llm_proxy(Some("1"), false));
        assert!(
            should_bind_llm_proxy(None, true),
            "ADR 207 container bridge requires the TCP Anthropic data-plane proxy"
        );
        assert!(should_bind_llm_proxy(Some("0"), true));
    }

    #[test]
    fn startup_binary_manifest_candidates_try_explicit_then_bundled() {
        let explicit = PathBuf::from("/tmp/dev/manifest.toml");
        let candidates = startup_binary_manifest_candidates(Some(explicit.clone()));
        let bundled = crate::binary_manifest::bundled_install_dir().join("manifest.toml");

        assert_eq!(
            candidates.first().map(PathBuf::as_path),
            Some(explicit.as_path())
        );
        assert_eq!(
            candidates.get(1).map(PathBuf::as_path),
            Some(bundled.as_path())
        );
        assert_eq!(
            candidates.len(),
            2,
            "startup selection must not include operator-home manifest fallback"
        );
    }

    #[test]
    fn startup_binary_manifest_candidates_default_to_bundled_only() {
        let candidates = startup_binary_manifest_candidates(None);
        let bundled = crate::binary_manifest::bundled_install_dir().join("manifest.toml");

        assert_eq!(
            candidates.first().map(PathBuf::as_path),
            Some(bundled.as_path())
        );
        assert_eq!(
            candidates.len(),
            1,
            "startup selection must not include operator-home manifest fallback"
        );
    }

    #[test]
    fn startup_binary_manifest_path_uses_explicit_manifest_first() {
        let explicit = PathBuf::from("/tmp/dev/manifest.toml");
        let bundled = crate::binary_manifest::bundled_install_dir().join("manifest.toml");
        let selected = resolve_startup_binary_manifest_path(Some(explicit.clone()), |path| {
            path == explicit || path == bundled
        });

        assert_eq!(selected, Some(explicit));
    }

    #[test]
    fn startup_binary_manifest_path_ignores_legacy_home_manifest() {
        let legacy = PathBuf::from("/var/empty/.ember/binaries/manifest.toml");
        let bundled = crate::binary_manifest::bundled_install_dir().join("manifest.toml");
        let selected =
            resolve_startup_binary_manifest_path(None, |path| path == bundled || path == legacy);

        assert_eq!(selected, Some(bundled));
    }

    #[test]
    fn startup_binary_manifest_path_does_not_fall_back_to_legacy_home() {
        let legacy = PathBuf::from("/var/empty/.ember/binaries/manifest.toml");
        let selected = resolve_startup_binary_manifest_path(None, |path| path == legacy);

        assert_eq!(selected, None);
    }

    #[test]
    fn startup_binary_manifest_path_uses_bundled_without_home() {
        let bundled = crate::binary_manifest::bundled_install_dir().join("manifest.toml");
        let selected = resolve_startup_binary_manifest_path(None, |path| path == bundled);

        assert_eq!(selected, Some(bundled));
    }

    #[test]
    fn startup_binary_manifest_candidates_skip_empty_explicit_manifest() {
        let candidates = startup_binary_manifest_candidates(Some(PathBuf::new()));
        let bundled = crate::binary_manifest::bundled_install_dir().join("manifest.toml");

        assert_eq!(
            candidates.first().map(PathBuf::as_path),
            Some(bundled.as_path())
        );
    }

    #[test]
    fn reload_policy_slot_swaps_live_policy_and_preserves_previous_on_error() {
        let tmp = TempDir::new().unwrap();
        let policy_file = tmp.path().join("policy.toml");
        let policy_slot = new_shared_policy_engine(PolicyEngine::default());

        assert_eq!(
            snapshot_policy_engine(&policy_slot)
                .evaluate("credential.access")
                .requirement,
            ApprovalRequirement::Required
        );

        std::fs::write(
            &policy_file,
            r#"
default_requirement = "denied"
default_risk = "critical"

[[rules]]
action = "credential.access"
risk = "low"
requirement = "auto"
"#,
        )
        .unwrap();

        reload_policy_slot_from_file(&policy_slot, &policy_file).unwrap();
        assert_eq!(
            snapshot_policy_engine(&policy_slot)
                .evaluate("credential.access")
                .requirement,
            ApprovalRequirement::Auto
        );

        std::fs::write(&policy_file, "not valid = [").unwrap();
        assert!(reload_policy_slot_from_file(&policy_slot, &policy_file).is_err());
        assert_eq!(
            snapshot_policy_engine(&policy_slot)
                .evaluate("credential.access")
                .requirement,
            ApprovalRequirement::Auto
        );
    }
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tempfile::TempDir;

    #[test]
    fn daemon_socket_path_defaults_to_config_socket_dir() {
        let tmp = TempDir::new().unwrap();
        let config = DaemonConfig::for_test(tmp.path());
        let resolved = daemon_socket_path_with(&config, None);

        assert_eq!(resolved, tmp.path().join("daemon.sock"));
    }

    #[test]
    fn daemon_socket_path_uses_env_override_when_present() {
        let tmp = TempDir::new().unwrap();
        let config = DaemonConfig::for_test(tmp.path());
        let resolved = daemon_socket_path_with(
            &config,
            Some(std::ffi::OsString::from("/tmp/daemon.dev.sock")),
        );

        assert_eq!(resolved, std::path::PathBuf::from("/tmp/daemon.dev.sock"));
    }

    #[test]
    fn startup_bootstrap_runs_for_bridge_or_env_bootstrap_lane() {
        let bridge_bind = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3141));

        assert!(should_bootstrap_vault_at_startup(bridge_bind));
        assert!(!should_bootstrap_vault_at_startup(None));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_startup_component_can_spawn_local_tasks() {
        let local = tokio::task::LocalSet::new();
        let started = start_local_startup_component_on_local(
            &local,
            "test local startup component",
            || async {
                let handle = tokio::task::spawn_local(async { 7usize });
                Ok(handle.await.expect("spawned local task must complete"))
            },
        )
        .await;

        assert_eq!(started, Some(7));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn proxy_supervisor_restarts_ephemeral_bind_on_last_bound_port() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
                let (startup_bind_tx, startup_bind_rx) = tokio::sync::oneshot::channel();
                let (restart_seen_tx, restart_seen_rx) = tokio::sync::oneshot::channel();
                let attempts = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
                let restart_seen_tx =
                    std::rc::Rc::new(std::cell::RefCell::new(Some(restart_seen_tx)));
                let attempts_for_task = attempts.clone();
                let restart_seen_for_task = restart_seen_tx.clone();

                tokio::task::spawn_local(supervise_local_proxy(
                    "test proxy",
                    "127.0.0.1:0".parse().expect("valid addr"),
                    shutdown_rx,
                    startup_bind_tx,
                    move |bind_addr, mut shutdown, bind_tx| {
                        let attempts = attempts_for_task.clone();
                        let restart_seen_tx = restart_seen_for_task.clone();
                        async move {
                            attempts.borrow_mut().push(bind_addr);
                            let attempt_no = attempts.borrow().len();
                            if attempt_no == 1 {
                                let bound: SocketAddr =
                                    "127.0.0.1:43123".parse().expect("valid bound addr");
                                let _ = bind_tx.send(Ok(bound));
                                Ok(())
                            } else {
                                let _ = bind_tx.send(Ok(bind_addr));
                                if let Some(tx) = restart_seen_tx.borrow_mut().take() {
                                    let _ = tx.send(bind_addr);
                                }
                                let _ = shutdown.changed().await;
                                Ok(())
                            }
                        }
                    },
                ));

                let first_bound = startup_bind_rx
                    .await
                    .expect("startup bind result")
                    .expect("bind success");
                let restarted_bound = restart_seen_rx.await.expect("restart bind seen");

                assert_eq!(first_bound, restarted_bound);
                assert_eq!(
                    attempts.borrow().as_slice(),
                    &["127.0.0.1:0".parse().expect("parse ephemeral"), first_bound,]
                );

                shutdown_tx.send(true).expect("signal shutdown");
            })
            .await;
    }

    /// Verifies that the rolling file appender creates `daemon.log.*` in the
    /// data directory and accepts writes. The global tracing subscriber is NOT
    /// initialised here — we write directly via the `Write` impl so this test
    /// can run alongside other tests without conflicting with the global state.
    #[test]
    fn rolling_appender_creates_log_file_in_data_dir() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();

        let mut appender = tracing_appender::rolling::daily(data_dir, "daemon.log");
        writeln!(
            appender,
            r#"{{"message":"daemon-log-test-probe","level":"INFO"}}"#
        )
        .unwrap();
        // Flush the internal buffer so the write reaches the OS before we read.
        appender.flush().unwrap();

        // tracing-appender rolling daily names files `<prefix>.<YYYY-MM-DD>`.
        let log_entry = std::fs::read_dir(data_dir)
            .unwrap()
            .flatten()
            .find(|e| e.file_name().to_string_lossy().starts_with("daemon.log"))
            .expect("daemon.log.* should exist after write");

        let contents = std::fs::read_to_string(log_entry.path()).unwrap();
        assert!(
            contents.contains("daemon-log-test-probe"),
            "expected probe string in log file, got: {contents:?}"
        );
    }

    #[test]
    fn optional_broker_startup_registers_real_when_configured() {
        let configured = Ok(true);
        assert_eq!(
            optional_broker_startup_action(&configured, false),
            OptionalBrokerStartupAction::RegisterReal
        );
    }

    #[test]
    fn optional_broker_startup_skips_absent_provider_without_mock_opt_in() {
        let configured = Ok(false);
        assert_eq!(
            optional_broker_startup_action(&configured, false),
            OptionalBrokerStartupAction::Skip
        );
    }

    #[test]
    fn optional_broker_startup_registers_mock_when_absent_but_allow_listed() {
        let configured = Ok(false);
        assert_eq!(
            optional_broker_startup_action(&configured, true),
            OptionalBrokerStartupAction::RegisterMock
        );
    }

    #[test]
    fn optional_broker_startup_registers_mock_when_probe_errors_but_allow_listed() {
        let configured = Err(BrokerAuthorityError::Message("broken metadata".into()));
        assert_eq!(
            optional_broker_startup_action(&configured, true),
            OptionalBrokerStartupAction::RegisterMock
        );
    }

    #[test]
    fn optional_broker_startup_skips_when_probe_errors_without_mock_opt_in() {
        let configured = Err(BrokerAuthorityError::Message("broken metadata".into()));
        assert_eq!(
            optional_broker_startup_action(&configured, false),
            OptionalBrokerStartupAction::Skip
        );
    }

    // ---- authenticate_peer_creds unit tests ----------------------------
    //
    // These tests use `authenticate_peer_creds_with` (the injectable seam)
    // so they do not require a second uid/gid or a hostile socket pair in CI.
    // Two cfg branches are gated: Linux uses SO_PEERCRED; macOS uses
    // LOCAL_PEERCRED. Tokio's `peer_cred()` abstracts both, so the seam
    // tests exercise the policy logic, not the syscall.

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    mod peer_creds_tests {
        use super::super::{authenticate_peer_creds_with, daemon_euid_runtime};
        use crate::infra::socket::PeerCreds;
        use std::io;

        fn make_peer(uid: u32, gid: u32, pid: Option<i32>) -> PeerCreds {
            PeerCreds { uid, gid, pid }
        }

        // --- development mode (no ember-clients group) ---

        #[test]
        fn dev_mode_accepts_same_uid() {
            let euid = daemon_euid_runtime();
            let peer = make_peer(euid, 1000, Some(42));
            let result = authenticate_peer_creds_with(
                || Ok(peer),
                euid,
                None, // no ember-clients group → dev mode
            );
            assert!(result.is_ok(), "dev mode: same-uid peer must be accepted");
            let creds = result.unwrap();
            assert_eq!(creds.uid, euid);
            assert_eq!(creds.gid, 1000);
            assert_eq!(creds.pid, Some(42));
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn dev_mode_accepts_same_uid_linux_no_pid() {
            // Linux SO_PEERCRED always provides pid, but test None path anyway.
            let euid = daemon_euid_runtime();
            let peer = make_peer(euid, 1000, None);
            let result = authenticate_peer_creds_with(|| Ok(peer), euid, None);
            assert!(
                result.is_ok(),
                "dev mode: same-uid peer with no pid must be accepted"
            );
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn dev_mode_accepts_same_uid_macos_no_pid() {
            // macOS LOCAL_PEERCRED may omit pid.
            let euid = daemon_euid_runtime();
            let peer = make_peer(euid, 1000, None);
            let result = authenticate_peer_creds_with(|| Ok(peer), euid, None);
            assert!(
                result.is_ok(),
                "dev mode: same-uid peer with no pid must be accepted on macOS"
            );
        }

        #[test]
        fn dev_mode_rejects_different_uid() {
            let euid = daemon_euid_runtime();
            let intruder_uid = euid.wrapping_add(1);
            let peer = make_peer(intruder_uid, 1000, Some(9999));
            let result = authenticate_peer_creds_with(|| Ok(peer), euid, None);
            assert!(
                result.is_err(),
                "dev mode: different-uid peer must be rejected"
            );
        }

        #[test]
        fn dev_mode_rejects_peer_cred_error() {
            let euid = daemon_euid_runtime();
            let result = authenticate_peer_creds_with::<fn() -> io::Result<PeerCreds>>(
                || {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "simulated failure",
                    ))
                },
                euid,
                None,
            );
            assert!(
                result.is_err(),
                "peer_cred error must fail closed in dev mode"
            );
        }

        // --- production mode (ember-clients group present) ---

        #[test]
        fn prod_mode_accepts_connected_peer_even_when_primary_gid_differs() {
            let euid = daemon_euid_runtime();
            let clients_gid: u32 = 54321;
            // The installed path provisions ember-clients as a supplementary
            // connect group; the peer's primary gid can legitimately differ.
            let peer = make_peer(euid.wrapping_add(1), 99999, Some(1234));
            let result = authenticate_peer_creds_with(|| Ok(peer), euid, Some(clients_gid));
            assert!(
                result.is_ok(),
                "prod mode: connected peer must be accepted via socket ACL even when \
                 primary gid differs"
            );
        }

        #[test]
        fn prod_mode_accepts_daemon_own_uid() {
            let euid = daemon_euid_runtime();
            let clients_gid: u32 = 54321;
            let different_gid: u32 = 99999;
            let peer = make_peer(euid, different_gid, Some(1));
            let result = authenticate_peer_creds_with(|| Ok(peer), euid, Some(clients_gid));
            assert!(
                result.is_ok(),
                "prod mode: daemon uid remains accepted on the installed path"
            );
        }

        #[test]
        fn prod_mode_accepts_non_daemon_uid_with_wrong_primary_gid() {
            let euid = daemon_euid_runtime();
            let clients_gid: u32 = 54321;
            let intruder_uid = euid.wrapping_add(1);
            let intruder_gid: u32 = 99999;
            let peer = make_peer(intruder_uid, intruder_gid, Some(555));
            let result = authenticate_peer_creds_with(|| Ok(peer), euid, Some(clients_gid));
            assert!(
                result.is_ok(),
                "prod mode: post-connect auth must not reject a peer solely because its \
                 primary gid differs from ember-clients"
            );
        }

        #[test]
        fn prod_mode_rejects_peer_cred_error() {
            let euid = daemon_euid_runtime();
            let clients_gid: u32 = 54321;
            let result = authenticate_peer_creds_with::<fn() -> io::Result<PeerCreds>>(
                || Err(io::Error::new(io::ErrorKind::Other, "kernel error")),
                euid,
                Some(clients_gid),
            );
            assert!(
                result.is_err(),
                "peer_cred error must fail closed in prod mode"
            );
        }

        /// Returned `PeerCreds` carries all three kernel fields through
        /// the accept path unchanged.
        #[test]
        fn returned_peer_creds_carry_uid_gid_pid() {
            let euid = daemon_euid_runtime();
            let peer = make_peer(euid, 7777, Some(99));
            let creds = authenticate_peer_creds_with(|| Ok(peer), euid, None)
                .expect("matching uid must be accepted");
            assert_eq!(creds.uid, euid);
            assert_eq!(creds.gid, 7777);
            assert_eq!(creds.pid, Some(99));
        }
    }

    // emberd_sandbox_startup_probe.
    //
    // The probe is best-effort by design (WARN-on-unsandboxed unless
    // EMBER_REQUIRE_SANDBOX=1). These tests verify the probe runs without
    // panicking + the strict-mode env-gate fires correctly. We don't assert
    // the SandboxState variant because test environments are inherently
    // unsandboxed (cargo test runs without launchd/systemd wrapping).
    #[test]
    fn sandbox_probe_runs_without_panic_in_test_env() {
        let _state = probe_sandbox_state();
        // No assertion on variant — test env is Unsandboxed by design.
    }

    #[test]
    fn sandbox_probe_default_mode_returns_ok_even_when_unsandboxed() {
        // SAFETY: this test reads + sets env via std::env. Other tests in
        // the same binary may race; we use a unique-name strategy by
        // explicitly unsetting before + after. The probe runs synchronously
        // so the env-state snapshot is consistent within one call.
        let prev = std::env::var("EMBER_REQUIRE_SANDBOX").ok();
        // SAFETY: see above.
        unsafe { std::env::remove_var("EMBER_REQUIRE_SANDBOX") };
        let result = check_sandbox_at_startup();
        // Restore.
        // SAFETY: see above.
        unsafe {
            if let Some(v) = prev {
                std::env::set_var("EMBER_REQUIRE_SANDBOX", v);
            }
        }
        assert!(
            result.is_ok(),
            "default mode must return Ok regardless of sandbox state"
        );
    }

    #[test]
    fn sandbox_probe_strict_mode_refuses_when_unsandboxed() {
        // Test env is Unsandboxed by design; strict mode must refuse.
        // Run only on platforms where the test env reliably reports Unsandboxed
        // (Linux containers + non-launchd-wrapped macOS shells). Cargo test on
        // a developer macOS workstation might run inside a sandboxed environment
        // (e.g. Xcode's test runner) — gate so we don't false-fail there.
        let baseline = probe_sandbox_state();
        if !matches!(baseline, SandboxState::Unsandboxed) {
            return; // test env IS sandboxed; can't exercise strict refusal here
        }
        let prev = std::env::var("EMBER_REQUIRE_SANDBOX").ok();
        // SAFETY: serial-mutation of env within a test that also restores.
        unsafe { std::env::set_var("EMBER_REQUIRE_SANDBOX", "1") };
        let result = check_sandbox_at_startup();
        // Restore.
        // SAFETY: see above.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("EMBER_REQUIRE_SANDBOX", v),
                None => std::env::remove_var("EMBER_REQUIRE_SANDBOX"),
            }
        }
        assert!(
            matches!(result, Err(SandboxProbeFailure::StrictModeUnsandboxed)),
            "strict mode must refuse when probe reports Unsandboxed; got: {result:?}"
        );
    }
}

async fn shutdown_signal() {
    let ctrl_c = signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut sigterm =
            signal::unix::signal(signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}

// macOS start-time binding (P22-S2) — macOS pid start-time
// reuse-immunity. macOS has no pidfd, so `is_alive()` re-reads the process
// start time and compares it to the value captured at accept; a PID-reuse
// collision is detected because the replacement process has a different start
// time.
#[cfg(all(test, target_os = "macos"))]
mod macos_starttime_tests {
    use super::{PeerCredPrincipal, proc_pid_start_time_usec};
    use std::path::PathBuf;

    fn principal_with_start_time(pid: i32, start_time_usec: Option<u64>) -> PeerCredPrincipal {
        PeerCredPrincipal {
            uid: 501,
            pid,
            socket_path: PathBuf::from("/tmp/test.sock"),
            start_time_usec,
        }
    }

    #[test]
    fn own_process_start_time_is_readable() {
        let me = std::process::id() as i32;
        assert!(
            proc_pid_start_time_usec(me).is_some(),
            "must read our own process start time"
        );
    }

    #[test]
    fn matching_start_time_is_alive() {
        let me = std::process::id() as i32;
        let captured = proc_pid_start_time_usec(me).expect("own start time");
        let p = principal_with_start_time(me, Some(captured));
        assert!(p.is_alive(), "unchanged start time → alive");
    }

    #[test]
    fn mismatched_start_time_is_dead() {
        // Simulate PID reuse: the captured start time differs from what
        // proc_pidinfo reports now for this live pid → the original process is
        // gone and the pid was reused.
        let me = std::process::id() as i32;
        let captured = proc_pid_start_time_usec(me).expect("own start time");
        let p = principal_with_start_time(me, Some(captured.wrapping_add(1)));
        assert!(
            !p.is_alive(),
            "start-time mismatch must read as dead (PID-reuse defense)"
        );
    }

    #[test]
    fn no_captured_start_time_falls_back_to_alive() {
        // Principal built via new()/Internal dispatch carries no start time —
        // retains the bare-PID posture (alive), mirroring Linux pidfd=None.
        let me = std::process::id() as i32;
        let p = principal_with_start_time(me, None);
        assert!(
            p.is_alive(),
            "no captured start time → bare-PID posture (alive)"
        );
    }

    #[test]
    fn nonexistent_pid_is_dead() {
        // A pid that cannot exist (i32::MAX) with a captured start time → the
        // re-read fails (process gone) → dead.
        let p = principal_with_start_time(i32::MAX, Some(123_456));
        assert!(!p.is_alive(), "vanished process must read as dead");
    }
}
