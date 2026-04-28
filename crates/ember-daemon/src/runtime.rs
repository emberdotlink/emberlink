use std::cell::RefCell;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Mutex;

use thiserror::Error;
use tokio::signal;
use tokio::sync::{oneshot, watch};
use tracing::info;

use crate::config::DaemonConfig;
use crate::dashboard::run_dashboard;
use crate::pid::{PidError, PidFile};
use crate::policy::{PolicyEngine, PolicyError};
use crate::rate_limit::RateLimiter;
use crate::socket::{SocketError, SocketListener};
use crate::store::DaemonStore;
use crate::vault::{AutoUnsealOutcome, Vault, log_vault_identity, try_auto_unseal_from_keyring};

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("config error: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("pid error: {0}")]
    Pid(#[from] PidError),
    #[error("socket error: {0}")]
    Socket(#[from] SocketError),
    #[error("store error: {0}")]
    Store(#[from] crate::store::StoreError),
    #[error("vault error: {0}")]
    Vault(String),
    #[error("policy error: {0}")]
    Policy(#[from] PolicyError),
    #[error("daemon is not running")]
    NotRunning,
    #[error("signal error: {0}")]
    Signal(std::io::Error),
}

/// Internal status of the vault auto-unseal step at daemon startup. Used to
/// label the audit event so operators can tell apart "keyring already had a
/// passphrase" from "first-run provisioning" from "fallback after error".
#[derive(Debug, Clone, Copy)]
enum VaultUnsealStatus {
    /// Keyring lookup succeeded — vault unsealed from stored passphrase.
    FromKeyring,
    /// No keyring entry yet — fell through to `Vault::open_from_config`,
    /// which auto-provisions a fresh passphrase. Expected on a brand-new
    /// install where the daemon comes up before `ember init`.
    Provisioned,
    /// Auto-unseal helper returned an error; fell back to `open_from_config`
    /// to keep the daemon running. Operator should investigate keyring state.
    Fallback,
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

/// implementation-note-19: outcome of the git-echo credential-injection proxy bind.
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

/// Aggregate bind report passed to `run()`'s `start_notify` callback. Carries
/// every listener that may have raced to bind during startup so the CLI can
/// render a consolidated banner. New listeners get a new field here rather
/// than a parallel callback. implementation-note-19.
#[derive(Debug, Clone)]
pub struct StartupBinds {
    pub dashboard: DashboardBind,
    pub git_proxy: GitProxyBind,
}

/// The daemon runtime — owns config, PID file, and socket listener.
pub struct DaemonRuntime {
    config: DaemonConfig,
    pid_file: PidFile,
    /// Path the config was loaded from — used for the vault identity warning in `run()`.
    /// `None` when config came from defaults (no file on disk).
    config_path: Option<std::path::PathBuf>,
    /// implementation-note-20: actual address the dashboard
    /// listener bound to (`Some(addr)`) or absent when the dashboard is
    /// disabled / failed to bind / timed out (`None`). Populated from inside
    /// `run()` after the bind result arrives. `Mutex` (not `RefCell`)
    /// because `DaemonRuntime` is held across await points in `run()` and
    /// the test harness reads it from a different thread than the one
    /// driving the daemon.
    pub dashboard_actual_addr: Mutex<Option<SocketAddr>>,
}

impl DaemonRuntime {
    pub fn new(config: DaemonConfig) -> Self {
        let pid_file = PidFile::new(config.pid_file.clone());
        Self {
            config,
            pid_file,
            config_path: None,
            dashboard_actual_addr: Mutex::new(None),
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
        }
    }

    /// Start the daemon: write PID, open store, bind socket, run until shutdown signal.
    ///
    /// `start_notify` is called exactly once, as soon as every startup listener's
    /// bind result is known (or the 2-second startup timeout expires), with a
    /// `StartupBinds` aggregate. Pass `None` to skip the notification (e.g., in
    /// background mode or tests).
    pub async fn run(&self, start_notify: Option<Box<dyn FnOnce(StartupBinds)>>) -> Result<(), DaemonError> {
        self.config.ensure_dirs()?;
        self.pid_file.write()?;

        let socket_path = self.config.socket_dir.join("daemon.sock");
        info!(pid = std::process::id(), socket = %socket_path.display(), "ember daemon starting");
        // CLI-VERSION-FLAG: log the binary's compile-time version + git SHA +
        // build timestamp at INFO so a stale binary running against a newer
        // codebase (the implementation-note-11 root cause) is
        // identifiable in seconds via `tail daemon.log`. Also surfaces the
        // `(no-git)` fallback if the build script ran without a working repo.
        info!(
            version = env!("CARGO_PKG_VERSION"),
            git_sha = env!("EMBERLINK_GIT_SHA"),
            build_timestamp = env!("EMBERLINK_BUILD_TIMESTAMP"),
            "ember daemon binary version"
        );

        // security check: load the per-op user-presence config from
        // [presence] in config.toml into the process-global gate. Done
        // BEFORE the vault unlock so the very first `mark_unlocked` call
        // applies the right idle-timeout window.
        {
            use std::time::Duration;
            let cfg = crate::presence::PresenceConfig {
                idle_timeout: self
                    .config
                    .presence
                    .idle_timeout_secs
                    .map(Duration::from_secs)
                    .unwrap_or(crate::presence::DEFAULT_IDLE_TIMEOUT),
                quiet_hours_start: self.config.presence.quiet_hours_start,
                quiet_hours_end: self.config.presence.quiet_hours_end,
            };
            crate::presence::configure(cfg);
        }

        // Open the store and vault. DaemonStore holds a rusqlite Connection which
        // is !Send + !Sync, so we wrap in Rc and run everything on a LocalSet.
        let db_path = self.config.data_dir.join("daemon.db");
        let store = Rc::new(DaemonStore::open(&db_path)?);

        // implementation-note-31: auto-unseal the vault from the system keyring. The
        // helper's contract: it succeeds only if a keyring entry already
        // exists (or `EMBER_VAULT_PASSPHRASE` is set) — never auto-provisions
        // on daemon start so a wiped keyring can't silently mint a fresh
        // vault key. Falls back to `Vault::open_from_config` which DOES
        // auto-provision; that path stays for first-run ergonomics
        // (a daemon started before `ember init` will still come up).
        //
        // Audit event for the success path is emitted below once the store
        // has the vault attached, so `audit show` reflects what happened.
        let (vault, vault_status) = match try_auto_unseal_from_keyring(&self.config) {
            AutoUnsealOutcome::Unsealed(v) => (Rc::new(v), VaultUnsealStatus::FromKeyring),
            AutoUnsealOutcome::NoKeyringEntry => {
                tracing::info!(
                    "vault: no keyring entry yet — falling back to open_from_config (will provision on first call)"
                );
                let v = Vault::open_from_config(&self.config)
                    .map_err(|e| DaemonError::Vault(e.to_string()))?;
                (Rc::new(v), VaultUnsealStatus::Provisioned)
            }
            AutoUnsealOutcome::Error(e) => {
                // Non-fatal: log and try the regular open path so the daemon
                // still starts. The operator can fix keyring state without a
                // daemon outage.
                tracing::warn!(error = %e, "vault: auto-unseal from keyring failed; falling back");
                let v = Vault::open_from_config(&self.config)
                    .map_err(|e| DaemonError::Vault(e.to_string()))?;
                (Rc::new(v), VaultUnsealStatus::Fallback)
            }
        };
        log_vault_identity(&self.config, self.config_path.as_deref());

        // F-05: attach the vault so persona-secret writes can encrypt at
        // rest. Fresh DBs under the V0 schema have no plaintext column;
        // every persona row is vault-sealed from inception.
        store.set_vault(Rc::clone(&vault));

        // implementation-note-31: emit an audit event for the auto-unseal so operators
        // running `audit show` see exactly when (and how) the vault came
        // online. Failures here are non-fatal — the audit log is for
        // observability, not correctness.
        let outcome_str = match vault_status {
            VaultUnsealStatus::FromKeyring => "auto_unseal_from_keyring",
            VaultUnsealStatus::Provisioned => "provisioned_on_first_run",
            VaultUnsealStatus::Fallback => "auto_unseal_failed_fallback_to_open",
        };
        if let Err(e) = store.log_event(
            None,
            "vault.auto_unseal_from_keyring",
            None,
            outcome_str,
            None,
        ) {
            tracing::warn!(error = %e, "vault: failed to log auto-unseal audit event");
        } else {
            tracing::info!(outcome = outcome_str, "vault: attached to store");
        }

        // Initialise the daemon's long-lived Ed25519 identity key used to
        // sign Grant Receipts (Stream D, design §Evidence). First-run
        // generates the key; subsequent runs re-load it. Failure here is
        // non-fatal — receipt emission will silently no-op if the key
        // can't be loaded, but the daemon keeps running.
        match crate::receipt::init_identity(&self.config.data_dir) {
            Ok(pubkey) => {
                info!(signer_pubkey = %pubkey, "daemon identity key loaded");
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "daemon identity key unavailable — receipts will not be emitted"
                );
            }
        }

        // implementation-note-17 (design Phase 2): install the credential
        // broker registry. Today the only registered provider is the
        // `MockBroker` (so `ember broker {issue,revoke,list}` round-trips
        // a deterministic canary credential end-to-end). The Anthropic
        // and Cloudflare implementations register themselves here once
        // their downstream tasks land. Calling `install_registry`
        // multiple times is a no-op after the first call (`OnceCell`).
        {
            use core_broker::{BrokerProvider, MockBroker};
            let mut registry = crate::broker_handler::BrokerRegistry::new();
            // Register one MockBroker per supported provider so the
            // daemon answers `broker_issue` for every well-known
            // provider until real impls land.
            for provider in [
                BrokerProvider::Cloudflare,
                BrokerProvider::Anthropic,
                BrokerProvider::Github,
                BrokerProvider::AwsSts,
                BrokerProvider::Gcp,
                BrokerProvider::Tailscale,
            ] {
                registry.register(Box::new(MockBroker::new(provider)));
            }
            crate::broker_handler::install_registry(registry);
            info!("broker registry installed (mock providers; real impls land per BROKER-* tasks)");
        }

        // NOTIF-2: sweep approval_requests that were left pending from a prior
        // session. Rows older than stale_approval_threshold_secs are marked
        // timed_out. Fires zero notifications — the user already saw the banner
        // when the request was first submitted.
        match store.expire_stale_pending_approvals(self.config.stale_approval_threshold_secs) {
            Ok(0) => {}
            Ok(n) => info!(count = n, "startup: auto-expired {n} stale pending approvals"),
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
        let policy = Rc::new(policy);
        let rate_limiter = Rc::new(RefCell::new(RateLimiter::default()));

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = SocketListener::new(
            socket_path,
            shutdown_rx,
            store.clone(),
            Rc::clone(&vault),
            Rc::clone(&policy),
            Rc::clone(&rate_limiter),
        );

        // Run socket listener and background tasks on a LocalSet (DaemonStore is !Send).
        let local = tokio::task::LocalSet::new();

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
                            tracing::info!(count = exhausted, "exhausted grants by wall-clock budget");
                        }
                        if warned > 0 {
                            tracing::info!(count = warned, "wall-clock 80% warnings emitted");
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "grant wall-clock sweep failed"),
                }
            }
        });

        // implementation-note-15 — background sweep marks pending
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
                    Ok(n) => tracing::info!(count = n, threshold_secs = stale_threshold, "background: auto-expired stale pending approvals"),
                    Err(e) => tracing::warn!(error = %e, "background stale-approval sweep failed"),
                }
            }
        });

        // Spawn the dashboard HTTP listener if configured. The bind result is captured via
        // a oneshot channel and driven to completion inside `local.run_until(bind_rx)` below,
        // before the main accept loop starts. This ensures the LocalSet is polled so the
        // dashboard task can actually run and send on the channel.
        //
        // We retain the configured address alongside the receiver so a bind failure can
        // report which port was attempted.
        let dashboard_bind_info: Option<(SocketAddr, oneshot::Receiver<Result<SocketAddr, std::io::Error>>)> =
            if let Some(dashboard_addr) = self.config.dashboard_addr {
                let db_path = self.config.data_dir.join("daemon.db");
                let version = env!("CARGO_PKG_VERSION").to_string();
                let dashboard_shutdown = shutdown_tx.subscribe();
                let (bind_tx, bind_rx) = oneshot::channel();
                local.spawn_local(run_dashboard(
                    dashboard_addr,
                    db_path,
                    version,
                    dashboard_shutdown,
                    Some(bind_tx),
                ));
                Some((dashboard_addr, bind_rx))
            } else {
                None
            };

        // implementation-note-19: spawn the git-echo credential-injection proxy if
        // configured. Bind result is captured via a oneshot channel and
        // driven below alongside the dashboard's. Each proxy task gets its
        // own DaemonStore (rusqlite Connection is !Send) and a clone of the
        // vault key — both reference the same on-disk DB and the same
        // master key the main daemon uses for grant resolution.
        let git_proxy_bind_info: Option<(SocketAddr, oneshot::Receiver<Result<SocketAddr, std::io::Error>>)> =
            if let Some(proxy_addr) = self.config.git_proxy_addr {
                let proxy_db_path = self.config.data_dir.join("daemon.db");
                let proxy_shutdown = shutdown_tx.subscribe();
                let (bind_tx, bind_rx) = oneshot::channel::<Result<SocketAddr, std::io::Error>>();
                let proxy_vault: Vault = (*vault).clone();
                // implementation-note-19 marker: spawn_local run_git_echo_proxy via this LocalSet.
                local.spawn_local(async move {
                    let store = match crate::store::DaemonStore::open(&proxy_db_path) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!(error = %e, "git proxy: failed to open store; proxy disabled");
                            // Best-effort: deliver a synthesized I/O error to
                            // the bind channel so the CLI banner can show
                            // "unavailable" instead of timing out.
                            let _ = bind_tx.send(Err(std::io::Error::other(
                                format!("git proxy store open: {e}"),
                            )));
                            return;
                        }
                    };
                    // ProxyState wraps a rusqlite Connection which is !Send + !Sync;
                    // the Arc is used only within this LocalSet (single-threaded runtime),
                    // mirroring run_proxy / run_git_echo_proxy themselves.
                    #[allow(clippy::arc_with_non_send_sync)]
                    let state = std::sync::Arc::new(crate::proxy::ProxyState::new(store, proxy_vault));
                    let cfg = crate::proxy::GitEchoConfig {
                        bind_addr: proxy_addr,
                        upstream_host: "github.com".to_string(),
                        state,
                        upstream_scheme: crate::proxy::Scheme::Https,
                    };
                    if let Err(e) = crate::proxy::run_git_echo_proxy(
                        cfg,
                        proxy_shutdown,
                        Some(bind_tx),
                    )
                    .await
                    {
                        tracing::warn!(error = %e, "git proxy exited with error");
                    }
                });
                Some((proxy_addr, bind_rx))
            } else {
                None
            };

        // Drive the LocalSet until both startup bind results arrive (or time out).
        // This polls spawned tasks so run_dashboard / run_git_echo_proxy actually
        // execute their TcpListener::bind. Both bind futures share a single
        // 2-second deadline — if either races past the deadline the CLI banner
        // shows `Timeout` for that listener but the daemon keeps running.
        let dashboard_attempt = dashboard_bind_info.as_ref().map(|(a, _)| *a);
        let proxy_attempt = git_proxy_bind_info.as_ref().map(|(a, _)| *a);
        let dashboard_rx = dashboard_bind_info.map(|(_, rx)| rx);
        let proxy_rx = git_proxy_bind_info.map(|(_, rx)| rx);

        let (dashboard_outcome, proxy_outcome) = local
            .run_until(async {
                let dashboard_fut = async {
                    match dashboard_rx {
                        None => None,
                        Some(rx) => Some(
                            tokio::time::timeout(std::time::Duration::from_secs(2), rx).await,
                        ),
                    }
                };
                let proxy_fut = async {
                    match proxy_rx {
                        None => None,
                        Some(rx) => Some(
                            tokio::time::timeout(std::time::Duration::from_secs(2), rx).await,
                        ),
                    }
                };
                tokio::join!(dashboard_fut, proxy_fut)
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
                let proxy_url = format!("http://{}", bound);
                info!(proxy_url = %proxy_url, "git proxy listening");
                // EMBER_PROXY_URL is set so sandbox.rs (which reads from env)
                // automatically forwards it into spawned containers.
                // SAFETY: the daemon runtime is single-threaded at this point
                // (tokio current-thread + LocalSet; we have not entered the
                // accept loop), so a race-free env mutation is acceptable.
                unsafe {
                    std::env::set_var("EMBER_PROXY_URL", &proxy_url);
                }
                let url_path = self.config.data_dir.join("proxy.url");
                if let Err(e) = std::fs::write(&url_path, &proxy_url) {
                    tracing::warn!(
                        path = %url_path.display(),
                        error = %e,
                        "git proxy: failed to write proxy.url sidecar"
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

        // implementation-note-20: persist the resolved bind
        // address on the runtime so out-of-band readers (tests, future
        // introspection helpers) see the same truth as `/api/status`. Only
        // the `Bound` variant maps to `Some`; `Failed`/`Disabled`/`Timeout`
        // all map to `None` so callers can distinguish "bound" from
        // "configured" without re-deriving from the bind report.
        let actual_dashboard_addr = match &dashboard_bind {
            DashboardBind::Bound(addr) => Some(*addr),
            DashboardBind::Failed { .. }
            | DashboardBind::Disabled
            | DashboardBind::Timeout => None,
        };
        if let Ok(mut slot) = self.dashboard_actual_addr.lock() {
            *slot = actual_dashboard_addr;
        }

        if let Some(notify) = start_notify {
            notify(StartupBinds {
                dashboard: dashboard_bind,
                git_proxy: git_proxy_bind,
            });
        }

        // Spawn a SIGHUP handler that reloads policy on signal.
        let policy_file = self.config.policy_file.clone();
        local.spawn_local(async move {
            #[cfg(unix)]
            {
                let mut sighup = tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::hangup(),
                )
                .expect("SIGHUP handler");
                loop {
                    sighup.recv().await;
                    match PolicyEngine::from_file(&policy_file) {
                        Ok(_engine) => {
                            tracing::info!(path = %policy_file.display(), "policy reloaded via SIGHUP");
                            // TODO: swap policy in handler when policy is wired through
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to reload policy");
                        }
                    }
                }
            }
        });

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
                let socket_path = self.config.socket_dir.join("daemon.sock");
                Ok(DaemonStatus {
                    pid,
                    socket: socket_path,
                    running: true,
                })
            }
            Ok(Some(pid)) => Ok(DaemonStatus {
                pid,
                socket: self.config.socket_dir.join("daemon.sock"),
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

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use tempfile::TempDir;

    /// Verifies that the rolling file appender creates `daemon.log.*` in the
    /// data directory and accepts writes. The global tracing subscriber is NOT
    /// initialised here — we write directly via the `Write` impl so this test
    /// can run alongside other tests without conflicting with the global state.
    #[test]
    fn rolling_appender_creates_log_file_in_data_dir() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();

        let mut appender = tracing_appender::rolling::daily(data_dir, "daemon.log");
        writeln!(appender, r#"{{"message":"daemon-log-test-probe","level":"INFO"}}"#).unwrap();
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
