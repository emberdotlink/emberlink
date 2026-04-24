use std::cell::RefCell;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::rc::Rc;

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
use crate::vault::{Vault, log_vault_identity};

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

/// The daemon runtime — owns config, PID file, and socket listener.
pub struct DaemonRuntime {
    config: DaemonConfig,
    pid_file: PidFile,
    /// Path the config was loaded from — used for the vault identity warning in `run()`.
    /// `None` when config came from defaults (no file on disk).
    config_path: Option<std::path::PathBuf>,
}

impl DaemonRuntime {
    pub fn new(config: DaemonConfig) -> Self {
        let pid_file = PidFile::new(config.pid_file.clone());
        Self { config, pid_file, config_path: None }
    }

    /// Like `new`, but records the path the config was loaded from.
    /// Used to emit the production-keyring-with-custom-config warning at startup.
    pub fn new_with_config_path(config: DaemonConfig, config_path: std::path::PathBuf) -> Self {
        let pid_file = PidFile::new(config.pid_file.clone());
        Self { config, pid_file, config_path: Some(config_path) }
    }

    /// Start the daemon: write PID, open store, bind socket, run until shutdown signal.
    ///
    /// `start_notify` is called exactly once, as soon as the dashboard bind result is
    /// known (or the 2-second startup timeout expires), with the `DashboardBind` outcome.
    /// Pass `None` to skip the notification (e.g., in background mode or tests).
    pub async fn run(&self, start_notify: Option<Box<dyn FnOnce(DashboardBind)>>) -> Result<(), DaemonError> {
        self.config.ensure_dirs()?;
        self.pid_file.write()?;

        let socket_path = self.config.socket_dir.join("daemon.sock");
        info!(pid = std::process::id(), socket = %socket_path.display(), "ember daemon starting");

        // Open the store and vault. DaemonStore holds a rusqlite Connection which
        // is !Send + !Sync, so we wrap in Rc and run everything on a LocalSet.
        let db_path = self.config.data_dir.join("daemon.db");
        let store = Rc::new(DaemonStore::open(&db_path)?);
        let vault = Rc::new(
            Vault::open_from_config(&self.config)
                .map_err(|e| DaemonError::Vault(e.to_string()))?,
        );
        log_vault_identity(&self.config, self.config_path.as_deref());

        // F-05: attach the vault so persona-secret writes can encrypt at
        // rest. Fresh DBs under the V0 schema have no plaintext column;
        // every persona row is vault-sealed from inception.
        store.set_vault(Rc::clone(&vault));

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
            vault,
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

        // Drive the LocalSet until the dashboard bind result arrives (or times out).
        // This polls spawned tasks so run_dashboard actually executes its TcpListener::bind.
        let dashboard_bind: DashboardBind = if let Some((attempted_addr, bind_rx)) = dashboard_bind_info {
            let result = local
                .run_until(tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    bind_rx,
                ))
                .await;
            match result {
                Ok(Ok(Ok(addr))) => DashboardBind::Bound(addr),
                Ok(Ok(Err(e))) => DashboardBind::Failed {
                    addr: attempted_addr,
                    error: e.to_string(),
                },
                Ok(Err(_)) => {
                    // Sender dropped without sending — should not happen.
                    tracing::warn!("dashboard bind channel closed before result was sent");
                    DashboardBind::Timeout
                }
                Err(_) => {
                    tracing::warn!("dashboard bind timed out after 2s");
                    DashboardBind::Timeout
                }
            }
        } else {
            DashboardBind::Disabled
        };

        if let Some(notify) = start_notify {
            notify(dashboard_bind);
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
