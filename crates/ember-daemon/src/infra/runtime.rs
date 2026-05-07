use std::cell::RefCell;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Mutex;

use thiserror::Error;
use tokio::signal;
use tokio::sync::{oneshot, watch};
use tracing::info;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use libc;

use crate::infra::config::DaemonConfig;
use crate::infra::dashboard::run_dashboard;
use crate::infra::pid::{PidError, PidFile};
use crate::trust::policy::{PolicyEngine, PolicyError};
use crate::infra::rate_limit::RateLimiter;
use crate::infra::socket::{SocketError, SocketListener};
use crate::infra::store::DaemonStore;
use crate::infra::vault::{AutoUnsealOutcome, Vault, log_vault_identity, try_auto_unseal_from_keyring};

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

/// implementation-note-36: outcome of the git-echo credential-injection proxy bind.
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

/// implementation-note-37: outcome of the general LLM/HTTP credential-
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

/// Aggregate bind report passed to `run()`'s `start_notify` callback. Carries
/// every listener that may have raced to bind during startup so the CLI can
/// render a consolidated banner. New listeners get a new field here rather
/// than a parallel callback. implementation-note-36.
#[derive(Debug, Clone)]
pub struct StartupBinds {
    pub dashboard: DashboardBind,
    pub git_proxy: GitProxyBind,
    /// implementation-note-37: bind outcome for the LLM proxy.
    pub llm_proxy: LlmProxyBind,
    /// Daemon's Ed25519 signing-identity pubkey (64-hex). Empty string if
    /// identity initialisation failed at startup. Used by the CLI to render
    /// the camera-clean Identity line in the foreground startup banner.
    pub identity_pubkey: String,
}

/// implementation-note-43 — render a 64-hex Ed25519 pubkey as a
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
/// - **production mode**: peer primary gid matches the `ember-clients` group.
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
            stream.peer_cred().map(|cred| crate::infra::socket::PeerCreds {
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

/// Return the daemon's effective uid. Separate from `socket::daemon_euid`
/// to keep runtime.rs self-contained.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn daemon_euid_runtime() -> u32 {
    // SAFETY: `geteuid` is a simple syscall wrapper with no preconditions.
    unsafe { libc::geteuid() }
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
    // existing development milestone behaviour on developer workstations.
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
            // Production mode: accept if the peer's primary gid is
            // ember-clients, OR if it is the daemon's own uid (so the
            // daemon itself can reconnect e.g. during tests).
            let ok = peer.gid == gid || peer.uid == daemon_uid;
            if !ok {
                tracing::warn!(
                    peer_uid = peer.uid,
                    peer_gid = peer.gid,
                    pid = ?peer.pid,
                    expected_clients_gid = gid,
                    daemon_uid,
                    "authenticate_peer_creds: peer not in ember-clients group — rejecting connection"
                );
            }
            ok
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
            "peer not authorised: uid/gid not in ember-clients group",
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
    /// implementation-note-40: actual address the dashboard
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

        // implementation-note-37 fix: install the rustls process-wide
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

        let socket_path = self.config.socket_dir.join("daemon.sock");
        info!(pid = std::process::id(), socket = %socket_path.display(), "ember daemon starting");
        // CLI-VERSION-FLAG: log the binary's compile-time version + git SHA +
        // build timestamp at INFO so a stale binary running against a newer
        // codebase (the implementation-note-26 root cause) is
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

        // Open the store and vault. DaemonStore holds a rusqlite Connection which
        // is !Send + !Sync, so we wrap in Rc and run everything on a LocalSet.
        let db_path = self.config.data_dir.join("daemon.db");
        let store = Rc::new(DaemonStore::open(&db_path)?);

        // PATH-PINNING-STARTUP-VERIFY: daemon refuses startup on manifest sig mismatch.
        {
            let manifest_path = std::env::var("HOME")
                .map(|home| {
                    std::path::PathBuf::from(home).join(".ember/binaries/manifest.toml")
                })
                .unwrap_or_else(|_| {
                    std::path::PathBuf::from("/usr/local/lib/ember/binaries/manifest.toml")
                });

            if manifest_path.exists() {
                // Use the trust graph's pinned IdentityRoot pubkey.
                let root_key = ed25519_dalek::VerifyingKey::from_bytes(
                    &crate::trust_graph::EMBER_SYSTEMS_PUBKEY_BYTES,
                );
                match root_key {
                    Ok(pk) => {
                        if let Err(e) =
                            crate::binary_manifest::verify_manifest_signature(&manifest_path, &pk)
                        {
                            tracing::error!(
                                manifest = %manifest_path.display(),
                                error = %e,
                                "PATH-PINNING-STARTUP-VERIFY: refusing to start — manifest signature failed"
                            );
                            std::process::exit(2);
                        }
                    }
                    Err(e) => {
                        // Pinned pubkey is the all-zero placeholder — daemon should
                        // log warning and continue ONLY if no manifest exists.
                        // Since manifest exists, fail closed.
                        tracing::error!(
                            error = %e,
                            "PATH-PINNING-STARTUP-VERIFY: pinned IdentityRoot pubkey invalid; refusing to start"
                        );
                        std::process::exit(2);
                    }
                }
            }
        }

        // implementation-note-88: auto-unseal the vault from the system keyring. The
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

        // implementation-note-88: emit an audit event for the auto-unseal so operators
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
        let mut identity_pubkey_hex = String::new();
        match crate::infra::receipt::init_identity(&self.config.data_dir) {
            Ok(pubkey) => {
                let fingerprint = daemon_identity_fingerprint(&pubkey);
                identity_pubkey_hex = pubkey.clone();
                info!(
                    signer_pubkey = %pubkey,
                    fingerprint = %fingerprint,
                    "daemon identity key loaded"
                );
                // implementation-note-43 — emit a structured
                // operator-facing log line that the demo teardown
                // script (and any future tooling) can grep without
                // re-deriving the fingerprint or hitting an HTTP
                // endpoint that may already be torn down. The daemon
                // is the authoritative source for its own identity;
                // surfacing it on every startup means the value is
                // available before, during, and after any shutdown.
                info!(
                    signer_pubkey = %pubkey,
                    fingerprint = %fingerprint,
                    canonical_version = %crate::infra::receipt::CANONICAL_VERSION,
                    "daemon-identity-anchor: pass --pubkey to `ember receipt verify` to verify offline"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "daemon identity key unavailable — receipts will not be emitted"
                );
            }
        }

        // implementation-note-29 (design Phase 2): install the credential
        // broker registry. Today the only registered provider is the
        // `MockBroker` (so `ember broker {issue,revoke,list}` round-trips
        // a deterministic canary credential end-to-end). The Anthropic
        // and Cloudflare implementations register themselves here once
        // their downstream tasks land. Calling `install_registry`
        // multiple times is a no-op after the first call (`OnceCell`).
        {
            use core_broker::{BrokerProvider, MockBroker};
            let mut registry = crate::broker::handler::BrokerRegistry::new();
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
            crate::broker::handler::install_registry(registry);
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

        // implementation-note-47 — background sweep marks pending
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

        // implementation-note-89 — session heartbeat + TTL watcher.
        // Runs every 60 s. Closes orphaned sessions (launcher PID dead > 5 min)
        // and sessions whose grant is past the 24-hour TTL backstop.
        let session_store_clone = Rc::clone(&store);
        let sessions_dir = crate::session_watcher::sessions_dir_from_data(&self.config.data_dir);
        local.spawn_local(async move {
            crate::session_watcher::run(session_store_clone, sessions_dir).await;
        });
        tracing::info!("session heartbeat watcher started");

        // design — periodic vault snapshot task.
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
                            Ok(Some(id)) => tracing::info!(snapshot_id = %id, "periodic vault snapshot emitted"),
                            Ok(None) => {}
                            Err(e) => tracing::warn!(error = %e, "periodic vault snapshot failed"),
                        }
                    }
                });
                tracing::info!(interval_secs = snapshot_interval, "vault snapshot task started");
            } else {
                tracing::warn!("snapshot task skipped — daemon identity not initialised");
            }
        }

        // implementation-note-38 — periodic cluster snapshot pull task.
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
                    let pull_vault: crate::infra::vault::Vault = (*Rc::clone(&vault)).clone();
                    let pull_store_path = self.config.data_dir.join("daemon.db");
                    let puller =
                        Rc::new(crate::snapshot::SnapshotPuller::new(pull_interval));
                    local.spawn_local(async move {
                        let tick_secs = pull_interval.min(60);
                        let mut interval =
                            tokio::time::interval(std::time::Duration::from_secs(tick_secs));
                        loop {
                            interval.tick().await;
                            // SnapshotPuller::maybe_pull is async and opens its
                            // own store connection (rusqlite is !Send).
                            let pull_store = match crate::infra::store::DaemonStore::open(&pull_store_path) {
                                Ok(s) => s,
                                Err(e) => {
                                    tracing::warn!(error = %e, "pull task: failed to open store");
                                    continue;
                                }
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
        let dashboard_bind_info: Option<(SocketAddr, oneshot::Receiver<Result<SocketAddr, std::io::Error>>)> =
            if let Some(dashboard_addr) = self.config.dashboard_addr {
                let db_path = self.config.data_dir.join("daemon.db");
                let version = env!("CARGO_PKG_VERSION").to_string();
                let dashboard_shutdown = shutdown_tx.subscribe();
                let (bind_tx, bind_rx) = oneshot::channel();
                // implementation-note-24 follow-up: hand the dashboard task its
                // own clone of the vault so its separate DaemonStore can
                // decrypt persona secrets when the WebAuthn-attested
                // approve path mints composite-grant chains. Mirrors the
                // git-echo proxy pattern below.
                let dashboard_vault: Vault = (*vault).clone();
                local.spawn_local(run_dashboard(
                    dashboard_addr,
                    db_path,
                    version,
                    Some(dashboard_vault),
                    dashboard_shutdown,
                    Some(bind_tx),
                ));
                Some((dashboard_addr, bind_rx))
            } else {
                None
            };

        // implementation-note-36: spawn the git-echo credential-injection proxy if
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
                // implementation-note-36 marker: spawn_local run_git_echo_proxy via this LocalSet.
                local.spawn_local(async move {
                    let store = match crate::infra::store::DaemonStore::open(&proxy_db_path) {
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
                    //
                    // implementation-note-18: attach the vault to this fresh
                    // store. Without this, increment_statement_usage's re-sign of
                    // block 0 calls persona_root_keypair → self.vault() → None →
                    // "no vault is attached", silently dropping every meter delta
                    // and breaking budget enforcement at the wire.
                    let proxy_store_vault = Rc::new(proxy_vault.clone());
                    store.set_vault(Rc::clone(&proxy_store_vault));
                    #[allow(clippy::arc_with_non_send_sync)]
                    let state = std::sync::Arc::new(crate::infra::proxy::ProxyState::new(store, proxy_vault));
                    let cfg = crate::infra::proxy::GitEchoConfig {
                        bind_addr: proxy_addr,
                        upstream_host: "github.com".to_string(),
                        state,
                        upstream_scheme: crate::infra::proxy::Scheme::Https,
                    };
                    if let Err(e) = crate::infra::proxy::run_git_echo_proxy(
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

        // implementation-note-37: spawn the general LLM/HTTP credential-
        // injection proxy (`run_proxy` — provider-aware auth, X-Ember-* header
        // protocol). This is the listener the Anthropic SDK demo posts to via
        // `base_url=$EMBER_PROXY_URL`; previously `run_proxy` was defined but
        // never spawned, so every Beat 4 call hit the git-echo proxy and 400'd.
        // Mirrors the git-proxy spawn block exactly: fresh DaemonStore (rusqlite
        // is !Send), cloned vault key, dedicated bind channel.
        let llm_proxy_bind_info: Option<(SocketAddr, oneshot::Receiver<Result<SocketAddr, std::io::Error>>)> =
            if let Some(proxy_addr) = self.config.llm_proxy_addr {
                let proxy_db_path = self.config.data_dir.join("daemon.db");
                let proxy_shutdown = shutdown_tx.subscribe();
                let (bind_tx, bind_rx) = oneshot::channel::<Result<SocketAddr, std::io::Error>>();
                let proxy_vault: Vault = (*vault).clone();
                local.spawn_local(async move {
                    let store = match crate::infra::store::DaemonStore::open(&proxy_db_path) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!(error = %e, "llm proxy: failed to open store; proxy disabled");
                            let _ = bind_tx.send(Err(std::io::Error::other(
                                format!("llm proxy store open: {e}"),
                            )));
                            return;
                        }
                    };
                    // implementation-note-18: attach vault to the fresh store
                    // so increment_statement_usage's block-0 re-sign can read the
                    // issuing persona's root keypair (vault-sealed). Same fix as
                    // the git-echo proxy spawn block above.
                    let proxy_store_vault = Rc::new(proxy_vault.clone());
                    store.set_vault(Rc::clone(&proxy_store_vault));
                    #[allow(clippy::arc_with_non_send_sync)]
                    let state = std::sync::Arc::new(crate::infra::proxy::ProxyState::new(store, proxy_vault));
                    let cfg = crate::infra::proxy::ProxyConfig {
                        bind_addr: proxy_addr,
                    };
                    if let Err(e) = crate::infra::proxy::run_proxy(
                        cfg,
                        state,
                        proxy_shutdown,
                        Some(bind_tx),
                    )
                    .await
                    {
                        tracing::warn!(error = %e, "llm proxy exited with error");
                    }
                });
                Some((proxy_addr, bind_rx))
            } else {
                None
            };

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
                let llm_fut = async {
                    match llm_rx {
                        None => None,
                        Some(rx) => Some(
                            tokio::time::timeout(std::time::Duration::from_secs(2), rx).await,
                        ),
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
                // implementation-note-37: this URL now lives at
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

        // implementation-note-40: persist the resolved bind
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
                llm_proxy: llm_proxy_bind,
                identity_pubkey: identity_pubkey_hex.clone(),
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

    // ---- authenticate_peer_creds unit tests ----------------------------
    //
    // These tests use `authenticate_peer_creds_with` (the injectable seam)
    // so they do not require a second uid/gid or a hostile socket pair in CI.
    // Two cfg branches are gated: Linux uses SO_PEERCRED; macOS uses
    // LOCAL_PEERCRED. Tokio's `peer_cred()` abstracts both, so the seam
    // tests exercise the policy logic, not the syscall.

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    mod peer_creds_tests {
        use std::io;
        use crate::infra::socket::PeerCreds;
        use super::super::{authenticate_peer_creds_with, daemon_euid_runtime};

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
            let result = authenticate_peer_creds_with(
                || Ok(peer),
                euid,
                None,
            );
            assert!(result.is_ok(), "dev mode: same-uid peer with no pid must be accepted");
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn dev_mode_accepts_same_uid_macos_no_pid() {
            // macOS LOCAL_PEERCRED may omit pid.
            let euid = daemon_euid_runtime();
            let peer = make_peer(euid, 1000, None);
            let result = authenticate_peer_creds_with(
                || Ok(peer),
                euid,
                None,
            );
            assert!(result.is_ok(), "dev mode: same-uid peer with no pid must be accepted on macOS");
        }

        #[test]
        fn dev_mode_rejects_different_uid() {
            let euid = daemon_euid_runtime();
            let intruder_uid = euid.wrapping_add(1);
            let peer = make_peer(intruder_uid, 1000, Some(9999));
            let result = authenticate_peer_creds_with(
                || Ok(peer),
                euid,
                None,
            );
            assert!(
                result.is_err(),
                "dev mode: different-uid peer must be rejected"
            );
        }

        #[test]
        fn dev_mode_rejects_peer_cred_error() {
            let euid = daemon_euid_runtime();
            let result = authenticate_peer_creds_with::<fn() -> io::Result<PeerCreds>>(
                || Err(io::Error::new(io::ErrorKind::PermissionDenied, "simulated failure")),
                euid,
                None,
            );
            assert!(result.is_err(), "peer_cred error must fail closed in dev mode");
        }

        // --- production mode (ember-clients group present) ---

        #[test]
        fn prod_mode_accepts_peer_in_ember_clients_group() {
            let euid = daemon_euid_runtime();
            let clients_gid: u32 = 54321;
            // Peer's primary gid is ember-clients.
            let peer = make_peer(euid.wrapping_add(1), clients_gid, Some(1234));
            let result = authenticate_peer_creds_with(
                || Ok(peer),
                euid,
                Some(clients_gid),
            );
            assert!(
                result.is_ok(),
                "prod mode: peer with ember-clients gid must be accepted"
            );
        }

        #[test]
        fn prod_mode_accepts_daemon_own_uid() {
            // The daemon's own uid is always accepted in production mode
            // (e.g. daemon reconnecting in tests or a privileged subprocess).
            let euid = daemon_euid_runtime();
            let clients_gid: u32 = 54321;
            let different_gid: u32 = 99999;
            let peer = make_peer(euid, different_gid, Some(1));
            let result = authenticate_peer_creds_with(
                || Ok(peer),
                euid,
                Some(clients_gid),
            );
            assert!(
                result.is_ok(),
                "prod mode: daemon's own uid must be accepted even when gid doesn't match"
            );
        }

        #[test]
        fn prod_mode_rejects_wrong_uid_and_wrong_gid() {
            let euid = daemon_euid_runtime();
            let clients_gid: u32 = 54321;
            let intruder_uid = euid.wrapping_add(1);
            let intruder_gid: u32 = 99999;
            let peer = make_peer(intruder_uid, intruder_gid, Some(555));
            let result = authenticate_peer_creds_with(
                || Ok(peer),
                euid,
                Some(clients_gid),
            );
            assert!(
                result.is_err(),
                "prod mode: peer with wrong uid and wrong gid must be rejected"
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
            assert!(result.is_err(), "peer_cred error must fail closed in prod mode");
        }

        /// Returned `PeerCreds` carries all three kernel fields through
        /// the accept path unchanged.
        #[test]
        fn returned_peer_creds_carry_uid_gid_pid() {
            let euid = daemon_euid_runtime();
            let peer = make_peer(euid, 7777, Some(99));
            let creds = authenticate_peer_creds_with(
                || Ok(peer),
                euid,
                None,
            )
            .expect("matching uid must be accepted");
            assert_eq!(creds.uid, euid);
            assert_eq!(creds.gid, 7777);
            assert_eq!(creds.pid, Some(99));
        }
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
