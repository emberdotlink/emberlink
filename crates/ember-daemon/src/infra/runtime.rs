use std::cell::RefCell;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

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

/// implementation-note-57: outcome of the git-echo credential-injection proxy bind.
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

/// implementation-note-58: outcome of the general LLM/HTTP credential-
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
/// than a parallel callback. implementation-note-57.
#[derive(Debug, Clone)]
pub struct StartupBinds {
    pub dashboard: DashboardBind,
    pub git_proxy: GitProxyBind,
    /// implementation-note-58: bind outcome for the LLM proxy.
    pub llm_proxy: LlmProxyBind,
    /// Daemon's Ed25519 signing-identity pubkey (64-hex). Empty string if
    /// identity initialisation failed at startup. Used by the CLI to render
    /// the camera-clean Identity line in the foreground startup banner.
    pub identity_pubkey: String,
}

/// implementation-note-68 — render a 64-hex Ed25519 pubkey as a
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
    /// implementation-note-65: actual address the dashboard
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

        // implementation-note-58 fix: install the rustls process-wide
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
        // codebase (the implementation-note-41 root cause) is
        // identifiable in seconds via `tail daemon.log`. Also surfaces the
        // `(no-git)` fallback if the build script ran without a working repo.
        info!(
            version = env!("CARGO_PKG_VERSION"),
            git_sha = env!("EMBERLINK_GIT_SHA"),
            build_timestamp = env!("EMBERLINK_BUILD_TIMESTAMP"),
            "ember daemon binary version"
        );

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

        // implementation-note-124: auto-unseal the vault from the system keyring. The
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

        // implementation-note-124: emit an audit event for the auto-unseal so operators
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
                // implementation-note-68 — emit a structured
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

        // implementation-note-125 (design sub-piece D): construct the
        // pluggable `CredentialStore` trait object from the
        // `[credential_store]` config section. Defaults to the
        // `LocalEncryptedStore` (which adapts the existing Vault) when
        // the section is absent or `backend = "local"`. The trait
        // object is shared across the broker-registration loop below
        // so each provider's `<provider>_config_from_store` sibling can
        // pull credentials from whatever backend the operator selected.
        let cred_store: Arc<dyn crate::infra::credential_store::CredentialStore> =
            match &self.config.credential_store {
                None => Arc::new(crate::infra::credential_store::LocalEncryptedStore::new(
                    Arc::new((*vault).clone()),
                    Rc::clone(&store),
                )),
                Some(cs) if cs.backend == "local" => {
                    Arc::new(crate::infra::credential_store::LocalEncryptedStore::new(
                        Arc::new((*vault).clone()),
                        Rc::clone(&store),
                    ))
                }
                Some(cs) if cs.backend == "hashicorp-vault" => {
                    use crate::infra::config::resolve_at_ref;
                    use crate::infra::credential_store::HashiVaultStore;
                    use crate::infra::credential_store::hashicorp_vault::{
                        HashiVaultAuth, ReqwestHttpClient, UnavailablePolicy,
                    };

                    let addr = cs.addr.clone().ok_or_else(|| {
                        DaemonError::Vault(
                            "credential_store backend=hashicorp-vault requires `addr`"
                                .to_string(),
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
                                    "credential_store auth=approle requires `role_id`"
                                        .to_string(),
                                )
                            })?;
                            let raw_secret = cs.secret_id.as_deref().ok_or_else(|| {
                                DaemonError::Vault(
                                    "credential_store auth=approle requires `secret_id`"
                                        .to_string(),
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
                            // implementation-note-39: AWS IAM auth.
                            // Daemon proves its surrounding AWS IAM
                            // identity (env vars / instance metadata
                            // / IRSA / ECS task role / Fargate) via a
                            // SigV4-signed sts:GetCallerIdentity
                            // request that Vault re-plays server-side.
                            // The `role` field names the Vault
                            // AWS-auth role (`vault auth/aws/role/<role>`).
                            let role = cs.role.clone().ok_or_else(|| {
                                DaemonError::Vault(
                                    "credential_store auth=aws requires `role`"
                                        .to_string(),
                                )
                            })?;
                            HashiVaultAuth::Aws { role }
                        }
                        "hcp-service-principal" => {
                            // implementation-note-60: HashiCorp Cloud
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
                            let raw_secret =
                                cs.client_secret.as_deref().ok_or_else(|| {
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
                        DaemonError::Vault(format!(
                            "credential_store: vault login failed: {}",
                            e
                        ))
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

        // implementation-note-47 (design Phase 2): install the credential
        // broker registry. Real provider implementations replace
        // `MockBroker` as their downstream tasks ship — currently the
        // GitHub App broker is wired (T-CONSTRUCT-DAEMON-GH-implementation-note-126);
        // Anthropic and Cloudflare follow. Calling `install_registry`
        // multiple times is a no-op after the first call (`OnceCell`).
        {
            use core_broker::{BrokerProvider, MockBroker};
            use ember_broker::{
                AwsStsBroker, AzureCliBroker, FlyBroker, GcpBroker, GitHubBroker,
                HashiVaultBroker, OktaBroker, VercelBroker,
            };
            let mut registry = crate::broker::handler::BrokerRegistry::new();

            // GitHub: real broker when ~/.config/emberlink/ember-engine.{env,pem}
            // exist; MockBroker fallback otherwise so dev hosts without
            // GH App config still answer broker_issue without a panic.
            //
            // implementation-note-125: try the credential-store path first;
            // fall back to the env-file loader on store-miss / store-error so
            // operators who haven't migrated keep working.
            let github_from_store = crate::broker::github_config::github_config_from_store(
                &*cred_store,
            )
            .await;
            let github_creds = match github_from_store {
                Ok(Some(c)) => Ok(Some(c)),
                Ok(None) => crate::broker::github_config::load_gh_app_credentials(),
                Err(e) => {
                    tracing::warn!(
                        provider = "github",
                        error = %e,
                        "broker: github credential-store read failed; falling back to env file"
                    );
                    crate::broker::github_config::load_gh_app_credentials()
                }
            };
            match github_creds {
                Ok(Some(creds)) => {
                    registry.register(Box::new(GitHubBroker::new(creds)));
                    info!(
                        provider = "github",
                        "broker registered: GitHubBroker (GH App credentials loaded)"
                    );
                }
                Ok(None) => {
                    registry.register(Box::new(MockBroker::new(BrokerProvider::Github)));
                    tracing::warn!(
                        provider = "github",
                        "broker registered: MockBroker fallback — GH App credentials not found at ~/.config/emberlink/ember-engine.{{env,pem}}; see project README for GitHub App setup to enable real installation-token minting"
                    );
                }
                Err(e) => {
                    registry.register(Box::new(MockBroker::new(BrokerProvider::Github)));
                    tracing::warn!(
                        provider = "github",
                        error = %e,
                        "broker registered: MockBroker fallback — GH App config present but malformed; daemon continues with mock"
                    );
                }
            }

            // AWS STS: real broker when ~/.config/emberlink/aws-sts.env
            // exists with the required AWS_LONG_LIVED_KEY_ID /
            // AWS_LONG_LIVED_KEY_SECRET / AWS_LONG_LIVED_REGION keys;
            // MockBroker fallback otherwise so dev hosts without AWS
            // config still answer broker_issue without a panic.
            //
            // implementation-note-125: store-first, env-fallback.
            let aws_creds = match crate::broker::aws_sts_config::aws_sts_config_from_store(
                &*cred_store,
            )
            .await
            {
                Ok(Some(c)) => Some(c),
                Ok(None) => crate::broker::aws_sts_config::load_aws_sts_credentials(),
                Err(e) => {
                    tracing::warn!(
                        provider = "aws_sts",
                        error = %e,
                        "broker: aws_sts credential-store read failed; falling back to env file"
                    );
                    crate::broker::aws_sts_config::load_aws_sts_credentials()
                }
            };
            match aws_creds {
                Some((creds, default_role_arn)) => {
                    registry.register(Box::new(AwsStsBroker::new(creds, default_role_arn)));
                    info!(
                        provider = "aws_sts",
                        "broker registered: AwsStsBroker (AWS long-lived credentials loaded)"
                    );
                }
                None => {
                    registry.register(Box::new(MockBroker::new(BrokerProvider::AwsSts)));
                    tracing::warn!(
                        provider = "aws_sts",
                        "broker registered: MockBroker fallback — AWS long-lived credentials not found at ~/.config/emberlink/aws-sts.env (or required keys missing)"
                    );
                }
            }

            // GCP: real broker when ~/.config/emberlink/gcp.env points
            // at a valid downloaded service-account JSON key file;
            // MockBroker fallback otherwise so dev hosts without GCP
            // config still answer broker_issue without a panic.
            //
            // implementation-note-125: store-first, env-fallback.
            let gcp_creds =
                match crate::broker::gcp_config::gcp_config_from_store(&*cred_store).await {
                    Ok(Some(c)) => Some(c),
                    Ok(None) => crate::broker::gcp_config::load_gcp_credentials(),
                    Err(e) => {
                        tracing::warn!(
                            provider = "gcp",
                            error = %e,
                            "broker: gcp credential-store read failed; falling back to env file"
                        );
                        crate::broker::gcp_config::load_gcp_credentials()
                    }
                };
            match gcp_creds {
                Some((key, default_target)) => {
                    registry.register(Box::new(GcpBroker::new(key, default_target)));
                    info!(
                        provider = "gcp",
                        "broker registered: GcpBroker (GCP service-account key loaded)"
                    );
                }
                None => {
                    registry.register(Box::new(MockBroker::new(BrokerProvider::Gcp)));
                    tracing::warn!(
                        provider = "gcp",
                        "broker registered: MockBroker fallback — GCP service-account key not found at ~/.config/emberlink/gcp.env (or required JSON fields missing)"
                    );
                }
            }

            // Azure: real broker when ~/.config/emberlink/azure.env
            // carries the AZURE_TENANT_ID + AZURE_CLIENT_ID +
            // AZURE_CLIENT_SECRET triple; MockBroker fallback otherwise
            // so dev hosts without Azure config still answer
            // broker_issue without a panic.
            //
            // implementation-note-125: store-first, env-fallback.
            let azure_creds = match crate::broker::azure_config::azure_config_from_store(
                &*cred_store,
            )
            .await
            {
                Ok(Some(c)) => Some(c),
                Ok(None) => crate::broker::azure_config::load_azure_credentials(),
                Err(e) => {
                    tracing::warn!(
                        provider = "azure_cli",
                        error = %e,
                        "broker: azure credential-store read failed; falling back to env file"
                    );
                    crate::broker::azure_config::load_azure_credentials()
                }
            };
            match azure_creds {
                Some(sp) => {
                    registry.register(Box::new(AzureCliBroker::new(sp)));
                    info!(
                        provider = "azure_cli",
                        "broker registered: AzureCliBroker (Azure AD service-principal credentials loaded)"
                    );
                }
                None => {
                    registry.register(Box::new(MockBroker::new(BrokerProvider::AzureCli)));
                    tracing::warn!(
                        provider = "azure_cli",
                        "broker registered: MockBroker fallback — Azure AD service-principal credentials not found at ~/.config/emberlink/azure.env (or required keys missing)"
                    );
                }
            }

            // Fly.io: real broker when ~/.config/emberlink/fly.env
            // carries FLY_API_TOKEN; MockBroker fallback otherwise so
            // dev hosts without Fly config still answer broker_issue
            // without a panic.
            //
            // implementation-note-125: store-first, env-fallback.
            let fly_creds =
                match crate::broker::fly_config::fly_config_from_store(&*cred_store).await {
                    Ok(Some(c)) => Some(c),
                    Ok(None) => crate::broker::fly_config::load_fly_credentials(),
                    Err(e) => {
                        tracing::warn!(
                            provider = "fly_io",
                            error = %e,
                            "broker: fly credential-store read failed; falling back to env file"
                        );
                        crate::broker::fly_config::load_fly_credentials()
                    }
                };
            match fly_creds {
                Some(parent) => {
                    registry.register(Box::new(FlyBroker::new(parent)));
                    info!(
                        provider = "fly_io",
                        "broker registered: FlyBroker (Fly.io parent token loaded)"
                    );
                }
                None => {
                    registry.register(Box::new(MockBroker::new(BrokerProvider::FlyIo)));
                    tracing::warn!(
                        provider = "fly_io",
                        "broker registered: MockBroker fallback — Fly.io parent token not found at ~/.config/emberlink/fly.env (or FLY_API_TOKEN missing)"
                    );
                }
            }

            // HashiCorp Vault: real broker when
            // ~/.config/emberlink/hashivault.env carries VAULT_TOKEN +
            // VAULT_ADDR; MockBroker fallback otherwise so dev hosts
            // without Vault config still answer broker_issue without a
            // panic.
            //
            // implementation-note-125: store-first, env-fallback.
            let hashivault_creds =
                match crate::broker::hashivault_config::hashivault_config_from_store(&*cred_store)
                    .await
                {
                    Ok(Some(c)) => Some(c),
                    Ok(None) => crate::broker::hashivault_config::load_hashivault_credentials(),
                    Err(e) => {
                        tracing::warn!(
                            provider = "hashi_vault",
                            error = %e,
                            "broker: hashivault credential-store read failed; falling back to env file"
                        );
                        crate::broker::hashivault_config::load_hashivault_credentials()
                    }
                };
            match hashivault_creds {
                Some(parent) => {
                    registry.register(Box::new(HashiVaultBroker::new(parent)));
                    info!(
                        provider = "hashi_vault",
                        "broker registered: HashiVaultBroker (Vault parent token loaded)"
                    );
                }
                None => {
                    registry.register(Box::new(MockBroker::new(BrokerProvider::HashiVault)));
                    tracing::warn!(
                        provider = "hashi_vault",
                        "broker registered: MockBroker fallback — HashiCorp Vault parent token not found at ~/.config/emberlink/hashivault.env (or VAULT_TOKEN/VAULT_ADDR missing)"
                    );
                }
            }

            // Okta: real broker when ~/.config/emberlink/okta.env
            // carries OKTA_ORG_URL + OKTA_CLIENT_ID +
            // OKTA_PRIVATE_KEY_PATH + OKTA_KEY_ID and the referenced
            // PEM file is readable; MockBroker fallback otherwise so
            // dev hosts without Okta config still answer broker_issue
            // without a panic.
            //
            // implementation-note-125: store-first, env-fallback.
            let okta_creds =
                match crate::broker::okta_config::okta_config_from_store(&*cred_store).await {
                    Ok(Some(c)) => Some(c),
                    Ok(None) => crate::broker::okta_config::load_okta_credentials(),
                    Err(e) => {
                        tracing::warn!(
                            provider = "okta",
                            error = %e,
                            "broker: okta credential-store read failed; falling back to env file"
                        );
                        crate::broker::okta_config::load_okta_credentials()
                    }
                };
            match okta_creds {
                Some(app) => {
                    registry.register(Box::new(OktaBroker::new(app)));
                    info!(
                        provider = "okta",
                        "broker registered: OktaBroker (Okta service-app credentials loaded)"
                    );
                }
                None => {
                    registry.register(Box::new(MockBroker::new(BrokerProvider::Okta)));
                    tracing::warn!(
                        provider = "okta",
                        "broker registered: MockBroker fallback — Okta service-app credentials not found at ~/.config/emberlink/okta.env (or required keys / PEM missing)"
                    );
                }
            }

            // Vercel: real broker when ~/.config/emberlink/vercel.env
            // carries VERCEL_TOKEN; MockBroker fallback otherwise so
            // dev hosts without Vercel config still answer broker_issue
            // without a panic.
            //
            // implementation-note-125: store-first, env-fallback.
            let vercel_creds =
                match crate::broker::vercel_config::vercel_config_from_store(&*cred_store).await {
                    Ok(Some(c)) => Some(c),
                    Ok(None) => crate::broker::vercel_config::load_vercel_credentials(),
                    Err(e) => {
                        tracing::warn!(
                            provider = "vercel",
                            error = %e,
                            "broker: vercel credential-store read failed; falling back to env file"
                        );
                        crate::broker::vercel_config::load_vercel_credentials()
                    }
                };
            match vercel_creds {
                Some(parent) => {
                    registry.register(Box::new(VercelBroker::new(parent)));
                    info!(
                        provider = "vercel",
                        "broker registered: VercelBroker (Vercel parent token loaded)"
                    );
                }
                None => {
                    registry.register(Box::new(MockBroker::new(BrokerProvider::Vercel)));
                    tracing::warn!(
                        provider = "vercel",
                        "broker registered: MockBroker fallback — Vercel parent token not found at ~/.config/emberlink/vercel.env (or VERCEL_TOKEN missing)"
                    );
                }
            }

            // All other providers still on MockBroker pending their
            // downstream wiring tasks. Keep this list explicit (not a
            // catch-all loop) so adding a real impl is a deliberate
            // edit, not a silent default.
            for provider in [
                BrokerProvider::Cloudflare,
                BrokerProvider::Anthropic,
                BrokerProvider::Tailscale,
            ] {
                registry.register(Box::new(MockBroker::new(provider)));
            }
            crate::broker::handler::install_registry(registry);
            info!("broker registry installed (github + aws_sts + gcp + azure_cli + fly_io + hashi_vault + okta + vercel real, others mock)");
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
        let sessions_dir = crate::session_watcher::sessions_dir_from_data(&self.config.data_dir);
        let listener = SocketListener::new(
            socket_path,
            shutdown_rx,
            store.clone(),
            Rc::clone(&vault),
            Rc::clone(&policy),
            Rc::clone(&rate_limiter),
        )
        .with_sessions_dir(sessions_dir.clone());

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

        // implementation-note-72 — background sweep marks pending
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

        // implementation-note-127 — session heartbeat + TTL watcher.
        // Runs every 60 s. Closes orphaned sessions (launcher PID dead > 5 min)
        // and sessions whose grant is past the 24-hour TTL backstop.
        let session_store_clone = Rc::clone(&store);
        let sessions_dir_for_watcher = sessions_dir.clone();
        local.spawn_local(async move {
            crate::session_watcher::run(session_store_clone, sessions_dir_for_watcher).await;
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

        // implementation-note-59 — periodic cluster snapshot pull task.
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
                // implementation-note-38 follow-up: hand the dashboard task its
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

        // implementation-note-57: spawn the git-echo credential-injection proxy if
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
                // implementation-note-57 marker: spawn_local run_git_echo_proxy via this LocalSet.
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
                    // implementation-note-22: attach the vault to this fresh
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

        // implementation-note-58: spawn the general LLM/HTTP credential-
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
                    // implementation-note-22: attach vault to the fresh store
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
                // implementation-note-58: this URL now lives at
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

        // implementation-note-88: extract the
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

        // implementation-note-65: persist the resolved bind
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
