use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::time::Duration;

use clap::{Parser, Subcommand};
use ember_daemon::grant::GrantInfo;
use core_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};
use ember_daemon::approval::ApprovalOutcome;
use ember_daemon::audit::AuditFilter;
use ember_daemon::config::DaemonConfig;
use ember_daemon::image_registry::ImageRegistry;
use ember_daemon::runtime::{DaemonRuntime, DashboardBind};
use ember_daemon::sandbox::SandboxCreateOpts;
use ember_daemon::store::DaemonStore;
use ember_daemon::vault::{
    keyring_writes_suppressed, verify_keyring_roundtrip, Vault, DEFAULT_KEYRING_ACCOUNT,
    DEFAULT_KEYRING_SERVICE,
};
use tracing_subscriber::EnvFilter;

#[path = "daemon_agent.rs"]
mod daemon_agent;

#[derive(Parser)]
#[command(name = "ember", about = "The trust layer for AI agents")]
struct Cli {
    /// Path to config file
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Output as JSON
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize ember — first-run setup
    Init {
        /// Your display name
        #[arg(long)]
        name: Option<String>,
        /// Keyring service name to write into config.toml (overrides default)
        #[arg(long)]
        keyring_service: Option<String>,
        /// Keyring account name to write into config.toml (overrides default)
        #[arg(long)]
        keyring_account: Option<String>,
    },
    /// Manage the ember daemon
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Manage agent personas
    Persona {
        #[command(subcommand)]
        action: PersonaAction,
    },
    /// Manage the credential vault
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },
    /// Manage access grants
    Grant {
        #[command(subcommand)]
        action: GrantAction,
    },
    /// Manage agent sandboxes
    Sandbox {
        #[command(subcommand)]
        action: SandboxAction,
    },
    /// Manage approval requests
    Approval {
        #[command(subcommand)]
        action: ApprovalAction,
    },
    /// View audit log
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Inspect Grant Receipts — signed artifacts emitted at terminal grant state
    Receipt {
        #[command(subcommand)]
        action: ReceiptAction,
    },
    /// View or evaluate policy rules
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// View configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Show daemon status overview
    Status,
    /// Show ember version
    Version,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show current configuration
    Show,
    /// Show config file path
    Path,
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Show current policy rules
    Show,
    /// Evaluate an action against the policy
    Eval {
        /// Action to evaluate (e.g., "git.push.main")
        action: String,
    },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the daemon (runs in foreground by default)
    Start {
        /// Run in background (daemonize)
        #[arg(long, short, conflicts_with = "foreground")]
        background: bool,
        /// Explicitly run in foreground (no-op unless used by launchd/systemd)
        #[arg(long)]
        foreground: bool,
    },
    /// Stop a running daemon
    Stop,
    /// Show daemon status
    Status,
    /// Gracefully restart the daemon (SIGTERM; managed service respawns)
    Reload {
        /// Seconds to wait for the new daemon to come up
        #[arg(long, default_value = "10")]
        timeout: u64,
    },
    /// Install the daemon as an always-up user service (LaunchAgent/systemd)
    InstallAgent {
        /// Write the service file but don't bootstrap/enable it
        #[arg(long)]
        no_autostart: bool,
    },
    /// Uninstall the daemon user service
    UninstallAgent,
}

#[derive(Subcommand)]
enum PersonaAction {
    /// Create a new agent persona
    Create {
        /// Human-readable name for the persona
        #[arg(long)]
        name: String,
    },
    /// List all personas
    List,
    /// Revoke a persona
    Revoke {
        /// Persona ID to revoke
        id: String,
    },
}

#[derive(Subcommand)]
enum VaultAction {
    /// Add a credential to the vault
    Add {
        /// Credential name
        #[arg(long)]
        name: String,
        /// Credential value
        #[arg(long)]
        value: String,
        /// Optional metadata
        #[arg(long)]
        metadata: Option<String>,
    },
    /// List stored credentials
    List,
    /// Retrieve a credential value
    Get {
        /// Credential name
        name: String,
    },
    /// Remove a credential
    Remove {
        /// Credential name
        name: String,
    },
}

#[derive(Subcommand)]
enum GrantAction {
    /// Create a new grant
    Create {
        /// Persona ID
        #[arg(long)]
        persona: String,
        /// Credential name
        #[arg(long)]
        credential: String,
        /// Access scope
        #[arg(long)]
        scope: String,
        /// Time-to-live in seconds
        #[arg(long)]
        ttl: Option<u64>,
        /// Max uses per hour (rate limit)
        #[arg(long)]
        rate_limit: Option<u64>,
        /// Allowed hours start (0-23 UTC)
        #[arg(long)]
        hours_start: Option<u32>,
        /// Allowed hours end (0-23 UTC)
        #[arg(long)]
        hours_end: Option<u32>,
        /// Allowed target domains (comma-separated)
        #[arg(long)]
        allowed_targets: Option<String>,
        /// Max delegation depth for sub-agents
        #[arg(long)]
        delegation_depth: Option<u32>,
        /// Token budget ceiling
        #[arg(long)]
        budget_tokens: Option<u64>,
        /// Cost budget ceiling in dollars (e.g. "0.50" → 50 cents)
        #[arg(long)]
        budget_cents: Option<String>,
        /// Request count budget ceiling
        #[arg(long)]
        budget_requests: Option<u64>,
        /// Wall-clock seconds budget ceiling
        #[arg(long)]
        budget_seconds: Option<u64>,
        /// Attestation runtime label (e.g. "claude_code")
        #[arg(long)]
        attestation_runtime: Option<String>,
    },
    /// Delegate a grant to a sub-agent with narrowed scope
    Delegate {
        /// Parent grant ID
        #[arg(long)]
        parent: String,
        /// Child persona ID
        #[arg(long)]
        persona: String,
        /// Narrowed scope
        #[arg(long)]
        scope: String,
        /// Time-to-live in seconds
        #[arg(long)]
        ttl: Option<u64>,
    },
    /// List all grants
    List {
        /// Show only active grants
        #[arg(long)]
        active: bool,
    },
    /// Revoke a grant
    Revoke {
        /// Grant ID to revoke
        id: String,
    },
    /// Expire stale grants
    Expire,
    /// Show budget and usage for a grant
    Budget {
        /// Grant ID
        grant_id: String,
    },
    /// Extend a grant's budget and/or TTL
    Extend {
        /// Grant ID
        grant_id: String,
        /// Additional tokens to add to budget
        #[arg(long)]
        tokens: Option<u64>,
        /// Additional cents to add to budget (e.g. "0.25")
        #[arg(long)]
        cents: Option<String>,
        /// Additional TTL duration (e.g. 15s, 5m, 2h, 1d, or bare seconds)
        #[arg(long)]
        ttl: Option<String>,
    },
}

#[derive(Subcommand)]
enum SandboxAction {
    /// Create a new sandbox
    Create {
        /// Sandbox name
        #[arg(long)]
        name: String,
        /// Container image
        #[arg(long, default_value = "ubuntu:24.04")]
        image: String,
        /// Run container with elevated privileges (refused by invariant unless --unsafe-root)
        #[arg(long)]
        privileged: bool,
        /// Bind mount in `host:container[:ro]` form. Denylisted sources are refused.
        #[arg(long = "volume", short = 'v')]
        volume: Vec<String>,
        /// User override. `--user 0` / `--user root` refused unless --unsafe-root.
        #[arg(long)]
        user: Option<String>,
        /// Docker network mode. Default is bridge. `host` is refused.
        #[arg(long)]
        network: Option<String>,
        /// Explicit opt-in to run as root (overrides the no-root-user invariant).
        #[arg(long)]
        unsafe_root: bool,
        /// Clone the given git URL into the sandbox's workspace before starting.
        #[arg(long = "workspace-from")]
        workspace_from: Option<String>,
        /// Additional `KEY=VAL` env var to pass into the container.
        #[arg(long = "env", short = 'e')]
        env: Vec<String>,
    },
    /// List all sandboxes
    List,
    /// Stop a sandbox
    Stop {
        /// Sandbox ID
        id: String,
    },
    /// Execute a command in a sandbox
    Exec {
        /// Sandbox ID
        id: String,
        /// Command to run
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Run an agent in a new sandbox with a 3-statement composite grant
    /// (Credential + Session + Time) in a single approval envelope.
    Run {
        /// Sandbox name
        name: String,
        /// Container image
        #[arg(long, default_value = "ubuntu:24.04")]
        image: String,
        /// Clone the given git URL into the sandbox's workspace before starting.
        #[arg(long = "workspace-from")]
        workspace_from: Option<String>,
        /// Additional `KEY=VAL` env var (or bare `KEY` to pass-through from host env) to inject.
        #[arg(long = "env", short = 'e')]
        env: Vec<String>,
        /// Credential object ID for the Credential statement (e.g. "obj-github-token").
        /// Required to mint the 3-statement composite grant; omit to skip grant creation.
        #[arg(long)]
        credential_resource: Option<String>,
        /// Token budget ceiling for the Session statement (LLM tokens).
        #[arg(long)]
        budget_tokens: Option<u64>,
        /// Cost budget ceiling in dollars (e.g. "0.50" → 50 cents) for the Session statement.
        #[arg(long)]
        budget_cents: Option<String>,
        /// Wall-clock seconds ceiling for the Time statement.
        #[arg(long)]
        budget_seconds: Option<u64>,
        /// Grant TTL (e.g. "30m", "2h", "1d"). Default: no expiry.
        #[arg(long)]
        ttl: Option<String>,
        /// Prompt to pass to the agent inside the sandbox.
        #[arg(long)]
        prompt: Option<String>,
    },
}

#[derive(Subcommand)]
enum ApprovalAction {
    /// List pending approval requests
    List,
    /// Approve a pending request
    Approve {
        /// Approval request ID
        id: String,
        /// Create a standing grant so future matching requests auto-approve
        #[arg(long)]
        always: bool,
        /// TTL for the standing grant (e.g. 7d, 30d, 90d, never). Default: 30d
        #[arg(long)]
        ttl: Option<String>,
    },
    /// Deny a pending request
    Deny {
        /// Approval request ID
        id: String,
        /// Reason for denial
        #[arg(long)]
        reason: String,
    },
    /// Narrow and approve with reduced scope
    Narrow {
        /// Approval request ID
        id: String,
        /// New narrowed scope
        #[arg(long)]
        scope: String,
    },
}

#[derive(Subcommand)]
enum ReceiptAction {
    /// List receipts, most-recent first
    List {
        /// Filter by persona id
        #[arg(long)]
        persona: Option<String>,
    },
    /// Show the full receipt for a given id
    Show {
        /// Receipt id (or grant id)
        id: String,
    },
    /// Export a receipt's signed JSON to stdout
    Export {
        /// Receipt id
        id: String,
    },
    /// Verify a receipt's Ed25519 signature against the daemon's identity key
    Verify {
        /// Receipt id
        id: String,
        /// Override the trust anchor — expected daemon pubkey (hex).
        /// When omitted, reads from the daemon's identity file under
        /// `<data_dir>/daemon_identity.key`.
        #[arg(long)]
        pubkey: Option<String>,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    /// Show recent audit entries
    Show {
        /// Filter by agent ID
        #[arg(long)]
        agent: Option<String>,
        /// Maximum number of entries
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// Export audit log
    Export {
        /// Output format (json or csv)
        #[arg(long, default_value = "json")]
        format: String,
        /// Maximum entries
        #[arg(long)]
        limit: Option<usize>,
        /// Filter by agent
        #[arg(long)]
        agent: Option<String>,
        /// Output file (stdout if not specified)
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Explain the full decision chain for an audit event
    Explain {
        /// Audit event ID
        id: String,
    },
}

/// Print the initial banner lines (version, socket, database, PID) immediately on startup.
/// Call `print_banner_dashboard` once the dashboard bind result is known.
fn print_banner_preamble(config: &DaemonConfig) {
    let version = env!("CARGO_PKG_VERSION");
    let socket = config.socket_dir.join("daemon.sock");
    let db = config.data_dir.join("daemon.db");
    let pid = std::process::id();

    eprintln!();
    eprintln!("  ember daemon v{version}");
    eprintln!("  The trust layer for AI agents");
    eprintln!();
    eprintln!("  Socket:    {}", socket.display());
    eprintln!("  Database:  {}", db.display());
    eprintln!("  PID:       {pid}");
}

/// Print the dashboard line of the banner, followed by the "Ctrl+C to stop" footer.
/// Called after the dashboard bind result is known (from the DashboardBind callback).
fn print_banner_dashboard(bind: &DashboardBind) {
    match bind {
        DashboardBind::Bound(addr) => {
            // Display loopback addresses as "localhost" for readability.
            if addr.ip().is_loopback() {
                eprintln!("  Dashboard: http://localhost:{}", addr.port());
            } else {
                eprintln!("  Dashboard: http://{addr}");
            }
        }
        DashboardBind::Failed { addr, error: _ } => {
            eprintln!("  Dashboard: unavailable (port {} in use)", addr.port());
        }
        DashboardBind::Disabled => {
            eprintln!("  Dashboard: disabled");
        }
        DashboardBind::Timeout => {
            eprintln!("  Dashboard: status unknown (startup timeout)");
        }
    }
    eprintln!();
    eprintln!("  Ctrl+C to stop");
    eprintln!();
}

fn effective_config_path(cli_config: Option<&PathBuf>) -> PathBuf {
    cli_config
        .cloned()
        .unwrap_or_else(DaemonConfig::default_config_path)
}

fn load_config(path: Option<&PathBuf>) -> DaemonConfig {
    match path {
        Some(p) => match DaemonConfig::load(p) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("error: failed to load config from {}: {e}", p.display());
                process::exit(1);
            }
        },
        None => {
            let default_path = DaemonConfig::default_config_path();
            if default_path.exists() {
                match DaemonConfig::load(&default_path) {
                    Ok(cfg) => cfg,
                    Err(e) => {
                        eprintln!(
                            "error: failed to load config from {}: {e}",
                            default_path.display()
                        );
                        process::exit(1);
                    }
                }
            } else {
                DaemonConfig::default()
            }
        }
    }
}

fn open_store(config: &DaemonConfig) -> DaemonStore {
    if let Err(e) = config.ensure_dirs() {
        eprintln!("error: failed to create directories: {e}");
        process::exit(1);
    }
    let db_path = config.data_dir.join("daemon.db");
    match DaemonStore::open(&db_path) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("error: failed to open database: {e}");
            process::exit(1);
        }
    }
}

/// Resolve an image digest via `docker inspect`. Returns None if docker is unavailable or fails.
fn resolve_image_digest(image: &str) -> Option<String> {
    let output = std::process::Command::new("docker")
        .args(["inspect", "--format={{.Id}}", image])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let digest = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if digest.is_empty() {
        None
    } else {
        Some(digest)
    }
}

/// Record an image digest into the registry at `registry_path`.
/// Prints a warning to stderr if the digest changed (tag mutation detected).
pub fn record_image_digest(registry_path: &Path, image: &str, digest: &str) {
    let mut registry = match ImageRegistry::load(registry_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("warning: could not load image registry: {e}");
            return;
        }
    };
    let already_known = registry.images.contains_key(image);
    let digest_changed = already_known && !registry.verify(image, digest);
    registry.record(image, digest, "docker");
    if let Err(e) = registry.save(registry_path) {
        eprintln!("warning: could not save image registry: {e}");
        return;
    }
    if digest_changed {
        eprintln!("warning: image {image} digest changed — possible tag mutation");
    }
}

fn cmd_init(
    config: &DaemonConfig,
    name: Option<String>,
    cli_config_path: Option<&PathBuf>,
    keyring_service_override: Option<String>,
    keyring_account_override: Option<String>,
) {
    // Respect --config: if the user passed one, use it as the init target;
    // otherwise fall back to the default (`~/.ember/config.toml`).
    let config_path = cli_config_path
        .cloned()
        .unwrap_or_else(DaemonConfig::default_config_path);

    if let Err(e) = config.ensure_dirs() {
        eprintln!("error: failed to create directories: {e}");
        process::exit(1);
    }

    // Determine the keyring service/account to embed in the config.
    // --keyring-service / --keyring-account flags override the defaults.
    let init_keyring_service = keyring_service_override
        .clone()
        .unwrap_or_else(|| DEFAULT_KEYRING_SERVICE.to_string());
    let init_keyring_account = keyring_account_override
        .clone()
        .unwrap_or_else(|| DEFAULT_KEYRING_ACCOUNT.to_string());

    // If the config file doesn't exist yet, write the default template.
    // If it already exists, respect the user's config and skip overwriting —
    // but refuse if a persona has already been created (truly already initialized).
    if !config_path.exists() {
        let default_config = format!(
            "\
# Ember daemon configuration

[daemon]
# socket_dir = \"~/.ember/run\"
# data_dir = \"~/.ember/data\"
log_level = \"info\"

[keyring]
service = \"{init_keyring_service}\"
account = \"{init_keyring_account}\"
"
        );
        if let Err(e) = fs::write(&config_path, &default_config) {
            eprintln!("error: failed to write config: {e}");
            process::exit(1);
        }
    }

    // Use the loaded config's policy_file path (respects --config + explicit overrides).
    let policy_path = config.policy_file.clone();
    if !policy_path.exists() {
        let default_policy = "\
# Ember daemon policy
# Rules evaluated in order — first match wins.

default_decision = \"require_approval\"
default_risk = \"medium\"

[[rules]]
action = \"git.push.main\"
risk = \"critical\"
decision = \"deny\"

[[rules]]
action = \"git.push.*\"
risk = \"medium\"
decision = \"auto_approve\"

[[rules]]
action = \"deploy.production\"
risk = \"critical\"
decision = \"require_approval\"

[[rules]]
action = \"deploy.staging\"
risk = \"medium\"
decision = \"auto_approve\"

[[rules]]
action = \"credential.access\"
risk = \"high\"
decision = \"require_approval\"
";
        if let Err(e) = fs::write(&policy_path, default_policy) {
            eprintln!("warning: failed to write policy: {e}");
        }
    }

    let store = open_store(config);
    let root_name = name.as_deref().unwrap_or("root");
    let persona = match store.create_persona(root_name) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: failed to create root persona: {e}");
            process::exit(1);
        }
    };

    let salt = Vault::generate_salt();
    let salt_path = config.data_dir.join("vault.salt");
    if let Err(e) = fs::write(&salt_path, salt) {
        eprintln!("warning: failed to write vault salt: {e}");
    }

    let service = init_keyring_service.clone();
    let account = init_keyring_account.clone();
    // Three-axis gate. `bin/ember.rs` is not covered by the gate inside
    // `resolve_passphrase` because it calls `keyring::Entry::new` directly.
    // Skipping here keeps `cargo test -p emberlink-cli --bin emberlink-cli`
    // from firing real keychain popups — that was the 2026-04-22 leak.
    if keyring_writes_suppressed() {
        println!("Initialized ember");
        println!("  Config:   {}", config_path.display());
        println!("  Policy:   {}", policy_path.display());
        println!("  Vault:    keyring write skipped (test/mock gate)");
        println!("  Persona:  {}", persona.name);
        return;
    }
    let vault_status = match keyring::Entry::new(&service, &account) {
        Ok(entry) => {
            // 32 chars from an alphanumeric alphabet (62 chars) → ~190 bits of entropy.
            // Rejection-sampled from OS entropy to avoid modulo bias. See the
            // matching implementation in ember-daemon::vault::generate_passphrase.
            const ALPHABET: &[u8; 62] =
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            let mut passphrase = String::with_capacity(32);
            let mut scratch = [0u8; 64];
            while passphrase.len() < 32 {
                getrandom::fill(&mut scratch).expect("OS entropy failure");
                for &b in &scratch {
                    if passphrase.len() == 32 {
                        break;
                    }
                    if b < 248 {
                        passphrase.push(ALPHABET[(b % 62) as usize] as char);
                    }
                }
            }
            match entry.set_password(&passphrase) {
                Ok(()) => {
                    match verify_keyring_roundtrip(&service, &account, &passphrase) {
                        Ok(()) => format!("passphrase stored in system keyring (service={service}, account={account})"),
                        Err(e) => {
                            eprintln!("  Vault:    keyring write succeeded but read-back failed ({e})");
                            eprintln!("           This usually means the keyring crate is using its in-memory mock backend.");
                            eprintln!("           Set EMBER_VAULT_PASSPHRASE env var to bypass the keyring.");
                            "keyring unavailable (see above)".to_string()
                        }
                    }
                }
                Err(e) => {
                    eprintln!("  Vault:    keyring unavailable ({e})");
                    eprintln!("           Set EMBER_VAULT_PASSPHRASE env var instead");
                    "keyring unavailable (see above)".to_string()
                }
            }
        }
        Err(e) => {
            eprintln!("  Vault:    keyring unavailable ({e})");
            eprintln!("           Set EMBER_VAULT_PASSPHRASE env var instead");
            "keyring unavailable (see above)".to_string()
        }
    };

    println!("Initialized ember");
    println!("  Config:   {}", config_path.display());
    println!("  Policy:   {}", policy_path.display());
    println!("  Database: {}", config.data_dir.join("daemon.db").display());
    println!("  Root:     {} ({})", persona.id, persona.name);
    println!("  Vault:    {vault_status}");
    println!();
    println!("Run `ember daemon start` to start the daemon.");
}

/// Install the ember daemon as a managed user service (LaunchAgent on macOS,
/// systemd user unit on Linux). See `daemon_agent` for the platform-specific
/// details. Prints a status summary on success; exits non-zero on failure.
fn cmd_daemon_install_agent(cli_config: Option<&PathBuf>, no_autostart: bool) {
    // Config path lookup: if the user passed --config, respect it; otherwise
    // fall back to the default (`~/.ember/config.toml`). We only pass a path
    // through to the plist/unit if the file actually exists — otherwise the
    // service would crash-loop on startup waiting for a config that isn't there.
    let config_path = cli_config
        .cloned()
        .or_else(|| {
            let default = DaemonConfig::default_config_path();
            if default.exists() { Some(default) } else { None }
        });

    match daemon_agent::install_agent(config_path.as_deref(), no_autostart) {
        Ok(outcome) => {
            if outcome.wrote_file {
                println!("Installed ember daemon as a user service");
            } else {
                println!("Service file already up to date (no changes)");
            }
            println!("  File:      {}", outcome.file_path.display());
            if let Ok(logs) = daemon_agent::logs_dir() {
                println!("  Logs:      {}/daemon.{{out,err}}", logs.display());
            }
            if outcome.bootstrapped {
                println!("  Status:    running (auto-start on login)");
            } else if no_autostart {
                println!("  Status:    installed, not started (--no-autostart)");
            } else {
                println!("  Status:    installed");
            }
            println!();
            println!("  Stop:      ember daemon stop            (graceful; service auto-restarts)");
            println!("  Reload:    ember daemon reload          (after rebuild)");
            println!("  Uninstall: ember daemon uninstall-agent");
        }
        Err(daemon_agent::AgentError::UnsupportedPlatform) => {
            eprintln!("error: ember daemon install-agent is only supported on macOS and Linux.");
            eprintln!("       Start the daemon manually with `ember daemon start --background`.");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("error: failed to install agent: {e}");
            process::exit(1);
        }
    }
}

/// Uninstall the managed user service. Idempotent — silently succeeds even if
/// nothing is currently installed.
fn cmd_daemon_uninstall_agent() {
    match daemon_agent::uninstall_agent() {
        Ok(outcome) => {
            if outcome.removed_file {
                println!("Uninstalled ember daemon user service");
                println!("  Removed: {}", outcome.file_path.display());
            } else {
                println!("ember daemon user service was not installed (nothing to remove)");
            }
            if outcome.unbootstrapped {
                println!("  Stopped: running service");
            }
        }
        Err(daemon_agent::AgentError::UnsupportedPlatform) => {
            eprintln!("error: not a managed-service platform — nothing to uninstall");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("error: failed to uninstall agent: {e}");
            process::exit(1);
        }
    }
}

/// Gracefully restart the running daemon. When the daemon is managed by
/// LaunchAgent/systemd, SIGTERM triggers an automatic restart with whatever
/// `ember` binary is on disk — this is the dev-rebuild-loop primitive.
///
/// When the daemon was started manually via `ember daemon start --background`,
/// `reload` falls back to re-spawning it in the same mode.
fn cmd_daemon_reload(config: &DaemonConfig, timeout_secs: u64, cli_config: Option<&PathBuf>) {
    let socket_path = config.socket_dir.join("daemon.sock");
    let pid_file = config.pid_file.clone();
    let managed_before = daemon_agent::is_managed_service();

    if !managed_before {
        // Best-effort: if the daemon was started manually (`--background`), try
        // to stop it and respawn it so the user isn't left with a dead daemon.
        match daemon_agent::reload_daemon(&pid_file, &socket_path, Duration::from_secs(timeout_secs))
        {
            Ok(_) => {
                // Shouldn't happen — if unmanaged, the daemon can't restart itself.
                // But if it did come back (e.g. user races install-agent), no harm.
                println!("Unexpected: unmanaged daemon reappeared after SIGTERM.");
            }
            Err(daemon_agent::AgentError::DaemonNotRunning) => {
                eprintln!("error: daemon is not running — run `ember daemon start` or `ember daemon install-agent`");
                process::exit(1);
            }
            Err(daemon_agent::AgentError::ReloadTimeout { .. }) => {
                // Expected: unmanaged daemon won't come back on its own.
                // Respawn it the same way the user originally started it.
                eprintln!("warning: daemon is not a managed service — spawning a fresh `--background` instance");
                let exe = match std::env::current_exe() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("error: could not resolve current exe: {e}");
                        process::exit(1);
                    }
                };
                let mut cmd = std::process::Command::new(exe);
                cmd.arg("daemon").arg("start").arg("--background");
                if let Some(path) = cli_config {
                    cmd.arg("--config").arg(path);
                }
                match cmd.spawn() {
                    Ok(_child) => {
                        println!("Respawned daemon with `ember daemon start --background`.");
                        println!("Tip: run `ember daemon install-agent` to make reload-on-SIGTERM automatic.");
                    }
                    Err(e) => {
                        eprintln!("error: failed to respawn daemon: {e}");
                        process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("error: reload failed: {e}");
                process::exit(1);
            }
        }
        return;
    }

    match daemon_agent::reload_daemon(&pid_file, &socket_path, Duration::from_secs(timeout_secs)) {
        Ok(outcome) => {
            let new_pid = outcome
                .new_pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "?".to_string());
            println!(
                "✓ ember daemon reloaded — old pid {}, new pid {}",
                outcome.old_pid, new_pid
            );
        }
        Err(daemon_agent::AgentError::DaemonNotRunning) => {
            eprintln!("error: daemon is not running — run `ember daemon start` or `ember daemon install-agent`");
            process::exit(1);
        }
        Err(daemon_agent::AgentError::ReloadTimeout { secs }) => {
            eprintln!("error: daemon did not come back up within {secs}s");
            if let Ok(logs) = daemon_agent::logs_dir() {
                let err_log = logs.join("daemon.err");
                let tail = daemon_agent::tail_file(&err_log, 20);
                if !tail.is_empty() {
                    eprintln!();
                    eprintln!("--- last 20 lines of {} ---", err_log.display());
                    eprintln!("{tail}");
                    eprintln!("--- end ---");
                }
            }
            process::exit(1);
        }
        Err(e) => {
            eprintln!("error: reload failed: {e}");
            process::exit(1);
        }
    }
}

/// Parse a decimal dollar string like "0.50" into integer cents (50).
/// Rejects negative values and non-numeric input.
fn parse_cents(s: &str) -> Result<u64, String> {
    let trimmed = s.trim();
    if trimmed.starts_with('-') {
        return Err("negative budget not allowed".to_string());
    }
    // Try parsing as a float and convert to integer cents.
    let val: f64 = trimmed
        .parse()
        .map_err(|_| format!("invalid decimal value '{s}'"))?;
    if val < 0.0 {
        return Err("negative budget not allowed".to_string());
    }
    // Round to nearest cent.
    Ok((val * 100.0).round() as u64)
}

/// Build a Budget from optional flag values. Returns None if no flag was set.
fn build_budget(
    tokens: Option<u64>,
    cents: Option<u64>,
    requests: Option<u64>,
    wall_clock_secs: Option<u64>,
) -> Option<Budget> {
    if tokens.is_none() && cents.is_none() && requests.is_none() && wall_clock_secs.is_none() {
        return None;
    }
    Some(Budget {
        tokens,
        cents,
        requests,
        wall_clock_secs,
        ..Budget::default()
    })
}

/// Build the 3-statement composite grant envelope for `ember sandbox run`.
///
/// Statement layout (per SESSION-composite-plan.md §Stream E):
///   1. Credential — `credential:read` on `<credential_resource>`, no budget.
///   2. Session    — `llm:generate` on `anthropic/*`, `budget.tokens = budget_tokens`.
///   3. Time       — `time:wall_clock` on `*`, `budget.wall_clock_secs = budget_seconds`.
///
/// When `credential_resource` is `None` the function returns an empty `Vec` so the
/// caller can skip grant creation for demo invocations that omit the flag.
/// When any budget flag is absent the corresponding budget axis is simply not set
/// (TTL-only for that statement).
pub fn build_composite_grant_statements(
    credential_resource: Option<&str>,
    budget_tokens: Option<u64>,
    budget_cents: Option<u64>,
    budget_seconds: Option<u64>,
) -> Vec<Statement> {
    let Some(cred_resource) = credential_resource else {
        return vec![];
    };

    // Statement 1: Credential — credential:read on the named object.
    let credential_stmt = Statement {
        sid: "s0-credential".to_string(),
        resource_type: ResourceType::Credential,
        actions: vec!["credential:read".to_string()],
        resource: ResourceSelector::Exact { value: cred_resource.to_string() },
        budget: None,
        usage: Usage::default(),
        conditions: vec![],
    };

    // Statement 2: Session — llm:generate on anthropic/*, token + cent budget.
    let session_budget = if budget_tokens.is_some() || budget_cents.is_some() {
        Some(Budget {
            tokens: budget_tokens,
            cents: budget_cents,
            ..Budget::default()
        })
    } else {
        None
    };
    let session_stmt = Statement {
        sid: "s1-session".to_string(),
        resource_type: ResourceType::Session,
        actions: vec!["llm:generate".to_string()],
        resource: ResourceSelector::Glob { pattern: "anthropic/*".to_string() },
        budget: session_budget,
        usage: Usage::default(),
        conditions: vec![],
    };

    // Statement 3: Time — time:wall_clock on *, wall_clock_secs budget.
    let time_budget = budget_seconds.map(|secs| Budget {
        wall_clock_secs: Some(secs),
        ..Budget::default()
    });
    let time_stmt = Statement {
        sid: "s2-time".to_string(),
        resource_type: ResourceType::Time,
        actions: vec!["time:wall_clock".to_string()],
        resource: ResourceSelector::Any,
        budget: time_budget,
        usage: Usage::default(),
        conditions: vec![],
    };

    vec![credential_stmt, session_stmt, time_stmt]
}

/// Parse a duration string (15s, 5m, 2h, 1d, or bare integer seconds).
fn parse_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('s') {
        n.parse::<u64>().map_err(|_| format!("invalid duration '{s}'"))
    } else if let Some(n) = s.strip_suffix('m') {
        n.parse::<u64>()
            .map(|v| v * 60)
            .map_err(|_| format!("invalid duration '{s}'"))
    } else if let Some(n) = s.strip_suffix('h') {
        n.parse::<u64>()
            .map(|v| v * 3600)
            .map_err(|_| format!("invalid duration '{s}'"))
    } else if let Some(n) = s.strip_suffix('d') {
        n.parse::<u64>()
            .map(|v| v * 86400)
            .map_err(|_| format!("invalid duration '{s}'"))
    } else {
        s.parse::<u64>()
            .map_err(|_| format!("invalid duration '{s}' (expected e.g. 15s, 5m, 2h, 1d, or bare seconds)"))
    }
}

/// Format a duration in seconds to a human-readable string.
fn format_duration(secs: u64) -> String {
    if secs.is_multiple_of(86400) {
        format!("{}d", secs / 86400)
    } else if secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{}s", secs)
    }
}

/// Truncate a string to `max` chars, adding an ellipsis if truncated.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// Resolve a receipt from either a receipt id (`rct-…`) or a grant id.
/// When the argument is a grant id, looks up the grant's `receipt_id`
/// and loads that.
fn resolve_receipt(
    store: &DaemonStore,
    id: &str,
) -> Result<core_types::grant_receipt::GrantReceipt, String> {
    if let Ok(r) = store.get_receipt(id) {
        return Ok(r);
    }
    match store.get_grant(id) {
        Ok(g) => {
            if let Some(rid) = g.receipt_id.as_deref() {
                store
                    .get_receipt(rid)
                    .map_err(|e| format!("grant has receipt_id={rid} but load failed: {e}"))
            } else {
                Err(format!(
                    "no receipt found for id '{id}' (grant exists but has not reached terminal state)"
                ))
            }
        }
        Err(_) => Err(format!("no receipt or grant found for id '{id}'")),
    }
}

/// Pretty-print a receipt to stdout in human-readable form.
fn print_receipt_summary(r: &core_types::grant_receipt::GrantReceipt) {
    use core_types::grant_receipt::{RevokeActor, TerminalReason};

    println!("Grant Receipt {}", r.id);
    println!("  Grant:       {}", r.grant_id);
    println!("  Persona:     {}", r.summary.persona_id);
    println!("  Owner:       {}", r.summary.human_owner);
    println!("  Service:     {}", r.summary.service);
    println!("  Resource:    {}", r.summary.resource);
    println!();
    println!("  Lifecycle:");
    println!("    Issued at:     epoch {}", r.lifecycle.issued_at);
    if let Some(lu) = r.lifecycle.last_used_at {
        println!("    Last used:     epoch {lu}");
    } else {
        println!("    Last used:     never");
    }
    println!("    Terminated at: epoch {}", r.lifecycle.terminated_at);
    let reason_str = match &r.lifecycle.terminal_reason {
        TerminalReason::Expired => "expired (TTL)".to_string(),
        TerminalReason::Revoked { by, reason } => {
            let actor = match by {
                RevokeActor::Operator => "operator",
                RevokeActor::Agent => "agent",
                RevokeActor::ParentCascade => "parent cascade",
            };
            if reason.is_empty() {
                format!("revoked by {actor}")
            } else {
                format!("revoked by {actor}: {reason}")
            }
        }
        TerminalReason::ExhaustedByBudget { statement_sid, axis } => {
            format!("exhausted_by_budget on statement {statement_sid} axis={axis:?}")
        }
        TerminalReason::ParentCascadeRevoked { parent_grant_id } => {
            format!("parent_cascade_revoked (parent={parent_grant_id})")
        }
    };
    println!("    Terminal reason: {reason_str}");
    println!();
    println!("  Per-Statement usage:");
    if r.per_statement_usage.is_empty() {
        println!("    (none)");
    } else {
        for (sid, u) in &r.per_statement_usage {
            println!(
                "    {sid:<8} tokens={:<8} cents={:<6} requests={:<6} wall_clock={}s",
                u.tokens, u.cents, u.requests, u.wall_clock_secs
            );
        }
    }
    println!();
    println!("  Evidence:");
    println!("    Signer pubkey: {}", r.evidence.signer_pubkey);
    println!("    Hash:          {}", r.evidence.hash);
    println!("    Signature:     {}", r.evidence.sig);
    println!("    Canonical v{}", r.evidence.canonical_version);
    println!();
    println!("  Chain snapshot: {} block(s)", r.approved_chain.len());
    println!("  Approval chain: {} event(s)", r.approval_chain.len());
    println!("  Actions observed: {} entry(ies)", r.actions_observed.len());
}

/// Render budget and usage for a grant.
fn cmd_grant_budget(info: &GrantInfo) {
    use std::time::{SystemTime, UNIX_EPOCH};

    println!("Grant {}", info.id);
    println!("  Persona: {}", info.persona_id);
    println!("  Scope:   {}", info.scope);
    println!("  Status:  {}", info.status);

    if let Some(ref exp) = info.expires_at {
        // Try to show remaining TTL
        if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(exp) {
            let remaining = parsed.timestamp() - chrono::Utc::now().timestamp();
            if remaining > 0 {
                println!("  TTL:     {}m remaining", remaining / 60);
            } else {
                println!("  TTL:     expired");
            }
        } else {
            println!("  TTL:     {exp}");
        }
    } else {
        println!("  TTL:     never");
    }

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if let Some(ref budget) = info.budget {
        println!("  Budget:");
        if let Some(bt) = budget.tokens {
            let used = info.usage.tokens;
            let pct = (used * 100).checked_div(bt).unwrap_or(0);
            println!("    tokens:   {:>9} / {:>9} ({}%)", used, bt, pct);
        }
        if let Some(bc) = budget.cents {
            let used = info.usage.cents;
            let pct = (used * 100).checked_div(bc).unwrap_or(0);
            println!("    cents:    {:>9} / {:>9} ({}%)", used, bc, pct);
        }
        if let Some(br) = budget.requests {
            let used = info.usage.requests;
            let pct = (used * 100).checked_div(br).unwrap_or(0);
            println!("    requests: {:>9} / {:>9} ({}%)", used, br, pct);
        }

        // Compute runway if usage is recent (last_updated within 5 minutes and non-zero)
        let last_updated = info.usage.last_updated;
        let age_secs = if last_updated > 0 && now_secs >= last_updated {
            now_secs - last_updated
        } else {
            u64::MAX
        };
        let stale = age_secs > 300 || last_updated == 0;

        if !stale {
            let minutes_elapsed = age_secs as f64 / 60.0;
            println!("  Runway:");
            if let Some(bt) = budget.tokens {
                let used = info.usage.tokens;
                if used > 0 && bt > used {
                    let rate = used as f64 / minutes_elapsed;
                    let remaining_min = (bt - used) as f64 / rate;
                    println!("    tokens:   ~{}m", remaining_min.round() as u64);
                } else {
                    println!("    tokens:   —");
                }
            }
            if let Some(bc) = budget.cents {
                let used = info.usage.cents;
                if used > 0 && bc > used {
                    let rate = used as f64 / minutes_elapsed;
                    let remaining_min = (bc - used) as f64 / rate;
                    println!("    cents:    ~{}m", remaining_min.round() as u64);
                } else {
                    println!("    cents:    —");
                }
            }
        } else {
            println!("  Runway:  —");
        }
    } else {
        println!("  Budget:  (none)");
    }
}

fn main() {
    let cli = Cli::parse();
    let config = load_config(cli.config.as_ref());

    match cli.command {
        Commands::Init { name, keyring_service, keyring_account } => {
            cmd_init(&config, name, cli.config.as_ref(), keyring_service, keyring_account)
        }

        Commands::Daemon { action } => match action {
            DaemonAction::Start { background, foreground: _ } => {
                if background {
                    if let Err(e) = config.ensure_dirs() {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                    let log_path = config.data_dir.join("daemon.log");
                    let log_file = fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&log_path)
                        .expect("open log file");
                    let err_file = log_file.try_clone().expect("clone log file");

                    let exe = std::env::current_exe().expect("current exe");
                    let mut cmd = std::process::Command::new(exe);
                    cmd.arg("daemon").arg("start");
                    if let Some(ref config_path) = cli.config {
                        cmd.arg("--config").arg(config_path);
                    }
                    cmd.stdout(log_file)
                        .stderr(err_file)
                        .stdin(std::process::Stdio::null());

                    let child = cmd.spawn().expect("spawn daemon");
                    println!("Daemon started in background (PID {})", child.id());
                    println!("  Log: {}", log_path.display());
                    #[allow(clippy::zombie_processes)]
                    std::mem::forget(child);
                    return;
                }

                tracing_subscriber::fmt()
                    .with_env_filter(
                        EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| EnvFilter::new(config.log_level.as_filter_str())),
                    )
                    .init();

                // Print everything except the dashboard line up-front.
                print_banner_preamble(&config);

                let runtime = match &cli.config {
                    Some(p) => DaemonRuntime::new_with_config_path(config, p.clone()),
                    None => {
                        let default_path = DaemonConfig::default_config_path();
                        if default_path.exists() {
                            DaemonRuntime::new_with_config_path(config, default_path)
                        } else {
                            DaemonRuntime::new(config)
                        }
                    }
                };
                let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

                // The start_notify callback fires from inside the async runtime once
                // the dashboard bind result is known (within 2 seconds of startup).
                // It prints the dashboard banner line + footer from the tokio thread,
                // which is fine because eprintln! is synchronous and we're not in
                // an async context that cares about thread identity.
                let notify: Box<dyn FnOnce(DashboardBind)> =
                    Box::new(|bind| print_banner_dashboard(&bind));

                if let Err(e) = rt.block_on(runtime.run(Some(notify))) {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
            }
            DaemonAction::Stop => {
                let runtime = DaemonRuntime::new(config);
                match runtime.stop() {
                    Ok(pid) => println!("Stopped ember daemon (PID {pid})"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                }
            }
            DaemonAction::Status => {
                let runtime = DaemonRuntime::new(config);
                match runtime.status() {
                    Ok(status) => {
                        if status.running {
                            println!("ember daemon is running");
                            println!("  PID:    {}", status.pid);
                            println!("  Socket: {}", status.socket.display());
                        } else {
                            println!("ember daemon is not running (stale PID {})", status.pid);
                            process::exit(1);
                        }
                    }
                    Err(_) => {
                        println!("ember daemon is not running");
                        process::exit(1);
                    }
                }
            }
            DaemonAction::Reload { timeout } => {
                cmd_daemon_reload(&config, timeout, cli.config.as_ref());
            }
            DaemonAction::InstallAgent { no_autostart } => {
                cmd_daemon_install_agent(cli.config.as_ref(), no_autostart);
            }
            DaemonAction::UninstallAgent => {
                cmd_daemon_uninstall_agent();
            }
        },

        Commands::Persona { action } => {
            let store = open_store(&config);
            match action {
                PersonaAction::Create { name } => match store.create_persona(&name) {
                    Ok(info) => {
                        println!("Created persona");
                        println!("  ID:         {}", info.id);
                        println!("  Name:       {}", info.name);
                        println!("  Public key: {}", info.public_key);
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                PersonaAction::List => match store.list_personas() {
                    Ok(personas) => {
                        if cli.json {
                            let arr: Vec<_> = personas.iter().map(|p| {
                                serde_json::json!({
                                    "id": p.id,
                                    "name": p.name,
                                    "status": p.status,
                                    "public_key": p.public_key,
                                })
                            }).collect();
                            println!("{}", serde_json::to_string_pretty(&arr).unwrap());
                        } else if personas.is_empty() {
                            println!("No personas");
                        } else {
                            for p in &personas {
                                let status_marker = if p.status == "revoked" {
                                    " [revoked]"
                                } else {
                                    ""
                                };
                                println!("{} ({}){}", p.name, p.id, status_marker);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                PersonaAction::Revoke { id } => match store.revoke_persona(&id) {
                    Ok(()) => println!("Revoked persona {id}"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
            }
        }

        Commands::Vault { action } => {
            let store = open_store(&config);
            let vault = Vault::open_from_config(&config)
                .expect("failed to resolve vault — is the daemon initialized?");

            match action {
                VaultAction::Add {
                    name,
                    value,
                    metadata,
                } => match vault.add(&store, &name, value.as_bytes(), metadata.as_deref()) {
                    Ok(info) => {
                        println!("Stored credential");
                        println!("  ID:   {}", info.id);
                        println!("  Name: {}", info.name);
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                VaultAction::List => match vault.list(&store) {
                    Ok(creds) => {
                        if cli.json {
                            let arr: Vec<_> = creds.iter().map(|c| {
                                serde_json::json!({
                                    "id": c.id,
                                    "name": c.name,
                                    "metadata": c.metadata,
                                })
                            }).collect();
                            println!("{}", serde_json::to_string_pretty(&arr).unwrap());
                        } else if creds.is_empty() {
                            println!("No credentials in vault");
                        } else {
                            for c in &creds {
                                let meta = c
                                    .metadata
                                    .as_deref()
                                    .map(|m| format!(" ({m})"))
                                    .unwrap_or_default();
                                println!("{}{}", c.name, meta);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                VaultAction::Get { name } => match vault.get(&store, &name) {
                    Ok(value) => {
                        let text = String::from_utf8_lossy(&value);
                        println!("{text}");
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                VaultAction::Remove { name } => match vault.remove(&store, &name) {
                    Ok(()) => println!("Removed credential {name}"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
            }
        }

        Commands::Grant { action } => {
            let store = open_store(&config);
            match action {
                GrantAction::Create {
                    persona,
                    credential,
                    scope,
                    ttl,
                    rate_limit,
                    hours_start,
                    hours_end,
                    allowed_targets,
                    delegation_depth,
                    budget_tokens,
                    budget_cents,
                    budget_requests,
                    budget_seconds,
                    attestation_runtime,
                } => {
                    let parsed_cents = match budget_cents.as_deref() {
                        Some(s) => match parse_cents(s) {
                            Ok(c) => Some(c),
                            Err(e) => {
                                eprintln!("error: --budget-cents: {e}");
                                process::exit(1);
                            }
                        },
                        None => None,
                    };
                    let budget = build_budget(budget_tokens, parsed_cents, budget_requests, budget_seconds);
                    match store.create_grant(&persona, &credential, &scope, ttl) {
                    Ok(info) => {
                        // Apply conditions via UPDATE if any are set
                        let targets_json = allowed_targets.as_ref().map(|t| {
                            let targets: Vec<&str> = t.split(',').collect();
                            serde_json::to_string(&targets).unwrap_or_default()
                        });
                        let budget_json = budget.as_ref().map(|b| serde_json::to_string(b).expect("Budget serializes"));
                        let attestation_json = attestation_runtime.as_ref().map(|r| {
                            serde_json::to_string(&serde_json::json!({"status": "unattested_local_dev", "runtime": r})).unwrap_or_default()
                        });
                        if rate_limit.is_some()
                            || hours_start.is_some()
                            || targets_json.is_some()
                            || delegation_depth.is_some()
                            || budget_json.is_some()
                            || attestation_json.is_some()
                        {
                            let _ = store.conn().execute(
                                "UPDATE grants SET max_uses_per_hour=?1, allowed_hours_start=?2, allowed_hours_end=?3, allowed_targets=?4, max_delegation_depth=?5, budget_json=?6 WHERE id=?7",
                                rusqlite::params![
                                    rate_limit.map(|v| v as i64),
                                    hours_start.map(|v| v as i64),
                                    hours_end.map(|v| v as i64),
                                    targets_json,
                                    delegation_depth.map(|v| v as i64),
                                    budget_json,
                                    info.id,
                                ],
                            );
                        }
                        println!("Created grant");
                        println!("  ID:         {}", info.id);
                        println!("  Persona:    {}", info.persona_id);
                        println!("  Credential: {}", info.credential_name);
                        println!("  Scope:      {}", info.scope);
                        if let Some(exp) = &info.expires_at {
                            println!("  Expires:    {exp}");
                        } else {
                            println!("  Expires:    never");
                        }
                        if let Some(rl) = rate_limit {
                            println!("  Rate limit: {rl}/hour");
                        }
                        if let Some(hs) = hours_start {
                            println!("  Hours:      {hs}:00-{}:00 UTC", hours_end.unwrap_or(0));
                        }
                        if let Some(ref t) = allowed_targets {
                            println!("  Targets:    {t}");
                        }
                        if let Some(d) = delegation_depth {
                            println!("  Delegation: max depth {d}");
                        }
                        if let Some(ref b) = budget {
                            if let Some(t) = b.tokens {
                                println!("  Budget:     {} tokens", t);
                            }
                            if let Some(c) = b.cents {
                                println!("  Budget:     ${:.2}", c as f64 / 100.0);
                            }
                            if let Some(r) = b.requests {
                                println!("  Budget:     {} requests", r);
                            }
                            if let Some(s) = b.wall_clock_secs {
                                println!("  Budget:     {}s wall-clock", s);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                    }
                }
                GrantAction::Delegate {
                    parent,
                    persona,
                    scope,
                    ttl,
                } => match store.delegate_grant(&parent, &persona, &scope, ttl) {
                    Ok(info) => {
                        println!("Delegated grant");
                        println!("  ID:     {}", info.id);
                        println!("  Parent: {}", parent);
                        println!("  Scope:  {}", info.scope);
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                GrantAction::List { active } => {
                    let grants = if active {
                        store.list_active_grants()
                    } else {
                        store.list_grants()
                    };
                    match grants {
                        Ok(list) => {
                            if cli.json {
                                let arr: Vec<_> = list.iter().map(|g| {
                                    serde_json::json!({
                                        "id": g.id,
                                        "persona_id": g.persona_id,
                                        "credential_name": g.credential_name,
                                        "scope": g.scope,
                                        "status": g.status,
                                        "expires_at": g.expires_at,
                                    })
                                }).collect();
                                println!("{}", serde_json::to_string_pretty(&arr).unwrap());
                            } else if list.is_empty() {
                                println!("No grants");
                            } else {
                                for g in &list {
                                    let exp = g.expires_at.as_deref().unwrap_or("never");
                                    let status = if g.status == "revoked" {
                                        " [revoked]"
                                    } else {
                                        ""
                                    };
                                    println!(
                                        "{} {} → {} ({}){} expires {}",
                                        g.id, g.persona_id, g.credential_name, g.scope, status, exp
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                GrantAction::Revoke { id } => match store.revoke_grant(&id) {
                    Ok(()) => println!("Revoked grant {id}"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                GrantAction::Expire => match store.expire_stale_grants() {
                    Ok(count) => println!("Expired {} stale grant(s)", count),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                GrantAction::Budget { grant_id } => match store.get_grant(&grant_id) {
                    Ok(info) => cmd_grant_budget(&info),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                GrantAction::Extend { grant_id, tokens, cents, ttl } => {
                    let parsed_cents = match cents.as_deref() {
                        Some(s) => match parse_cents(s) {
                            Ok(c) => Some(c),
                            Err(e) => {
                                eprintln!("error: --cents: {e}");
                                process::exit(1);
                            }
                        },
                        None => None,
                    };
                    let ttl_secs = match ttl.as_deref() {
                        Some(s) => match parse_duration(s) {
                            Ok(secs) => Some(secs),
                            Err(e) => {
                                eprintln!("error: --ttl: {e}");
                                process::exit(1);
                            }
                        },
                        None => None,
                    };
                    match store.extend_grant(&grant_id, tokens, parsed_cents, ttl_secs) {
                        Ok(_) => {
                            let mut parts = Vec::new();
                            if let Some(t) = tokens {
                                parts.push(format!("+{} tokens", t));
                            }
                            if let Some(c) = parsed_cents {
                                parts.push(format!("+${:.2}", c as f64 / 100.0));
                            }
                            if let Some(s) = ttl_secs {
                                parts.push(format!("+{}", format_duration(s)));
                            }
                            if parts.is_empty() {
                                println!("Extended: (no changes)");
                            } else {
                                println!("Extended: {}", parts.join(", "));
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                },
            }
        }

        Commands::Sandbox { action } => {
            let store = open_store(&config);
            match action {
                SandboxAction::Create {
                    name,
                    image,
                    privileged,
                    volume,
                    user,
                    network,
                    unsafe_root,
                    workspace_from,
                    env,
                } => {
                    let extra_env: Vec<(String, String)> = env
                        .iter()
                        .filter_map(|kv| {
                            kv.split_once('=').map(|(k, v)| (k.to_string(), v.to_string()))
                        })
                        .collect();
                    let opts = SandboxCreateOpts {
                        name: name.clone(),
                        image: image.clone(),
                        privileged,
                        volumes: volume.clone(),
                        user: user.clone(),
                        network: network.clone(),
                        unsafe_root,
                        workspace_from: workspace_from.clone(),
                        extra_env: extra_env.clone(),
                    };
                    let sandbox = match store
                        .create_sandbox_with_opts(&opts, Some(&config.data_dir))
                    {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };
                    let container_id = match store.start_container(
                        &sandbox.id,
                        &config.socket_dir,
                        network.as_deref(),
                        &extra_env,
                    ) {
                        Ok(cid) => cid,
                        Err(e) => {
                            eprintln!("warning: sandbox created but container failed: {e}");
                            "none".to_string()
                        }
                    };
                    // Record image digest to ~/.ember/images.toml
                    let registry_path = config.data_dir.join("images.toml");
                    match resolve_image_digest(&image) {
                        Some(digest) => {
                            record_image_digest(&registry_path, &image, &digest);
                        }
                        None => {
                            eprintln!("warning: could not resolve image digest for {image} — docker may not be available");
                        }
                    }
                    println!("Created sandbox");
                    println!("  ID:        {}", sandbox.id);
                    println!("  Persona:   {}", sandbox.persona_id);
                    println!("  Container: {container_id}");
                    if let Some(ws) = &sandbox.workspace_path {
                        println!("  Workspace: {ws}");
                    }
                }
                SandboxAction::List => match store.list_sandboxes() {
                    Ok(sandboxes) => {
                        if sandboxes.is_empty() {
                            println!("No sandboxes");
                        } else {
                            for s in &sandboxes {
                                let cid = s.container_id.as_deref().unwrap_or("-");
                                println!(
                                    "{} {} [{}] persona={} container={}",
                                    s.id, s.name, s.status, s.persona_id, cid
                                );
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                SandboxAction::Stop { id } => match store.stop_sandbox(&id) {
                    Ok(()) => println!("Stopped sandbox {id}"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                SandboxAction::Exec { id, command } => {
                    let refs: Vec<&str> = command.iter().map(String::as_str).collect();
                    match store.exec_sandbox(&id, &refs) {
                        Ok(output) => print!("{output}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                SandboxAction::Run {
                    name,
                    image,
                    workspace_from,
                    env,
                    credential_resource,
                    budget_tokens,
                    budget_cents: budget_cents_str,
                    budget_seconds,
                    ttl,
                    prompt,
                } => {
                    // Parse --budget-cents into integer cents.
                    let parsed_cents = match budget_cents_str.as_deref() {
                        Some(s) => match parse_cents(s) {
                            Ok(c) => Some(c),
                            Err(e) => {
                                eprintln!("error: --budget-cents: {e}");
                                process::exit(1);
                            }
                        },
                        None => None,
                    };

                    // Build the 3-statement composite envelope.
                    let statements = build_composite_grant_statements(
                        credential_resource.as_deref(),
                        budget_tokens,
                        parsed_cents,
                        budget_seconds,
                    );
                    let statement_count = statements.len();

                    // Parse TTL.
                    let ttl_secs = match ttl.as_deref() {
                        Some(s) => match parse_duration(s) {
                            Ok(v) => Some(v),
                            Err(e) => {
                                eprintln!("error: --ttl: {e}");
                                process::exit(1);
                            }
                        },
                        None => None,
                    };

                    // Build sandbox opts.
                    let extra_env: Vec<(String, String)> = env
                        .iter()
                        .filter_map(|kv| {
                            if let Some((k, v)) = kv.split_once('=') {
                                Some((k.to_string(), v.to_string()))
                            } else {
                                // Bare key — pass-through from host environment.
                                std::env::var(kv).ok().map(|v| (kv.clone(), v))
                            }
                        })
                        .collect();

                    let opts = SandboxCreateOpts {
                        name: name.clone(),
                        image: image.clone(),
                        privileged: false,
                        volumes: vec![],
                        user: None,
                        network: None,
                        unsafe_root: false,
                        workspace_from: workspace_from.clone(),
                        extra_env: extra_env.clone(),
                    };

                    let sandbox = match store.create_sandbox_with_opts(&opts, Some(&config.data_dir)) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };

                    // Start the container.
                    let container_id = match store.start_container(
                        &sandbox.id,
                        &config.socket_dir,
                        None,
                        &extra_env,
                    ) {
                        Ok(cid) => cid,
                        Err(e) => {
                            eprintln!("warning: sandbox created but container failed: {e}");
                            "none".to_string()
                        }
                    };

                    println!("Started sandbox");
                    println!("  ID:        {}", sandbox.id);
                    println!("  Persona:   {}", sandbox.persona_id);
                    println!("  Container: {container_id}");
                    if let Some(ws) = &sandbox.workspace_path {
                        println!("  Workspace: {ws}");
                    }

                    // Mint the composite grant if a credential resource was supplied.
                    if statement_count > 0 {
                        let credential_res = credential_resource.as_deref().unwrap_or("");
                        match store.create_grant(
                            &sandbox.persona_id,
                            credential_res,
                            "composite",
                            ttl_secs,
                        ) {
                            Ok(grant_info) => {
                                // Replace the single-statement shim create_grant wrote with
                                // the canonical 3-statement envelope in blocks_json so the
                                // dashboard + handler emit per-Statement arrays.
                                let created_at_epoch =
                                    chrono::Utc::now().timestamp().max(0) as u64;
                                let expires_at_epoch = ttl_secs.map(|s| {
                                    created_at_epoch.saturating_add(s)
                                });
                                // Block 0 is signed under the sandbox
                                // persona's root Ed25519 key — the daemon
                                // owns that key material so the CLI looks it
                                // up from the same store it writes through.
                                let composite_result = store
                                    .persona_root_keypair(&sandbox.persona_id)
                                    .and_then(|root| {
                                        ember_daemon::grant::access_grant_from_statements(
                                            &grant_info.id,
                                            &sandbox.persona_id,
                                            credential_res,
                                            statements.clone(),
                                            created_at_epoch,
                                            expires_at_epoch,
                                            &root,
                                        )
                                    });
                                match composite_result {
                                    Ok(composite) => {
                                        if let Err(e) =
                                            store.overwrite_grant_blocks(&grant_info.id, &composite)
                                        {
                                            eprintln!(
                                                "warning: grant minted but composite chain overwrite failed: {e}"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "warning: grant minted but composite chain signing failed: {e}"
                                        );
                                    }
                                }
                                println!("Minted 3-statement composite grant");
                                println!("  Grant ID:   {}", grant_info.id);
                                println!("  Statements: {statement_count}");
                                println!("    [0] credential:read  on {credential_res}");
                                if let Some(t) = budget_tokens {
                                    println!("    [1] llm:generate     on anthropic/*  budget={t} tokens");
                                } else {
                                    println!("    [1] llm:generate     on anthropic/*  (no token budget)");
                                }
                                if let Some(s) = budget_seconds {
                                    println!("    [2] time:wall_clock  on *             budget={s}s");
                                } else {
                                    println!("    [2] time:wall_clock  on *             (no time budget)");
                                }
                                println!("  One approval. Three meters. One receipt at the end.");
                                if let Some(ref p) = prompt {
                                    println!("  Prompt: {p}");
                                }
                            }
                            Err(e) => {
                                eprintln!("warning: sandbox started but grant creation failed: {e}");
                            }
                        }
                    } else {
                        println!("  (no --credential-resource supplied — grant not minted)");
                    }
                }
            }
        }

        Commands::Approval { action } => {
            let store = open_store(&config);
            match action {
                ApprovalAction::List => match store.list_pending_approvals() {
                    Ok(requests) => {
                        if requests.is_empty() {
                            println!("No pending approvals");
                        } else {
                            for r in &requests {
                                println!(
                                    "{} {} → {} ({}) [{}]",
                                    r.id, r.persona_id, r.credential_name, r.action, r.risk_level
                                );
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                ApprovalAction::Approve { id, always, ttl } => {
                    let outcome = if always {
                        let expires_at = match ttl.as_deref() {
                            Some("never") => {
                                eprintln!("warning: standing grant has no expiry (--ttl never)");
                                None
                            }
                            Some(s) => {
                                let days: i64 = if let Some(d) = s.strip_suffix('d') {
                                    d.parse().unwrap_or_else(|_| {
                                        eprintln!("error: invalid --ttl value '{s}'; expected e.g. 7d, 30d, never");
                                        process::exit(1);
                                    })
                                } else {
                                    eprintln!("error: invalid --ttl value '{s}'; expected e.g. 7d, 30d, never");
                                    process::exit(1);
                                };
                                let exp = chrono::Utc::now() + chrono::Duration::days(days);
                                Some(exp.format("%Y-%m-%dT%H:%M:%S").to_string())
                            }
                            None => {
                                // Default: 30 days
                                let exp = chrono::Utc::now() + chrono::Duration::days(30);
                                Some(exp.format("%Y-%m-%dT%H:%M:%S").to_string())
                            }
                        };
                        ApprovalOutcome::Always {
                            scope: None,
                            expires_at,
                        }
                    } else {
                        ApprovalOutcome::Approved
                    };
                    match store.resolve_approval(&id, &outcome) {
                        Ok(()) => {
                            if always {
                                println!("Approved {id}");
                                println!("  Standing grant created: future requests for this action will auto-approve.");
                                println!("  Review: ember grant standing list");
                            } else {
                                println!("Approved {id}");
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                ApprovalAction::Deny { id, reason } => {
                    match store
                        .resolve_approval(&id, &ApprovalOutcome::Denied { reason: reason.clone() })
                    {
                        Ok(()) => println!("Denied {id}: {reason}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                ApprovalAction::Narrow { id, scope } => {
                    match store.resolve_approval(
                        &id,
                        &ApprovalOutcome::Narrowed {
                            new_scope: scope.clone(),
                        },
                    ) {
                        Ok(()) => println!("Narrowed {id} to scope: {scope}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
            }
        }

        Commands::Audit { action } => {
            let store = open_store(&config);
            match action {
                AuditAction::Show { agent, limit } => {
                    let filter = AuditFilter {
                        agent_id: agent,
                        limit: Some(limit),
                        ..Default::default()
                    };
                    match store.query_audit(&filter) {
                        Ok(entries) => {
                            if cli.json {
                                let arr: Vec<_> = entries.iter().map(|e| {
                                    serde_json::json!({
                                        "timestamp": e.timestamp,
                                        "agent_id": e.agent_id,
                                        "action": e.action,
                                        "credential": e.credential,
                                        "outcome": e.outcome,
                                    })
                                }).collect();
                                println!("{}", serde_json::to_string_pretty(&arr).unwrap());
                            } else if entries.is_empty() {
                                println!("No audit entries");
                            } else {
                                for e in &entries {
                                    let agent = e.agent_id.as_deref().unwrap_or("-");
                                    let cred = e.credential.as_deref().unwrap_or("-");
                                    println!(
                                        "{} {} {} {} {}",
                                        e.timestamp, agent, e.action, cred, e.outcome
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                AuditAction::Export { format, limit, agent, output } => {
                    let filter = AuditFilter {
                        agent_id: agent,
                        limit,
                        ..Default::default()
                    };
                    let entries = store.query_audit(&filter).unwrap_or_default();

                    let content = match format.as_str() {
                        "csv" => {
                            let mut lines = vec!["timestamp,agent_id,action,credential,outcome,details".to_string()];
                            for e in &entries {
                                lines.push(format!("{},{},{},{},{},{}",
                                    e.timestamp,
                                    e.agent_id.as_deref().unwrap_or(""),
                                    e.action,
                                    e.credential.as_deref().unwrap_or(""),
                                    e.outcome,
                                    e.details.as_deref().unwrap_or(""),
                                ));
                            }
                            lines.join("\n")
                        }
                        _ => serde_json::to_string_pretty(&entries.iter().map(|e| {
                            serde_json::json!({
                                "timestamp": e.timestamp,
                                "agent_id": e.agent_id,
                                "action": e.action,
                                "credential": e.credential,
                                "outcome": e.outcome,
                                "details": e.details,
                            })
                        }).collect::<Vec<_>>()).unwrap_or_default(),
                    };

                    match output {
                        Some(path) => {
                            fs::write(&path, &content).expect("write output file");
                            eprintln!("Exported {} entries to {}", entries.len(), path.display());
                        }
                        None => println!("{content}"),
                    }
                }
                AuditAction::Explain { id } => {
                    let filter = AuditFilter { limit: Some(1000), ..Default::default() };
                    let entries = store.query_audit(&filter).unwrap_or_default();
                    let entry = entries.iter().find(|e| e.id.to_string() == id);

                    match entry {
                        Some(e) => {
                            println!("EVENT {}", e.id);
                            println!("  Timestamp:  {}", e.timestamp);
                            println!("  Agent:      {}", e.agent_id.as_deref().unwrap_or("-"));
                            println!("  Action:     {}", e.action);
                            println!("  Credential: {}", e.credential.as_deref().unwrap_or("-"));
                            println!("  Outcome:    {}", e.outcome);
                            if let Some(ref details) = e.details {
                                println!("  Details:    {}", details);
                            }
                            println!();

                            if let Some(ref cred) = e.credential
                                && let Some(ref agent) = e.agent_id
                            {
                                match store.evaluate_grant(agent, cred) {
                                    Ok(grant) => {
                                        println!("GRANT {}", grant.id);
                                        println!("  Scope:      {}", grant.scope);
                                        println!("  Created:    {}", grant.created_at);
                                        println!("  Expires:    {}", grant.expires_at.as_deref().unwrap_or("never"));
                                        println!("  Status:     {}", grant.status);
                                    }
                                    Err(_) => println!("GRANT: no active grant found"),
                                }
                            }
                            println!();

                            let policy_path = effective_config_path(cli.config.as_ref())
                                .parent()
                                .unwrap()
                                .join("policy.toml");
                            let engine = if policy_path.exists() {
                                ember_daemon::policy::PolicyEngine::from_file(&policy_path)
                                    .unwrap_or_default()
                            } else {
                                ember_daemon::policy::PolicyEngine::default()
                            };
                            let eval = engine.evaluate(&e.action);
                            println!("POLICY");
                            println!("  Decision:   {:?}", eval.decision);
                            println!("  Risk:       {:?}", eval.risk);
                            println!("  Rule:       {}", eval.matched_rule.as_deref().unwrap_or("(default)"));
                        }
                        None => {
                            eprintln!("Event {} not found", id);
                            process::exit(1);
                        }
                    }
                }
            }
        }

        Commands::Receipt { action } => {
            let store = open_store(&config);
            match action {
                ReceiptAction::List { persona } => {
                    let receipts = match store.list_receipts(persona.as_deref()) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&receipts).unwrap_or_default());
                    } else if receipts.is_empty() {
                        println!("No receipts found.");
                    } else {
                        let h_receipt = "RECEIPT";
                        let h_grant = "GRANT";
                        let h_persona = "PERSONA";
                        let h_reason = "REASON";
                        println!(
                            "{h_receipt:<30} {h_grant:<38} {h_persona:<22} {h_reason}"
                        );
                        for r in &receipts {
                            let reason_short = match &r.lifecycle.terminal_reason {
                                core_types::grant_receipt::TerminalReason::Expired => "expired".to_string(),
                                core_types::grant_receipt::TerminalReason::Revoked { .. } => "revoked".to_string(),
                                core_types::grant_receipt::TerminalReason::ExhaustedByBudget { .. } => "exhausted".to_string(),
                                core_types::grant_receipt::TerminalReason::ParentCascadeRevoked { .. } => "cascaded".to_string(),
                            };
                            let persona_short: String = r.summary.persona_id.chars().take(20).collect();
                            println!(
                                "{:<30} {:<38} {:<22} {}",
                                truncate(&r.id, 28),
                                truncate(&r.grant_id, 36),
                                persona_short,
                                reason_short
                            );
                        }
                    }
                }
                ReceiptAction::Show { id } => {
                    let r = match resolve_receipt(&store, &id) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
                    } else {
                        print_receipt_summary(&r);
                    }
                }
                ReceiptAction::Export { id } => {
                    let r = match resolve_receipt(&store, &id) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };
                    match serde_json::to_string_pretty(&r) {
                        Ok(s) => println!("{s}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                ReceiptAction::Verify { id, pubkey } => {
                    let r = match resolve_receipt(&store, &id) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };
                    let expected_pubkey = match pubkey {
                        Some(p) => p,
                        None => {
                            // Read pubkey from the identity file.
                            let path = ember_daemon::receipt::identity_key_path(&config.data_dir);
                            match ember_daemon::receipt::DaemonIdentity::load_or_create(&config.data_dir) {
                                Ok(id) => id.pubkey_hex(),
                                Err(e) => {
                                    eprintln!(
                                        "error: could not load trust anchor from {}: {e}",
                                        path.display()
                                    );
                                    process::exit(1);
                                }
                            }
                        }
                    };
                    match ember_daemon::receipt::verify_receipt(&r, &expected_pubkey) {
                        Ok(()) => {
                            println!("Verified: receipt {}", r.id);
                            println!("  Signer pubkey: {}", expected_pubkey);
                            println!("  Hash: {}", r.evidence.hash);
                            println!("  Canonical version: v{}", r.evidence.canonical_version);
                        }
                        Err(e) => {
                            eprintln!("Verification FAILED: {e}");
                            process::exit(2);
                        }
                    }
                }
            }
        }

        Commands::Policy { action } => {
            let policy = ember_daemon::policy::PolicyEngine::default();
            match action {
                PolicyAction::Show => {
                    println!("Policy rules (first match wins):");
                    println!();
                    let (h1, h2, h3) = ("ACTION", "RISK", "DECISION");
                    println!("  {h1:25} {h2:10} {h3}");
                    println!("  {}", "-".repeat(55));
                    for (action, risk, decision) in [
                        ("git.push.main", "critical", "deny"),
                        ("git.push.*", "medium", "auto_approve"),
                        ("deploy.production", "critical", "require_approval"),
                        ("deploy.staging", "medium", "auto_approve"),
                        ("credential.access", "high", "require_approval"),
                        ("*", "medium", "require_approval"),
                    ] {
                        println!("  {action:25} {risk:10} {decision}");
                    }
                }
                PolicyAction::Eval { action: act } => {
                    let eval = policy.evaluate(&act);
                    let risk = format!("{:?}", eval.risk).to_lowercase();
                    let decision = format!("{:?}", eval.decision);
                    let rule = eval.matched_rule.as_deref().unwrap_or("(default)");
                    println!("Action:   {act}");
                    println!("Decision: {decision}");
                    println!("Risk:     {risk}");
                    println!("Rule:     {rule}");
                }
            }
        }

        Commands::Status => {
            let runtime = DaemonRuntime::new(config.clone());
            let store = open_store(&config);

            let personas = store.list_personas().unwrap_or_default();
            let active = personas.iter().filter(|p| p.status == "active").count();
            let revoked = personas.iter().filter(|p| p.status == "revoked").count();

            let grants = store.list_active_grants().unwrap_or_default();

            let sandboxes = store.list_sandboxes().unwrap_or_default();
            let running = sandboxes.iter().filter(|s| s.status == "running").count();

            let approvals = store.list_pending_approvals().unwrap_or_default();

            let filter = AuditFilter {
                limit: Some(5),
                ..Default::default()
            };
            let entries = store.query_audit(&filter).unwrap_or_default();
            let total = store.audit_count().unwrap_or(0);

            if cli.json {
                let (daemon_running, daemon_pid, daemon_socket) = match runtime.status() {
                    Ok(s) => (s.running, Some(s.pid), Some(s.socket.display().to_string())),
                    Err(_) => (false, None, None),
                };
                let standing_grants = store.list_standing_grants().unwrap_or_default();
                let status = serde_json::json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "daemon": { "running": daemon_running, "pid": daemon_pid, "socket": daemon_socket },
                    "personas": active,
                    "grants": { "active": grants.len(), "expired_sweep_interval_sec": 60 },
                    "approvals": { "pending": approvals.len() },
                    "standing_grants": standing_grants.len(),
                    "audit_events": total,
                });
                println!("{}", serde_json::to_string_pretty(&status).unwrap());
            } else {
                // Check daemon status
                match runtime.status() {
                    Ok(status) if status.running => {
                        println!("DAEMON             running (PID {})", status.pid);
                        println!("  Socket:    {}", status.socket.display());
                        match config.dashboard_addr {
                            Some(addr) if addr.ip().is_loopback() => {
                                println!("  Dashboard: http://localhost:{}", addr.port());
                            }
                            Some(addr) => {
                                println!("  Dashboard: http://{addr}");
                            }
                            None => {
                                println!("  Dashboard: disabled");
                            }
                        }
                    }
                    Ok(status) => {
                        println!("DAEMON             stopped (stale PID {})", status.pid);
                    }
                    Err(_) => {
                        println!("DAEMON             not running");
                    }
                }
                println!();
                println!("PERSONAS           {} active, {} revoked", active, revoked);
                for p in &personas {
                    let st = if p.status == "revoked" { "revoked" } else { "active " };
                    println!("  {:<18} {}  {}", p.name, st, p.id);
                }
                println!();

                println!("ACTIVE GRANTS      {}", grants.len());
                for g in &grants {
                    let exp = g.expires_at.as_deref().unwrap_or("never");
                    println!(
                        "  {} {} → {} ({}) expires {}",
                        g.id, g.persona_id, g.credential_name, g.scope, exp
                    );
                }
                println!();

                println!("SANDBOXES          {} running", running);
                for s in sandboxes.iter().filter(|s| s.status == "running") {
                    let cid = s.container_id.as_deref().unwrap_or("-");
                    println!("  {} {} container={}", s.id, s.name, cid);
                }
                println!();

                println!("PENDING APPROVALS  {}", approvals.len());
                for r in &approvals {
                    println!(
                        "  {} {} → {} ({}) [{}]",
                        r.id, r.persona_id, r.credential_name, r.action, r.risk_level
                    );
                }
                println!();

                println!("RECENT ACTIVITY    (last {})", entries.len());
                for e in &entries {
                    let ag = e.agent_id.as_deref().unwrap_or("-");
                    let cr = e.credential.as_deref().unwrap_or("-");
                    println!("  {} {} {} {} {}", e.timestamp, ag, e.action, cr, e.outcome);
                }

                println!("\nAUDIT TOTAL        {} events", total);
            }
        }

        Commands::Config { action } => match action {
            ConfigAction::Show => {
                println!("Socket dir:  {}", config.socket_dir.display());
                println!("Data dir:    {}", config.data_dir.display());
                println!("PID file:    {}", config.pid_file.display());
                println!("Log level:   {}", config.log_level.as_filter_str());
                println!("Config file: {}", effective_config_path(cli.config.as_ref()).display());
            }
            ConfigAction::Path => {
                println!("{}", effective_config_path(cli.config.as_ref()).display());
            }
        },

        Commands::Version => {
            if cli.json {
                let v = serde_json::json!({
                    "name": "ember",
                    "version": env!("CARGO_PKG_VERSION"),
                });
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            } else {
                println!("ember {}", env!("CARGO_PKG_VERSION"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::Usage;
    use tempfile::NamedTempFile;

    #[test]
    fn record_image_digest_new_image() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path();
        record_image_digest(path, "alpine:latest", "sha256:abc123");
        let registry = ImageRegistry::load(path).unwrap();
        assert!(registry.images.contains_key("alpine:latest"));
        assert_eq!(registry.images["alpine:latest"].digest, "sha256:abc123");
        assert_eq!(registry.images["alpine:latest"].source, "docker");
    }

    #[test]
    fn record_image_digest_same_digest_no_mutation() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path();
        record_image_digest(path, "alpine:latest", "sha256:abc123");
        // Record same digest again — should succeed, no mutation
        record_image_digest(path, "alpine:latest", "sha256:abc123");
        let registry = ImageRegistry::load(path).unwrap();
        assert_eq!(registry.images["alpine:latest"].digest, "sha256:abc123");
    }

    #[test]
    fn record_image_digest_mutation_detected() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path();
        record_image_digest(path, "alpine:latest", "sha256:aaa111");
        // Record different digest — should update and would print warning to stderr
        record_image_digest(path, "alpine:latest", "sha256:bbb222");
        let registry = ImageRegistry::load(path).unwrap();
        // Digest should be updated to the new one
        assert_eq!(registry.images["alpine:latest"].digest, "sha256:bbb222");
    }

    #[test]
    fn record_image_digest_roundtrip() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path();
        record_image_digest(path, "ubuntu:22.04", "sha256:deadbeef");
        record_image_digest(path, "alpine:3.18", "sha256:cafebabe");
        let registry = ImageRegistry::load(path).unwrap();
        assert_eq!(registry.images.len(), 2);
        assert!(registry.verify("ubuntu:22.04", "sha256:deadbeef"));
        assert!(registry.verify("alpine:3.18", "sha256:cafebabe"));
    }

    #[test]
    fn ember_init_writes_keyring_section_with_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        let data_dir = tmp.path().join("data");
        let run_dir = tmp.path().join("run");

        // Build a minimal DaemonConfig pointing at the temp dir.
        let config = ember_daemon::config::DaemonConfig {
            socket_dir: run_dir.clone(),
            data_dir: data_dir.clone(),
            pid_file: run_dir.join("emberd.pid"),
            policy_file: tmp.path().join("policy.toml"),
            log_level: ember_daemon::config::LogLevel::Info,
            dashboard_addr: None,
            keyring: ember_daemon::config::KeyringConfig::default(),
        };

        // Suppress keyring and passphrase side-effects.
        unsafe {
            std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-passphrase");
        }

        cmd_init(&config, Some("test".to_string()), Some(&config_path), None, None);

        unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE"); }

        let contents = std::fs::read_to_string(&config_path).unwrap();
        assert!(contents.contains("[keyring]"), "config must contain [keyring] section");
        assert!(
            contents.contains(&format!("service = \"{}\"", DEFAULT_KEYRING_SERVICE)),
            "config must contain default service name"
        );
        assert!(
            contents.contains(&format!("account = \"{}\"", DEFAULT_KEYRING_ACCOUNT)),
            "config must contain default account name"
        );
    }

    #[test]
    fn ember_init_with_keyring_service_flag_overrides_default() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        let data_dir = tmp.path().join("data");
        let run_dir = tmp.path().join("run");

        let config = ember_daemon::config::DaemonConfig {
            socket_dir: run_dir.clone(),
            data_dir: data_dir.clone(),
            pid_file: run_dir.join("emberd.pid"),
            policy_file: tmp.path().join("policy.toml"),
            log_level: ember_daemon::config::LogLevel::Info,
            dashboard_addr: None,
            keyring: ember_daemon::config::KeyringConfig::default(),
        };

        unsafe {
            std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-passphrase");
        }

        cmd_init(
            &config,
            Some("test".to_string()),
            Some(&config_path),
            Some("custom-service".to_string()),
            Some("custom-account".to_string()),
        );

        unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE"); }

        let contents = std::fs::read_to_string(&config_path).unwrap();
        assert!(contents.contains("service = \"custom-service\""), "config must use custom service");
        assert!(contents.contains("account = \"custom-account\""), "config must use custom account");
    }

    #[test]
    fn effective_config_path_with_some_returns_that_path() {
        let p = PathBuf::from("/tmp/foo/config.toml");
        assert_eq!(effective_config_path(Some(&p)), p);
    }

    #[test]
    fn effective_config_path_with_none_returns_default() {
        assert_eq!(
            effective_config_path(None),
            DaemonConfig::default_config_path()
        );
    }

    #[test]
    fn status_json_has_required_keys() {
        let status = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "daemon": { "running": false, "pid": null, "socket": null },
            "personas": 0_usize,
            "grants": { "active": 0_usize, "expired_sweep_interval_sec": 60_u64 },
            "approvals": { "pending": 0_usize },
            "standing_grants": 0_usize,
            "audit_events": 0_u64,
        });
        let obj = status.as_object().unwrap();
        assert!(obj.contains_key("version"), "missing version");
        assert!(obj.contains_key("daemon"), "missing daemon");
        assert!(obj.contains_key("personas"), "missing personas");
        assert!(obj.contains_key("grants"), "missing grants");
        assert!(obj.contains_key("approvals"), "missing approvals");
        assert!(obj.contains_key("standing_grants"), "missing standing_grants");
        assert!(obj.contains_key("audit_events"), "missing audit_events");
        let daemon = obj["daemon"].as_object().unwrap();
        assert!(daemon.contains_key("running"), "daemon missing running");
        assert!(daemon.contains_key("pid"), "daemon missing pid");
        assert!(daemon.contains_key("socket"), "daemon missing socket");
        let grants = obj["grants"].as_object().unwrap();
        assert!(grants.contains_key("active"), "grants missing active");
        assert!(grants.contains_key("expired_sweep_interval_sec"), "grants missing expired_sweep_interval_sec");
        assert!(obj["personas"].is_number(), "personas should be a count");
        assert!(obj["standing_grants"].is_number(), "standing_grants should be a count");
        assert!(obj["audit_events"].is_number(), "audit_events should be a count");
    }

    #[test]
    fn parse_cents_accepts_decimal() {
        assert_eq!(parse_cents("0.50").unwrap(), 50);
        assert_eq!(parse_cents("1.00").unwrap(), 100);
        assert_eq!(parse_cents("0.01").unwrap(), 1);
        assert_eq!(parse_cents("10").unwrap(), 1000);
    }

    #[test]
    fn parse_cents_rejects_negative() {
        assert!(parse_cents("-1.00").is_err());
        assert!(parse_cents("-0.01").is_err());
    }

    #[test]
    fn parse_duration_s_m_h_d() {
        assert_eq!(parse_duration("15s").unwrap(), 15);
        assert_eq!(parse_duration("5m").unwrap(), 300);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration("1d").unwrap(), 86400);
        assert_eq!(parse_duration("60").unwrap(), 60);
    }

    #[test]
    fn build_budget_from_flags_all_set() {
        let b = build_budget(Some(20_000), Some(50), Some(100), Some(3600)).unwrap();
        assert_eq!(b.tokens, Some(20_000));
        assert_eq!(b.cents, Some(50));
        assert_eq!(b.requests, Some(100));
        assert_eq!(b.wall_clock_secs, Some(3600));
    }

    #[test]
    fn build_budget_from_flags_none_set() {
        assert!(build_budget(None, None, None, None).is_none());
    }

    #[test]
    fn build_composite_grant_statements_three_statements() {
        let stmts = build_composite_grant_statements(
            Some("obj-github-token"),
            Some(20_000),
            Some(50),
            Some(1800),
        );
        assert_eq!(stmts.len(), 3, "expected 3 statements");

        // Statement 0: Credential
        assert_eq!(stmts[0].sid, "s0-credential");
        assert_eq!(stmts[0].resource_type, ResourceType::Credential);
        assert!(stmts[0].actions.contains(&"credential:read".to_string()));
        assert_eq!(
            stmts[0].resource,
            ResourceSelector::Exact { value: "obj-github-token".to_string() }
        );
        assert!(stmts[0].budget.is_none(), "credential statement must have no budget");

        // Statement 1: Session
        assert_eq!(stmts[1].sid, "s1-session");
        assert_eq!(stmts[1].resource_type, ResourceType::Session);
        assert!(stmts[1].actions.contains(&"llm:generate".to_string()));
        assert_eq!(
            stmts[1].resource,
            ResourceSelector::Glob { pattern: "anthropic/*".to_string() }
        );
        let session_budget = stmts[1].budget.as_ref().expect("session must have a budget");
        assert_eq!(session_budget.tokens, Some(20_000));
        assert_eq!(session_budget.cents, Some(50));

        // Statement 2: Time
        assert_eq!(stmts[2].sid, "s2-time");
        assert_eq!(stmts[2].resource_type, ResourceType::Time);
        assert!(stmts[2].actions.contains(&"time:wall_clock".to_string()));
        assert_eq!(stmts[2].resource, ResourceSelector::Any);
        let time_budget = stmts[2].budget.as_ref().expect("time must have a budget");
        assert_eq!(time_budget.wall_clock_secs, Some(1800));
    }

    #[test]
    fn build_composite_grant_statements_no_credential_returns_empty() {
        let stmts = build_composite_grant_statements(None, Some(20_000), Some(50), Some(1800));
        assert!(stmts.is_empty(), "no credential_resource means no statements");
    }

    #[test]
    fn build_composite_grant_statements_no_budgets_still_three_statements() {
        let stmts =
            build_composite_grant_statements(Some("obj-github-token"), None, None, None);
        assert_eq!(stmts.len(), 3);
        assert!(stmts[1].budget.is_none(), "session budget absent when no token/cent flags");
        assert!(stmts[2].budget.is_none(), "time budget absent when no seconds flag");
    }

    #[test]
    fn grant_budget_renders_populated_grant() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let info = ember_daemon::grant::GrantInfo {
            id: "grant-test123".to_string(),
            persona_id: "persona-xyz".to_string(),
            credential_name: "api-key".to_string(),
            scope: "github:push:owner/repo:feat/*".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: Some(chrono::Utc::now().to_rfc3339()),
            status: "active".to_string(),
            max_uses_per_hour: None,
            allowed_hours_start: None,
            allowed_hours_end: None,
            allowed_targets: None,
            parent_grant_id: None,
            max_delegation_depth: None,
            spending_limit_cents: None,
            budget: Some(Budget {
                tokens: Some(20_000),
                cents: Some(50),
                requests: None,
                wall_clock_secs: None,
                ..Budget::default()
            }),
            usage: Usage {
                tokens: 14_342,
                cents: 37,
                last_updated: now_secs - 60,
                ..Usage::default()
            },
            paused: false,
            receipt_id: None,
        };
        // Should not panic; budget and usage are populated.
        cmd_grant_budget(&info);
    }

    #[test]
    fn grant_budget_renders_dash_when_usage_stale() {
        let info = ember_daemon::grant::GrantInfo {
            id: "grant-stale".to_string(),
            persona_id: "persona-xyz".to_string(),
            credential_name: "api-key".to_string(),
            scope: "read".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: None,
            status: "active".to_string(),
            max_uses_per_hour: None,
            allowed_hours_start: None,
            allowed_hours_end: None,
            allowed_targets: None,
            parent_grant_id: None,
            max_delegation_depth: None,
            spending_limit_cents: None,
            budget: Some(Budget {
                tokens: Some(20_000),
                cents: None,
                requests: None,
                wall_clock_secs: None,
                ..Budget::default()
            }),
            usage: Usage {
                tokens: 5_000,
                last_updated: 0, // stale — never updated
                ..Usage::default()
            },
            paused: false,
            receipt_id: None,
        };
        // Should not panic; runway should show dash.
        cmd_grant_budget(&info);
    }
}
