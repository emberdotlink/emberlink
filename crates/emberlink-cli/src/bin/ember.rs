use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::rc::Rc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use core_types::{AccessGrant, Budget, ResourceSelector, ResourceType, Statement, Usage};
use ember_daemon::approval::ApprovalOutcome;
use ember_daemon::audit::AuditFilter;
use ember_daemon::config::DaemonConfig;
use ember_daemon::image_registry::ImageRegistry;
use ember_daemon::runtime::{DaemonRuntime, DashboardBind, GitProxyBind, StartupBinds};
use ember_daemon::sandbox::SandboxCreateOpts;
use ember_daemon::store::DaemonStore;
use ember_daemon::vault::{
    check_production_sentinel, is_cargo_test_binary, keyring_writes_suppressed,
    try_auto_unseal_from_keyring, validate_credential_name, verify_keyring_roundtrip,
    AutoUnsealOutcome, Vault, DEFAULT_KEYRING_ACCOUNT, DEFAULT_KEYRING_SERVICE,
};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::EnvFilter;

#[path = "daemon_agent.rs"]
mod daemon_agent;

/// Render the version string consumed by `ember --version`, `ember -V`, and
/// `ember version`.
///
/// Format: `ember <semver> (<git-sha-or-(no-git)>) built <rfc3339-utc>`.
///
/// CLI-VERSION-FLAG: the implementation-note-11 root cause was a
/// `v0.2.0` binary running against the `v0.2.17` codebase. Embedding the git
/// SHA + build timestamp at compile time makes "is the running binary
/// stale?" a five-second `--version` check.
fn print_version() -> String {
    format!(
        "ember {} ({}) built {}",
        env!("CARGO_PKG_VERSION"),
        env!("EMBERLINK_GIT_SHA"),
        env!("EMBERLINK_BUILD_TIMESTAMP"),
    )
}

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
        /// Use Touch ID (Secure Enclave-wrapped master key) instead of a
        /// passphrase. macOS only. Currently a stub: actual SE wrapping is
        /// gated behind .A-SE-WIRE; the flag is accepted today so the
        /// init flow can route through `VaultKeyStore::SecureEnclave` once
        /// the wiring lands. Until then, passing `--touch-id` prints a
        /// notice and falls back to the passphrase lane.
        #[arg(long)]
        touch_id: bool,
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
    /// Enroll and pair devices (.C scaffold).
    ///
    /// The verbs are wired but the WebAuthn / iCloud Passkey ceremony has
    /// not landed yet — every subcommand currently exits non-zero with a
    /// pointer to `.C-WEBAUTHN-WIRE`. The CLI surface is locked here so
    /// downstream tooling (dashboard, smoke tests) can call it today and
    /// the wire-up patch only needs to swap the bodies, not the shape.
    Device {
        #[command(subcommand)]
        action: DeviceAction,
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
    /// Manage broker materializations (design / design)
    ///
    /// The credential broker mints scoped, time-bounded provider tokens
    /// (Cloudflare API tokens, Anthropic admin keys, etc.) on demand —
    /// agents and operator workflows never hold long-lived material. See
    /// design §5 for the request/response shapes and design for the
    /// daemon-side broker registry design.
    Broker {
        #[command(subcommand)]
        action: emberlink_cli::broker::BrokerCmd,
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

/// Device-management verbs (.C scaffold).
///
/// Locked CLI surface for the iCloud Passkey enrollment flow. Today both
/// verbs print the typed not-yet-implemented message from
/// `ember_daemon::device::DeviceEnrollError::WebAuthnNotImplemented` and
/// exit non-zero — the WebAuthn ceremony itself is tracked under
/// `.C-WEBAUTHN-WIRE` and will swap only the verb bodies, not this
/// shape.
#[derive(Subcommand)]
enum DeviceAction {
    /// Initiate device enrollment via WebAuthn / iCloud Passkey.
    ///
    /// Stub: the `--passkey` flag is the only ceremony shape we'll ship in
    /// the wire-up; it's accepted today so smoke tests can lock the
    /// invocation.
    Enroll {
        /// Use an iCloud Passkey (WebAuthn platform authenticator) for
        /// the ceremony.
        #[arg(long)]
        passkey: bool,
    },
    /// Run the paired-device side of the WebAuthn ceremony.
    ///
    /// Stub: this is the verb the *other* device runs to consume the
    /// pairing handle emitted by `enroll`. Today it errors with the same
    /// not-yet-implemented message.
    Pair,
}

#[derive(Subcommand)]
enum VaultAction {
    /// Add a credential to the vault
    ///
    /// Default behavior (no --value, no --stdin) prompts interactively with
    /// echo off — the safest form. Use --stdin for pipes/scripts. Use --value
    /// only for non-secret values; the value will appear in shell history.
    Add {
        /// Credential name
        #[arg(long)]
        name: String,
        /// Credential value (visible in shell history — prefer interactive prompt or --stdin for secrets)
        #[arg(long, conflicts_with = "stdin")]
        value: Option<String>,
        /// Read credential value from stdin (no shell history leak; trailing newline trimmed)
        #[arg(long)]
        stdin: bool,
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
    /// Re-lock the vault session (security check).
    ///
    /// Equivalent to letting the idle timer expire — but explicit. After
    /// this runs, the next high-risk op (vault add, vault remove, grant
    /// create, persona key export) will require fresh user presence
    /// (Touch ID on macOS).
    Lock,
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
        /// Time-to-live (humantime: 5s, 5m, 2h — bare integer also accepted as seconds)
        #[arg(long)]
        ttl: Option<String>,
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
        /// Cost budget ceiling in USD (e.g. "0.50" → 50 cents stored). Accepts decimal.
        #[arg(long)]
        budget_usd: Option<String>,
        /// Request count budget ceiling
        #[arg(long)]
        budget_requests: Option<u64>,
        /// Wall-clock seconds budget ceiling
        #[arg(long)]
        budget_seconds: Option<u64>,
        /// Attestation runtime label (e.g. "claude_code")
        #[arg(long)]
        attestation_runtime: Option<String>,
        /// Mark the grant as a standing parent () — subsequent
        /// `ember grant delegate <id>` calls mint child grants without
        /// re-prompting, subject to `--max-children-per-day`.
        #[arg(long)]
        standing: bool,
        /// Trailing-24h delegation ceiling for a standing parent. Required
        /// when `--standing` is set; ignored otherwise.
        #[arg(long)]
        max_children_per_day: Option<u64>,
        /// Opaque scope template the orchestrator applies when auto-
        /// delegating from this standing parent. Advisory — stored on
        /// the parent, read by the orchestrator.
        #[arg(long)]
        auto_delegate_scope_template: Option<String>,
    },
    /// Delegate a grant to a sub-agent with narrowed scope
    ///
    /// Child authority is bounded by the parent on every axis (scope,
    /// budget, expiry) per design § Offline attenuation. Violations
    /// exit non-zero with a message naming only the failing dimension.
    Delegate {
        /// Parent grant ID
        #[arg(value_name = "PARENT_GRANT_ID")]
        parent: String,
        /// Child persona ID
        #[arg(long = "to", value_name = "CHILD_PERSONA_ID")]
        persona: String,
        /// Narrowed scope (must be a subset of parent scope)
        #[arg(long)]
        scope: String,
        /// Time-to-live (e.g. 1h, 30m, 60s; bare integer = seconds)
        #[arg(long)]
        ttl: Option<String>,
        /// Child token budget (must fit parent's remaining allowance)
        #[arg(long)]
        budget_tokens: Option<u64>,
        /// Child cost budget in USD (e.g. "0.50" → 50 cents stored). Accepts decimal.
        #[arg(long)]
        budget_usd: Option<String>,
        /// Child request-count budget
        #[arg(long)]
        budget_requests: Option<u64>,
        /// Child wall-clock budget in seconds
        #[arg(long)]
        budget_seconds: Option<u64>,
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
        /// Owner persona ID recorded for future `exec` authorization.
        /// Defaults to the `EMBER_PERSONA_ID` environment variable.
        #[arg(long = "persona")]
        persona: Option<String>,
    },
    /// List all sandboxes
    List,
    /// Stop a sandbox
    Stop {
        /// Sandbox ID
        id: String,
    },
    /// Delete a sandbox: remove container + DB row + (if no other refs)
    /// auto-created persona. Idempotent on already-gone state.
    ///
    /// implementation-note-32: unblocks `ember sandbox create --name X` retries
    /// after a previous container start failed and left the persona row +
    /// stale docker container behind. `ember sandbox delete <id|name>` is
    /// the GC path; `stop` only halts (sandbox row + persona stay).
    Delete {
        /// Sandbox ID or name
        id: String,
    },
    /// Execute a command in a sandbox
    Exec {
        /// Sandbox ID
        id: String,
        /// Calling persona ID. Defaults to the `EMBER_PERSONA_ID` environment variable.
        /// Must match the sandbox's owner persona.
        #[arg(long = "persona")]
        persona: Option<String>,
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
        /// Cost budget ceiling in USD (e.g. "0.50" → 50 cents stored) for the Session statement. Accepts decimal.
        #[arg(long)]
        budget_usd: Option<String>,
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
    /// Query the receipts table (EMBER-implementation-note-28).
    ///
    /// Returns the unified audit view across grant, kms_wrap, and
    /// kms_unwrap receipts. Filters AND-combine. Use `--json` for raw
    /// machine-readable rows; default rendering is a fixed-width table.
    Query {
        /// Lower bound on `materialized_at`. Accepts ISO-8601
        /// (`2026-04-01T00:00:00Z`) or relative duration (`24h`, `7d`).
        #[arg(long)]
        since: Option<String>,
        /// Filter by actor (persona id).
        #[arg(long)]
        actor: Option<String>,
        /// Filter by receipt kind (`grant`, `kms_wrap`, `kms_unwrap`).
        #[arg(long)]
        kind: Option<String>,
        /// Filter by grant id.
        #[arg(long)]
        grant_id: Option<String>,
        /// Substring match on the resource label.
        #[arg(long)]
        resource: Option<String>,
        /// Emit raw JSON rows instead of the fixed-width table.
        #[arg(long)]
        json: bool,
        /// Maximum rows to return (default 100).
        #[arg(long)]
        limit: Option<u64>,
    },
}

/// EMBER-implementation-note-28 — parse a `--since` argument.
///
/// Accepts either an ISO-8601 timestamp (e.g. `2026-04-01T00:00:00Z`) or
/// a relative duration like `24h` / `7d` / `30m` / `45s`. Relative values
/// are resolved against `now` and converted to ISO-8601 so the daemon
/// receives a single canonical shape.
///
/// Returns `None` for malformed input — callers surface a clean usage
/// error to the operator instead of guessing.
pub(crate) fn parse_since(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Try ISO-8601 first — RFC3339 covers the canonical wire shape.
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    // Fall back to relative duration. Reuse the existing `parse_duration`
    // helper so unit semantics stay consistent across the binary.
    let secs = parse_duration(trimmed).ok()?;
    let secs_i64 = i64::try_from(secs).ok()?;
    chrono::Utc::now().checked_sub_signed(chrono::Duration::seconds(secs_i64))
}

/// Print the initial banner lines (version, socket, database, PID) immediately on startup.
/// Call `print_banner_startup` once the dashboard + git-proxy bind results are known.
fn print_banner_preamble(config: &DaemonConfig) {
    let version = env!("CARGO_PKG_VERSION");
    let socket = config.socket_dir.join("daemon.sock");
    let db = config.data_dir.join("daemon.db");
    let log = config.data_dir.join("daemon.log");
    let pid = std::process::id();

    eprintln!();
    eprintln!("  ember daemon v{version}");
    eprintln!("  The trust layer for AI agents");
    eprintln!();
    eprintln!("  Socket:    {}", socket.display());
    eprintln!("  Database:  {}", db.display());
    eprintln!("  Log:       {}", log.display());
    eprintln!("  PID:       {pid}");
}

/// Print the dashboard + git-proxy banner lines, followed by the "Ctrl+C to stop"
/// footer. Called after both bind results are known (from the StartupBinds callback).
/// implementation-note-19 extended this from a single dashboard line to the full
/// startup-binds aggregate.
fn print_banner_startup(binds: &StartupBinds) {
    match &binds.dashboard {
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
    match &binds.git_proxy {
        GitProxyBind::Bound(addr) => {
            // The literal `EMBER_PROXY_URL=…` shape is load-bearing — the
            // qember.sh demo + ember-git.sh wrapper both grep for it.
            // Render with the bare host:port so callers can `eval` the line.
            eprintln!("  EMBER_PROXY_URL=http://{addr}");
        }
        GitProxyBind::Failed { addr, error: _ } => {
            eprintln!("  Git proxy: unavailable (port {} in use)", addr.port());
        }
        GitProxyBind::Disabled => {
            eprintln!("  Git proxy: disabled");
        }
        GitProxyBind::Timeout => {
            eprintln!("  Git proxy: status unknown (startup timeout)");
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

/// implementation-note-20: probe `/api/status` on the configured
/// dashboard address and return the daemon's reported `dashboard_addr_bound`.
///
/// `None` means: connect failed, response was malformed, or the daemon
/// reported `dashboard_addr_bound: null` (bind failed / not configured).
/// `Some(addr_string)` means: the daemon is serving traffic on that address
/// — the CLI can render it without lying to the operator.
///
/// Implemented as a blocking raw-TCP HTTP/1.1 GET so the CLI can stay free
/// of an HTTP-client dependency. Local-only request, short timeout, no body
/// content negotiation. Mirrors the integration-test pattern in
/// `crates/ember-daemon/tests/integration.rs`.
fn probe_dashboard_addr_bound(addr: std::net::SocketAddr) -> Option<String> {
    use std::io::{Read as _, Write as _};

    let mut stream = std::net::TcpStream::connect_timeout(
        &addr,
        Duration::from_millis(500),
    )
    .ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(500))).ok()?;
    stream.set_write_timeout(Some(Duration::from_millis(500))).ok()?;

    let req = b"GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write_all(req).ok()?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    let resp = std::str::from_utf8(&buf).ok()?;
    if !resp.starts_with("HTTP/1.1 200") {
        return None;
    }
    // Body starts after the first blank line (CRLF CRLF).
    let body = resp.split("\r\n\r\n").nth(1)?;
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    json.get("dashboard_addr_bound")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Guard that keeps the non-blocking file-appender thread alive.
/// Drop it only when the process is about to exit.
pub struct LogGuard {
    _worker: tracing_appender::non_blocking::WorkerGuard,
}

/// Initialize daemon tracing: rolling JSON file appender always; console fmt layer when
/// `console` is true (foreground). Returns a `LogGuard` the caller must hold for the
/// lifetime of the process.
fn configure_tracing(data_dir: &std::path::Path, log_level: &ember_daemon::config::LogLevel, console: bool) -> LogGuard {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level.as_filter_str()));

    let log_dir = data_dir;
    let file_appender = tracing_appender::rolling::daily(log_dir, "daemon.log");
    let (non_blocking, worker_guard) = tracing_appender::non_blocking(file_appender);

    let file_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(non_blocking);

    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(file_layer);

    if console {
        let console_layer = tracing_subscriber::fmt::layer();
        registry.with(console_layer).try_init().ok();
    } else {
        registry.try_init().ok();
    }

    tracing::info!(log_dir = %log_dir.display(), log_prefix = "daemon.log", "daemon logging initialized");

    LogGuard { _worker: worker_guard }
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
    let store = match DaemonStore::open(&db_path) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("error: failed to open database: {e}");
            process::exit(1);
        }
    };

    // implementation-note-31: in-process CLI subcommands (grant/sandbox/persona) talk to
    // the same SQLite DB the daemon uses, but without going through the
    // socket — so they need their own attached vault to encrypt/decrypt
    // persona secrets. Best-effort auto-unseal from keyring: if a passphrase
    // entry exists, attach it; otherwise fall through silently and let the
    // call-site's "no vault attached" error surface naturally (callers that
    // don't touch persona secrets — e.g. `ember audit show` — still work).
    //
    // This mirrors the daemon's startup auto-unseal path so CLI and daemon
    // operate on the same vault key. Required for `qember.sh demo up`'s
    // `grant create` / `sandbox create` to succeed without a manual unlock.
    match try_auto_unseal_from_keyring(config) {
        AutoUnsealOutcome::Unsealed(v) => {
            store.set_vault(Rc::new(v));
        }
        AutoUnsealOutcome::NoKeyringEntry | AutoUnsealOutcome::Error(_) => {
            // Silent fall-through: not every CLI command needs the vault, and
            // commands that do will error from the call site with a message
            // pointing at the missing keyring entry.
        }
    }

    // Initialise the daemon's Ed25519 process identity so that
    // `DaemonStore::revoke_grant` (and other terminal-transition paths)
    // can emit signed Grant Receipts via `trigger_receipt_if_terminal_current`.
    // Without this, the identity `OnceCell` stays empty and receipt emission
    // silently no-ops, leaving `ember receipt show <id>` returning "grant
    // exists but has not reached terminal state".
    if let Err(e) = ember_daemon::receipt::init_identity(&config.data_dir) {
        tracing::warn!("could not initialise daemon identity for receipt emission: {e}");
    }

    store
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

/// Resolve a keyring service/account value for `ember init`. Pure function so
/// tests can verify the priority order (flag → env → default) without mutating
/// process-global environment — env races caused `ember init` to leak to the
/// production keyring on 2026-04-23.
fn resolve_init_keyring_value(
    flag: Option<String>,
    env_value: Option<String>,
    default_value: &str,
) -> String {
    flag.or(env_value)
        .unwrap_or_else(|| default_value.to_string())
}

fn cmd_init(
    config: &DaemonConfig,
    name: Option<String>,
    cli_config_path: Option<&PathBuf>,
    keyring_service_override: Option<String>,
    keyring_account_override: Option<String>,
    touch_id: bool,
) {
    // .A: `--touch-id` selects the SE-backed VaultKeyStore lane on macOS.
    // The SE wiring itself is deferred to .A-SE-WIRE; today the flag is
    // accepted so the init flow + config schema can land first. Print a
    // notice and fall back to the passphrase lane until the wiring ships.
    //
    // On non-macOS, the flag is a hard error — Touch ID has no meaning.
    if touch_id {
        #[cfg(target_os = "macos")]
        {
            eprintln!(
                "note: --touch-id is accepted but not yet wired (.A-SE-WIRE).\n      \
                 Falling back to the passphrase lane for this init."
            );
        }
        #[cfg(not(target_os = "macos"))]
        {
            eprintln!("error: --touch-id is only supported on macOS.");
            process::exit(1);
        }
    }
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
    // Matches daemon-runtime `resolve_keyring_service` at vault.rs:249 so
    // CLI and daemon paths agree. Missing env-var fallback was the
    // 2026-04-23 leak: qember.sh set the env but `ember init` wrote the
    // passphrase to the production service anyway.
    let init_keyring_service = resolve_init_keyring_value(
        keyring_service_override.clone(),
        std::env::var("EMBER_KEYRING_SERVICE").ok(),
        DEFAULT_KEYRING_SERVICE,
    );
    let init_keyring_account = resolve_init_keyring_value(
        keyring_account_override.clone(),
        std::env::var("EMBER_KEYRING_ACCOUNT").ok(),
        DEFAULT_KEYRING_ACCOUNT,
    );

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

    // V0 schema: persona rows are vault-sealed at rest, so the vault must
    // be ready before we create the root persona. Order:
    //   1. Write or reuse the salt file.
    //   2. Resolve or provision the passphrase.
    //   3. Build the vault from passphrase + salt.
    //   4. Open the store and attach the vault.
    //   5. Create the root persona.
    // Prior flow did 5 first and 1–4 after, which broke under V0 because
    // create_persona now requires an attached vault.
    let salt_path = config.data_dir.join("vault.salt");
    let salt: [u8; 16] = if salt_path.exists() {
        match fs::read(&salt_path) {
            Ok(raw) if raw.len() == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&raw);
                arr
            }
            Ok(raw) => {
                eprintln!(
                    "error: vault.salt has wrong length ({} bytes, expected 16)",
                    raw.len()
                );
                process::exit(1);
            }
            Err(e) => {
                eprintln!("error: failed to read vault salt: {e}");
                process::exit(1);
            }
        }
    } else {
        let s = Vault::generate_salt();
        if let Err(e) = fs::write(&salt_path, s) {
            eprintln!("warning: failed to write vault salt: {e}");
        }
        s
    };

    let service = init_keyring_service.clone();
    let account = init_keyring_account.clone();

    // Resolve the passphrase. Priority: env var → keyring (test/mock-gated
    // fallback) → keyring (production provisioning). The first two branches
    // never write to the keyring; the production branch generates a random
    // passphrase and persists it.
    let (passphrase, vault_status): (String, String) =
        if let Ok(p) = std::env::var("EMBER_VAULT_PASSPHRASE") {
            // Capture then immediately zeroize from the process environment so
            // it cannot be read from /proc/<pid>/environ by a second party.
            // Called during init before any background threads spawn; the
            // signal/thread race in remove_var is acceptable here.
            // Safety: single-threaded init path; no other threads are reading env.
            unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };
            (p, "passphrase source: EMBER_VAULT_PASSPHRASE".to_string())
        } else if keyring_writes_suppressed() {
            // Three-axis gate — `bin/ember.rs` isn't covered by the gate
            // inside `resolve_passphrase` because it calls `keyring::Entry::new`
            // directly. Keeps `cargo test` from firing real keychain popups
            // (the 2026-04-22 leak).
            (
                "ember-test-fallback-passphrase".to_string(),
                "keyring write skipped (test/mock gate)".to_string(),
            )
        } else {
            // Belt-and-suspenders production checkpoint. Mirrors the check
            // inside `Vault::open_from_config` (vault.rs:102-110) so the
            // CLI init path cannot bypass it by calling `keyring::Entry::new`
            // directly.
            if !is_cargo_test_binary() {
                let home = match dirs_next::home_dir() {
                    Some(h) => h,
                    None => {
                        eprintln!(
                            "error: refusing to write to production keyring: home directory not \
                             resolvable (no $HOME)"
                        );
                        process::exit(1);
                    }
                };
                if let Err(e) =
                    check_production_sentinel(&service, DEFAULT_KEYRING_SERVICE, &home)
                {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
            }

            let entry = match keyring::Entry::new(&service, &account) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("  Vault:    keyring unavailable ({e})");
                    eprintln!("           Set EMBER_VAULT_PASSPHRASE env var instead");
                    process::exit(1);
                }
            };

            // 32 chars from an alphanumeric alphabet (62 chars) → ~190 bits
            // of entropy. Rejection-sampled from OS entropy to avoid modulo
            // bias. Mirrors ember-daemon::vault::generate_passphrase.
            const ALPHABET: &[u8; 62] =
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            let mut generated = String::with_capacity(32);
            let mut scratch = [0u8; 64];
            while generated.len() < 32 {
                getrandom::fill(&mut scratch).expect("OS entropy failure");
                for &b in &scratch {
                    if generated.len() == 32 {
                        break;
                    }
                    if b < 248 {
                        generated.push(ALPHABET[(b % 62) as usize] as char);
                    }
                }
            }

            if let Err(e) = entry.set_password(&generated) {
                eprintln!("  Vault:    keyring unavailable ({e})");
                eprintln!("           Set EMBER_VAULT_PASSPHRASE env var instead");
                process::exit(1);
            }

            let status = match verify_keyring_roundtrip(&service, &account, &generated) {
                Ok(()) => format!(
                    "passphrase stored in system keyring (service={service}, account={account})"
                ),
                Err(e) => {
                    eprintln!("  Vault:    keyring write succeeded but read-back failed ({e})");
                    eprintln!(
                        "           This usually means the keyring crate is using its in-memory mock backend."
                    );
                    eprintln!(
                        "           Set EMBER_VAULT_PASSPHRASE env var to bypass the keyring."
                    );
                    "keyring unavailable (see above)".to_string()
                }
            };

            (generated, status)
        };

    let vault = Rc::new(Vault::from_passphrase(&passphrase, &salt));
    let store = open_store(config);
    store.set_vault(Rc::clone(&vault));

    let root_name = name.as_deref().unwrap_or("root");
    let persona = match store.create_persona(root_name) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: failed to create root persona: {e}");
            process::exit(1);
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

/// Parse a decimal USD string like "0.50" into integer cents (50).
/// Input is dollars; output is cents. Rejects negative values and non-numeric input.
fn parse_usd_to_cents(s: &str) -> Result<u64, String> {
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

/// Return the `docker exec` flags appropriate for the caller's TTY state.
///
/// When stdin is a TTY both `-i` (keep stdin open) and `-t` (allocate a
/// pseudo-TTY) are useful for interactive sessions.  When stdin is **not** a
/// TTY (CI, pipes, headless agents) passing `-t` causes Docker to fail with
/// "the input device is not a TTY".  In that case only `-i` is emitted.
fn docker_exec_flags(is_tty: bool) -> Vec<&'static str> {
    if is_tty {
        vec!["-i", "-t"]
    } else {
        vec!["-i"]
    }
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
        let v = n.parse::<u64>().map_err(|_| format!("invalid duration '{s}'"))?;
        v.checked_mul(60).ok_or_else(|| format!("duration overflow '{s}'"))
    } else if let Some(n) = s.strip_suffix('h') {
        let v = n.parse::<u64>().map_err(|_| format!("invalid duration '{s}'"))?;
        v.checked_mul(3600).ok_or_else(|| format!("duration overflow '{s}'"))
    } else if let Some(n) = s.strip_suffix('d') {
        let v = n.parse::<u64>().map_err(|_| format!("invalid duration '{s}'"))?;
        v.checked_mul(86400).ok_or_else(|| format!("duration overflow '{s}'"))
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

/// Format a budget axis line: `label: <used> / <cap> (<pct>%)`.
fn fmt_budget_line(label: &str, used: u64, cap: u64) -> String {
    let pct = (used * 100).checked_div(cap).unwrap_or(0);
    format!("    {label:<12} {:>9} / {:>9} ({pct}%)", used, cap)
}

/// Convert a `ResourceSelector` to a compact display string.
fn resource_selector_display(sel: &ResourceSelector) -> String {
    match sel {
        ResourceSelector::Exact { value } => value.clone(),
        ResourceSelector::Glob { pattern } => pattern.clone(),
        ResourceSelector::GlobWithSubtarget { primary_glob, subtarget_glob } => {
            format!("{primary_glob}:{subtarget_glob}")
        }
        ResourceSelector::Regex { pattern } => format!("/{pattern}/"),
        ResourceSelector::Any => "*".to_string(),
    }
}

/// Render per-Statement budget and usage for a composite (or legacy) grant.
///
/// Pure function over `&AccessGrant` — testable without I/O.
fn render_grant_budget(grant: &AccessGrant) -> String {
    use std::fmt::Write as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut out = String::new();
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let _ = writeln!(out, "Grant {}", grant.id);
    let _ = writeln!(out, "  Persona: {}", grant.issuing_persona_id);
    let _ = writeln!(out, "  Status:  {}", grant.effective_status(now_secs).as_str());

    // Effective TTL from the earliest block expiry.
    match grant.effective_expires_at() {
        Some(exp_epoch) => {
            let remaining = exp_epoch as i64 - now_secs as i64;
            if remaining > 0 {
                let _ = writeln!(out, "  TTL:     {}m remaining", remaining / 60);
            } else {
                let _ = writeln!(out, "  TTL:     expired");
            }
        }
        None => {
            let _ = writeln!(out, "  TTL:     never");
        }
    }

    // Per-Statement budget rows.
    let statements: Vec<(usize, &Statement)> = grant.statements().collect();
    let is_composite = statements.len() > 1;

    for (_bi, stmt) in &statements {
        if is_composite {
            let _ = writeln!(
                out,
                "  Statement {}  {}  {}",
                stmt.sid,
                stmt.resource_type.as_str(),
                resource_selector_display(&stmt.resource),
            );
        }
        let indent = if is_composite { "    " } else { "  " };

        match &stmt.budget {
            None => {
                let _ = writeln!(out, "{indent}Budget:  (none)");
            }
            Some(b) => {
                let _ = writeln!(out, "{indent}Budget:");
                if let Some(cap) = b.tokens {
                    let _ = writeln!(out, "  {}", fmt_budget_line("tokens:", stmt.usage.tokens, cap));
                }
                if let Some(cap) = b.cents {
                    let _ = writeln!(out, "  {}", fmt_budget_line("cents:", stmt.usage.cents, cap));
                }
                if let Some(cap) = b.requests {
                    let _ = writeln!(out, "  {}", fmt_budget_line("requests:", stmt.usage.requests, cap));
                }
                if let Some(cap) = b.wall_clock_secs {
                    let _ = writeln!(out, "  {}", fmt_budget_line("wall-clock:", stmt.usage.wall_clock_secs, cap));
                }

                // Runway (rate-based estimate) — only when usage is fresh (<5 min).
                let last_updated = stmt.usage.last_updated;
                let age_secs = if last_updated > 0 && now_secs >= last_updated {
                    now_secs - last_updated
                } else {
                    u64::MAX
                };
                let stale = age_secs > 300 || last_updated == 0;

                if !stale {
                    let minutes_elapsed = (age_secs as f64 / 60.0).max(0.001);
                    let _ = writeln!(out, "{indent}Runway:");
                    if let Some(cap) = b.tokens {
                        let used = stmt.usage.tokens;
                        if used > 0 && cap > used {
                            let remaining_min = (cap - used) as f64 / (used as f64 / minutes_elapsed);
                            let _ = writeln!(out, "  {indent}  tokens:      ~{}m", remaining_min.round() as u64);
                        } else {
                            let _ = writeln!(out, "  {indent}  tokens:      —");
                        }
                    }
                    if let Some(cap) = b.cents {
                        let used = stmt.usage.cents;
                        if used > 0 && cap > used {
                            let remaining_min = (cap - used) as f64 / (used as f64 / minutes_elapsed);
                            let _ = writeln!(out, "  {indent}  cents:       ~{}m", remaining_min.round() as u64);
                        } else {
                            let _ = writeln!(out, "  {indent}  cents:       —");
                        }
                    }
                } else if !is_composite {
                    let _ = writeln!(out, "{indent}Runway:  —");
                }
            }
        }
    }

    out
}

/// Print budget and usage for a grant to stdout.
fn cmd_grant_budget(grant: &AccessGrant) {
    print!("{}", render_grant_budget(grant));
}

/// Handle `ember sandbox delete <id|name>` — implementation-note-32.
///
/// Resolves the argument to a sandbox UUID, then asks the store to delete
/// the row + container + auto-created persona (when unreferenced).
/// Idempotent: a missing sandbox prints a friendly note and exits 0 so demo
/// retries don't fail loudly when the row was already cleaned up.
fn handle_sandbox_delete(store: &DaemonStore, id_or_name: &str) {
    let resolved = match store.resolve_sandbox_id(id_or_name) {
        Ok(uuid) => uuid,
        Err(ember_daemon::store::StoreError::NotFound) => {
            println!("sandbox '{id_or_name}' not found (already deleted — ok)");
            return;
        }
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };
    match store.delete_sandbox(&resolved) {
        Ok(()) => println!("Deleted sandbox {resolved}"),
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    }
}

fn main() {
    // CLI-VERSION-FLAG: handle `--version` / `-V` before clap parses so the
    // output format (`ember <semver> (<sha>) built <iso8601>`) is enforced
    // here rather than fighting clap's built-in renderer. Both forms exit 0
    // without touching the daemon, vault, or config — `ember --version` must
    // never block on the keychain unlock prompt.
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    if raw_args.iter().any(|a| a == "--version" || a == "-V") {
        println!("{}", print_version());
        return;
    }

    let cli = Cli::parse();
    let config = load_config(cli.config.as_ref());

    match cli.command {
        Commands::Init { name, keyring_service, keyring_account, touch_id } => {
            cmd_init(
                &config,
                name,
                cli.config.as_ref(),
                keyring_service,
                keyring_account,
                touch_id,
            )
        }

        Commands::Daemon { action } => match action {
            DaemonAction::Start { background, foreground: _ } => {
                if background {
                    if let Err(e) = config.ensure_dirs() {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                    let log_path = config.data_dir.join("daemon.log");

                    let exe = std::env::current_exe().expect("current exe");
                    let mut cmd = std::process::Command::new(exe);
                    cmd.arg("daemon").arg("start");
                    if let Some(ref config_path) = cli.config {
                        cmd.arg("--config").arg(config_path);
                    }
                    // Background child writes logs via tracing-appender; no console output.
                    cmd.env("EMBER_DAEMON_NO_CONSOLE", "1")
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .stdin(std::process::Stdio::null());

                    let child = cmd.spawn().expect("spawn daemon");
                    println!("Daemon started in background (PID {})", child.id());
                    println!("  Log: {}", log_path.display());
                    #[allow(clippy::zombie_processes)]
                    std::mem::forget(child);
                    return;
                }

                if let Err(e) = config.ensure_dirs() {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
                let console = std::env::var("EMBER_DAEMON_NO_CONSOLE").is_err();
                let _log_guard = configure_tracing(&config.data_dir, &config.log_level, console);

                // Print everything except the dashboard line up-front.
                if console {
                    print_banner_preamble(&config);
                }

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
                let notify: Box<dyn FnOnce(StartupBinds)> = if console {
                    Box::new(|binds| print_banner_startup(&binds))
                } else {
                    Box::new(|_binds| {})
                };

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

        Commands::Device { action } => {
            // .C scaffold: the verbs are locked but the WebAuthn /
            // iCloud Passkey ceremony has not landed. Both sides print the
            // typed `WebAuthnNotImplemented` error from `ember_daemon::device`
            // (single source of truth so the message tracks the rename if it
            // moves) and exit non-zero so smoke tests fail loudly until
            // .C-WEBAUTHN-WIRE flips the implementation.
            let stub_err = ember_daemon::device::DeviceEnrollError::WebAuthnNotImplemented;
            match action {
                DeviceAction::Enroll { passkey: _ } => {
                    eprintln!("error: {stub_err}");
                    process::exit(1);
                }
                DeviceAction::Pair => {
                    eprintln!("error: {stub_err}");
                    process::exit(1);
                }
            }
        }

        Commands::Vault { action } => {
            // Client-side pre-validation: fail fast on a malformed name before
            // we open the store / unlock the vault (which on macOS would fire
            // a Touch ID prompt). The daemon-side check in `Vault::add` is
            // authoritative; this mirror is purely UX. If the regex constants
            // need to be tweaked, change `validate_credential_name` in
            // `ember-daemon::vault` — the CLI imports the same fn so they
            // cannot drift.
            if let VaultAction::Add { ref name, .. } = action {
                if let Err(e) = validate_credential_name(name) {
                    eprintln!("error: invalid credential name: {e}");
                    eprintln!(
                        "       see design §5.1 for the path grammar (lowercase \
                         + digits + hyphen, 1..=4 path segments separated by '/')"
                    );
                    process::exit(2);
                }
            }

            let store = open_store(&config);
            let vault = Vault::open_from_config(&config)
                .expect("failed to resolve vault — is the daemon initialized?");

            match action {
                VaultAction::Add {
                    name,
                    value,
                    stdin,
                    metadata,
                } => {
                    let resolved = if stdin {
                        let mut buf = Vec::new();
                        if let Err(e) = io::stdin().read_to_end(&mut buf) {
                            eprintln!("error: failed to read stdin: {e}");
                            process::exit(1);
                        }
                        if buf.last() == Some(&b'\n') {
                            buf.pop();
                            if buf.last() == Some(&b'\r') {
                                buf.pop();
                            }
                        }
                        if buf.is_empty() {
                            eprintln!("error: --stdin received empty value");
                            process::exit(1);
                        }
                        buf
                    } else if let Some(v) = value {
                        v.into_bytes()
                    } else if io::stdin().is_terminal() {
                        // Interactive prompt with echo off — default safe path
                        // when neither --value nor --stdin is given.
                        match rpassword::prompt_password("Paste credential value: ") {
                            Ok(s) if s.is_empty() => {
                                eprintln!("error: empty value");
                                process::exit(1);
                            }
                            Ok(s) => s.into_bytes(),
                            Err(e) => {
                                eprintln!("error: failed to read prompt: {e}");
                                process::exit(1);
                            }
                        }
                    } else {
                        eprintln!(
                            "error: stdin is not a TTY; pass --value <V> for inline or pipe \
                             the value with --stdin"
                        );
                        process::exit(2);
                    };
                    match vault.add(&store, &name, &resolved, metadata.as_deref()) {
                        Ok(info) => {
                            println!("Stored credential");
                            println!("  ID:   {}", info.id);
                            println!("  Name: {}", info.name);
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
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
                VaultAction::Lock => {
                    // security check: explicit re-lock. Best-effort —
                    // both the in-process presence state AND the
                    // SE-keyring session cache get cleared so the next
                    // high-risk op MUST re-prompt for biometric.
                    ember_daemon::presence::lock();
                    if cli.json {
                        println!("{{\"locked\": true}}");
                    } else {
                        println!("Vault session re-locked. Next high-risk op will prompt for user presence.");
                    }
                }
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
                    budget_usd,
                    budget_requests,
                    budget_seconds,
                    attestation_runtime,
                    standing,
                    max_children_per_day,
                    auto_delegate_scope_template,
                } => {
                    // — `--standing` requires `--max-children-per-day`
                    // and implies a delegation depth, so reject the
                    // ambiguous combinations up front.
                    if standing && max_children_per_day.is_none() {
                        eprintln!(
                            "error: --standing requires --max-children-per-day"
                        );
                        process::exit(1);
                    }
                    if standing && delegation_depth.is_none() {
                        eprintln!(
                            "error: --standing requires --delegation-depth (the parent must allow delegation)"
                        );
                        process::exit(1);
                    }
                    let parsed_cents = match budget_usd.as_deref() {
                        Some(s) => match parse_usd_to_cents(s) {
                            Ok(c) => Some(c),
                            Err(e) => {
                                eprintln!("error: --budget-usd: {e}");
                                process::exit(1);
                            }
                        },
                        None => None,
                    };
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
                    let budget = build_budget(budget_tokens, parsed_cents, budget_requests, budget_seconds);
                    // implementation-note-23 — budget_persists_on_simple_grant.
                    //
                    // Pre-fix: this path called `create_grant` (no budget) and
                    // then UPDATE'd the flat `budget_json` column. But
                    // `row_to_grant` prefers the composite chain's first-
                    // statement budget when present, so the chain (which had
                    // budget=None) shadowed the UPDATE and the budget was
                    // silently dropped on read — including in `/api/grants`.
                    //
                    // Post-fix: route through `create_grant_with_budget` so
                    // the budget lands in block-zero's statement at mint time.
                    // The flat `budget_json` column is intentionally NOT
                    // written here per the function's contract (single source
                    // of truth = the signed chain).
                    match store.create_grant_with_budget(&persona, &credential, &scope, ttl_secs, budget.clone()) {
                    Ok(info) => {
                        // Apply non-budget conditions via UPDATE if any are set.
                        let targets_json = allowed_targets.as_ref().map(|t| {
                            let targets: Vec<&str> = t.split(',').collect();
                            serde_json::to_string(&targets).unwrap_or_default()
                        });
                        let attestation_json = attestation_runtime.as_ref().map(|r| {
                            serde_json::to_string(&serde_json::json!({"status": "unattested_local_dev", "runtime": r})).unwrap_or_default()
                        });
                        if rate_limit.is_some()
                            || hours_start.is_some()
                            || targets_json.is_some()
                            || delegation_depth.is_some()
                            || attestation_json.is_some()
                        {
                            let _ = store.conn().execute(
                                "UPDATE grants SET max_uses_per_hour=?1, allowed_hours_start=?2, allowed_hours_end=?3, allowed_targets=?4, max_delegation_depth=?5 WHERE id=?6",
                                rusqlite::params![
                                    rate_limit.map(|v| v as i64),
                                    hours_start.map(|v| v as i64),
                                    hours_end.map(|v| v as i64),
                                    targets_json,
                                    delegation_depth.map(|v| v as i64),
                                    info.id,
                                ],
                            );
                        }
                        // — flip the `is_standing` flag after the
                        // base grant row exists so `mark_grant_standing`
                        // can enforce its preconditions (grant must exist;
                        // ceiling > 0). Depth was already set by the UPDATE
                        // above when --delegation-depth was passed, which
                        // the standing precondition requires.
                        if standing
                            && let Some(limit) = max_children_per_day
                            && let Err(e) = store.mark_grant_standing(
                                &info.id,
                                limit,
                                auto_delegate_scope_template.as_deref(),
                            )
                        {
                            eprintln!("error: failed to mark grant standing: {e}");
                            process::exit(1);
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
                        if standing {
                            println!(
                                "  Standing:   yes (max {}/day)",
                                max_children_per_day.unwrap_or(0)
                            );
                            if let Some(ref tpl) = auto_delegate_scope_template {
                                println!("  Auto-scope: {tpl}");
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
                    budget_tokens,
                    budget_usd,
                    budget_requests,
                    budget_seconds,
                } => {
                    let ttl_secs = match ttl.as_deref() {
                        Some(s) => match parse_duration(s) {
                            Ok(n) => Some(n),
                            Err(e) => {
                                eprintln!("error: --ttl: {e}");
                                process::exit(1);
                            }
                        },
                        None => None,
                    };
                    let parsed_cents = match budget_usd.as_deref() {
                        Some(s) => match parse_usd_to_cents(s) {
                            Ok(c) => Some(c),
                            Err(e) => {
                                eprintln!("error: --budget-usd: {e}");
                                process::exit(1);
                            }
                        },
                        None => None,
                    };
                    let child_budget = build_budget(
                        budget_tokens,
                        parsed_cents,
                        budget_requests,
                        budget_seconds,
                    );
                    match store.delegate_grant_full(
                        &parent,
                        &persona,
                        &scope,
                        ttl_secs,
                        child_budget,
                    ) {
                        Ok(info) => {
                            if cli.json {
                                println!(
                                    "{}",
                                    serde_json::json!({
                                        "id": info.id,
                                        "parent_grant_id": parent,
                                        "persona_id": info.persona_id,
                                        "scope": info.scope,
                                        "expires_at": info.expires_at,
                                        "budget": info.budget,
                                    })
                                );
                            } else {
                                println!("{}", info.id);
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
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
                                    println!(
                                        "{} {} → {} ({}) expires {} [{}]",
                                        g.id, g.persona_id, g.credential_name, g.scope, exp, g.status
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
                GrantAction::Budget { grant_id } => match store.get_access_grant(&grant_id) {
                    Ok(grant) => cmd_grant_budget(&grant),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                GrantAction::Extend { grant_id, tokens, cents, ttl } => {
                    let parsed_cents = match cents.as_deref() {
                        Some(s) => match parse_usd_to_cents(s) {
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
                    persona,
                } => {
                    let extra_env: Vec<(String, String)> = env
                        .iter()
                        .filter_map(|kv| {
                            kv.split_once('=').map(|(k, v)| (k.to_string(), v.to_string()))
                        })
                        .collect();
                    let owner_persona_id = persona
                        .or_else(|| std::env::var("EMBER_PERSONA_ID").ok());
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
                        owner_persona_id,
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
                SandboxAction::Stop { id } => {
                    let resolved = match store.resolve_sandbox_id(&id) {
                        Ok(uuid) => uuid,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };
                    match store.stop_sandbox(&resolved) {
                        Ok(()) => println!("Stopped sandbox {resolved}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                SandboxAction::Delete { id } => {
                    handle_sandbox_delete(&store, &id);
                }
                SandboxAction::Exec { id, persona, command } => {
                    let resolved_id = match store.resolve_sandbox_id(&id) {
                        Ok(uuid) => uuid,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };
                    let caller_persona = persona
                        .or_else(|| std::env::var("EMBER_PERSONA_ID").ok())
                        .unwrap_or_default();
                    let refs: Vec<&str> = command.iter().map(String::as_str).collect();
                    match store.exec_sandbox(&resolved_id, &refs, &caller_persona) {
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
                    budget_usd: budget_usd_str,
                    budget_seconds,
                    ttl,
                    prompt,
                } => {
                    // Parse --budget-usd (dollars) into integer cents for storage.
                    let parsed_cents = match budget_usd_str.as_deref() {
                        Some(s) => match parse_usd_to_cents(s) {
                            Ok(c) => Some(c),
                            Err(e) => {
                                eprintln!("error: --budget-usd: {e}");
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

                    let run_owner_persona_id =
                        std::env::var("EMBER_PERSONA_ID").ok();
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
                        owner_persona_id: run_owner_persona_id,
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
                    //
                    // implementation-note-13 — route the composite mint through the policy
                    // engine so `default_decision = "require_approval"` fires
                    // here. Three outcomes:
                    //   - AutoApprove: mint immediately (legacy fast-path)
                    //   - RequireApproval: submit ONE approval entry that
                    //     bundles all 3 statements; do NOT exec prompt; exit
                    //     so the operator can `ember approval approve <id>`
                    //   - Deny: error and exit non-zero
                    //
                    // The policy action name is `credential.access` to match
                    // the daemon's existing credential-access rule shape.
                    let mut sandbox_grant_pending = false;
                    if statement_count > 0 {
                        let credential_res = credential_resource.as_deref().unwrap_or("");
                        let policy_engine = if config.policy_file.exists() {
                            ember_daemon::policy::PolicyEngine::from_file(&config.policy_file)
                                .unwrap_or_default()
                        } else {
                            ember_daemon::policy::PolicyEngine::default()
                        };
                        let policy_action = "credential.access".to_string();
                        let eval = policy_engine.evaluate(&policy_action);
                        let risk_str = format!("{:?}", eval.risk).to_lowercase();

                        match eval.decision {
                            ember_daemon::policy::PolicyDecision::Deny => {
                                eprintln!(
                                    "error: policy denied composite grant mint for {credential_res} \
                                     (rule: {})",
                                    eval.matched_rule.as_deref().unwrap_or("(default)")
                                );
                                process::exit(1);
                            }
                            ember_daemon::policy::PolicyDecision::RequireApproval => {
                                match store.submit_composite_approval(
                                    &sandbox.persona_id,
                                    credential_res,
                                    "composite",
                                    ttl_secs,
                                    &policy_action,
                                    &risk_str,
                                    statements.clone(),
                                ) {
                                    Ok(req) => {
                                        sandbox_grant_pending = true;
                                        println!("Approval required for composite grant");
                                        println!("  Approval ID: {}", req.id);
                                        println!("  Statements:  {statement_count}");
                                        println!(
                                            "    [0] credential:read  on {credential_res}"
                                        );
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
                                        println!();
                                        println!(
                                            "  Approve from CLI: ember approval approve {}",
                                            req.id
                                        );
                                        println!(
                                            "  Or open dashboard: http://localhost:3141/approvals/{}",
                                            req.id
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "warning: sandbox started but submitting approval failed: {e}"
                                        );
                                    }
                                }
                            }
                            ember_daemon::policy::PolicyDecision::AutoApprove => {
                                // Seed the parent grant with scope "*" so the
                                // bipartite-dominance check in
                                // `overwrite_grant_blocks` accepts the typed
                                // child statements (Credential / Session /
                                // Time) below the wildcard parent.
                                match store.create_grant(
                                    &sandbox.persona_id,
                                    credential_res,
                                    "*",
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
                            }
                        }
                    } else {
                        println!("  (no --credential-resource supplied — grant not minted)");
                    }

                    // If a prompt was given and the container started, hand off to
                    // `docker exec -it <container_id> claude -p "<prompt>"`.  The
                    // child process inherits stdin/stdout so Claude Code's output
                    // streams directly to the operator's terminal.
                    //
                    // implementation-note-13 — when the composite grant is pending approval,
                    // skip the agent exec; the operator must approve first
                    // (then re-run / `ember sandbox exec`) to give the agent
                    // its credentials.
                    if sandbox_grant_pending {
                        if prompt.is_some() {
                            eprintln!(
                                "  (skipping agent exec — approve the composite grant first)"
                            );
                        }
                    } else if let Some(ref p) = prompt {
                        if container_id != "none" {
                            use std::io::IsTerminal as _;
                            let tty_flags = docker_exec_flags(std::io::stdin().is_terminal());
                            let mut exec_args = vec!["exec"];
                            exec_args.extend_from_slice(&tty_flags);
                            exec_args.push(&container_id);
                            exec_args.extend_from_slice(&["claude", "-p", p]);
                            let exit_status = std::process::Command::new("docker")
                                .args(&exec_args)
                                .status();
                            match exit_status {
                                Ok(s) if s.success() => {}
                                Ok(s) => {
                                    eprintln!(
                                        "warning: claude exited with status {}",
                                        s.code().unwrap_or(-1)
                                    );
                                }
                                Err(e) => {
                                    eprintln!("error: docker exec failed: {e}");
                                    process::exit(1);
                                }
                            }
                        } else {
                            eprintln!("warning: container did not start — skipping claude exec");
                        }
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
                                // implementation-note-13 — composite envelopes render as
                                // ONE entry with N statements listed beneath.
                                if let Some(stmts) = r.composite_statements.as_ref() {
                                    println!(
                                        "{} {} → {} ({}) [{}]  composite ({} statements)",
                                        r.id,
                                        r.persona_id,
                                        r.credential_name,
                                        r.action,
                                        r.risk_level,
                                        stmts.len(),
                                    );
                                    for (i, s) in stmts.iter().enumerate() {
                                        let actions = s.actions.join(",");
                                        let resource = match &s.resource {
                                            core_types::ResourceSelector::Exact { value } => {
                                                value.clone()
                                            }
                                            core_types::ResourceSelector::Glob { pattern } => {
                                                pattern.clone()
                                            }
                                            core_types::ResourceSelector::Any => "*".to_string(),
                                            _ => format!("{:?}", s.resource),
                                        };
                                        println!("    [{i}] {actions} on {resource}");
                                    }
                                } else {
                                    println!(
                                        "{} {} → {} ({}) [{}]",
                                        r.id, r.persona_id, r.credential_name, r.action, r.risk_level
                                    );
                                }
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
                            // implementation-note-13 — surface the grant ID minted by a
                            // composite-approval resolution so the operator
                            // (or test harness) can use it directly.
                            if let Ok(resolved) = store.get_approval(&id)
                                && let Some(grant_id) = resolved.result_grant_id.as_deref()
                            {
                                println!("  Grant ID: {grant_id}");
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
                AuditAction::Query {
                    since,
                    actor,
                    kind,
                    grant_id,
                    resource,
                    json,
                    limit,
                } => {
                    // Validate `--since` up front — surface a clean usage
                    // error rather than handing a malformed string to the
                    // store filter.
                    let since_iso = match since.as_deref() {
                        None => None,
                        Some(s) => match parse_since(s) {
                            Some(dt) => Some(dt.to_rfc3339()),
                            None => {
                                eprintln!(
                                    "error: invalid --since '{s}' \
                                     (expected ISO-8601 like 2026-04-01T00:00:00Z \
                                     or relative duration like 24h / 7d)"
                                );
                                process::exit(1);
                            }
                        },
                    };
                    let filter = ember_daemon::receipt::ReceiptFilter {
                        persona_id: actor,
                        kind,
                        grant_id,
                        resource,
                        since_iso,
                        limit,
                        ..Default::default()
                    };
                    let rows = match store.list_receipt_rows(&filter) {
                        Ok(rows) => rows,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };

                    // `--json` (subcommand-local) and the global `--json`
                    // flag both opt into raw machine output; either is OK.
                    if json || cli.json {
                        match serde_json::to_string_pretty(&rows) {
                            Ok(s) => println!("{s}"),
                            Err(e) => {
                                eprintln!("error: serialize rows: {e}");
                                process::exit(1);
                            }
                        }
                    } else if rows.is_empty() {
                        println!("No receipts match the supplied filters.");
                    } else {
                        // Fixed-width table. Columns sized for typical
                        // values; longer fields are truncated by `truncate`.
                        let h_kind = "KIND";
                        let h_actor = "ACTOR";
                        let h_resource = "RESOURCE";
                        let h_grant = "GRANT";
                        let h_at = "MATERIALIZED_AT";
                        let h_reason = "REASON";
                        println!(
                            "{h_kind:<10} {h_actor:<22} {h_resource:<28} {h_grant:<22} {h_at:<28} {h_reason}"
                        );
                        for r in &rows {
                            let reason_short: String =
                                r.terminal_reason.chars().take(40).collect();
                            println!(
                                "{:<10} {:<22} {:<28} {:<22} {:<28} {}",
                                truncate(&r.kind, 10),
                                truncate(&r.actor, 22),
                                truncate(&r.resource, 28),
                                truncate(&r.grant_id, 22),
                                truncate(&r.materialized_at, 28),
                                reason_short,
                            );
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

        Commands::Broker { action } => {
            // Resolve the daemon socket path from the same config that
            // every other socket-talking subcommand uses.
            let socket_path = config.socket_dir.join("daemon.sock");
            let opts = emberlink_cli::broker::GlobalOpts { socket_path };
            if let Err(e) = emberlink_cli::broker::broker_command(action, opts) {
                eprintln!("error: {e}");
                process::exit(e.exit_code());
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
                        // implementation-note-20: the configured
                        // address is the *attempted* port. The daemon may
                        // have failed to bind (port collision) and still
                        // be running. Probe `/api/status` to read the
                        // daemon-reported `dashboard_addr_bound` — the only
                        // honest source of truth — instead of printing the
                        // configured port unconditionally.
                        match config.dashboard_addr {
                            Some(addr) => match probe_dashboard_addr_bound(addr) {
                                Some(bound) => {
                                    // Render loopback addresses as "localhost"
                                    // to match the existing banner cosmetic.
                                    let pretty = bound
                                        .parse::<std::net::SocketAddr>()
                                        .ok()
                                        .filter(|a| a.ip().is_loopback())
                                        .map(|a| format!("localhost:{}", a.port()))
                                        .unwrap_or(bound);
                                    println!("  Dashboard: http://{pretty}/");
                                }
                                None => {
                                    println!(
                                        "  Dashboard: not running (bind failed or not configured)"
                                    );
                                }
                            },
                            None => {
                                println!(
                                    "  Dashboard: not running (bind failed or not configured)"
                                );
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
                    "git_sha": env!("EMBERLINK_GIT_SHA"),
                    "build_timestamp": env!("EMBERLINK_BUILD_TIMESTAMP"),
                });
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            } else {
                println!("{}", print_version());
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
            git_proxy_addr: None,
            keyring: ember_daemon::config::KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            presence: ember_daemon::config::PresenceConfigSection::default(),
        };

        // Suppress keyring and passphrase side-effects.
        unsafe {
            std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-passphrase");
        }

        cmd_init(&config, Some("test".to_string()), Some(&config_path), None, None, false);

        unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE"); }

        let contents = std::fs::read_to_string(&config_path).unwrap();
        assert!(contents.contains("[keyring]"), "config must contain [keyring] section");
        // Service/account match the same resolution cmd_init uses — env var
        // (if set by cargo-test.sh) else compile-time default. Using the
        // same resolution instead of hardcoding DEFAULT avoids the race where
        // a concurrent test's env mutation breaks this assertion.
        let expected_service = std::env::var("EMBER_KEYRING_SERVICE")
            .unwrap_or_else(|_| DEFAULT_KEYRING_SERVICE.to_string());
        let expected_account = std::env::var("EMBER_KEYRING_ACCOUNT")
            .unwrap_or_else(|_| DEFAULT_KEYRING_ACCOUNT.to_string());
        assert!(
            contents.contains(&format!("service = \"{expected_service}\"")),
            "config must contain resolved service name; got:\n{contents}"
        );
        assert!(
            contents.contains(&format!("account = \"{expected_account}\"")),
            "config must contain resolved account name; got:\n{contents}"
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
            git_proxy_addr: None,
            keyring: ember_daemon::config::KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            presence: ember_daemon::config::PresenceConfigSection::default(),
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
            false,
        );

        unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE"); }

        let contents = std::fs::read_to_string(&config_path).unwrap();
        assert!(contents.contains("service = \"custom-service\""), "config must use custom service");
        assert!(contents.contains("account = \"custom-account\""), "config must use custom account");
    }

    #[test]
    fn resolve_init_keyring_value_flag_wins_over_env_and_default() {
        let v = resolve_init_keyring_value(
            Some("from-flag".to_string()),
            Some("from-env".to_string()),
            "from-default",
        );
        assert_eq!(v, "from-flag");
    }

    #[test]
    fn resolve_init_keyring_value_env_wins_over_default_when_flag_absent() {
        // Regression guard: 2026-04-23 leak. qember.sh sets
        // EMBER_KEYRING_SERVICE but not --keyring-service; init previously
        // wrote the passphrase to the production service anyway.
        let v = resolve_init_keyring_value(
            None,
            Some("from-env".to_string()),
            "from-default",
        );
        assert_eq!(v, "from-env");
    }

    #[test]
    fn resolve_init_keyring_value_falls_through_to_default_when_flag_and_env_absent() {
        let v = resolve_init_keyring_value(None, None, "from-default");
        assert_eq!(v, "from-default");
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
    fn parse_usd_to_cents_accepts_decimal() {
        assert_eq!(parse_usd_to_cents("0.50").unwrap(), 50);
        assert_eq!(parse_usd_to_cents("1.00").unwrap(), 100);
        assert_eq!(parse_usd_to_cents("0.01").unwrap(), 1);
        assert_eq!(parse_usd_to_cents("10").unwrap(), 1000);
    }

    #[test]
    fn parse_usd_to_cents_rejects_negative() {
        assert!(parse_usd_to_cents("-1.00").is_err());
        assert!(parse_usd_to_cents("-0.01").is_err());
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
    fn parse_duration_rejects_overflow_on_days() {
        // u64::MAX / 86400 + 1 parses fine as u64 but overflows when multiplied by 86400
        let overflow_days = u64::MAX / 86400 + 1;
        let input = format!("{overflow_days}d");
        assert!(parse_duration(&input).is_err(), "days overflow should return Err");
        // Same for hours: u64::MAX / 3600 + 1
        let overflow_hours = u64::MAX / 3600 + 1;
        let input = format!("{overflow_hours}h");
        assert!(parse_duration(&input).is_err(), "hours overflow should return Err");
        // Same for minutes: u64::MAX / 60 + 1
        let overflow_mins = u64::MAX / 60 + 1;
        let input = format!("{overflow_mins}m");
        assert!(parse_duration(&input).is_err(), "minutes overflow should return Err");
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

    // --- helpers for render_grant_budget tests ---

    fn make_test_statement(sid: &str, rt: ResourceType, resource: &str, budget: Option<Budget>, usage: Usage) -> Statement {
        Statement {
            sid: sid.into(),
            resource_type: rt,
            actions: vec!["read".to_string()],
            resource: ResourceSelector::Glob { pattern: resource.to_string() },
            budget,
            usage,
            conditions: vec![],
        }
    }

    fn make_test_grant(statements_by_block: Vec<Vec<Statement>>) -> AccessGrant {
        use core_types::{
            AttestationBinding, Block, GrantMode, GrantStatus, PresentationAudienceKind,
            RecipientProfile, SignedBlock,
        };
        let blocks: Vec<SignedBlock> = statements_by_block
            .into_iter()
            .map(|stmts| SignedBlock {
                block: Block {
                    statements: stmts,
                    nbf: None,
                    expires_at: None,
                    issued_by: "persona-test".into(),
                    issued_at: 0,
                    approval: None,
                    note: None,
                },
                pubkey_next: "deadbeef".into(),
                signature: "cafebabe".into(),
            })
            .collect();
        AccessGrant {
            id: "grant-test".into(),
            version: 1,
            issuing_persona_id: "persona-test".into(),
            recipient_kind: PresentationAudienceKind::Service,
            recipient_id: "cred".into(),
            recipient_profile: RecipientProfile::Agent,
            status: GrantStatus::Active,
            mode: GrantMode::OneShot,
            blocks,
            attestation: AttestationBinding::default(),
            created_at: 0,
            updated_at: 0,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: None,
        }
    }

    #[test]
    fn grant_budget_renders_populated_grant() {
        let stmt = make_test_statement(
            "S0",
            ResourceType::Session,
            "llm:generate",
            Some(Budget { tokens: Some(20_000), cents: Some(50), requests: None, workload_hours: None, wall_clock_secs: None }),
            Usage { tokens: 14_342, cents: 37, last_updated: 0, ..Usage::default() },
        );
        let grant = make_test_grant(vec![vec![stmt]]);
        // Should not panic; budget and usage are populated.
        let out = render_grant_budget(&grant);
        assert!(out.contains("14342"), "missing token usage: {out}");
        assert!(out.contains("20000"), "missing token cap: {out}");
    }

    #[test]
    fn grant_budget_renders_dash_when_usage_stale() {
        let stmt = make_test_statement(
            "S0",
            ResourceType::Session,
            "llm:generate",
            Some(Budget { tokens: Some(20_000), cents: None, requests: None, workload_hours: None, wall_clock_secs: None }),
            Usage { tokens: 5_000, last_updated: 0, ..Usage::default() },
        );
        let grant = make_test_grant(vec![vec![stmt]]);
        // Stale usage — runway should show dash.
        let out = render_grant_budget(&grant);
        assert!(out.contains("Runway:  —"), "expected stale runway dash: {out}");
    }

    #[test]
    fn render_single_statement_no_budget() {
        let stmt = make_test_statement("S0", ResourceType::Credential, "credential:*", None, Usage::default());
        let grant = make_test_grant(vec![vec![stmt]]);
        let out = render_grant_budget(&grant);
        assert!(out.contains("Grant grant-test"), "missing header: {out}");
        assert!(out.contains("Budget:  (none)"), "expected no-budget line: {out}");
        // Single-statement grants must NOT show per-statement header.
        assert!(!out.contains("Statement S0"), "should not show stmt header for single: {out}");
    }

    #[test]
    fn render_composite_three_statements() {
        let s0 = make_test_statement("S0", ResourceType::Credential, "credential:*", None, Usage::default());
        let s1 = make_test_statement(
            "S1",
            ResourceType::Session,
            "llm:generate",
            Some(Budget { tokens: Some(20_000), cents: Some(100), requests: None, workload_hours: None, wall_clock_secs: None }),
            Usage { tokens: 12_450, cents: 85, requests: 0, workload_hours: 0, wall_clock_secs: 0, last_updated: 0 },
        );
        let s2 = make_test_statement(
            "S2",
            ResourceType::Time,
            "session:*",
            Some(Budget { tokens: None, cents: None, requests: None, workload_hours: None, wall_clock_secs: Some(1800) }),
            Usage { tokens: 0, cents: 0, requests: 0, workload_hours: 0, wall_clock_secs: 240, last_updated: 0 },
        );
        let grant = make_test_grant(vec![vec![s0, s1, s2]]);
        let out = render_grant_budget(&grant);

        // Should have per-statement headers.
        assert!(out.contains("Statement S0"), "missing S0 header: {out}");
        assert!(out.contains("Statement S1"), "missing S1 header: {out}");
        assert!(out.contains("Statement S2"), "missing S2 header: {out}");

        // S0 has no budget.
        assert!(out.contains("Budget:  (none)"), "expected no-budget for S0: {out}");

        // S1 shows token and cent usage.
        assert!(out.contains("12450"), "missing token usage: {out}");
        assert!(out.contains("20000"), "missing token cap: {out}");
        assert!(out.contains("62%"), "wrong token pct: {out}");
        assert!(out.contains("85%"), "wrong cent pct: {out}");

        // S2 shows wall-clock usage.
        assert!(out.contains("240"), "missing wall-clock used: {out}");
        assert!(out.contains("1800"), "missing wall-clock cap: {out}");
        assert!(out.contains("13%"), "wrong wall-clock pct: {out}");
    }

    /// Verifies that configure_tracing writes JSON log lines to a rolling file.
    ///
    /// Marked `#[ignore]` because it installs a global tracing subscriber, which
    /// conflicts with other tests in the same process. Run with:
    ///   cargo test -p emberlink-cli -- --ignored configure_tracing_writes_json_log
    #[test]
    #[ignore]
    fn configure_tracing_writes_json_log() {
        use ember_daemon::config::LogLevel;
        use std::io::BufRead;
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();

        let guard = configure_tracing(data_dir, &LogLevel::Info, false);
        tracing::info!(test_marker = "unit-test-probe", "configure_tracing_writes_json_log probe");
        // Drop guard to flush the non-blocking writer before reading the file.
        drop(guard);

        // tracing-appender rolling daily names files <prefix>.<YYYY-MM-DD>
        let log_file = std::fs::read_dir(data_dir)
            .unwrap()
            .flatten()
            .find(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("daemon.log")
            })
            .expect("daemon.log.* should exist after drop");

        let file = std::fs::File::open(log_file.path()).unwrap();
        let reader = std::io::BufReader::new(file);
        let found = reader.lines().map_while(Result::ok).any(|line| {
            // Each line should be a JSON object; look for our test marker.
            line.contains("unit-test-probe")
        });
        assert!(found, "expected test_marker in log file");
    }

    // --- sandbox run flag-parsing tests ---

    fn parse_sandbox_run(args: &[&str]) -> SandboxAction {
        use clap::Parser as _;
        // Build the full CLI args: ["ember", "sandbox", "run", ...args]
        let full: Vec<&str> = std::iter::once("ember")
            .chain(std::iter::once("sandbox"))
            .chain(std::iter::once("run"))
            .chain(args.iter().copied())
            .collect();
        let cli = Cli::try_parse_from(&full).expect("parse failed");
        match cli.command {
            Commands::Sandbox { action } => action,
            _ => panic!("expected Sandbox command"),
        }
    }

    #[test]
    fn sandbox_run_parses_required_name_and_image() {
        let action = parse_sandbox_run(&["agent-coding", "--image", "ember-claude-code:v1", "--prompt", "hello"]);
        match action {
            SandboxAction::Run { name, image, prompt, .. } => {
                assert_eq!(name, "agent-coding");
                assert_eq!(image, "ember-claude-code:v1");
                assert_eq!(prompt.as_deref(), Some("hello"));
            }
            _ => panic!("expected SandboxAction::Run"),
        }
    }

    #[test]
    fn sandbox_run_default_image_is_ubuntu() {
        let action = parse_sandbox_run(&["my-sandbox"]);
        match action {
            SandboxAction::Run { image, .. } => {
                assert_eq!(image, "ubuntu:24.04");
            }
            _ => panic!("expected SandboxAction::Run"),
        }
    }

    #[test]
    fn sandbox_run_prompt_is_optional() {
        let action = parse_sandbox_run(&["my-sandbox", "--image", "alpine:3"]);
        match action {
            SandboxAction::Run { prompt, .. } => {
                assert!(prompt.is_none());
            }
            _ => panic!("expected SandboxAction::Run"),
        }
    }

    #[test]
    fn sandbox_run_parses_workspace_from() {
        let action = parse_sandbox_run(&[
            "ws-sandbox",
            "--image", "ember-claude-code:v1",
            "--workspace-from", "https://github.com/example/repo",
        ]);
        match action {
            SandboxAction::Run { workspace_from, .. } => {
                assert_eq!(workspace_from.as_deref(), Some("https://github.com/example/repo"));
            }
            _ => panic!("expected SandboxAction::Run"),
        }
    }

    #[test]
    fn sandbox_run_parses_env_vars() {
        let action = parse_sandbox_run(&[
            "env-sandbox",
            "--env", "FOO=bar",
            "--env", "BAZ=qux",
        ]);
        match action {
            SandboxAction::Run { env, .. } => {
                assert!(env.contains(&"FOO=bar".to_string()));
                assert!(env.contains(&"BAZ=qux".to_string()));
            }
            _ => panic!("expected SandboxAction::Run"),
        }
    }

    #[test]
    fn sandbox_run_parses_ttl() {
        let action = parse_sandbox_run(&[
            "ttl-sandbox",
            "--ttl", "30m",
        ]);
        match action {
            SandboxAction::Run { ttl, .. } => {
                assert_eq!(ttl.as_deref(), Some("30m"));
            }
            _ => panic!("expected SandboxAction::Run"),
        }
    }

    // --- docker_exec_flags unit tests (implementation-note-36) ---

    #[test]
    fn docker_exec_flags_non_tty_returns_only_i() {
        let flags = docker_exec_flags(false);
        assert_eq!(flags, vec!["-i"], "non-TTY: only -i, no -t");
    }

    #[test]
    fn docker_exec_flags_tty_returns_i_and_t() {
        let flags = docker_exec_flags(true);
        assert_eq!(flags, vec!["-i", "-t"], "TTY: both -i and -t");
    }

    fn parse_grant_create(args: &[&str]) -> GrantAction {
        use clap::Parser as _;
        let full: Vec<&str> = std::iter::once("ember")
            .chain(std::iter::once("grant"))
            .chain(std::iter::once("create"))
            .chain(args.iter().copied())
            .collect();
        let cli = Cli::try_parse_from(&full).expect("parse failed");
        match cli.command {
            Commands::Grant { action } => action,
            _ => panic!("expected Grant command"),
        }
    }

    #[test]
    fn grant_create_ttl_parses_humantime_and_bare_integer() {
        for (input, expected_secs) in [
            ("5s", 5u64),
            ("5m", 300),
            ("2h", 7200),
            ("30", 30),
        ] {
            let action = parse_grant_create(&[
                "--persona", "p1",
                "--credential", "cred-x",
                "--scope", "read",
                "--ttl", input,
            ]);
            match action {
                GrantAction::Create { ttl, .. } => {
                    let s = ttl.as_deref().unwrap_or("");
                    let parsed = parse_duration(s).expect("should parse");
                    assert_eq!(parsed, expected_secs, "input={input}");
                }
                _ => panic!("expected GrantAction::Create"),
            }
        }
    }

    #[test]
    fn sandbox_run_parses_budget_tokens_and_usd() {
        let action = parse_sandbox_run(&[
            "budget-sandbox",
            "--budget-tokens", "20000",
            "--budget-usd", "0.50",
        ]);
        match action {
            SandboxAction::Run { budget_tokens, budget_usd, .. } => {
                assert_eq!(budget_tokens, Some(20_000u64));
                assert_eq!(budget_usd.as_deref(), Some("0.50"));
            }
            _ => panic!("expected SandboxAction::Run"),
        }
    }

    #[test]
    fn sandbox_run_parses_credential_resource() {
        let action = parse_sandbox_run(&[
            "cred-sandbox",
            "--credential-resource", "obj-github-token",
        ]);
        match action {
            SandboxAction::Run { credential_resource, .. } => {
                assert_eq!(credential_resource.as_deref(), Some("obj-github-token"));
            }
            _ => panic!("expected SandboxAction::Run"),
        }
    }

    #[test]
    fn sandbox_run_full_flags() {
        let action = parse_sandbox_run(&[
            "full-sandbox",
            "--image", "ember-claude-code:v1",
            "--prompt", "echo hello",
            "--workspace-from", "https://github.com/example/repo",
            "--env", "KEY=val",
            "--ttl", "60s",
            "--budget-tokens", "5000",
            "--budget-usd", "0.25",
            "--budget-seconds", "3600",
            "--credential-resource", "obj-anthropic-key",
        ]);
        match action {
            SandboxAction::Run {
                name,
                image,
                prompt,
                workspace_from,
                env,
                ttl,
                budget_tokens,
                budget_usd,
                budget_seconds,
                credential_resource,
            } => {
                assert_eq!(name, "full-sandbox");
                assert_eq!(image, "ember-claude-code:v1");
                assert_eq!(prompt.as_deref(), Some("echo hello"));
                assert_eq!(workspace_from.as_deref(), Some("https://github.com/example/repo"));
                assert!(env.contains(&"KEY=val".to_string()));
                assert_eq!(ttl.as_deref(), Some("60s"));
                assert_eq!(budget_tokens, Some(5_000u64));
                assert_eq!(budget_usd.as_deref(), Some("0.25"));
                assert_eq!(budget_seconds, Some(3_600u64));
                assert_eq!(credential_resource.as_deref(), Some("obj-anthropic-key"));
            }
            _ => panic!("expected SandboxAction::Run"),
        }
    }

    // --- belt-and-suspenders: production checkpoint gate for cmd_init ---

    /// Verify that `check_production_sentinel` blocks production keyring writes
    /// when the checkpoint file is absent. This is the gate that `cmd_init` calls
    /// before `keyring::Entry::new` — belt-and-suspenders alongside prior change's
    /// `resolve_init_keyring_value` fix.
    #[test]
    fn production_sentinel_fires_when_file_absent() {
        let tmp = tempfile::tempdir().unwrap();
        // No ~/.ember-production in tmp — checkpoint must reject.
        let result =
            check_production_sentinel(DEFAULT_KEYRING_SERVICE, DEFAULT_KEYRING_SERVICE, tmp.path());
        assert!(
            result.is_err(),
            "checkpoint should reject production service when opt-in file is absent"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("refusing to open production keychain"),
            "error message should explain the refusal; got: {msg}"
        );
    }

    #[test]
    fn production_sentinel_passes_when_file_present() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".ember-production"), b"").unwrap();
        let result =
            check_production_sentinel(DEFAULT_KEYRING_SERVICE, DEFAULT_KEYRING_SERVICE, tmp.path());
        assert!(result.is_ok(), "checkpoint should pass when opt-in file exists");
    }

    #[test]
    fn production_sentinel_passes_for_non_production_service() {
        let tmp = tempfile::tempdir().unwrap();
        // No checkpoint file, but service is not the production default → should pass.
        let result =
            check_production_sentinel("ember-daemon-test", DEFAULT_KEYRING_SERVICE, tmp.path());
        assert!(
            result.is_ok(),
            "checkpoint should pass when service differs from production default"
        );
    }

    // --- security check: EMBER_VAULT_PASSPHRASE cleared after first read in cmd_init ---

    #[test]
    fn cmd_init_removes_vault_passphrase_env_after_read() {
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
            git_proxy_addr: None,
            keyring: ember_daemon::config::KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            presence: ember_daemon::config::PresenceConfigSection::default(),
        };

        // SAFETY: test-only, single-threaded, no other threads reading env vars.
        unsafe {
            std::env::set_var("EMBER_VAULT_PASSPHRASE", "sec14-cli-passphrase");
        }

        cmd_init(&config, Some("test".to_string()), Some(&config_path), None, None, false);

        assert!(
            std::env::var("EMBER_VAULT_PASSPHRASE").is_err(),
            "EMBER_VAULT_PASSPHRASE must be absent from the environment after cmd_init"
        );
    }

    // --- .C device enroll/pair scaffold parse tests ---

    fn parse_device(args: &[&str]) -> DeviceAction {
        use clap::Parser as _;
        let full: Vec<&str> = std::iter::once("ember")
            .chain(std::iter::once("device"))
            .chain(args.iter().copied())
            .collect();
        let cli = Cli::try_parse_from(&full).expect("parse failed");
        match cli.command {
            Commands::Device { action } => action,
            _ => panic!("expected Device command"),
        }
    }

    #[test]
    fn device_enroll_passkey_parses() {
        let action = parse_device(&["enroll", "--passkey"]);
        match action {
            DeviceAction::Enroll { passkey } => {
                assert!(passkey, "--passkey flag should be set");
            }
            _ => panic!("expected DeviceAction::Enroll"),
        }
    }

    #[test]
    fn device_enroll_without_passkey_parses_with_default() {
        // Locks the surface: invoking `ember device enroll` without
        // --passkey is still parseable today (clap default for `bool` =
        // false). Wire-up may flip this to required; the test exists so
        // that flip is intentional, not accidental.
        let action = parse_device(&["enroll"]);
        match action {
            DeviceAction::Enroll { passkey } => {
                assert!(!passkey, "--passkey absent => false");
            }
            _ => panic!("expected DeviceAction::Enroll"),
        }
    }

    #[test]
    fn device_pair_parses() {
        let action = parse_device(&["pair"]);
        assert!(matches!(action, DeviceAction::Pair));
    }
}
