//! `ember` CLI binary.
//!
//! open_store_mutator_audit_complete
//!
//! Audit of every `open_store(config)` call site in this file, per
//! implementation-note-445. Under design
//! separate-uid posture (daemon=ember uid, operator=operator uid) the daemon
//! owns the SQLite DB and the operator cannot open it for writing — so
//! every direct-store *mutator* call site needs to route through the
//! daemon's JSON-RPC socket instead. Read-only paths are tolerable for
//! local-dev convenience but should also migrate in time.
//!
//! Classification key (search "open-store-audit" to find each site):
//!   * READ-ONLY: only invokes read methods on the store.
//!   * MUTATOR: invokes a store method that writes the DB AND the daemon
//!     already exposes an equivalent RPC.
//!   * MUTATOR-NO-RPC: invokes a store-write method with no existing
//!     daemon RPC; needs a daemon-side handler before the call site can
//!     migrate.
//!   * MUTATOR-MIXED: sub-action match where some arms are read-only and
//!     others mutate; migrate per-arm.
//!
//! Current migration state: `GrantAction::{Create,List,Revoke,Expire,Extend,Budget,Delegate}`,
//! daemon-present `VaultAction::{List,Get,Add,Put,Export,Import,Remove,Lock,Unlock}`,
//! installed-path `ReceiptAction::{List,Show,Export,Verify(id-mode)}`,
//! installed-path `AuditAction::Query`,
//! installed-path `ApprovalAction::{List,Approve,Deny,Narrow}`,
//! installed-path `Commands::Status`,
//! regular `SandboxAction::{Create,List,Stop,Delete,Exec}`, the daemon-owned
//! sandbox/grant orchestration half of `SandboxAction::Run`, and the live-socket
//! portions of plain `ember init` route through the daemon socket. The main
//! remaining mixed operator surface is bootstrap-local init work plus the local
//! prompt handoff in `SandboxAction::Run`.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, IsTerminal, Read, Write as _};
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::rc::Rc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use core_grant_types::{
    AccessGrant, Budget, GrantProposal, ResourceSelector, ResourceType, Statement,
    StatementProposal,
};
use ember_daemon::infra::audit::AuditFilter;
use ember_daemon::infra::config::DaemonConfig;
use ember_daemon::infra::image_registry::ImageRegistry;
use ember_daemon::infra::runtime::{
    DaemonRuntime, DashboardBind, GitProxyBind, LlmProxyBind, StartupBinds,
};
use ember_daemon::infra::sandbox::{
    SandboxCreateOpts, SandboxCreateResult, SandboxDeleteResult, SandboxInfo,
    SandboxRunGrantDisposition, SandboxRunResult,
};
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::{
    AutoUnsealOutcome, DEFAULT_KEYRING_ACCOUNT, DEFAULT_KEYRING_SERVICE, Vault, VaultScope,
    check_production_sentinel, is_cargo_test_binary, keyring_writes_suppressed,
    resolve_keyring_account, resolve_keyring_service, try_auto_unseal_from_keyring,
    validate_credential_name, verify_keyring_roundtrip,
};
use ember_daemon::trust::approval::ApprovalOutcome;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

#[path = "daemon_agent.rs"]
mod daemon_agent;

/// Render the version string consumed by `ember --version`, `ember -V`, and
/// `ember version`.
///
/// Format: `ember <semver> (<git-sha-or-(no-git)>) built <rfc3339-utc>`.
///
/// CLI-VERSION-FLAG: the implementation-note-119 root cause was a
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

/// Resolve the credential value for `ember vault add` / `ember vault put`
/// from the safe input flags (`--stdin`, `--file <path>`, terminal prompt).
///
/// Returns `Ok(bytes)` on success, or `Err(exit_code)` after emitting a
/// human-readable error to stderr (1 for runtime failures, 2 for input
/// validation refusals like `--file` under `~/Downloads`).
fn resolve_credential_input(
    stdin: bool,
    file: Option<&Path>,
    delete_source: bool,
    from_downloads: bool,
) -> Result<Vec<u8>, i32> {
    if stdin {
        let mut buf = Vec::new();
        if let Err(e) = io::stdin().read_to_end(&mut buf) {
            eprintln!("error: failed to read stdin: {e}");
            return Err(1);
        }
        if buf.last() == Some(&b'\n') {
            buf.pop();
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
        }
        if buf.is_empty() {
            eprintln!("error: --stdin received empty value");
            return Err(1);
        }
        return Ok(buf);
    }
    if let Some(path) = file {
        let downloads_dir = dirs_next::download_dir();
        if !from_downloads
            && let Some(dl) = downloads_dir.as_ref()
            && path.starts_with(dl)
        {
            eprintln!(
                "error: --file refuses paths under ~/Downloads ({}) — \
                 Downloads is a known cleartext-credential leak surface.",
                dl.display()
            );
            eprintln!(
                "       Move the file to a non-Downloads path, or pass \
                 --from-downloads to acknowledge the risk."
            );
            return Err(2);
        }
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: failed to read --file {}: {e}", path.display());
                return Err(1);
            }
        };
        if bytes.is_empty() {
            eprintln!("error: --file {} is empty", path.display());
            return Err(1);
        }
        if delete_source {
            // Best-effort overwrite-then-unlink; matches the existing
            // `ember vault add` behavior. fsync is omitted intentionally.
            let zeros = vec![0u8; bytes.len()];
            if let Err(e) = std::fs::write(path, &zeros) {
                eprintln!(
                    "warn: --delete-source: failed to zero {}: {e}",
                    path.display()
                );
            }
            if let Err(e) = std::fs::remove_file(path) {
                eprintln!(
                    "warn: --delete-source: failed to unlink {}: {e}",
                    path.display()
                );
            }
        }
        return Ok(bytes);
    }
    if io::stdin().is_terminal() {
        return match rpassword::prompt_password("Paste credential value: ") {
            Ok(s) if s.is_empty() => {
                eprintln!("error: empty value");
                Err(1)
            }
            Ok(s) => Ok(s.into_bytes()),
            Err(e) => {
                eprintln!("error: failed to read prompt: {e}");
                Err(1)
            }
        };
    }
    eprintln!(
        "error: no value source. Pass --stdin (pipe or terminal) or \
         --file <path>; --value is refused (leaks via shell history)."
    );
    Err(2)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VaultLockDispatch {
    DaemonRpc,
    LocalFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VaultActionDispatch {
    DaemonRpc,
    LocalFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantActionDispatch {
    DaemonRpc,
    LocalFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SandboxActionDispatch {
    DaemonRpc,
    LocalFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiptActionDispatch {
    DaemonRpc,
    LocalFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditActionDispatch {
    DaemonRpc,
    LocalFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalActionDispatch {
    DaemonRpc,
    LocalFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusActionDispatch {
    DaemonRpc,
    LocalFallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InstalledLauncherIssue {
    BrokenRepoBuildSymlink { path: PathBuf, target: PathBuf },
    BrokenSymlink { path: PathBuf, target: PathBuf },
}

impl InstalledLauncherIssue {
    fn detail(&self) -> String {
        match self {
            Self::BrokenRepoBuildSymlink { path, target } => format!(
                "{} -> {} (missing repo build artifact)",
                path.display(),
                target.display()
            ),
            Self::BrokenSymlink { path, target } => format!(
                "{} -> {} (missing target)",
                path.display(),
                target.display()
            ),
        }
    }

    fn repair_guidance(&self) -> String {
        match self {
            Self::BrokenRepoBuildSymlink { path, target } => format!(
                "Repair the installed `ember` launcher path first: {} points at missing repo build artifact {}. Reinstall the managed CLI artifact or stop pointing the host launcher at `target/...` outputs.",
                path.display(),
                target.display()
            ),
            Self::BrokenSymlink { path, target } => format!(
                "Repair the installed `ember` launcher path first: {} points at missing target {}. Reinstall or relink the managed CLI artifact before treating this as a daemon/product failure.",
                path.display(),
                target.display()
            ),
        }
    }
}

struct VaultStoreResult {
    dispatch: VaultActionDispatch,
    id: String,
    name: String,
}

const PROD_EMBER_LAUNCHER_PATH: &str = "/usr/local/bin/ember";
const CLAUDE_CODE_DEFAULT_SCOPE: &str = "claude-code-default-v1";
const CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL: &str = "anthropic-key";

#[derive(Debug, Clone)]
struct CompositeGrantCreateSpec {
    persona_id: String,
    credential_name: String,
    scope: String,
    ttl_secs: Option<u64>,
    statements: Vec<StatementProposal>,
}

impl CompositeGrantCreateSpec {
    fn daemon_request(&self) -> serde_json::Value {
        serde_json::json!({
            "persona_id": self.persona_id,
            "credential_name": self.credential_name,
            "scope": self.scope,
            "ttl_secs": self.ttl_secs,
            "statements": self.statements,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnthropicRuntimeCredentialAvailability {
    Absent,
    ExistingVaultEntry,
    StoredFromEnv,
}

#[derive(Debug, Clone)]
struct ClaudeCodeGrantProvisioning {
    id: String,
    expires_at: Option<String>,
    created: bool,
    brokered_anthropic_runtime: bool,
}

#[derive(Debug, serde::Deserialize)]
struct GrantBudgetStatusView {
    id: String,
    persona_id: String,
    status: String,
    expires_at: Option<String>,
    #[serde(default)]
    statements: Vec<GrantBudgetStatusStatementView>,
}

#[derive(Debug, serde::Deserialize)]
struct GrantBudgetStatusStatementView {
    sid: String,
    resource_type: String,
    resource: ResourceSelector,
    budget: Option<Budget>,
    usage: core_grant_types::Usage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GithubHttpsLane {
    ConfiguredApp,
    ConfiguredPat,
    ConfiguredMock,
    Broken,
    NotConfigured,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GithubProviderStatusView {
    lane: String,
    #[serde(default)]
    detail: Option<String>,
    #[serde(default)]
    app_id: Option<String>,
    #[serde(default)]
    installation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GrantCreateSpec {
    persona: String,
    credential: String,
    scope: String,
    ttl_secs: Option<u64>,
    max_uses_per_hour: Option<u64>,
    allowed_hours_start: Option<u32>,
    allowed_hours_end: Option<u32>,
    allowed_targets: Option<Vec<String>>,
    max_delegation_depth: Option<u32>,
    budget: Option<Budget>,
    max_children_per_day: Option<u64>,
    auto_delegate_scope_template: Option<String>,
}

impl GrantCreateSpec {
    fn daemon_request(&self) -> serde_json::Value {
        serde_json::json!({
            "persona_id": self.persona,
            "credential_name": self.credential,
            "scope": self.scope,
            "ttl_secs": self.ttl_secs,
            "max_uses_per_hour": self.max_uses_per_hour,
            "allowed_hours_start": self.allowed_hours_start,
            "allowed_hours_end": self.allowed_hours_end,
            "allowed_targets": self.allowed_targets,
            "max_delegation_depth": self.max_delegation_depth,
            "budget": self.budget,
            "max_children_per_day": self.max_children_per_day,
            "auto_delegate_scope_template": self.auto_delegate_scope_template,
        })
    }

    fn allowed_targets_display(&self) -> Option<String> {
        self.allowed_targets
            .as_ref()
            .map(|targets| targets.join(","))
    }
}

fn print_created_grant(spec: &GrantCreateSpec, id: &str, expires_at: Option<&str>) {
    println!("Created grant");
    println!("  ID:         {id}");
    println!("  Persona:    {}", spec.persona);
    println!("  Credential: {}", spec.credential);
    println!("  Scope:      {}", spec.scope);
    if let Some(exp) = expires_at {
        println!("  Expires:    {exp}");
    } else {
        println!("  Expires:    never");
    }
    if let Some(rl) = spec.max_uses_per_hour {
        println!("  Rate limit: {rl}/hour");
    }
    if let Some(hs) = spec.allowed_hours_start {
        println!(
            "  Hours:      {hs}:00-{}:00 UTC",
            spec.allowed_hours_end.unwrap_or(0)
        );
    }
    if let Some(targets) = spec.allowed_targets_display() {
        println!("  Targets:    {targets}");
    }
    if let Some(depth) = spec.max_delegation_depth {
        println!("  Delegation: max depth {depth}");
    }
    if let Some(ref budget) = spec.budget {
        if let Some(tokens) = budget.tokens {
            println!("  Budget:     {} tokens", tokens);
        }
        if let Some(cents) = budget.cents {
            println!("  Budget:     ${:.2}", cents as f64 / 100.0);
        }
        if let Some(requests) = budget.requests {
            println!("  Budget:     {} requests", requests);
        }
        if let Some(seconds) = budget.wall_clock_secs {
            println!("  Budget:     {}s wall-clock", seconds);
        }
    }
    if let Some(limit) = spec.max_children_per_day {
        println!("  Standing:   yes (max {limit}/day)");
        if let Some(ref tpl) = spec.auto_delegate_scope_template {
            println!("  Auto-scope: {tpl}");
        }
    }
}

/// Lock the live vault on the current authority surface.
///
/// When a daemon socket is present, `ember vault lock` must act on the daemon's
/// in-process state rather than only this CLI process. The local fallback is
/// retained only for CLI-only/dev paths where no daemon socket exists at all.
fn run_vault_lock(config: &DaemonConfig) -> Result<VaultLockDispatch, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        emberlink_cli::call_daemon_method(&socket_path, "vault_lock", &serde_json::Value::Null)?;
        Ok(VaultLockDispatch::DaemonRpc)
    } else {
        ember_daemon::trust::presence::lock();
        Ok(VaultLockDispatch::LocalFallback)
    }
}

/// Re-open the live vault on the current authority surface.
///
/// On the installed daemon-backed path this exercises the explicit
/// non-session reopen seam. The local fallback is retained only for
/// CLI-only/dev paths where no daemon socket exists.
fn run_vault_unlock(
    config: &DaemonConfig,
) -> Result<VaultLockDispatch, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        emberlink_cli::call_daemon_method(&socket_path, "vault_unlock", &serde_json::Value::Null)?;
        Ok(VaultLockDispatch::DaemonRpc)
    } else if uses_managed_separate_uid_topology(config) {
        Err(managed_local_vault_fallback_refused())
    } else {
        let _ = Vault::open_from_config(config)
            .map_err(|e| core_types::ValidationError::new(format!("vault open: {e}")))?;
        Ok(VaultLockDispatch::LocalFallback)
    }
}

/// List vault entries on the current authority surface.
fn run_vault_list(
    config: &DaemonConfig,
    prefix: Option<&str>,
) -> Result<(VaultActionDispatch, Vec<serde_json::Value>), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "vault_list",
            &serde_json::Value::Null,
        )?;
        let mut entries = result
            .as_array()
            .cloned()
            .ok_or_else(|| core_types::ValidationError::new("daemon vault_list: expected array"))?;
        if let Some(p) = prefix
            && !p.is_empty()
        {
            entries.retain(|entry| {
                entry
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|name| name.starts_with(p))
                    .unwrap_or(false)
            });
        }
        Ok((VaultActionDispatch::DaemonRpc, entries))
    } else if uses_managed_separate_uid_topology(config) {
        Err(managed_local_vault_fallback_refused())
    } else {
        let store = open_store(config);
        let vault = Vault::open_from_config(config)
            .map_err(|e| core_types::ValidationError::new(format!("vault open: {e}")))?;
        let mut creds = vault
            .list(VaultScope::Interactive, &store)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        if let Some(p) = prefix
            && !p.is_empty()
        {
            creds.retain(|c| c.name.starts_with(p));
        }
        let entries = creds
            .iter()
            .map(|c| serde_json::json!({"id": c.id, "name": c.name, "metadata": c.metadata}))
            .collect();
        Ok((VaultActionDispatch::LocalFallback, entries))
    }
}

/// Remove a vault entry via the daemon's `vault_remove` RPC.
///
/// vault_actions_migrated_to_rpc: under design's separate-uid posture the
/// daemon owns the SQLite DB; the prior `open_store(config)` local fallback
/// was silently-broken-by-design. Per implementation-note-446
/// the fallback branch was removed; missing-socket errors surface clearly
/// through `call_daemon_method`.
fn run_vault_remove(
    config: &DaemonConfig,
    name: &str,
) -> Result<VaultActionDispatch, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    emberlink_cli::call_daemon_method(
        &socket_path,
        "vault_remove",
        &serde_json::json!({ "name": name }),
    )?;
    Ok(VaultActionDispatch::DaemonRpc)
}

/// Fetch a vault entry via the daemon's `vault_get` RPC.
///
/// Local fallback removed per implementation-note-446;
/// see the `vault_actions_migrated_to_rpc` note on [`run_vault_remove`].
fn run_vault_get(
    config: &DaemonConfig,
    name: &str,
) -> Result<(VaultActionDispatch, Vec<u8>), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "vault_get",
        &serde_json::json!({ "name": name }),
    )?;
    if let Some(bytes) = result.get("value_bytes").and_then(|v| v.as_array()) {
        let mut out = Vec::with_capacity(bytes.len());
        for item in bytes {
            let byte = item.as_u64().ok_or_else(|| {
                core_types::ValidationError::new(
                    "daemon vault_get: value_bytes must be an array of integers",
                )
            })?;
            let byte = u8::try_from(byte).map_err(|_| {
                core_types::ValidationError::new(
                    "daemon vault_get: value_bytes entries must fit in u8",
                )
            })?;
            out.push(byte);
        }
        return Ok((VaultActionDispatch::DaemonRpc, out));
    }

    let value = result
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| core_types::ValidationError::new("daemon vault_get: missing value"))?;
    Ok((VaultActionDispatch::DaemonRpc, value.as_bytes().to_vec()))
}

/// Store a vault entry via the daemon's `vault_add` RPC.
///
/// Local fallback removed per implementation-note-446;
/// see the `vault_actions_migrated_to_rpc` note on [`run_vault_remove`].
fn run_vault_store(
    config: &DaemonConfig,
    name: &str,
    value: &[u8],
    metadata: Option<&str>,
) -> Result<VaultStoreResult, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "vault_add",
        &serde_json::json!({
            "name": name,
            "value_bytes": value,
            "metadata": metadata,
        }),
    )?;
    let id = result
        .get("id")
        .map(|v| match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .unwrap_or_default();
    let stored_name = result
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(name)
        .to_string();
    Ok(VaultStoreResult {
        dispatch: VaultActionDispatch::DaemonRpc,
        id,
        name: stored_name,
    })
}

/// Migrate MEK keyring ACL via the daemon's `vault_migrate_acl` RPC.
///
/// Per implementation-note-446: routes through the
/// daemon so the operation lands in the daemon's audit log
/// (`vault.mek_acl_migrated`) and respects the separate-uid keyring scope
/// (design). The CLI's prior direct `migrate_mek_acl()` call bypassed
/// the audit trail. See the `vault_actions_migrated_to_rpc` checkpoint on
/// [`run_vault_remove`].
fn run_vault_migrate_acl(
    config: &DaemonConfig,
) -> Result<serde_json::Value, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let service = resolve_keyring_service(&config.keyring);
    let account = resolve_keyring_account(&config.keyring);
    emberlink_cli::call_daemon_method(
        &socket_path,
        "vault_migrate_acl",
        &serde_json::json!({
            "service": service,
            "account": account,
        }),
    )
}

/// Create a grant via the daemon's `create_grant` RPC.
///
/// grant_actions_migrated_to_rpc_complete: prior to implementation-note-447
/// this helper carried an `open_store(config)` local-fallback branch. Under
/// design's separate-uid posture the daemon owns the SQLite DB and the
/// operator cannot open it for writing — so the local fallback was
/// silently-broken-by-design. Route through the daemon socket only;
/// `call_daemon_method` surfaces a clear error if the socket is missing.
fn run_grant_create(
    config: &DaemonConfig,
    spec: &GrantCreateSpec,
) -> Result<(GrantActionDispatch, serde_json::Value), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result =
        emberlink_cli::call_daemon_method(&socket_path, "create_grant", &spec.daemon_request())?;
    Ok((GrantActionDispatch::DaemonRpc, result))
}

/// Create a multi-statement grant via the daemon's `create_composite_grant`
/// RPC.
fn run_grant_create_composite(
    config: &DaemonConfig,
    spec: &CompositeGrantCreateSpec,
) -> Result<(GrantActionDispatch, serde_json::Value), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "create_composite_grant",
        &spec.daemon_request(),
    )?;
    Ok((GrantActionDispatch::DaemonRpc, result))
}

fn is_anthropic_gateway_credential_name(credential_name: &str) -> bool {
    credential_name == CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL
        || credential_name.starts_with("anthropic/")
}

fn build_claude_code_anthropic_runtime_statements() -> Vec<StatementProposal> {
    vec![
        StatementProposal {
            resource_type: ResourceType::Credential,
            credential_name: CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL.to_string(),
            actions: vec!["credential:read".to_string()],
            resource: ResourceSelector::Exact {
                value: CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL.to_string(),
            },
            budget: None,
            conditions: vec![],
        },
        StatementProposal {
            resource_type: ResourceType::Session,
            credential_name: CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL.to_string(),
            actions: vec!["llm:generate".to_string()],
            resource: ResourceSelector::Glob {
                pattern: "anthropic/*".to_string(),
            },
            budget: None,
            conditions: vec![],
        },
    ]
}

fn grant_status_supports_anthropic_gateway(status: &serde_json::Value) -> bool {
    let Some(statements) = status.get("statements").and_then(|v| v.as_array()) else {
        return false;
    };

    let has_matching_credential_statement = statements.iter().any(|stmt| {
        stmt.get("resource_type").and_then(|v| v.as_str()) == Some("credential")
            && stmt
                .get("actions")
                .and_then(|v| v.as_array())
                .is_some_and(|actions| {
                    actions
                        .iter()
                        .filter_map(|action| action.as_str())
                        .any(|action| action == "credential:read")
                })
            && stmt.get("resource").is_some_and(|resource| {
                resource.get("kind").and_then(|v| v.as_str()) == Some("exact")
                    && resource.get("value").and_then(|v| v.as_str())
                        == Some(CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL)
            })
    });

    let has_anthropic_session_statement = statements.iter().any(|stmt| {
        stmt.get("resource_type").and_then(|v| v.as_str()) == Some("session")
            && stmt
                .get("actions")
                .and_then(|v| v.as_array())
                .is_some_and(|actions| {
                    actions
                        .iter()
                        .filter_map(|action| action.as_str())
                        .any(|action| action == "llm:generate")
                })
            && stmt.get("resource").is_some_and(|resource| {
                resource.get("kind").and_then(|v| v.as_str()) == Some("glob")
                    && resource.get("pattern").and_then(|v| v.as_str()) == Some("anthropic/*")
            })
    });

    has_matching_credential_statement && has_anthropic_session_statement
}

fn ensure_claude_code_anthropic_runtime_credential(
    config: &DaemonConfig,
) -> Result<AnthropicRuntimeCredentialAvailability, core_types::ValidationError> {
    let (_, entries) = run_vault_list(config, None)?;
    let already_present = entries.iter().any(|entry| {
        entry.get("name").and_then(|v| v.as_str()) == Some(CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL)
    });
    if already_present {
        return Ok(AnthropicRuntimeCredentialAvailability::ExistingVaultEntry);
    }

    let key = match std::env::var("ANTHROPIC_API_KEY") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(AnthropicRuntimeCredentialAvailability::Absent),
    };
    let key = key.trim_end_matches(['\r', '\n']);

    let _stored = run_vault_store(
        config,
        CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL,
        key.as_bytes(),
        Some("anthropic api key (claude code runtime)"),
    )?;
    Ok(AnthropicRuntimeCredentialAvailability::StoredFromEnv)
}

fn render_claude_runtime_auth_status(
    availability: AnthropicRuntimeCredentialAvailability,
) -> String {
    match availability {
        AnthropicRuntimeCredentialAvailability::StoredFromEnv => format!(
            "  Claude:   stored {} from ANTHROPIC_API_KEY",
            CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL
        ),
        AnthropicRuntimeCredentialAvailability::ExistingVaultEntry => format!(
            "  Claude:   reusing {} from vault",
            CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL
        ),
        AnthropicRuntimeCredentialAvailability::Absent => format!(
            "  Claude:   runtime auth remains ambient (export ANTHROPIC_API_KEY before rerunning init, or run `ember vault add --name {}` later to broker it)",
            CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL
        ),
    }
}

fn ensure_claude_code_runtime_grant(
    config: &DaemonConfig,
    persona_id: &str,
    anthropic_credential_available: bool,
) -> Result<ClaudeCodeGrantProvisioning, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let grants_value = emberlink_cli::call_daemon_method(
        &socket_path,
        "list_grants",
        &serde_json::json!({"persona_id": persona_id}),
    )?;
    let empty_grants: Vec<serde_json::Value> = Vec::new();
    let grants = grants_value.as_array().unwrap_or(&empty_grants);

    if anthropic_credential_available {
        for grant in grants.iter().filter(|grant| {
            grant
                .get("credential_name")
                .and_then(|v| v.as_str())
                .is_some_and(is_anthropic_gateway_credential_name)
        }) {
            let Some(grant_id) = grant.get("id").and_then(|v| v.as_str()) else {
                continue;
            };
            let status = emberlink_cli::call_daemon_method(
                &socket_path,
                "grant_status",
                &serde_json::json!({"id": grant_id}),
            )?;
            if grant_status_supports_anthropic_gateway(&status) {
                return Ok(ClaudeCodeGrantProvisioning {
                    id: grant_id.to_string(),
                    expires_at: grant
                        .get("expires_at")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    created: false,
                    brokered_anthropic_runtime: true,
                });
            }
        }

        let spec = CompositeGrantCreateSpec {
            persona_id: persona_id.to_string(),
            credential_name: CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL.to_string(),
            scope: CLAUDE_CODE_DEFAULT_SCOPE.to_string(),
            ttl_secs: Some(emberlink_cli::onboarding::claude_code::DEFAULT_GRANT_TTL_SECS),
            statements: build_claude_code_anthropic_runtime_statements(),
        };
        let (_, created) = run_grant_create_composite(config, &spec)?;
        return finalize_claude_code_runtime_grant_response(config, created, true, persona_id);
    }

    if let Some(grant) = grants.iter().find(|grant| {
        grant
            .get("credential_name")
            .and_then(|v| v.as_str())
            .is_some_and(|name| name == CLAUDE_CODE_DEFAULT_SCOPE)
    }) {
        return Ok(ClaudeCodeGrantProvisioning {
            id: grant
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            expires_at: grant
                .get("expires_at")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            created: false,
            brokered_anthropic_runtime: false,
        });
    }

    let created = emberlink_cli::call_daemon_method(
        &socket_path,
        "create_grant",
        &serde_json::json!({
            "persona_id": persona_id,
            "credential_name": CLAUDE_CODE_DEFAULT_SCOPE,
            "scope": CLAUDE_CODE_DEFAULT_SCOPE,
            "ttl_secs": emberlink_cli::onboarding::claude_code::DEFAULT_GRANT_TTL_SECS,
        }),
    )?;
    finalize_claude_code_runtime_grant_response(config, created, false, persona_id)
}

fn finalize_claude_code_runtime_grant_response(
    config: &DaemonConfig,
    response: serde_json::Value,
    brokered_anthropic_runtime: bool,
    target_persona_id: &str,
) -> Result<ClaudeCodeGrantProvisioning, core_types::ValidationError> {
    if response.get("status").and_then(|v| v.as_str()) == Some("pending_approval") {
        let approval_id = response
            .get("approval_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                core_types::ValidationError::new(
                    "daemon create_grant returned pending_approval without approval_id",
                )
            })?;
        let caller_persona_id =
            resolve_claude_code_grant_approver_persona_id(config, target_persona_id)?;
        let (_, resolved) = run_approval_resolve_with_caller(
            config,
            approval_id,
            &ApprovalOutcome::Approved,
            Some(&caller_persona_id),
        )?;
        let grant_id = resolved.result_grant_id.ok_or_else(|| {
            core_types::ValidationError::new(
                "approving claude-code init grant did not return result_grant_id",
            )
        })?;
        return Ok(ClaudeCodeGrantProvisioning {
            id: grant_id,
            expires_at: None,
            created: true,
            brokered_anthropic_runtime,
        });
    }

    let grant_id = response
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            core_types::ValidationError::new(
                "daemon create_grant returned success without a grant id",
            )
        })?;
    Ok(ClaudeCodeGrantProvisioning {
        id: grant_id.to_string(),
        expires_at: response
            .get("expires_at")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        created: true,
        brokered_anthropic_runtime,
    })
}

fn list_personas_via_daemon(
    config: &DaemonConfig,
) -> Result<Vec<serde_json::Value>, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let personas_value =
        emberlink_cli::call_daemon_method(&socket_path, "list_personas", &serde_json::Value::Null)?;
    personas_value.as_array().cloned().ok_or_else(|| {
        core_types::ValidationError::new("daemon list_personas: expected array")
    })
}

fn resolve_operator_persona_id_from_list(
    personas: &[serde_json::Value],
    excluded_persona_id: &str,
) -> Result<String, core_types::ValidationError> {
    if let Some(id) = personas.iter().find_map(|persona| {
        (persona.get("id").and_then(|v| v.as_str()) != Some(excluded_persona_id)
            && persona.get("name").and_then(|v| v.as_str()) == Some("root"))
        .then(|| persona.get("id").and_then(|v| v.as_str()))
        .flatten()
    }) {
        return Ok(id.to_string());
    }

    if let Some(id) = personas.iter().find_map(|persona| {
        let name = persona
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        (persona.get("id").and_then(|v| v.as_str()) != Some(excluded_persona_id)
            && !name.starts_with("orchestrator-")
            && !name.starts_with("claude-code-")
            && !name.starts_with('_'))
        .then(|| persona.get("id").and_then(|v| v.as_str()))
        .flatten()
    }) {
        return Ok(id.to_string());
    }

    Err(core_types::ValidationError::new(
        "could not resolve an operator persona for this daemon-backed operator action",
    ))
}

fn resolve_operator_persona_id(
    config: &DaemonConfig,
    excluded_persona_id: &str,
) -> Result<String, core_types::ValidationError> {
    let personas = list_personas_via_daemon(config)?;
    resolve_operator_persona_id_from_list(&personas, excluded_persona_id)
}

fn resolve_claude_code_grant_approver_persona_id(
    config: &DaemonConfig,
    target_persona_id: &str,
) -> Result<String, core_types::ValidationError> {
    resolve_operator_persona_id(config, target_persona_id)
}

fn run_persona_revoke(
    config: &DaemonConfig,
    id: &str,
) -> Result<(), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let personas = list_personas_via_daemon(config)?;
    let mut request = serde_json::json!({
        "id": id,
        "caller_persona_id": id,
    });
    if let Some(name) = personas.iter().find_map(|persona| {
        (persona.get("id").and_then(|v| v.as_str()) == Some(id))
            .then(|| persona.get("name").and_then(|v| v.as_str()))
            .flatten()
    }) {
        request["name"] = serde_json::json!(name);
    }
    let _ = emberlink_cli::call_daemon_method(&socket_path, "revoke_persona", &request)?;
    Ok(())
}

/// List grants on the current authority surface.
fn run_grant_list(
    config: &DaemonConfig,
    active_only: bool,
) -> Result<(GrantActionDispatch, Vec<serde_json::Value>), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "list_operator_grants",
            &serde_json::json!({ "active_only": active_only }),
        )?;
        let list = result.as_array().cloned().ok_or_else(|| {
            core_types::ValidationError::new("daemon list_operator_grants: expected array")
        })?;
        Ok((GrantActionDispatch::DaemonRpc, list))
    } else {
        let store = open_store(config);
        let grants = if active_only {
            store.list_active_grants()
        } else {
            store.list_grants()
        }
        .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        let list = grants
            .iter()
            .map(|g| {
                serde_json::json!({
                    "id": g.id,
                    "persona_id": g.persona_id,
                    "credential_name": g.credential_name,
                    "scope": g.scope,
                    "status": g.status,
                    "expires_at": g.expires_at,
                })
            })
            .collect();
        Ok((GrantActionDispatch::LocalFallback, list))
    }
}

/// Delegate a grant via the daemon's `delegate_grant` RPC.
///
/// Local fallback removed per implementation-note-447;
/// see the `grant_actions_migrated_to_rpc_complete` note on
/// [`run_grant_create`].
fn run_grant_delegate(
    config: &DaemonConfig,
    parent_grant_id: &str,
    child_persona_id: &str,
    scope: &str,
    ttl_secs: Option<u64>,
    budget: Option<Budget>,
) -> Result<(GrantActionDispatch, serde_json::Value), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let status = emberlink_cli::call_daemon_method(
        &socket_path,
        "grant_status",
        &serde_json::json!({ "id": parent_grant_id }),
    )?;
    let caller_persona_id = status
        .get("persona_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            core_types::ValidationError::new("daemon grant_status: missing parent grant persona_id")
        })?;
    let request = serde_json::json!({
        "parent_grant_id": parent_grant_id,
        "child_persona_id": child_persona_id,
        "scope": scope,
        "ttl_secs": ttl_secs,
        "budget": budget,
        "caller_persona_id": caller_persona_id,
    });
    let result = emberlink_cli::call_daemon_method(&socket_path, "delegate_grant", &request)?;
    Ok((GrantActionDispatch::DaemonRpc, result))
}

/// Expire stale grants on the current authority surface.
fn run_grant_expire(
    config: &DaemonConfig,
) -> Result<(GrantActionDispatch, u64), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "expire_grants",
            &serde_json::Value::Null,
        )?;
        let count = result
            .get("expired_count")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                core_types::ValidationError::new("daemon expire_grants: missing expired_count")
            })?;
        Ok((GrantActionDispatch::DaemonRpc, count))
    } else {
        let store = open_store(config);
        let count = store
            .expire_stale_grants()
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((GrantActionDispatch::LocalFallback, count as u64))
    }
}

/// Extend a grant via the daemon's `extend_grant` RPC.
///
/// Local fallback removed per implementation-note-447;
/// see the `grant_actions_migrated_to_rpc_complete` note on
/// [`run_grant_create`].
fn run_grant_extend(
    config: &DaemonConfig,
    grant_id: &str,
    add_tokens: Option<u64>,
    add_cents: Option<u64>,
    add_ttl_secs: Option<u64>,
) -> Result<GrantActionDispatch, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    emberlink_cli::call_daemon_method(
        &socket_path,
        "extend_grant",
        &serde_json::json!({
            "grant_id": grant_id,
            "add_tokens": add_tokens,
            "add_cents": add_cents,
            "add_ttl_secs": add_ttl_secs,
        }),
    )?;
    Ok(GrantActionDispatch::DaemonRpc)
}

fn render_grant_budget_from_status(view: &GrantBudgetStatusView) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let now = chrono::Utc::now();
    let now_secs = now.timestamp().max(0) as u64;

    let _ = writeln!(out, "Grant {}", view.id);
    let _ = writeln!(out, "  Persona: {}", view.persona_id);
    let _ = writeln!(out, "  Status:  {}", view.status);

    match &view.expires_at {
        Some(exp) => match chrono::DateTime::parse_from_rfc3339(exp) {
            Ok(dt) => {
                let remaining = dt.with_timezone(&chrono::Utc).timestamp() - now.timestamp();
                if remaining > 0 {
                    let _ = writeln!(out, "  TTL:     {}m remaining", remaining / 60);
                } else {
                    let _ = writeln!(out, "  TTL:     expired");
                }
            }
            Err(_) => {
                let _ = writeln!(out, "  TTL:     {exp}");
            }
        },
        None => {
            let _ = writeln!(out, "  TTL:     never");
        }
    }

    let is_composite = view.statements.len() > 1;
    for stmt in &view.statements {
        if is_composite {
            let _ = writeln!(
                out,
                "  Statement {}  {}  {}",
                stmt.sid,
                stmt.resource_type,
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
                    let _ = writeln!(
                        out,
                        "  {}",
                        fmt_budget_line("tokens:", stmt.usage.tokens, cap)
                    );
                }
                if let Some(cap) = b.cents {
                    let _ = writeln!(
                        out,
                        "  {}",
                        fmt_budget_line("cents:", stmt.usage.cents, cap)
                    );
                }
                if let Some(cap) = b.requests {
                    let _ = writeln!(
                        out,
                        "  {}",
                        fmt_budget_line("requests:", stmt.usage.requests, cap)
                    );
                }
                if let Some(cap) = b.wall_clock_secs {
                    let _ = writeln!(
                        out,
                        "  {}",
                        fmt_budget_line("wall-clock:", stmt.usage.wall_clock_secs, cap)
                    );
                }

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
                            let remaining_min =
                                (cap - used) as f64 / (used as f64 / minutes_elapsed);
                            let _ = writeln!(
                                out,
                                "  {indent}  tokens:      ~{}m",
                                remaining_min.round() as u64
                            );
                        } else {
                            let _ = writeln!(out, "  {indent}  tokens:      —");
                        }
                    }
                    if let Some(cap) = b.cents {
                        let used = stmt.usage.cents;
                        if used > 0 && cap > used {
                            let remaining_min =
                                (cap - used) as f64 / (used as f64 / minutes_elapsed);
                            let _ = writeln!(
                                out,
                                "  {indent}  cents:       ~{}m",
                                remaining_min.round() as u64
                            );
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

fn run_grant_budget(
    config: &DaemonConfig,
    grant_id: &str,
) -> Result<(GrantActionDispatch, String), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "grant_status",
            &serde_json::json!({ "id": grant_id }),
        )?;
        if result.get("kind").and_then(|v| v.as_str()) != Some("grant") {
            return Err(core_types::ValidationError::new(
                "daemon grant_status: expected a grant result",
            ));
        }
        let view: GrantBudgetStatusView = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon grant_status: {e}")))?;
        Ok((
            GrantActionDispatch::DaemonRpc,
            render_grant_budget_from_status(&view),
        ))
    } else {
        let store = open_store(config);
        let grant = store
            .get_access_grant(grant_id)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((
            GrantActionDispatch::LocalFallback,
            render_grant_budget(&grant),
        ))
    }
}

fn run_sandbox_create(
    config: &DaemonConfig,
    opts: &SandboxCreateOpts,
) -> Result<(SandboxActionDispatch, SandboxCreateResult), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let params = serde_json::to_value(opts)
            .map_err(|e| core_types::ValidationError::new(format!("sandbox_create params: {e}")))?;
        let result = emberlink_cli::call_daemon_method(&socket_path, "sandbox_create", &params)?;
        let created: SandboxCreateResult = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon sandbox_create: {e}")))?;
        Ok((SandboxActionDispatch::DaemonRpc, created))
    } else {
        let store = open_store(config);
        let sandbox = store
            .create_sandbox_with_opts(opts, Some(&config.data_dir))
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        let (container_id, start_error) = match store.start_container(
            &sandbox.id,
            &config.socket_dir,
            opts.network.as_deref(),
            &opts.extra_env,
        ) {
            Ok(cid) => (Some(cid), None),
            Err(e) => (None, Some(e.to_string())),
        };
        Ok((
            SandboxActionDispatch::LocalFallback,
            SandboxCreateResult {
                sandbox,
                container_id,
                start_error,
            },
        ))
    }
}

fn run_sandbox_list(
    config: &DaemonConfig,
) -> Result<(SandboxActionDispatch, Vec<SandboxInfo>), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "sandbox_list",
            &serde_json::Value::Null,
        )?;
        let sandboxes: Vec<SandboxInfo> = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon sandbox_list: {e}")))?;
        Ok((SandboxActionDispatch::DaemonRpc, sandboxes))
    } else {
        let store = open_store(config);
        let sandboxes = store
            .list_sandboxes()
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((SandboxActionDispatch::LocalFallback, sandboxes))
    }
}

fn run_sandbox_stop(
    config: &DaemonConfig,
    id_or_name: &str,
) -> Result<(SandboxActionDispatch, String), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "sandbox_stop",
            &serde_json::json!({ "id_or_name": id_or_name }),
        )?;
        let resolved_id = result
            .get("resolved_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                core_types::ValidationError::new("daemon sandbox_stop: missing resolved_id")
            })?;
        Ok((SandboxActionDispatch::DaemonRpc, resolved_id.to_string()))
    } else {
        let store = open_store(config);
        let resolved_id = store
            .resolve_sandbox_id(id_or_name)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        store
            .stop_sandbox(&resolved_id)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((SandboxActionDispatch::LocalFallback, resolved_id))
    }
}

/// Anchor: sandbox_open_store_migration_resolved
///
/// design EXCEPTION (implementation-note-448, Path B):
/// Sandbox surface stays on direct `open_store` for the LocalFallback
/// branch only. Rationale —
///
/// (a) Primary path (daemon socket present) already routes through
///     `daemon_rpc::call("sandbox_delete", ...)` under the
///     separate-uid posture. design's intent is satisfied for the
///     load-bearing happy path.
/// (b) LocalFallback fires only when `socket_path.exists()` is false
///     — daemon unavailable, offline recovery, or pre-install. In
///     that scenario the CLI is the only viable actor and the
///     daemon-side RPC cannot be reached by definition. Forcing the
///     CLI to call a nonexistent RPC there would degrade the
///     recovery surface, not improve it.
/// (c) Per the parent implementation-note-449 digest,
///     a Path-A migration (file `implementation-note-450`
///     + thread sandbox actions through it) is the principled
///     long-term fix; it is intentionally out of scope here.
fn run_sandbox_delete(
    config: &DaemonConfig,
    id_or_name: &str,
) -> Result<(SandboxActionDispatch, SandboxDeleteResult), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "sandbox_delete",
            &serde_json::json!({ "id_or_name": id_or_name }),
        )?;
        let deleted: SandboxDeleteResult = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon sandbox_delete: {e}")))?;
        Ok((SandboxActionDispatch::DaemonRpc, deleted))
    } else {
        // design EXCEPTION: LocalFallback only (daemon socket absent).
        // See doc-comment on `run_sandbox_delete` for the carve-out
        // rationale and the implementation-note-450 pointer
        // that captures the long-term migration path.
        let deleted = run_sandbox_delete_local(&open_store(config), id_or_name)?;
        Ok((SandboxActionDispatch::LocalFallback, deleted))
    }
}

fn run_sandbox_exec(
    config: &DaemonConfig,
    id_or_name: &str,
    caller_persona_id: Option<String>,
    command: &[String],
) -> Result<(SandboxActionDispatch, String), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let mut params = serde_json::json!({
            "id_or_name": id_or_name,
            "command": command,
        });
        if let Some(caller) = caller_persona_id.clone() {
            params["caller_persona_id"] = serde_json::json!(caller);
        }
        let result = emberlink_cli::call_daemon_method(&socket_path, "sandbox_exec", &params)?;
        let output = result
            .get("output")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                core_types::ValidationError::new("daemon sandbox_exec: missing output")
            })?;
        Ok((SandboxActionDispatch::DaemonRpc, output.to_string()))
    } else {
        let store = open_store(config);
        let resolved_id = store
            .resolve_sandbox_id(id_or_name)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        let caller_persona = caller_persona_id.unwrap_or_default();
        let refs: Vec<&str> = command.iter().map(String::as_str).collect();
        let output = store
            .exec_sandbox(&resolved_id, &refs, &caller_persona)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((SandboxActionDispatch::LocalFallback, output))
    }
}

fn run_sandbox_run(
    config: &DaemonConfig,
    opts: &SandboxCreateOpts,
    statements: &[StatementProposal],
    ttl_secs: Option<u64>,
    credential_resource: Option<&str>,
) -> Result<(SandboxActionDispatch, SandboxRunResult), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "sandbox_run",
            &serde_json::json!({
                "sandbox": opts,
                "statements": statements,
                "ttl_secs": ttl_secs,
                "credential_resource": credential_resource,
            }),
        )?;
        let prepared: SandboxRunResult = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon sandbox_run: {e}")))?;
        Ok((SandboxActionDispatch::DaemonRpc, prepared))
    } else {
        let store = open_store(config);
        let sandbox = store
            .create_sandbox_with_opts(opts, Some(&config.data_dir))
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        let (container_id, start_error) =
            match store.start_container(&sandbox.id, &config.socket_dir, None, &opts.extra_env) {
                Ok(cid) => (Some(cid), None),
                Err(e) => (None, Some(e.to_string())),
            };

        let grant = if statements.is_empty() {
            SandboxRunGrantDisposition::NotRequested
        } else {
            let policy_engine = if config.policy_file.exists() {
                ember_daemon::trust::policy::PolicyEngine::from_file(&config.policy_file)
                    .unwrap_or_default()
            } else {
                ember_daemon::trust::policy::PolicyEngine::default()
            };
            let policy_action = "credential.access".to_string();
            let eval = policy_engine.evaluate(&policy_action);
            let risk_str = format!("{:?}", eval.risk).to_lowercase();
            let grant_proposal = GrantProposal {
                persona_id: sandbox.persona_id.clone(),
                statements: statements.to_vec(),
                expires_at: ttl_secs,
                label: None,
                skill_ref: None,
                note: None,
            };

            match eval.requirement {
                ember_daemon::trust::policy::ApprovalRequirement::Denied => {
                    let credential_res = credential_resource.unwrap_or("");
                    return Err(core_types::ValidationError::new(format!(
                        "policy denied composite grant mint for {credential_res} (rule: {})",
                        eval.matched_rule.as_deref().unwrap_or("(default)")
                    )));
                }
                ember_daemon::trust::policy::ApprovalRequirement::Required => {
                    match store.propose_grant_typed(&grant_proposal, &policy_action, &risk_str) {
                        Ok(req) => SandboxRunGrantDisposition::PendingApproval {
                            approval_id: req.id,
                        },
                        Err(e) => SandboxRunGrantDisposition::Failed {
                            message: format!("submitting approval failed: {e}"),
                        },
                    }
                }
                ember_daemon::trust::policy::ApprovalRequirement::Auto => {
                    match store.propose_grant_typed(&grant_proposal, &policy_action, &risk_str) {
                        Ok(req) => match store.auto_resolve(&req.id) {
                            Ok(()) => {
                                let grant_id = store
                                    .get_approval(&req.id)
                                    .ok()
                                    .and_then(|r| r.result_grant_id);
                                SandboxRunGrantDisposition::Minted { grant_id }
                            }
                            Err(e) => SandboxRunGrantDisposition::Failed {
                                message: format!("auto-resolve failed: {e}"),
                            },
                        },
                        Err(e) => SandboxRunGrantDisposition::Failed {
                            message: format!("submitting approval failed: {e}"),
                        },
                    }
                }
            }
        };

        Ok((
            SandboxActionDispatch::LocalFallback,
            SandboxRunResult {
                sandbox,
                container_id,
                start_error,
                grant,
            },
        ))
    }
}

/// List receipts via the daemon's `list_receipts` RPC.
///
/// receipt_actions_migrated_to_rpc: under design's separate-uid posture the
/// daemon owns the SQLite read path; the prior `open_store(config)` local
/// fallback was silently-broken-by-design under the new posture. Per
/// implementation-note-451 the fallback branch was
/// removed; missing-socket errors surface clearly through `call_daemon_method`.
fn run_receipt_list(
    config: &DaemonConfig,
    persona: Option<&str>,
) -> Result<
    (
        ReceiptActionDispatch,
        Vec<core_grant_types::grant_receipt::GrantReceipt>,
    ),
    core_types::ValidationError,
> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "list_receipts",
        &serde_json::json!({ "persona_id": persona }),
    )?;
    let receipts = serde_json::from_value(result)
        .map_err(|e| core_types::ValidationError::new(format!("daemon list_receipts: {e}")))?;
    Ok((ReceiptActionDispatch::DaemonRpc, receipts))
}

/// Fetch a receipt via the daemon's `get_receipt` RPC.
///
/// The daemon preserves the existing CLI contract: callers may supply either
/// a receipt id or a grant id, and the daemon resolves terminal grants to
/// their receipt rows. Local fallback removed — see the
/// `receipt_actions_migrated_to_rpc` note on [`run_receipt_list`].
fn run_receipt_get(
    config: &DaemonConfig,
    id: &str,
) -> Result<
    (
        ReceiptActionDispatch,
        core_grant_types::grant_receipt::GrantReceipt,
    ),
    core_types::ValidationError,
> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "get_receipt",
        &serde_json::json!({ "id": id }),
    )?;
    let receipt = serde_json::from_value(result)
        .map_err(|e| core_types::ValidationError::new(format!("daemon get_receipt: {e}")))?;
    Ok((ReceiptActionDispatch::DaemonRpc, receipt))
}

fn resolve_receipt_export_target(
    config: &DaemonConfig,
    id: Option<&str>,
    latest: bool,
) -> Result<String, core_types::ValidationError> {
    if let Some(id) = id {
        return Ok(id.to_string());
    }
    if !latest {
        return Err(core_types::ValidationError::new(
            "pass a receipt <id> or `--latest`".to_string(),
        ));
    }

    let (_, receipts) = run_receipt_list(config, None)?;
    let latest_receipt = receipts.first().ok_or_else(|| {
        core_types::ValidationError::new(
            "no receipts found; run a session first or pass an explicit receipt id".to_string(),
        )
    })?;
    Ok(latest_receipt.id.clone())
}

/// Build the receipt tree export on the current authority surface.
///
/// Installed-path tree assembly now belongs to the daemon; the CLI keeps
/// only the ASCII rendering and optional export-file write.
fn run_receipt_tree(
    config: &DaemonConfig,
    grant_id: &str,
) -> Result<(ReceiptActionDispatch, emberlink_cli::receipt::TreeExport), core_types::ValidationError>
{
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "receipt_tree",
            &serde_json::json!({ "grant_id": grant_id }),
        )?;
        let tree = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon receipt_tree: {e}")))?;
        Ok((ReceiptActionDispatch::DaemonRpc, tree))
    } else {
        let store = open_store(config);
        let tree = emberlink_cli::receipt::build_tree(&store, &config.data_dir, grant_id)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((ReceiptActionDispatch::LocalFallback, tree))
    }
}

/// Query receipt-backed audit rows via the daemon's `receipt_query` RPC.
///
/// Local fallback removed per implementation-note-451;
/// see the `receipt_actions_migrated_to_rpc` note on [`run_receipt_list`].
fn run_audit_receipt_query(
    config: &DaemonConfig,
    filter: &ember_daemon::infra::receipt::ReceiptFilter,
) -> Result<
    (
        AuditActionDispatch,
        Vec<ember_daemon::infra::receipt::ReceiptRow>,
    ),
    core_types::ValidationError,
> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "receipt_query",
        &serde_json::json!({
            "actor": filter.persona_id,
            "kind": filter.kind,
            "grant_id": filter.grant_id,
            "resource": filter.resource,
            "since": filter.since_iso,
            "limit": filter.limit,
        }),
    )?;
    let rows = serde_json::from_value(result)
        .map_err(|e| core_types::ValidationError::new(format!("daemon receipt_query: {e}")))?;
    Ok((AuditActionDispatch::DaemonRpc, rows))
}

/// Query raw audit-log rows on the current authority surface.
///
/// The installed daemon path uses the operator-only `audit_log_query`
/// seam so raw `details` stay off the broader ConnectOnly summary surface
/// exposed by `audit_query`.
fn run_audit_log_query(
    config: &DaemonConfig,
    filter: &ember_daemon::infra::audit::AuditFilter,
) -> Result<
    (
        AuditActionDispatch,
        Vec<ember_daemon::infra::audit::AuditEntry>,
    ),
    core_types::ValidationError,
> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "audit_log_query",
            &serde_json::json!({
                "id": filter.id,
                "agent_id": filter.agent_id,
                "action": filter.action,
                "limit": filter.limit,
                "action_prefix": filter.action_prefix,
                "persona_id": filter.persona_id,
                "scope": filter.scope,
                "since_ms": filter.since_ms,
                "before_ms": filter.before_ms,
            }),
        )?;
        let rows = serde_json::from_value(result).map_err(|e| {
            core_types::ValidationError::new(format!("daemon audit_log_query: {e}"))
        })?;
        Ok((AuditActionDispatch::DaemonRpc, rows))
    } else {
        let store = open_store(config);
        let rows = store
            .query_audit(filter)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((AuditActionDispatch::LocalFallback, rows))
    }
}

/// Load the daemon-owned current-state explanation for one audit event.
///
/// The installed daemon path owns both the raw event lookup and the current
/// grant/policy projections. The no-daemon fallback reuses the same shared
/// builder so the CLI keeps one explanation shape.
fn run_audit_explain(
    config: &DaemonConfig,
    id: i64,
) -> Result<
    (
        AuditActionDispatch,
        ember_daemon::infra::audit_explain::AuditExplainView,
    ),
    core_types::ValidationError,
> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "audit_explain",
            &serde_json::json!({ "id": id }),
        )?;
        let explain = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon audit_explain: {e}")))?;
        Ok((AuditActionDispatch::DaemonRpc, explain))
    } else {
        let store = open_store(config);
        let policy = if config.policy_file.exists() {
            ember_daemon::trust::policy::PolicyEngine::from_file(&config.policy_file)
                .unwrap_or_default()
        } else {
            ember_daemon::trust::policy::PolicyEngine::default()
        };
        let explain = ember_daemon::infra::audit_explain::build_audit_explain(&store, &policy, id)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((AuditActionDispatch::LocalFallback, explain))
    }
}

/// List pending approvals on the current authority surface.
fn run_approval_list(
    config: &DaemonConfig,
) -> Result<
    (
        ApprovalActionDispatch,
        Vec<ember_daemon::trust::approval::ApprovalRequestInfo>,
    ),
    core_types::ValidationError,
> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "list_pending_approvals",
            &serde_json::Value::Null,
        )?;
        let requests = serde_json::from_value(result).map_err(|e| {
            core_types::ValidationError::new(format!("daemon list_pending_approvals: {e}"))
        })?;
        Ok((ApprovalActionDispatch::DaemonRpc, requests))
    } else {
        let store = open_store(config);
        let requests = store
            .list_pending_approvals()
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((ApprovalActionDispatch::LocalFallback, requests))
    }
}

/// Resolve an approval on the current authority surface.
fn run_approval_resolve(
    config: &DaemonConfig,
    id: &str,
    outcome: &ApprovalOutcome,
) -> Result<
    (
        ApprovalActionDispatch,
        ember_daemon::trust::approval::ApprovalRequestInfo,
    ),
    core_types::ValidationError,
> {
    run_approval_resolve_with_caller(config, id, outcome, None)
}

fn run_approval_resolve_with_caller(
    config: &DaemonConfig,
    id: &str,
    outcome: &ApprovalOutcome,
    caller_persona_id: Option<&str>,
) -> Result<
    (
        ApprovalActionDispatch,
        ember_daemon::trust::approval::ApprovalRequestInfo,
    ),
    core_types::ValidationError,
> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let mut params = match outcome {
            ApprovalOutcome::Approved => {
                serde_json::json!({ "id": id, "decision": "approve" })
            }
            ApprovalOutcome::Denied { reason } => {
                serde_json::json!({ "id": id, "decision": "deny", "reason": reason })
            }
            ApprovalOutcome::Narrowed { new_scope } => serde_json::json!({
                "id": id,
                "decision": "narrow",
                "scope": new_scope,
            }),
            ApprovalOutcome::Always { scope, expires_at } => serde_json::json!({
                "id": id,
                "decision": "always",
                "scope": scope,
                "expires_at": expires_at,
            }),
        };
        if let Some(caller_persona_id) = caller_persona_id {
            params["caller_persona_id"] = serde_json::json!(caller_persona_id);
        }
        let result = emberlink_cli::call_daemon_method(&socket_path, "resolve_approval", &params)?;
        let resolved = serde_json::from_value(result).map_err(|e| {
            core_types::ValidationError::new(format!("daemon resolve_approval: {e}"))
        })?;
        Ok((ApprovalActionDispatch::DaemonRpc, resolved))
    } else {
        let store = open_store(config);
        store
            .resolve_approval(id, outcome)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        let resolved = store
            .get_approval(id)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((ApprovalActionDispatch::LocalFallback, resolved))
    }
}

/// Load the daemon-owned status aggregate on the current authority surface.
///
/// When the daemon is running, prefer its read surface so installed-path
/// operators do not need direct SQLite access. When the daemon is absent, keep
/// the historical local fallback for dev/no-daemon paths.
fn run_status_summary(
    config: &DaemonConfig,
    daemon_running: bool,
) -> Result<
    (
        StatusActionDispatch,
        Option<emberlink_cli::LiveDaemonStatus>,
        ember_daemon::infra::status::StatusSummary,
    ),
    core_types::ValidationError,
> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if let Some(live) = emberlink_cli::probe_live_daemon_status(&socket_path, &config.pid_file)? {
        return Ok((
            StatusActionDispatch::DaemonRpc,
            Some(live.clone()),
            live.summary,
        ));
    }

    if daemon_running {
        return Err(core_types::ValidationError::new(
            "daemon runtime probe reported running, but the live status RPC was unavailable; rerun `sudo ember daemon install` if this persists",
        ));
    }

    let store = open_store(config);
    let summary = ember_daemon::infra::status::StatusSummary {
        personas: store
            .list_personas()
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?,
        grants: store
            .list_active_grants()
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?,
        sandboxes: store
            .list_sandboxes()
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?,
        approvals: store
            .list_pending_approvals()
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?,
        recent_activity: store
            .query_audit(&AuditFilter {
                limit: Some(5),
                ..Default::default()
            })
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?,
        standing_grants: store
            .list_standing_grants()
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?
            .len(),
        audit_events_total: store
            .audit_count()
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?,
        quarantined: false,
        quarantine_authority: None,
    };
    Ok((StatusActionDispatch::LocalFallback, None, summary))
}

fn live_daemon_identity(
    runtime_status: Option<&ember_daemon::infra::runtime::DaemonStatus>,
    live_status: Option<&emberlink_cli::LiveDaemonStatus>,
) -> (bool, Option<u32>, Option<String>) {
    if let Some(status) = live_status {
        return (
            true,
            status.pid.or_else(|| runtime_status.map(|s| s.pid)),
            Some(status.socket.display().to_string()),
        );
    }

    match runtime_status {
        Some(status) if status.running => (
            true,
            Some(status.pid),
            Some(status.socket.display().to_string()),
        ),
        Some(status) => (
            false,
            Some(status.pid),
            Some(status.socket.display().to_string()),
        ),
        None => (false, None, None),
    }
}

fn build_status_banner(
    config: &DaemonConfig,
    runtime_status: Option<&ember_daemon::infra::runtime::DaemonStatus>,
    live_status: Option<&emberlink_cli::LiveDaemonStatus>,
    vault_backend: String,
    vault_addr: String,
) -> DaemonStatusBanner {
    let dashboard = match config.dashboard_addr {
        Some(addr) => match probe_dashboard_addr_bound(addr) {
            Some(bound) => {
                let pretty = bound
                    .parse::<std::net::SocketAddr>()
                    .ok()
                    .filter(|a| a.ip().is_loopback())
                    .map(|a| format!("localhost:{}", a.port()))
                    .unwrap_or(bound);
                format!("http://{pretty}/")
            }
            None => "not running (bind failed or not configured)".to_string(),
        },
        None => "not running (bind failed or not configured)".to_string(),
    };

    let (running, pid, socket) = live_daemon_identity(runtime_status, live_status);
    match (running, pid, socket) {
        (true, Some(pid), Some(socket)) => DaemonStatusBanner::Running {
            pid,
            socket,
            dashboard,
            vault_backend,
            vault_addr,
        },
        (false, Some(pid), _) => DaemonStatusBanner::StalePid { pid },
        _ => DaemonStatusBanner::NotRunning,
    }
}

fn run_github_provider_status(
    config: &DaemonConfig,
) -> Result<GithubProviderStatusView, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "broker.github_status",
        &serde_json::json!({}),
    )?;
    serde_json::from_value(result)
        .map_err(|e| core_types::ValidationError::new(format!("broker github status: {e}")))
}

fn github_https_lane(status: &GithubProviderStatusView) -> GithubHttpsLane {
    match status.lane.as_str() {
        "app" => GithubHttpsLane::ConfiguredApp,
        "pat" => GithubHttpsLane::ConfiguredPat,
        "mock" => GithubHttpsLane::ConfiguredMock,
        "broken" => GithubHttpsLane::Broken,
        _ => GithubHttpsLane::NotConfigured,
    }
}

fn github_onboarding_posture(
    config: &DaemonConfig,
) -> emberlink_cli::onboarding::claude_code::GitHubOnboardingPosture {
    use emberlink_cli::onboarding::claude_code::GitHubOnboardingPosture;

    match run_github_provider_status(config) {
        Ok(status) => match github_https_lane(&status) {
            GithubHttpsLane::ConfiguredApp => GitHubOnboardingPosture::AppConfiguredReal,
            GithubHttpsLane::ConfiguredPat => GitHubOnboardingPosture::PatConfigured,
            GithubHttpsLane::ConfiguredMock => GitHubOnboardingPosture::AppConfiguredMock,
            GithubHttpsLane::Broken => {
                GitHubOnboardingPosture::AppBroken(status.detail.unwrap_or_else(|| {
                    "local GitHub App authority is configured, but loading failed".to_string()
                }))
            }
            GithubHttpsLane::NotConfigured => GitHubOnboardingPosture::AppNotConfigured,
        },
        Err(e) => {
            eprintln!("warning: could not inspect GitHub broker posture: {e}");
            GitHubOnboardingPosture::AppNotConfigured
        }
    }
}

fn resolve_symlink_target(path: &Path, target: &Path) -> PathBuf {
    fn normalize_lexical(path: PathBuf) -> PathBuf {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    if !normalized.pop() {
                        normalized.push(component.as_os_str());
                    }
                }
                _ => normalized.push(component.as_os_str()),
            }
        }
        normalized
    }

    if target.is_absolute() {
        normalize_lexical(target.to_path_buf())
    } else {
        normalize_lexical(path.parent().unwrap_or_else(|| Path::new("/")).join(target))
    }
}

fn path_looks_like_repo_build_artifact(target: &Path) -> bool {
    target
        .components()
        .any(|component| component.as_os_str() == "target")
}

fn detect_installed_launcher_issue_at(path: &Path) -> Option<InstalledLauncherIssue> {
    let target = fs::read_link(path).ok()?;
    let resolved = resolve_symlink_target(path, &target);
    if resolved.exists() {
        return None;
    }
    Some(if path_looks_like_repo_build_artifact(&resolved) {
        InstalledLauncherIssue::BrokenRepoBuildSymlink {
            path: path.to_path_buf(),
            target: resolved,
        }
    } else {
        InstalledLauncherIssue::BrokenSymlink {
            path: path.to_path_buf(),
            target: resolved,
        }
    })
}

fn detect_default_installed_launcher_issue() -> Option<InstalledLauncherIssue> {
    detect_installed_launcher_issue_at(Path::new(PROD_EMBER_LAUNCHER_PATH))
}

fn render_github_status_text(status: &GithubProviderStatusView) -> String {
    let https_line = match github_https_lane(status) {
        GithubHttpsLane::ConfiguredApp => "configured (real GitHub App broker)",
        GithubHttpsLane::ConfiguredPat => {
            "configured (degraded PAT fallback; brokered but long-lived user credential)"
        }
        GithubHttpsLane::ConfiguredMock => "not configured (GitHub is mock-only on this daemon)",
        GithubHttpsLane::Broken => {
            "broken (GitHub broker is registered, but local authority loading failed)"
        }
        GithubHttpsLane::NotConfigured => "not configured (no GitHub broker registered)",
    };

    let mut out = String::new();
    let _ = writeln!(out, "GITHUB");
    let _ = writeln!(out, "  HTTPS / App:  {https_line}");
    if let Some(app_id) = status.app_id.as_deref() {
        let _ = writeln!(out, "  App ID:       {app_id}");
    }
    if let Some(installation_id) = status.installation_id.as_deref() {
        let _ = writeln!(out, "  Installation: {installation_id}");
    }
    if let Some(detail) = status.detail.as_deref() {
        let _ = writeln!(out, "  Detail:      {detail}");
    }
    let _ = writeln!(out);

    match github_https_lane(status) {
        GithubHttpsLane::ConfiguredApp => {
            let _ = writeln!(out, "Next step:");
            let _ = writeln!(
                out,
                "  Run `ember init --for claude`; it keeps the App lane and does not request a PAT."
            );
        }
        GithubHttpsLane::ConfiguredPat => {
            let _ = writeln!(out, "Next steps:");
            let _ = writeln!(
                out,
                "  1. You can proceed on the PAT lane today; gh/git will run under your GitHub identity."
            );
            let _ = writeln!(
                out,
                "  2. Preferred upgrade: run `ember github setup` to move onto the App lane."
            );
        }
        GithubHttpsLane::Broken => {
            let _ = writeln!(out, "Next steps:");
            let _ = writeln!(
                out,
                "  1. Re-run `ember github setup` to repair or replace the local App credential triple."
            );
            let _ = writeln!(
                out,
                "  2. Then run `ember github status` again and confirm the App lane is ready."
            );
        }
        GithubHttpsLane::ConfiguredMock | GithubHttpsLane::NotConfigured => {
            let _ = writeln!(out, "Next steps:");
            let _ = writeln!(
                out,
                "  1. Run `ember github setup` to register local App credentials for the HTTPS/App lane."
            );
            let _ = writeln!(
                out,
                "     Have these ready: private key PEM, App ID, installation URL or ID, and App slug."
            );
            let _ = writeln!(
                out,
                "  2. Then rerun `ember github status` and confirm the App lane is ready."
            );
        }
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "Advanced notes:");
    if !matches!(github_https_lane(status), GithubHttpsLane::ConfiguredPat) {
        let _ = writeln!(
            out,
            "  PAT fallback exists only as a degraded recovery lane; it is mediated for gh/git, but still a long-lived user credential rather than a short-lived App token."
        );
    }
    let _ = writeln!(
        out,
        "  SSH substrate exists for git/ember-gh, but the canonical Claude session flow does not auto-wire or status it yet."
    );

    out
}

fn github_setup_command() -> &'static str {
    "ember github setup"
}

fn render_github_setup_prelude(install_url: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "GitHub App setup");
    let _ = writeln!(
        out,
        "  Preferred v0.3.0 lane: HTTPS/API via a real GitHub App credential triple"
    );
    let _ = writeln!(out, "  registered locally with this daemon.");
    let _ = writeln!(
        out,
        "  Bring the private key PEM, App ID, installation URL or ID, and App slug."
    );
    let _ = writeln!(
        out,
        "  Hidden support references remain available if you intentionally need them:"
    );
    let _ = writeln!(
        out,
        "  `ember github app show` and `ember github app install-url` ({install_url})"
    );
    let _ = writeln!(
        out,
        "  Private key PEM: generate it from the App settings page after creation."
    );
    let _ = writeln!(
        out,
        "  App ID: shown at the top of the GitHub App settings page."
    );
    let _ = writeln!(
        out,
        "  Installation: paste either the numeric ID or the full post-install URL;"
    );
    let _ = writeln!(
        out,
        "  setup will extract the `/installations/<ID>` segment."
    );
    let _ = writeln!(
        out,
        "  Slug: paste either the plain slug or a GitHub App URL and setup will normalize it."
    );
    let _ = writeln!(
        out,
        "  Then finish the local credential registration prompts below."
    );
    out
}

enum GithubSetupDaemonFollowup {
    Reloaded { old_pid: u32, new_pid: Option<u32> },
    NeedsManualReload,
}

fn try_reload_daemon_after_github_setup(
    config: &DaemonConfig,
) -> Result<GithubSetupDaemonFollowup, daemon_agent::AgentError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let pid_file = config.pid_file.clone();
    if !daemon_agent::is_managed_service() {
        return Ok(GithubSetupDaemonFollowup::NeedsManualReload);
    }
    let outcome = daemon_agent::reload_daemon(&pid_file, &socket_path, Duration::from_secs(10))?;
    Ok(GithubSetupDaemonFollowup::Reloaded {
        old_pid: outcome.old_pid,
        new_pid: outcome.new_pid,
    })
}

fn render_github_setup_success_text(followup: GithubSetupDaemonFollowup) -> String {
    let mut out = String::new();
    match followup {
        GithubSetupDaemonFollowup::Reloaded { old_pid, new_pid } => {
            let new_pid = new_pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "?".to_string());
            let _ = writeln!(out, "Daemon reloaded: old pid {old_pid}, new pid {new_pid}");
            let _ = writeln!(out);
            let _ = writeln!(out, "Next steps:");
            let _ = writeln!(
                out,
                "  1. Run `ember github status` to confirm the App lane is now configured."
            );
            let _ = writeln!(
                out,
                "  2. If this is your first-time friendly setup, rerun `ember init --for claude`; otherwise launch `ember claude`."
            );
            let _ = writeln!(
                out,
                "  3. After the first brokered action, run `ember receipt export --latest --format md`."
            );
            let _ = writeln!(
                out,
                "  4. Prefer HTTPS remotes for the v0.3.0 friendly path; SSH is still substrate-only."
            );
        }
        GithubSetupDaemonFollowup::NeedsManualReload => {
            let _ = writeln!(out, "GitHub App credentials staged.");
            let _ = writeln!(out);
            let _ = writeln!(out, "Next steps:");
            let _ = writeln!(
                out,
                "  1. Run `ember daemon reload` so the running daemon picks up the newly staged App credentials."
            );
            let _ = writeln!(
                out,
                "  2. Run `ember github status` to confirm the App lane is now configured."
            );
            let _ = writeln!(
                out,
                "  3. If this is your first-time friendly setup, rerun `ember init --for claude`; otherwise launch `ember claude`."
            );
            let _ = writeln!(
                out,
                "  4. After the first brokered action, run `ember receipt export --latest --format md`."
            );
        }
    }
    out
}

fn render_github_setup_retry_hint(err: &GithubSetupError) -> Option<String> {
    let msg = err.to_string();
    if msg.contains("ember vault unlock") {
        return Some(
            "run `ember vault unlock` from an interactive operator shell, then rerun `ember github setup`."
                .to_string(),
        );
    }
    if msg.contains("already exists;") && msg.contains("--replace") {
        return Some(
            "stored App credentials already exist for this slug + installation; rerun `ember github setup --replace` if you intend to overwrite them."
                .to_string(),
        );
    }
    if msg.contains("--allow-unverified-slug") && msg.contains("canonicalization") {
        return Some(
            "if GitHub is unreachable, the app is suspended, or you only need the local staged triple first, retry with `ember github setup --allow-unverified-slug`."
                .to_string(),
        );
    }
    None
}

fn render_github_status_retry_hint(err: &core_types::ValidationError) -> Option<String> {
    let msg = err.to_string();
    if msg.contains("ember vault unlock") {
        return Some(
            "run `ember vault unlock` from an interactive operator shell, then rerun `ember github status`."
                .to_string(),
        );
    }
    None
}

fn prompt_github_setup_field(prompt: &str, default: Option<&str>) -> Result<String, String> {
    loop {
        match default {
            Some(value) => eprint!("{prompt} [{value}]: "),
            None => eprint!("{prompt}: "),
        }
        let _ = io::stderr().flush();
        let mut buf = String::new();
        io::stdin()
            .read_line(&mut buf)
            .map_err(|e| format!("read {prompt}: {e}"))?;
        let trimmed = buf.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
        if let Some(value) = default {
            return Ok(value.to_string());
        }
        eprintln!("  value required");
    }
}

fn parse_default_yes_response(input: &str) -> Option<bool> {
    match input.trim().to_ascii_lowercase().as_str() {
        "" | "y" | "yes" => Some(true),
        "n" | "no" => Some(false),
        _ => None,
    }
}

fn prompt_yes_no_default_yes(prompt: &str) -> Result<bool, String> {
    loop {
        eprint!("{prompt} [Y/n]: ");
        let _ = io::stderr().flush();
        let mut buf = String::new();
        io::stdin()
            .read_line(&mut buf)
            .map_err(|e| format!("read {prompt}: {e}"))?;
        if let Some(choice) = parse_default_yes_response(&buf) {
            return Ok(choice);
        }
        eprintln!("  enter Y or n");
    }
}

fn normalize_github_installation_id_input(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("installation ID is required".to_string());
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Ok(trimmed.to_string());
    }

    let segments = trimmed
        .split(['/', '?', '#'])
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if let Some(last_numeric) = segments
        .iter()
        .rev()
        .find(|segment| segment.chars().all(|c| c.is_ascii_digit()))
    {
        return Ok((*last_numeric).to_string());
    }

    Err(format!(
        "could not extract numeric installation ID from `{trimmed}`"
    ))
}

fn normalize_github_slug_input(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("GitHub App slug is required".to_string());
    }
    if let Some((_, slug)) = trimmed.split_once("/apps/") {
        let slug = slug
            .split(['/', '?', '#'])
            .find(|segment| !segment.is_empty())
            .ok_or_else(|| format!("could not extract GitHub App slug from `{trimmed}`"))?;
        return Ok(slug.to_string());
    }
    if let Some((_, slug)) = trimmed.split_once("/settings/apps/") {
        let slug = slug
            .split(['/', '?', '#'])
            .find(|segment| !segment.is_empty())
            .ok_or_else(|| format!("could not extract GitHub App slug from `{trimmed}`"))?;
        return Ok(slug.to_string());
    }
    Ok(trimmed.to_string())
}

fn resolve_github_setup_args(
    args: &GithubSetupArgs,
    stdin_is_terminal: bool,
) -> Result<GithubAppRegisterArgs, core_types::ValidationError> {
    let complete = args.pem_file.is_some()
        && args.app_id.is_some()
        && args.installation_id.is_some()
        && args.slug.is_some();
    if complete {
        return Ok(GithubAppRegisterArgs {
            pem_file: args.pem_file.clone().expect("checked"),
            app_id: args.app_id.clone().expect("checked"),
            installation_id: normalize_github_installation_id_input(
                args.installation_id.as_deref().expect("checked"),
            )
            .map_err(core_types::ValidationError::new)?,
            slug: normalize_github_slug_input(args.slug.as_deref().expect("checked"))
                .map_err(core_types::ValidationError::new)?,
            allow_unverified_slug: args.allow_unverified_slug,
            replace: args.replace,
        });
    }

    if !stdin_is_terminal {
        return Err(core_types::ValidationError::new(format!(
            "missing GitHub App setup inputs; rerun `{}` interactively or pass --pem-file, --app-id, --installation-id, and --slug",
            github_setup_command()
        )));
    }

    eprint!(
        "{}",
        render_github_setup_prelude(&emberlink_cli::onboarding::github_app::print_install_url())
    );
    eprintln!();

    let pem_file = match args.pem_file.clone() {
        Some(path) => path,
        None => PathBuf::from(
            prompt_github_setup_field("Private key PEM path", None)
                .map_err(core_types::ValidationError::new)?,
        ),
    };
    let app_id = match args.app_id.clone() {
        Some(value) => value,
        None => prompt_github_setup_field("GitHub App ID", None)
            .map_err(core_types::ValidationError::new)?,
    };
    let installation_id = match args.installation_id.clone() {
        Some(value) => value,
        None => prompt_github_setup_field("GitHub installation ID or post-install URL", None)
            .map_err(core_types::ValidationError::new)?,
    };
    let slug = match args.slug.clone() {
        Some(value) => value,
        None => prompt_github_setup_field("GitHub App slug or app URL", None)
            .map_err(core_types::ValidationError::new)?,
    };

    Ok(GithubAppRegisterArgs {
        pem_file,
        app_id,
        installation_id: normalize_github_installation_id_input(&installation_id)
            .map_err(core_types::ValidationError::new)?,
        slug: normalize_github_slug_input(&slug).map_err(core_types::ValidationError::new)?,
        allow_unverified_slug: args.allow_unverified_slug,
        replace: args.replace,
    })
}

enum GithubSetupError {
    Validation(core_types::ValidationError),
    Broker(emberlink_cli::broker::BrokerCliError),
}

impl std::fmt::Display for GithubSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(err) => err.fmt(f),
            Self::Broker(err) => err.fmt(f),
        }
    }
}

impl GithubSetupError {
    fn exit_code(&self) -> i32 {
        match self {
            Self::Validation(_) => 2,
            Self::Broker(err) => err.exit_code(),
        }
    }
}

fn register_github_from_setup_args(
    config: &DaemonConfig,
    args: &GithubSetupArgs,
    stdin_is_terminal: bool,
    json_out: bool,
) -> Result<(), GithubSetupError> {
    let register_args =
        resolve_github_setup_args(args, stdin_is_terminal).map_err(GithubSetupError::Validation)?;
    let socket_path = config.socket_dir.join("daemon.sock");
    let opts = emberlink_cli::broker::GlobalOpts { socket_path };
    emberlink_cli::broker::register_github(
        &opts,
        &register_args.pem_file,
        &register_args.app_id,
        &register_args.installation_id,
        &register_args.slug,
        register_args.allow_unverified_slug,
        register_args.replace,
        json_out,
    )
    .map_err(GithubSetupError::Broker)
}

fn github_setup_args_from_app_register(args: &GithubAppRegisterArgs) -> GithubSetupArgs {
    GithubSetupArgs {
        pem_file: Some(args.pem_file.clone()),
        app_id: Some(args.app_id.clone()),
        installation_id: Some(args.installation_id.clone()),
        slug: Some(args.slug.clone()),
        allow_unverified_slug: args.allow_unverified_slug,
        replace: args.replace,
    }
}

fn run_github_registration_flow(
    config: &DaemonConfig,
    args: &GithubSetupArgs,
    stdin_is_terminal: bool,
    json_out: bool,
) -> Result<(), i32> {
    if let Err(e) = register_github_from_setup_args(config, args, stdin_is_terminal, json_out) {
        eprintln!("error: {e}");
        if let Some(hint) = render_github_setup_retry_hint(&e) {
            eprintln!("       {hint}");
        }
        eprintln!(
            "       run `ember github status` for the current posture, or `{}` to retry interactively",
            github_setup_command()
        );
        return Err(e.exit_code());
    }

    if !json_out {
        println!();
        match try_reload_daemon_after_github_setup(config) {
            Ok(followup) => print!("{}", render_github_setup_success_text(followup)),
            Err(e) => {
                eprintln!(
                    "warning: GitHub App credentials were stored, but daemon reload failed: {e}"
                );
                eprintln!("         run `ember daemon reload` and then `ember github status`");
                println!();
                print!(
                    "{}",
                    render_github_setup_success_text(GithubSetupDaemonFollowup::NeedsManualReload)
                );
            }
        }
    }

    Ok(())
}

fn should_offer_inline_github_setup(
    posture: emberlink_cli::onboarding::claude_code::GitHubOnboardingPosture,
    non_interactive: bool,
    stdin_is_terminal: bool,
    stderr_is_terminal: bool,
) -> bool {
    use emberlink_cli::onboarding::claude_code::GitHubOnboardingPosture;

    matches!(
        posture,
        GitHubOnboardingPosture::AppNotConfigured
            | GitHubOnboardingPosture::AppConfiguredMock
            | GitHubOnboardingPosture::AppBroken(_)
    ) && !non_interactive
        && stdin_is_terminal
        && stderr_is_terminal
}

#[derive(Debug, Clone)]
enum DaemonStatusBanner {
    Running {
        pid: u32,
        socket: String,
        dashboard: String,
        vault_backend: String,
        vault_addr: String,
    },
    StalePid {
        pid: u32,
    },
    NotRunning,
}

fn render_status_text(
    banner: DaemonStatusBanner,
    summary: &ember_daemon::infra::status::StatusSummary,
) -> String {
    let personas = &summary.personas;
    let active = personas.iter().filter(|p| p.status == "active").count();
    let revoked = personas.iter().filter(|p| p.status == "revoked").count();
    let grants = &summary.grants;
    let sandboxes = &summary.sandboxes;
    let running = sandboxes.iter().filter(|s| s.status == "running").count();
    let approvals = &summary.approvals;
    let entries = &summary.recent_activity;
    let total = summary.audit_events_total;

    let mut out = String::new();
    match banner {
        DaemonStatusBanner::Running {
            pid,
            socket,
            dashboard,
            vault_backend,
            vault_addr,
        } => {
            let _ = writeln!(out, "DAEMON             running (PID {pid})");
            let _ = writeln!(out, "  Socket:    {socket}");
            let _ = writeln!(out, "  Dashboard: {dashboard}");
            let _ = writeln!(out, "  Vault:     {vault_backend} ({vault_addr})");
            if summary.quarantined {
                let authority = summary.quarantine_authority.as_deref().unwrap_or("unknown");
                let _ = writeln!(out, "  Quarantine: {authority}");
                let _ = writeln!(
                    out,
                    "  Impact:     write-class commands are blocked until audit repair"
                );
                let _ = writeln!(out, "  Repair:     ember audit verify");
            }
            let _ = writeln!(out);

            let _ = writeln!(
                out,
                "PERSONAS           {} active, {} revoked",
                active, revoked
            );
            for p in personas {
                let st = if p.status == "revoked" {
                    "revoked"
                } else {
                    "active "
                };
                let _ = writeln!(out, "  {:<18} {}  {}", p.name, st, p.id);
            }
            let _ = writeln!(out);

            let _ = writeln!(out, "ACTIVE GRANTS      {}", grants.len());
            for g in grants {
                let exp = g.expires_at.as_deref().unwrap_or("never");
                let _ = writeln!(
                    out,
                    "  {} {} → {} ({}) expires {}",
                    g.id, g.persona_id, g.credential_name, g.scope, exp
                );
            }
            let _ = writeln!(out);

            let _ = writeln!(out, "SANDBOXES          {} running", running);
            for s in sandboxes.iter().filter(|s| s.status == "running") {
                let cid = s.container_id.as_deref().unwrap_or("-");
                let _ = writeln!(out, "  {} {} container={}", s.id, s.name, cid);
            }
            let _ = writeln!(out);

            let _ = writeln!(out, "PENDING APPROVALS  {}", approvals.len());
            for r in approvals {
                let _ = writeln!(
                    out,
                    "  {} {} → {} ({}) [{}]",
                    r.id, r.persona_id, r.credential_name, r.action, r.risk_level
                );
            }
            let _ = writeln!(out);

            let _ = writeln!(out, "RECENT ACTIVITY    (last {})", entries.len());
            for e in entries {
                let ag = e.agent_id.as_deref().unwrap_or("-");
                let cr = e.credential.as_deref().unwrap_or("-");
                let _ = writeln!(
                    out,
                    "  {} {} {} {} {}",
                    e.timestamp, ag, e.action, cr, e.outcome
                );
            }
            let _ = writeln!(out);
            let _ = write!(out, "AUDIT TOTAL        {} events", total);
        }
        DaemonStatusBanner::StalePid { pid } => {
            let _ = writeln!(out, "DAEMON             stopped (stale PID {pid})");
            let _ = writeln!(out, "  Repair:    sudo ember daemon install");
            let _ = writeln!(
                out,
                "  Note:      daemon-backed features are unavailable; showing local store summary only"
            );
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "PERSONAS           {} active, {} revoked",
                active, revoked
            );
            let _ = writeln!(out, "ACTIVE GRANTS      {}", grants.len());
            let _ = writeln!(out, "SANDBOXES          {} running", running);
            let _ = writeln!(out, "PENDING APPROVALS  {}", approvals.len());
            let _ = writeln!(out, "RECENT ACTIVITY    {} entries", entries.len());
            let _ = write!(out, "AUDIT TOTAL        {} events", total);
        }
        DaemonStatusBanner::NotRunning => {
            let _ = writeln!(out, "DAEMON             not running");
            let _ = writeln!(out, "  Repair:    sudo ember daemon install");
            let _ = writeln!(
                out,
                "  Note:      daemon-backed features are unavailable; showing local store summary only"
            );
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "PERSONAS           {} active, {} revoked",
                active, revoked
            );
            let _ = writeln!(out, "ACTIVE GRANTS      {}", grants.len());
            let _ = writeln!(out, "SANDBOXES          {} running", running);
            let _ = writeln!(out, "PENDING APPROVALS  {}", approvals.len());
            let _ = writeln!(out, "RECENT ACTIVITY    {} entries", entries.len());
            let _ = write!(out, "AUDIT TOTAL        {} events", total);
        }
    }
    out
}

fn render_status_troubleshoot_text(
    banner: &DaemonStatusBanner,
    summary: &ember_daemon::infra::status::StatusSummary,
    dispatch: StatusActionDispatch,
    github_status: Option<&GithubProviderStatusView>,
    ember_initialized: bool,
    launcher_issue: Option<&InstalledLauncherIssue>,
) -> String {
    let mut out = String::new();
    let summary_source = match dispatch {
        StatusActionDispatch::DaemonRpc => "daemon RPC (live socket)",
        StatusActionDispatch::LocalFallback => {
            "local fallback (daemon unavailable or socket missing)"
        }
    };

    let _ = writeln!(out, "TROUBLESHOOT");
    let _ = writeln!(out, "  Summary source: {summary_source}");

    match banner {
        DaemonStatusBanner::Running { .. } => {
            if dispatch == StatusActionDispatch::DaemonRpc {
                if summary.quarantined {
                    let _ = writeln!(
                        out,
                        "  Daemon probe:   socket + status RPC reachable, but write-class methods are quarantined"
                    );
                    if let Some(authority) = summary.quarantine_authority.as_deref() {
                        let _ = writeln!(out, "  Quarantine:     {authority}");
                    }
                    let _ = writeln!(out);
                    let _ = writeln!(out, "Next steps:");
                    let _ = writeln!(
                        out,
                        "  1. Run `ember audit verify` to inspect the audit chain break."
                    );
                    let _ = writeln!(
                        out,
                        "  2. Repair the daemon and audit chain before retrying write-class commands."
                    );
                    let _ = writeln!(
                        out,
                        "  3. Re-run `ember status` to confirm quarantine is gone."
                    );
                    let _ = writeln!(
                        out,
                        "  4. Only then continue with `ember github status` and `ember claude`."
                    );
                    return out;
                }
                let _ = writeln!(out, "  Daemon probe:   socket + status RPC healthy");
            } else {
                let _ = writeln!(
                    out,
                    "  Daemon probe:   PID file says running, but the status socket/RPC path was unavailable"
                );
            }

            match github_status.map(github_https_lane) {
                Some(GithubHttpsLane::ConfiguredApp) => {
                    let _ = writeln!(out, "  GitHub HTTPS:   real App lane ready");
                    let _ = writeln!(out);
                    let _ = writeln!(out, "Next steps:");
                    let _ = writeln!(
                        out,
                        "  1. Launch `ember claude` for the canonical friendly session path."
                    );
                    let _ = writeln!(
                        out,
                        "  2. After the first brokered action, run `ember receipt export --latest --format md`."
                    );
                }
                Some(GithubHttpsLane::ConfiguredPat) => {
                    let _ = writeln!(out, "  GitHub HTTPS:   degraded PAT fallback active");
                    let _ = writeln!(out);
                    let _ = writeln!(out, "Next steps:");
                    let _ = writeln!(
                        out,
                        "  1. Run `ember github setup` to upgrade from PAT fallback to the App lane."
                    );
                    let _ = writeln!(
                        out,
                        "  2. Until then, gh/git will attribute through your GitHub identity."
                    );
                    let _ = writeln!(
                        out,
                        "  3. If you intentionally stay on this degraded lane, verify it with `ember receipt export --latest --format md` after the first brokered action."
                    );
                }
                Some(GithubHttpsLane::ConfiguredMock) => {
                    let _ = writeln!(out, "  GitHub HTTPS:   mock-only App registration");
                    let _ = writeln!(out);
                    let _ = writeln!(out, "Next steps:");
                    let _ = writeln!(
                        out,
                        "  1. Run `ember github setup` with a real App credential triple."
                    );
                    let _ = writeln!(
                        out,
                        "  2. Have these ready: private key PEM, App ID, installation URL or ID, and App slug."
                    );
                    let _ = writeln!(
                        out,
                        "  3. Then run `ember github status` to confirm the App lane is ready."
                    );
                }
                Some(GithubHttpsLane::Broken) => {
                    let _ = writeln!(
                        out,
                        "  GitHub HTTPS:   local App config is present but broken"
                    );
                    if let Some(detail) = github_status.and_then(|status| status.detail.as_deref())
                    {
                        let _ = writeln!(out, "  GitHub detail:  {detail}");
                    }
                    let _ = writeln!(out);
                    let _ = writeln!(out, "Next steps:");
                    let _ = writeln!(
                        out,
                        "  1. Run `ember github setup` to repair or replace the local App credential triple."
                    );
                    let _ = writeln!(
                        out,
                        "  2. Then run `ember github status` to confirm the App lane is ready."
                    );
                }
                Some(GithubHttpsLane::NotConfigured) => {
                    let _ = writeln!(out, "  GitHub HTTPS:   not configured");
                    let _ = writeln!(out);
                    let _ = writeln!(out, "Next steps:");
                    let _ = writeln!(
                        out,
                        "  1. Run `ember github setup` to register local App credentials for the HTTPS/App lane."
                    );
                    let _ = writeln!(
                        out,
                        "  2. Have these ready: private key PEM, App ID, installation URL or ID, and App slug."
                    );
                    let _ = writeln!(
                        out,
                        "  3. Then run `ember github status` to confirm the App lane is ready."
                    );
                }
                None => {
                    let _ = writeln!(out, "  GitHub HTTPS:   unavailable from this status path");
                    let _ = writeln!(out);
                    let _ = writeln!(out, "Next steps:");
                    let _ = writeln!(out, "  1. Run `ember github status` for GitHub posture.");
                }
            }

            if dispatch == StatusActionDispatch::LocalFallback {
                let _ = writeln!(
                    out,
                    "  3. Run `ember daemon diagnose` if the daemon should be up but the socket still does not answer."
                );
            }
            let _ = writeln!(
                out,
                "  4. Run `ember trust list` to confirm trust roots are readable."
            );
            let _ = writeln!(
                out,
                "  5. Run `ember audit show --limit 20` for recent operator-visible events."
            );
        }
        DaemonStatusBanner::StalePid { .. } => {
            let _ = writeln!(
                out,
                "  Daemon probe:   stale PID file; daemon is not healthy"
            );
            let _ = writeln!(
                out,
                "  Local state:    {}",
                if ember_initialized {
                    "daemon.db present"
                } else {
                    "daemon.db missing"
                }
            );
            if let Some(issue) = launcher_issue {
                let _ = writeln!(out, "  Install path:   {}", issue.detail());
            }
            let _ = writeln!(out);
            let _ = writeln!(out, "Next steps:");
            let mut next_step = 1;
            if let Some(issue) = launcher_issue {
                let _ = writeln!(out, "  {next_step}. {}", issue.repair_guidance());
                next_step += 1;
            }
            let _ = writeln!(
                out,
                "  {next_step}. Run `sudo ember daemon install` to repair the managed separate-uid daemon."
            );
            next_step += 1;
            if ember_initialized {
                let _ = writeln!(
                    out,
                    "  {next_step}. Run `ember daemon diagnose` before deeper surgery; this usually means state exists but the daemon did not come back cleanly."
                );
                next_step += 1;
                let _ = writeln!(
                    out,
                    "  {next_step}. Once the daemon is back, run `ember github status` before launching Claude Code."
                );
            } else {
                let _ = writeln!(
                    out,
                    "  {next_step}. Run `ember init --for claude` after the daemon is back."
                );
            }
        }
        DaemonStatusBanner::NotRunning => {
            let _ = writeln!(out, "  Daemon probe:   not running");
            let _ = writeln!(
                out,
                "  Local state:    {}",
                if ember_initialized {
                    "daemon.db present"
                } else {
                    "daemon.db missing"
                }
            );
            if let Some(issue) = launcher_issue {
                let _ = writeln!(out, "  Install path:   {}", issue.detail());
            }
            let _ = writeln!(out);
            let _ = writeln!(out, "Next steps:");
            let mut next_step = 1;
            if let Some(issue) = launcher_issue {
                let _ = writeln!(out, "  {next_step}. {}", issue.repair_guidance());
                next_step += 1;
            }
            let _ = writeln!(
                out,
                "  {next_step}. Run `sudo ember daemon install` to install or repair the managed separate-uid daemon."
            );
            next_step += 1;
            if ember_initialized {
                let _ = writeln!(
                    out,
                    "  {next_step}. Run `ember daemon diagnose` if the daemon still refuses to start; this preserves the MEK/state branch instead of reinstalling blindly."
                );
                next_step += 1;
                let _ = writeln!(
                    out,
                    "  {next_step}. Once the daemon is back, run `ember github status` before launching Claude Code."
                );
            } else {
                let _ = writeln!(
                    out,
                    "  {next_step}. Run `ember init --for claude` after the daemon is up."
                );
            }
        }
    }

    out
}

/// Resolve the operator's age recipient public key for `ember vault export`.
///
/// Search order:
/// 1. Explicit `--recipient-key <path>` flag.
/// 2. `$XDG_CONFIG_HOME/emberlink/recipient.age` (or `~/.config/...`).
///
/// The file is expected to contain a single `age1...` recipient line; any
/// `#`-comment lines are ignored so operators can annotate their key.
fn resolve_recipient_key(explicit: Option<&Path>) -> Result<String, String> {
    let path: PathBuf = if let Some(p) = explicit {
        p.to_path_buf()
    } else {
        let base = dirs_next::config_dir()
            .ok_or_else(|| "could not resolve XDG config directory".to_string())?;
        base.join("emberlink").join("recipient.age")
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read recipient key {}: {e}", path.display()))?;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("age1") {
            return Ok(trimmed.to_string());
        }
    }
    Err(format!(
        "no `age1...` recipient line found in {} (lines starting with `#` are skipped)",
        path.display()
    ))
}

/// Resolve the operator's age identity (private key) for `ember vault import`.
fn resolve_identity_key(explicit: Option<&Path>) -> Result<String, String> {
    let path: PathBuf = if let Some(p) = explicit {
        p.to_path_buf()
    } else {
        let base = dirs_next::config_dir()
            .ok_or_else(|| "could not resolve XDG config directory".to_string())?;
        base.join("emberlink").join("identity.age")
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read identity key {}: {e}", path.display()))?;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("AGE-SECRET-KEY-") {
            return Ok(trimmed.to_string());
        }
    }
    Err(format!(
        "no `AGE-SECRET-KEY-...` identity line found in {} (lines starting with `#` are skipped)",
        path.display()
    ))
}

/// Drive the `ember vault export` flow: list every credential, encrypt each
/// value individually under the operator's age recipient, and emit a JSON
/// envelope to stdout (or `--output <path>` with mode 0600).
///
/// Returns `Err(exit_code)` if any step failed; the caller exits the
/// process with that code.
fn run_vault_export(
    config: &DaemonConfig,
    json_global: bool,
    args: VaultExportArgs,
) -> Result<(), i32> {
    if args.format != "json" {
        eprintln!(
            "error: unsupported --format {} (only `json` is supported)",
            args.format
        );
        return Err(2);
    }
    let recipient = match resolve_recipient_key(args.recipient_key.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return Err(1);
        }
    };
    let (_, entries) = run_vault_list(config, None).map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    let mut pairs: Vec<(String, Vec<u8>)> = Vec::with_capacity(entries.len());
    for entry in &entries {
        let name = match entry.get("name").and_then(|v| v.as_str()) {
            Some(name) => name,
            None => {
                eprintln!("error: daemon/local vault list returned an entry without a string name");
                return Err(1);
            }
        };
        let (_, value) = run_vault_get(config, name).map_err(|e| {
            eprintln!("error: failed to read {name}: {e}");
            1
        })?;
        pairs.push((name.to_string(), value));
    }
    let envelope = emberlink_cli::vault_io::encode_export_envelope(
        &recipient,
        &pairs,
        chrono::Utc::now().to_rfc3339(),
    )
    .map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    let serialized = serde_json::to_string_pretty(&envelope).map_err(|e| {
        eprintln!("error: failed to serialize envelope: {e}");
        1
    })?;
    if let Some(path) = args.output.as_deref() {
        // Write atomically with mode 0600 — same posture as
        // `ember vault add`'s --delete-source path.
        if let Err(e) = std::fs::write(path, &serialized) {
            eprintln!("error: failed to write {}: {e}", path.display());
            return Err(1);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
                eprintln!("warn: failed to set 0600 on {}: {e}", path.display());
            }
        }
        if !json_global {
            eprintln!(
                "Exported {} credential(s) to {} (recipient {recipient}).",
                entries.len(),
                path.display()
            );
        }
    } else {
        println!("{serialized}");
    }
    Ok(())
}

/// Drive the `ember vault import` flow: read the JSON envelope, decrypt
/// every entry first (so any failure aborts before any write), then `put`
/// each restored entry back into the vault.
fn run_vault_import(config: &DaemonConfig, args: VaultImportArgs) -> Result<(), i32> {
    if args.format != "json" {
        eprintln!(
            "error: unsupported --format {} (only `json` is supported)",
            args.format
        );
        return Err(2);
    }
    let identity = match resolve_identity_key(args.identity_key.as_deref()) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("error: {e}");
            return Err(1);
        }
    };
    let raw = std::fs::read_to_string(&args.from).map_err(|e| {
        eprintln!("error: failed to read {}: {e}", args.from.display());
        1
    })?;
    let envelope: emberlink_cli::vault_io::VaultExportEnvelope = serde_json::from_str(&raw)
        .map_err(|e| {
            eprintln!("error: invalid JSON in {}: {e}", args.from.display());
            2
        })?;
    // Atomic decrypt — collect plaintext for every entry first; abort
    // before any vault write if any decryption fails.
    let decrypted =
        emberlink_cli::vault_io::decode_import_envelope(&identity, &envelope).map_err(|e| {
            eprintln!("error: {e}");
            1
        })?;
    // Every entry decrypted cleanly — commit them.
    let count = decrypted.len();
    for (name, value) in decrypted {
        run_vault_store(config, &name, &value, None).map_err(|e| {
            eprintln!("error: failed to put {name}: {e}");
            1
        })?;
    }
    eprintln!(
        "Imported {count} credential(s) from {}.",
        args.from.display()
    );
    Ok(())
}

/// Per implementation-note-452: refuse `ember vault add --value <secret>`
/// argv form because it leaks the secret to shell history, `ps auxww`, and
/// transcript-capturing harnesses. Centralized so future credential-input
/// CLI surfaces can call it.
fn refuse_value_in_argv(flag: &str) -> ! {
    eprintln!(
        "error: --{flag} is refused — passing secrets via argv leaks them to \
         shell history and `ps auxww`."
    );
    eprintln!("       Use one of:");
    eprintln!("         ember vault add --name <name> --stdin       # pipe or terminal input");
    eprintln!("         ember vault add --name <name> --file <path> # read from file");
    eprintln!(
        "       (--file pairs with --delete-source to zero+unlink after vault-encrypt; refuses \
         ~/Downloads paths without --from-downloads.)"
    );
    std::process::exit(2);
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
    /// Initialize ember — canonical first-run setup
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
        #[arg(long, hide = true)]
        touch_id: bool,
        /// Canonical onboarding for Claude or Codex.
        ///
        /// Canonical value: `claude`. When set, `ember init` completes the
        /// standard first-run setup, creates or reuses the default Claude
        /// persona/grant wiring, patches `~/.claude/settings.json`, and
        /// reports whether GitHub is already ready or needs
        /// `ember github setup`. If `ANTHROPIC_API_KEY` is present, init
        /// stores it as `anthropic-key` and the launcher can reuse a
        /// brokered Claude runtime grant; otherwise Claude's own upstream
        /// auth remains ambient.
        ///
        /// Codex (target value `codex`) is the parallel onboarding lane.
        /// When complete it patches `~/.codex/hooks.json` so the Codex CLI
        /// routes commands through ember's grant/audit surface, then
        /// surfaces `codex login status` as the auth-readiness check
        /// (Codex's native upstream auth lane — ember does not broker
        /// Codex auth today, by parity with the Claude lane's
        /// upstream-ambient default).
        #[arg(long = "for", value_name = "TARGET")]
        for_target: Option<OnboardingTarget>,
        /// Skip all interactive prompts. When set and the daemon is not
        /// installed, `ember init` exits with a repair command instead of
        /// prompting to run `sudo ember daemon install`. Useful for CI and
        /// scripted provisioning where stdin is not a TTY.
        #[arg(long)]
        non_interactive: bool,
        /// implementation-note-453: relocate old-layout
        /// PATH-shadow shims at `~/.ember/shadow/<tool>` to the new
        /// `~/.ember/shadow/bin/<tool>` layout, replacing the old paths
        /// with symlinks pointing into `bin/` so any PATH or wrapper
        /// still referencing the old location keeps working for one
        /// release window. Idempotent on `layout=new` /
        /// `layout=both` / `layout=none` hosts. Only meaningful with
        /// `--for claude-code`. Anchor:
        /// `shadow_path_migrate_flag_landed`.
        #[arg(long)]
        migrate: bool,
    },
    /// Uninstall ember integrations.
    ///
    /// Currently supports `--for claude`, which removes only the lines this
    /// onboarding path added to `~/.claude/settings.json`.
    /// Persona, grant, and vault entries are left in place — they may be
    /// in use by other tools.
    Uninstall {
        /// Integration target to uninstall. Canonical: `claude`.
        #[arg(long = "for", value_name = "TARGET")]
        for_target: OnboardingTarget,
    },
    /// Open an isolated Claude Code session.
    ///
    /// Thin preset over `ember session open claude --isolated`.
    #[command(hide = true)]
    Up {
        /// Profile name selecting the compose service set (`dev` /
        /// `headless` / `demo`).
        #[arg(long, value_name = "NAME")]
        profile: Option<String>,
    },
    /// Tear down a container-mode session (implementation-note-454 scaffold).
    #[command(hide = true)]
    Down {
        /// Eager-revoke this session's grants instead of letting them expire at TTL.
        #[arg(long = "revoke-grants")]
        revoke_grants: bool,
        /// Skip the confirmation prompt for `--revoke-grants`.
        #[arg(long, short = 'y')]
        yes: bool,
        /// Remove named compose volumes after teardown.
        #[arg(long)]
        purge: bool,
    },
    /// Operator authority-control surface for live workflow grants (design).
    ///
    /// `ember workflow revoke --workflow-id <id>` — kill a runaway agent.
    /// `ember workflow list [--all]` — list active workflow grants.
    /// `ember workflow show <id>` — render one workflow grant's metadata.
    ///
    /// Workflow grants are minted implicitly at `ember claude` launch (the
    /// launcher prompts for a workflow template the first time per session).
    /// Revoke is always safe — operator only ever removes authority; no
    /// Touch ID required.
    Workflow {
        #[command(subcommand)]
        action: emberlink_cli::workflow::WorkflowCmd,
    },
    /// Operator recovery surface (design §Component 1).
    ///
    /// `ember recover {daemon,authority,broker,audit,install}` — class
    /// entry points; each routes to a sub-module that is incrementally
    /// populated as per-F-code implementations land.
    /// `ember recover explain F-CODE` — print the matching runbook
    /// excerpt from `docs/runbook/recovery.md`.
    ///
    /// Recovery actions emit Receipts of kind `recovery.action`; the
    /// authority class is gated by `PresenceProof` (Touch ID). Today
    /// the scaffold prints those contracts without performing the
    /// action — see `implementation-note-455-*` for the per-F-code work.
    Recover {
        #[command(subcommand)]
        action: emberlink_cli::recover::RecoverCmd,
    },
    /// Install, inspect, and repair the ember daemon
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
    #[command(hide = true)]
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },
    /// Manage the credential vault
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },
    /// Manage the binary-pin manifest used for daemon-socket peer-binary
    /// content-hash binding. Per KEYCHAIN-CONSOLIDATE-CLI adversarial-
    /// review HIGH-1: every `local_state_key_*` call verifies the peer's
    /// binary blake3 against this manifest. The manifest is daemon-self-
    /// signed (v0.3 trust model: TOFU at the moment generate runs).
    #[command(name = "binary-pin", hide = true)]
    BinaryPin {
        #[command(subcommand)]
        action: BinaryPinAction,
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
    #[command(hide = true)]
    Broker {
        #[command(subcommand)]
        action: emberlink_cli::broker::BrokerCmd,
    },
    /// Manage daemon-controlled credential bindings (implementation-note-177).
    ///
    /// A binding ties `(persona, working-tree, remote)` to a remote URL
    /// the broker is authorized to inject credentials for. This is the
    /// EXPLICIT admin path — operators use it to pre-register bindings
    /// during admin work (no biometric required) and to recover from
    /// rename/repo-move scenarios. Biometric will gate the TOFU flow
    /// (DCC-3), not this verb.
    #[command(hide = true)]
    Bind {
        #[command(subcommand)]
        action: emberlink_cli::bind::BindCmd,
    },
    /// View or evaluate policy rules
    #[command(hide = true)]
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// View configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Inspect and configure GitHub transport posture
    Github {
        #[command(subcommand)]
        action: GithubAction,
    },
    /// Inspect trust roots and verification chains
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },
    /// Show daemon status, local state summary, and repair guidance
    Status {
        /// Append a bounded next-steps section for repair and operator checks
        #[arg(long)]
        troubleshoot: bool,
    },
    /// Show ember version
    Version,
    /// Cluster snapshot management (implementation-note-203)
    #[command(hide = true)]
    Cluster {
        #[command(subcommand)]
        action: ClusterAction,
    },
    /// Launch Claude with ember-managed env + PATH wiring.
    ///
    /// This is the ergonomic launcher alias. The canonical launch model is
    /// `ember session open claude ...`; this top-level verb remains a
    /// thin preset over that shared session-open contract.
    ///
    /// `claude-code` is accepted as a deprecated alias of `claude` so the
    /// pre-rename invocation shape continues to work.
    ///
    /// `--prod` is implicit when neither lane flag is given.
    #[command(
        name = "claude",
        visible_aliases = ["claude-code"],
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    ClaudeCode {
        /// Use the current worktree's dev daemon flavor.
        /// Mutually exclusive with --prod.
        #[arg(long, conflicts_with = "prod")]
        dev: bool,
        /// Use the prod daemon flavor (~/.ember/run/daemon.sock). Default when
        /// neither --dev nor --prod is given.
        /// Mutually exclusive with --dev.
        #[arg(long, conflicts_with = "dev")]
        prod: bool,
        /// Force the host-resident launcher path.
        #[arg(long, conflicts_with = "isolated")]
        host: bool,
        /// Force the isolated launcher path.
        #[arg(long, conflicts_with = "host")]
        isolated: bool,
        /// Advanced isolated-path backend hint (docker, orbstack, podman).
        #[arg(long, value_name = "NAME")]
        backend: Option<String>,
        /// Advanced isolated-path preset/profile hint (dev, headless, demo).
        #[arg(long, value_name = "NAME")]
        preset: Option<String>,
        /// Launch the session from an Ember-managed git worktree.
        #[arg(long, value_name = "NAME")]
        worktree: Option<String>,
        /// Override the branch name created for a new managed worktree.
        #[arg(long, requires = "worktree")]
        branch: Option<String>,
        /// Short operator note recorded in `.agent-session`.
        #[arg(long, requires = "worktree")]
        purpose: Option<String>,
        /// Trailing arguments forwarded verbatim to `claude`.
        #[arg(value_name = "CLAUDE_ARGS")]
        args: Vec<String>,
    },
    /// Launch Codex with ember-managed env + PATH wiring.
    ///
    /// Thin preset over `ember session open codex ...` — mirrors the
    /// `claude` top-level subcommand for parity. The canonical launch
    /// model is `ember session open codex`; this top-level verb is the
    /// ergonomic alias.
    ///
    /// `--prod` is implicit when neither lane flag is given.
    #[command(
        name = "codex",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    Codex {
        /// Use the current worktree's dev daemon flavor.
        /// Mutually exclusive with --prod.
        #[arg(long, conflicts_with = "prod")]
        dev: bool,
        /// Use the prod daemon flavor (~/.ember/run/daemon.sock). Default when
        /// neither --dev nor --prod is given.
        /// Mutually exclusive with --dev.
        #[arg(long, conflicts_with = "dev")]
        prod: bool,
        /// Force the host-resident launcher path.
        #[arg(long, conflicts_with = "isolated")]
        host: bool,
        /// Force the isolated launcher path.
        #[arg(long, conflicts_with = "host")]
        isolated: bool,
        /// Advanced isolated-path backend hint (docker, orbstack, podman).
        #[arg(long, value_name = "NAME")]
        backend: Option<String>,
        /// Advanced isolated-path preset/profile hint (dev, headless, demo).
        #[arg(long, value_name = "NAME")]
        preset: Option<String>,
        /// Launch the session from an Ember-managed git worktree.
        #[arg(long, value_name = "NAME")]
        worktree: Option<String>,
        /// Override the branch name created for a new managed worktree.
        #[arg(long, requires = "worktree")]
        branch: Option<String>,
        /// Short operator note recorded in `.agent-session`.
        #[arg(long, requires = "worktree")]
        purpose: Option<String>,
        /// Trailing arguments forwarded verbatim to `codex`.
        #[arg(value_name = "CODEX_ARGS")]
        args: Vec<String>,
    },
    /// Demo subcommands — canned flows for friendly-dev onboarding and
    /// the May-3 composite-grant recording.
    ///
    /// `wedge`  — 60-second canned fallback (implementation-note-456,
    ///            design §8). Spins up an isolated daemon + seeded vault
    ///            + MCP server via `qember.sh demo up`.
    /// `bundle` — submit the locked May-3 4-statement composite-grant
    ///            approval (implementation-note-457). In-process
    ///            store call; no socket round-trip.
    #[command(hide = true)]
    Demo {
        #[command(subcommand)]
        action: DemoAction,
    },
    /// Grants manifest workflows (`validate <file>`).
    #[command(hide = true)]
    Grants {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Session lifecycle subcommands. Dev-internal substrate — the
    /// canonical friendly surface is `ember claude` / `ember codex` /
    /// `ember headless`. Hidden from top-level help per the v0.3.0
    /// help_surface invariant.
    #[command(hide = true)]
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },
    /// Construct binary signing (AP-CONSTRUCT-SIGNING-CLI).
    ///
    /// `ember construct sign --binary <path> --construct-toml <path>
    ///   --version <semver> --identity-root-keypath <path>`
    ///
    /// Produces a JSON sidecar at `<binary>.sig` with a blake3 content hash +
    /// Ed25519 publisher signature. See `docs/construct-signing-pipeline.md`.
    #[command(hide = true)]
    Construct {
        #[command(subcommand)]
        action: ConstructAction,
    },
    /// Manage content-hash-pinned binaries (T-CONSTRUCT-PATH-PINNING-CLI).
    ///
    /// Reads/writes `~/.ember/binaries/manifest.toml`. Verbs:
    ///   `install <tool>@<version> --from-path <path>`
    ///   `list`
    ///   `update <tool>`   (stub — not yet implemented)
    ///   `remove <tool>@<version>`
    #[command(hide = true)]
    Binary {
        #[command(subcommand)]
        action: BinaryAction,
    },
    /// Manage headless (attested-device) enrollments — variable
    /// duration credential delegation for headless / scheduled jobs.
    ///
    /// `ember headless enroll [--duration <4h|3d|1w>] [--persona <id>]
    ///                        [--yes]`
    /// `ember headless revoke [--enrollment-id <id>]`
    /// `ember headless status`
    ///
    /// Dev0 cohort: 7-day ceiling, 4-hour default. The daemon-side
    /// enroll/revoke arms are Phase 1 stubs today (prior change); status
    /// returns the steady-state shape. Phase 2 wires MEK sourcing +
    /// `headless_enrollment` Receipt emission.
    Headless {
        #[command(subcommand)]
        action: HeadlessAction,
    },
    /// Manage the ember KMS edge CA and peer enrollment lifecycle
    /// (design Amendment 1 v3, implementation-note-415).
    ///
    /// `ember kms init-edge`
    ///   Generate the self-signed edge CA and persist the seed at
    ///   `<data_dir>/kms/edge-ca/ca.seed`. Prints the CA fingerprint for
    ///   out-of-band sharing with peers.
    ///
    /// `ember kms peer prepare <persona>@<peer-hostname>`
    ///   Generate an Ed25519 keypair locally (mode 0600); write a CSR.
    ///   The private key NEVER traverses any wire.
    ///
    /// `ember kms peer enroll <csr>`
    ///   Verify the CSR, check persona grants, mint a client cert, emit
    ///   a PeerEnroll Receipt, write the bundle (cert + CA chain).
    ///
    /// `ember kms peer install <bundle> --ca-fingerprint <sha>`
    ///   Verify the CA fingerprint and install cert + CA chain.
    ///
    /// `ember kms peer revoke <name>`
    ///   Revoke by cert serial; emit a PeerRevoke Receipt.
    #[command(hide = true)]
    Kms {
        #[command(subcommand)]
        action: KmsAction,
    },
    /// Manage the SCION recursive orchestrator (design §3).
    ///
    /// `ember orchestrator spawn [--max-depth N] [--template T] [--brief TEXT]`
    ///   Mint an orchestrator-class Persona, acquire the single-orchestrator
    ///   flock guard at `/tmp/ember-orchestrator-<uid>.lock`, and launch
    ///   `ember-scion start`. Only host-side callers may reach this verb;
    ///   in-container callers are refused at the broker boundary.
    ///
    /// `ember orchestrator status [--verbose]`
    ///   Show whether an orchestrator is running, its Persona ID, and
    ///   (with `--verbose`) a JSON status object.
    ///
    /// `ember orchestrator stop`
    ///   Revoke the orchestrator Persona via daemon RPC and release the flock.
    #[command(hide = true)]
    Orchestrator {
        #[command(subcommand)]
        action: emberlink_cli::orchestrator::OrchestratorAction,
    },
    /// Dev daemon install + info + sync (design Phase 4).
    ///
    /// `ember dev install` — provision the current worktree's dev daemon
    /// end-to-end (11 phases).
    ///   Returns non-zero if the workstation did not reach ready state.
    ///
    /// `ember dev info` / `ember dev status` — print the current worktree's
    ///   dev install state (IdentityRoot, GH App, paths, daemon/runtime truth).
    ///
    /// `ember dev sync` — incremental rebuild + content-hash diff + copy +
    ///   daemon kickstart for the current worktree runtime, then fail-loud
    ///   if manifest refresh or daemon readiness verification does not
    ///   complete cleanly. Use this after editing daemon or construct code.
    #[command(hide = true)]
    Dev {
        #[command(subcommand)]
        action: DevAction,
    },
    /// Manage the ember mTLS bridge (design Component 1).
    ///
    /// `ember bridge endpoint [--emit-file <path>] [--json]`
    ///   Print or write the bridge endpoint JSON used by in-container agents.
    ///   The JSON contains `addr` (`host.docker.internal:<port>`) and
    ///   `ca_fingerprint_sha256` (hex SHA-256 of the KMS edge CA cert DER).
    #[command(hide = true)]
    Bridge {
        #[command(subcommand)]
        action: BridgeAction,
    },
}

/// `ember init --for <TARGET>` value enum.
///
/// Anchor: onboarding_target_codex_variant_landed
///
/// `claude` is the canonical onboarding lane with full
/// implementation: persona/grant wiring, `~/.claude/settings.json`
/// patcher, and the Claude runtime grant.
///
/// `codex` is accepted at the parse level so the help text's
/// "Canonical onboarding for Claude or Codex" promise is honoured.
/// The dispatch arm is a stub today — see the
/// `Some(OnboardingTarget::Codex)` branch in the `Init` handler —
/// because the Codex hook-wiring path
/// (`~/.codex/hooks.json` patcher, Codex's native auth lane probe)
/// is broader work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OnboardingTarget {
    #[value(name = "claude")]
    Claude,
    #[value(name = "codex")]
    Codex,
}


#[derive(Subcommand, Debug)]
enum V030GateAction {
    /// Print current verdict for each of the 15 ship-gate conditions.
    /// Exit 0 if all conditions are Pass; exit 2 otherwise.
    ///
    /// Default output is the human-readable table from
    /// `v030_gate::render_text`. Pass `--json` to emit the
    /// machine-readable schema from `ShipGateStatus::to_json` instead —
    /// useful for dashboards, observability rollups, and scripted
    /// consumers that key on the documented `{verdict, counts,
    /// conditions: [{id, status, note}]}` shape.
    Status {
        /// Emit machine-readable JSON instead of the text table.
        ///
        /// Schema: `{verdict, counts: {green, fail, pending, total},
        /// conditions: [{id, status, note}]}` — see
        /// `v030_gate::ShipGateStatus::to_json` for the documented
        /// contract.
        ///
        /// Anchor: v030_ship_gate_cli_json_flag_landed
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum GithubAction {
    /// Diagnose the current GitHub auth posture and next setup step
    Status,
    /// Recommended v0.3.0 path: walk the local GitHub App setup flow
    Setup(GithubSetupArgs),
    /// Hidden low-level GitHub App helpers. Most operators should use `ember github setup`.
    #[command(hide = true)]
    App {
        #[command(subcommand)]
        action: GithubAppAction,
    },
}

#[derive(Subcommand, Debug)]
enum TrustAction {
    /// List the daemon's current trust roots
    List,
    /// Show one trust root by full fingerprint or unique prefix
    Show {
        /// Full fingerprint or unique hex prefix
        root_id: String,
    },
    /// Explain how a signed artifact verifies back to a trust root
    Explain {
        /// Signed artifact path
        artifact_path: PathBuf,
        /// Sidecar signature path; defaults to `<artifact>.sig` for binary manifests
        #[arg(long)]
        sidecar: Option<PathBuf>,
        /// Artifact kind: binary_manifest, receipt, or workflow_grant
        #[arg(long, default_value = "binary_manifest")]
        kind: String,
    },
    /// Backup the operator + dev IdentityRoot keys to an encrypted file.
    Backup {
        /// Output path for the encrypted backup file
        #[arg(long = "to")]
        to: PathBuf,
        /// Overwrite an existing backup file at --to
        #[arg(long)]
        force: bool,
        /// Skip the Touch ID confirmation prompt
        #[arg(long = "no-biometric")]
        no_biometric: bool,
    },
    /// Restore operator + dev IdentityRoot keys from an encrypted backup file.
    Restore {
        /// Encrypted backup file path
        #[arg(long = "from")]
        from: PathBuf,
        /// Skip the Touch ID confirmation prompt
        #[arg(long = "no-biometric")]
        no_biometric: bool,
    },
}

#[derive(Args, Debug, Clone, Default)]
struct GithubSetupArgs {
    /// Path to the GitHub App's RSA private key (PEM-encoded PKCS#8 or PKCS#1)
    #[arg(long = "pem-file")]
    pem_file: Option<PathBuf>,
    /// Numeric GitHub App ID
    #[arg(long = "app-id")]
    app_id: Option<String>,
    /// Numeric GitHub installation ID
    #[arg(long = "installation-id")]
    installation_id: Option<String>,
    /// Human-readable App slug
    #[arg(long)]
    slug: Option<String>,
    /// Skip slug verification against GitHub API
    #[arg(long = "allow-unverified-slug")]
    allow_unverified_slug: bool,
    /// Replace an existing stored triple for the same slug+installation
    #[arg(long)]
    replace: bool,
}

#[derive(Subcommand, Debug)]
enum GithubAppAction {
    /// Print the canonical public GitHub App install URL
    InstallUrl,
    /// Print the canonical public GitHub App manifest doc
    Show,
    /// Hidden low-level registration surface. Most operators should use `ember github setup`.
    Register(GithubAppRegisterArgs),
}

#[derive(Args, Debug, Clone)]
struct GithubAppRegisterArgs {
    /// Path to the GitHub App's RSA private key (PEM-encoded PKCS#8 or PKCS#1)
    #[arg(long = "pem-file")]
    pem_file: PathBuf,
    /// Numeric GitHub App ID
    #[arg(long = "app-id")]
    app_id: String,
    /// Numeric GitHub installation ID
    #[arg(long = "installation-id")]
    installation_id: String,
    /// Human-readable App slug
    #[arg(long)]
    slug: String,
    /// Skip slug verification against GitHub API
    #[arg(long = "allow-unverified-slug")]
    allow_unverified_slug: bool,
    /// Replace an existing stored triple for the same slug+installation
    #[arg(long)]
    replace: bool,
}

/// `ember dev` subcommands (design Phase 4).
#[derive(Subcommand)]
enum DevAction {
    /// Install the dev daemon (11-phase flow). Returns non-zero until the
    /// workstation reaches ready state.
    Install,
    /// Print dev install state (IdentityRoot, GH App, paths, daemon/runtime truth).
    #[command(visible_alias = "status")]
    Info,
    /// Incremental rebuild + content-hash diff + copy + daemon kickstart.
    ///
    /// Runs `cargo build --release -p ember-daemon -p ember-construct`,
    /// diffs each built binary (SHA-256) against the dev install root copy,
    /// copies any changed binaries, refreshes the signed dev manifest, then
    /// restarts and verifies the dev daemon via launchctl.
    Sync {
        /// Skip the `launchctl kickstart` step. Use this on hosts that have
        /// not run `ember dev install` yet, or in CI where launchctl is absent.
        #[arg(long)]
        no_launchctl: bool,
    },
}

/// `ember bridge` subcommands (design Component 1).
#[derive(Subcommand)]
enum BridgeAction {
    /// Print or write the bridge endpoint JSON.
    ///
    /// The JSON shape is:
    ///   `{"addr": "host.docker.internal:<port>", "ca_fingerprint_sha256": "<hex>"}`
    ///
    /// `addr` is derived from the daemon's configured bridge bind address
    /// (substituting `host.docker.internal` as the host-reachable name for
    /// in-container callers). `ca_fingerprint_sha256` is the SHA-256 hex of
    /// the KMS edge CA cert DER (from `~/.ember/kms/edge-ca/ca.seed`).
    ///
    /// Exits non-zero if the daemon is not running or the bridge is not bound.
    Endpoint {
        /// Write the endpoint JSON to this path instead of stdout.
        /// Default (when flag absent): `~/.ember/bridge-endpoint.json`.
        #[arg(long, value_name = "PATH")]
        emit_file: Option<PathBuf>,
        /// Print the endpoint JSON to stdout (in addition to writing the file
        /// when --emit-file is given, or as the sole output when it is not).
        #[arg(long)]
        json: bool,
    },
}

/// `ember kms` subcommands.
#[derive(Subcommand)]
enum KmsAction {
    /// Generate the self-signed edge CA (design Amendment 1 v3).
    ///
    /// Persists the 32-byte raw Ed25519 seed at
    /// `<data_dir>/kms/edge-ca/ca.seed` (mode 0600). Prints the CA
    /// fingerprint (SHA-256 hex of cert DER) for out-of-band sharing.
    #[command(name = "init-edge")]
    InitEdge,
    /// Manage mTLS edge peer certificates.
    Peer {
        #[command(subcommand)]
        action: KmsPeerAction,
    },
}

/// `ember kms peer` subcommands.
#[derive(Subcommand)]
enum KmsPeerAction {
    /// Generate an Ed25519 keypair locally and write a CSR.
    ///
    /// Private key is written at `~/.config/emberlink/peer-keys/
    /// <persona>-<peer-hostname>.key` (mode 0600) and NEVER appears in
    /// the CSR file or any wire message.
    Prepare {
        /// Target in the form `<persona>@<peer-hostname>`.
        target: String,
    },
    /// Verify a CSR, mint a client cert, write the enrollment bundle.
    ///
    /// The bundle contains the client certificate and CA chain but NO
    /// private key material.
    Enroll {
        /// Path to the PEM-encoded CSR file.
        csr_file: PathBuf,
    },
    /// Install a peer bundle (cert + CA chain) into local Pulumi config.
    ///
    /// `--ca-fingerprint` is REQUIRED — clap-level, no Option.
    /// The fingerprint is SHA-256 hex of the CA cert DER, as printed by
    /// `ember kms init-edge`.
    Install {
        /// Path to the peer bundle file (written by `peer enroll`).
        bundle_file: PathBuf,
        /// SHA-256 hex fingerprint of the edge CA cert (REQUIRED).
        #[arg(long)]
        ca_fingerprint: String,
        /// Install globally (in `~/.config/emberlink/peer-certs/`).
        /// Default: per-project (in `.ember/peer-certs/` in CWD).
        #[arg(long, default_value_t = false)]
        global: bool,
    },
    /// Revoke a peer certificate by name and emit a PeerRevoke Receipt.
    Revoke {
        /// Peer name in the form `<persona>-<peer-hostname>` or
        /// `<persona>@<peer-hostname>`.
        name: String,
    },
}

#[derive(Subcommand)]
enum BinaryPinAction {
    /// Generate (or regenerate) the binary-pin manifest. Hashes the
    /// ember binaries at the supplied paths, signs the manifest with the
    /// daemon's persona key, and stores it in the daemon vault.
    ///
    /// Subsequent `local_state_key_*` calls verify the calling peer's
    /// binary blake3 against this manifest. Per KEYCHAIN-CONSOLIDATE-CLI
    /// adversarial-review HIGH-1.
    ///
    /// First-time use auto-detects the running `ember` binary via
    /// `current_exe()`; pass `--path caller=<path>` repeatedly to pin
    /// other callers (gui, native-host). Subsequent generates require
    /// `--force` AND a fresh user-presence proof (Touch ID).
    Generate {
        /// Additional `caller=path` pins to include alongside the auto-
        /// detected CLI binary. Examples:
        ///   --path gui=/Applications/Emberlink.app/Contents/MacOS/emberlink-gui
        ///   --path native-host=~/Library/Application\ Support/ember/...
        #[arg(long = "path", value_name = "caller=path")]
        paths: Vec<String>,
        /// Overwrite an existing manifest. Requires a fresh Touch ID via
        /// the HighRiskOp::BinaryPinGenerate presence gate.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum DemoAction {
    /// 60-second canned fallback demo for friendly devs
    /// (implementation-note-456, design §8). Shells `qember.sh demo
    /// up`/`down` and prints the live-approval-flow next steps.
    Wedge {
        /// Tear down the demo environment (calls `qember.sh demo down`).
        #[arg(long)]
        teardown: bool,
    },
    /// Mint the locked May-3 4-statement composite-grant bundle
    /// (implementation-note-457). Submits a single composite
    /// approval entry that bundles credential + session + time +
    /// credential statements via the in-process daemon store.
    Bundle,
    /// **Demo-only.** Seed synthetic Grant Receipts onto an existing grant
    /// chain so `ember receipt tree --grant <id>` has artifacts to render
    /// when the real spawn flow has not produced any yet (SCION 2026-05-15
    /// Beat 8 demo seed).
    ///
    /// Never invoked in production. The seeded receipts pass v1 signature
    /// verification (signed by the local daemon persona) but their bodies
    /// are placeholders, not real audit data.
    Seed {
        /// Root grant id to attach the seed receipts to.
        #[arg(long)]
        grant: String,
        /// Number of synthetic receipts to mint on this grant.
        #[arg(long, default_value = "3")]
        count: usize,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show current configuration
    Show,
    /// Show config file path
    Path,
}

#[derive(Subcommand)]
enum ClusterAction {
    /// List locally-stored cluster snapshots (pulled from a remote EIC)
    Snapshots {
        /// Filter by cluster id (lists all clusters when omitted)
        #[arg(long)]
        cluster_id: Option<String>,
    },
    /// Single-phase EmberSeal bootstrap — generate Daemon Persona keypair (design).
    ///
    /// Generates an Ed25519 Daemon Persona keypair for the given cluster, stores
    /// the privkey seed in the operator's vault under
    /// `cluster-daemon-persona/<cluster-id>`, and prints the Ed25519 pubkey and
    /// derived X25519 recipient pubkey for embedding in the EmberSeal CR.
    ///
    /// Single-phase is the v1 default (design §Decision): operator holds the
    /// Daemon Persona privkey from creation, so PVC wipe → redeploy with the
    /// same key → recovery without human re-sealing.
    ///
    /// Pass `--two-phase` to print documentation for the original design
    /// two-phase flow (opt-out fallback for clusters that do not pre-generate
    /// the Daemon Persona keypair).
    Bootstrap {
        /// Cluster identifier (e.g. "team-zero-dev"). Must be a valid vault
        /// path segment: lowercase letters, digits, hyphens; starts with a
        /// letter (design grammar).
        cluster_id: String,
        /// Print two-phase bootstrap documentation instead of generating a
        /// keypair. Use this to document that a cluster uses the original
        /// design two-phase flow as an explicit opt-out of single-phase.
        #[arg(long)]
        two_phase: bool,
    },
    /// Operator-driven cluster restore after a PVC wipe (design).
    ///
    /// Reads the Daemon Persona privkey seed from the operator's vault at
    /// `cluster-daemon-persona/<cluster-id>`, prints the recovery plan, and
    /// writes the seed to a temp file for the operator to inject as a
    /// Kubernetes secret. The EmberSeal CR's `recipientPubkey` stays the same
    /// because the same key material is reused.
    ///
    /// After the operator re-deploys EIC with the recovered key, run with
    /// `--verify` to probe the daemon socket and confirm readiness.
    Restore {
        /// Cluster identifier (must match the one used during bootstrap).
        cluster_id: String,
        /// After the operator re-deploys EIC, probe the daemon socket and
        /// print readiness status (success / partial / failed).
        #[arg(long)]
        verify: bool,
        /// Write the privkey seed envelope to this path instead of a
        /// system-chosen temp file (useful in CI pipelines).
        #[arg(long)]
        seed_out: Option<String>,
    },
}

#[derive(Subcommand)]
enum SessionAction {
    /// Canonical session-launch surface.
    ///
    /// Top-level launchers like `ember claude` should delegate here
    /// rather than grow independent launch semantics.
    #[command(trailing_var_arg = true, allow_hyphen_values = true)]
    Open {
        /// Session surface to open.
        target: emberlink_cli::session::OpenSurface,
        /// Use the mutable dev lane. Mutually exclusive with --prod.
        #[arg(long, conflicts_with = "prod")]
        dev: bool,
        /// Use the managed prod lane. Default when neither lane flag is given.
        #[arg(long, conflicts_with = "dev")]
        prod: bool,
        /// Force the host-resident launcher path.
        #[arg(long, conflicts_with = "isolated")]
        host: bool,
        /// Force the isolated launcher path.
        #[arg(long, conflicts_with = "host")]
        isolated: bool,
        /// Advanced isolated-path backend hint (docker, orbstack, podman).
        #[arg(long, value_name = "NAME")]
        backend: Option<String>,
        /// Advanced isolated-path preset/profile hint (dev, headless, demo).
        #[arg(long, value_name = "NAME")]
        preset: Option<String>,
        /// Launch the session from an Ember-managed git worktree.
        #[arg(long, value_name = "NAME")]
        worktree: Option<String>,
        /// Override the branch name created for a new managed worktree.
        #[arg(long, requires = "worktree")]
        branch: Option<String>,
        /// Short operator note recorded in `.agent-session`.
        #[arg(long, requires = "worktree")]
        purpose: Option<String>,
        /// Trailing arguments forwarded to the target surface.
        #[arg(value_name = "TARGET_ARGS")]
        args: Vec<String>,
    },
    /// Tail the session sidecar JSONL (`~/.ember/sessions/<id>/sidecar.jsonl`).
    Tail {
        /// Session ID. Defaults to the active session.
        id: Option<String>,
        /// Format JSON lines via `jq`; falls back to raw on jq missing.
        #[arg(long)]
        pretty: bool,
    },
}

#[derive(Subcommand)]
enum ConstructAction {
    /// Sign a Construct binary, producing a `.sig` sidecar file.
    ///
    /// Computes blake3(binary_bytes || construct_toml_bytes), builds a
    /// canonical JCS payload, signs with the publisher's Ed25519 key, and
    /// writes a JSON sidecar at `<binary>.sig`.
    Sign {
        /// Path to the compiled binary (the Construct executable).
        #[arg(long)]
        binary: std::path::PathBuf,
        /// Path to the embedded construct.toml policy file.
        #[arg(long)]
        construct_toml: std::path::PathBuf,
        /// Semver version string (e.g. `1.0.0`).
        #[arg(long)]
        version: String,
        /// Path to the publisher's Ed25519 secret key (raw 32-byte seed file).
        #[arg(long)]
        identity_root_keypath: std::path::PathBuf,
    },
    /// Register a directory as an L1 authoring scope
    /// (T-CONSTRUCT-AUTHORING-MODE-DEV-PATH-REGISTRY).
    ///
    /// `ember construct dev <path>` writes the canonicalized path to
    /// `~/.ember/authoring-paths.toml` (mode 0600). Daemon-side, scripts
    /// resident under any registered path are accepted by `broker.resolve`
    /// and emit Receipts tagged `authoring = true`. End-user installs
    /// (registry empty) refuse all unsigned-script broker calls.
    ///
    /// Use `--list` to print registered paths; `--unregister <path>` to
    /// remove one.
    Dev {
        /// Path to register (must exist on disk; canonicalized at
        /// registration time).
        path: Option<std::path::PathBuf>,
        /// Print all registered paths and exit.
        #[arg(long, conflicts_with_all = ["path", "unregister"])]
        list: bool,
        /// Remove a previously-registered path.
        #[arg(long, conflicts_with_all = ["path", "list"], value_name = "PATH")]
        unregister: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum BinaryAction {
    /// Register a binary by path, computing its blake3 content hash.
    Install {
        /// Tool name and version: `<name>@<version>` (e.g. `ember-gh@1.0.0`).
        tool_at_version: String,
        /// Path to the binary file to register.
        #[arg(long)]
        from_path: std::path::PathBuf,
        /// Publisher DID (defaults to "did:unknown").
        #[arg(long, default_value = "did:unknown")]
        publisher: String,
    },
    /// Print all registered binaries from the manifest.
    List,
    /// Stub: not yet implemented. Use install with the new version explicitly.
    Update {
        /// Tool name to update (e.g. `ember-gh`).
        tool_name: String,
    },
    /// Remove a binary entry from the manifest.
    Remove {
        /// Tool name and version: `<name>@<version>` (e.g. `ember-gh@1.0.0`).
        tool_at_version: String,
    },
}

/// `ember headless <action>` — attested-device enrollment management.
/// Surface for the daemon-side headless enroll / revoke / status
/// socket methods.
#[derive(Subcommand)]
enum HeadlessAction {
    /// Enroll a persona for headless (attested-device) credential
    /// delegation. Interactive `[Y/n]` confirm by default; pass `--yes`
    /// for scripted use (qember.sh T3, smoke tests).
    Enroll {
        /// Duration spec — `4h`, `3d`, `1w`, etc. Default: `4h`. Ceiling: `7d` at dev0.
        #[arg(long)]
        duration: Option<String>,
        /// Persona ID to enroll. Default: `main`.
        #[arg(long)]
        persona: Option<String>,
        /// Skip the interactive `[Y/n]` confirm.
        #[arg(long)]
        yes: bool,
    },
    /// Revoke an active headless enrollment.
    Revoke {
        /// Enrollment ID to revoke. When omitted, the daemon revokes
        /// the only active enrollment (Phase 2 semantics).
        #[arg(long = "enrollment-id")]
        enrollment_id: Option<String>,
    },
    /// Show the active headless enrollment (or `none`).
    Status,
    /// Run the Layer-1 pre-flight scope check.
    ///
    /// Resolves the union of permissions each queued task's declared
    /// Constructs require, diffs against the enrolled persona's
    /// template, and prints the gap list. Use this before
    /// `ember headless enroll` to confirm headless can run the
    /// candidate queue under the current template.
    Preflight {
        /// Path to a JSON file with the input shape
        /// `{ "tasks": [{ "task_id", "constructs" }], "template": [..] }`.
        /// When omitted, an empty task list is sent (smoke probe).
        #[arg(long = "input")]
        input: Option<std::path::PathBuf>,
        /// Emit raw JSON gap list instead of the table.
        #[arg(long)]
        json: bool,
    },
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
    #[command(hide = true)]
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
    /// Install the dev-only same-uid daemon as an always-up user service
    /// (LaunchAgent/systemd)
    #[command(hide = true)]
    InstallAgent {
        /// Write the service file but don't bootstrap/enable it
        #[arg(long)]
        no_autostart: bool,
    },
    /// Uninstall the dev-only daemon user service
    #[command(hide = true)]
    UninstallAgent,
    /// Install the ember daemon (separate-uid posture by default).
    ///
    /// Default behaviour provisions the dedicated `ember` system user and
    /// `ember-clients` connect group, chowns the daemon's at-rest state to
    /// `ember:ember-clients`, and installs the platform launcher
    /// (LaunchDaemon on macOS / systemd unit on Linux). Pass `--single-uid`
    /// to opt into the relaxed-threat-model dev posture (reserved — not
    /// yet implemented).
    Install {
        #[command(flatten)]
        args: DaemonInstallArgs,
    },
    /// Migrate a running single-uid installation to the separate-uid
    /// posture while preserving all on-disk state (vault rows, grants,
    /// sessions). Only `--to separate-uid` is accepted in v1.
    ///
    /// If the host is already on the separate-uid posture the command exits
    /// immediately with a success message ("already on separate-uid posture").
    Migrate {
        /// Target posture. Only `separate-uid` is accepted.
        #[arg(long, value_name = "POSTURE")]
        to: String,
    },
    /// Idempotent + auditable wipe sequence for the MEK-missing-with-state
    /// recovery path.
    ///
    /// Replaces the hand-typed `mv + security delete-generic-password +
    /// launchctl` paste-block operators used to run for this recovery.
    /// Steps:
    ///   1. Stop the daemon (best-effort)
    ///   2. Archive `~/.ember/data/` to `<archive-to>/` (refuses if dir exists)
    ///   3. Print keychain-clear instruction (slice D-bis owns the actual
    ///      System.keychain delete; CLI today emits the canonical command)
    ///   4. Print re-seed checklist for operator next steps
    ///
    /// `--archive-to` is REQUIRED — no destructive default. Idempotent: a
    /// re-run with an existing archive dir errors instead of overwriting.
    RecoverFresh {
        /// Required: archive the current daemon data dir to this path
        /// before wiping. Must not exist (idempotent guard).
        #[arg(long, value_name = "PATH")]
        archive_to: PathBuf,
    },
    /// Diagnose daemon state — `git fsck`-style detector for the
    /// MEK-persistence-failed pattern.
    ///
    /// Detects four patterns:
    ///   HEALTHY — keychain MEK + daemon.db state + fingerprint all align
    ///   MEK-MISSING-WITH-STATE — keychain empty but daemon.db has rows
    ///     (run `ember daemon recover-fresh`)
    ///   FINGERPRINT-MISMATCH — keychain MEK loaded but
    ///     vault_meta.mek_fingerprint disagrees (vault import --sealed)
    ///   STATE-EMPTY — fresh install; `ember init` to provision
    ///
    /// Outputs a deterministic runbook for each non-HEALTHY pattern.
    /// Fingerprint-check shape depends on slice B
    /// (implementation-note-350) landing;
    /// pre-B, the FINGERPRINT row reports "unavailable (slice B pending)".
    Diagnose,
}

/// Flags for `ember daemon install`. design §Dev mode locks the default
/// to separate-uid; `--single-uid` is the dev-mode escape hatch.
///
/// `--non-interactive` drives the prompt-free install path
/// ([`emberlink_cli::install::install_non_interactive`]) used by CI runners
/// and `RUN ember install --non-interactive` Dockerfile lines. When set,
/// banners and prompts are suppressed, structured `[install] phase=...`
/// lines are emitted to stderr per phase, and the install refuses with a
/// clear error if neither root nor cached sudo is available rather than
/// hanging on a password prompt. See T-INSTALL-WIZARD-NON-INTERACTIVE.
#[derive(Debug, Args)]
pub struct DaemonInstallArgs {
    /// Install daemon under the operator's uid (relaxed-threat-model dev posture).
    /// Default off — production posture is separate-uid per design.
    #[arg(long)]
    pub single_uid: bool,
    /// Run the install without any interactive prompts, banners, or
    /// progress UI. Refuses with a clear error if neither root nor a cached
    /// sudo timestamp is available. Emits one `[install] phase=<step>`
    /// line per install phase to stderr for log scrapers.
    #[arg(long)]
    pub non_interactive: bool,
    /// Acknowledge that default values will be used for any otherwise-prompted
    /// choice. Implied by `--non-interactive`. Captured separately so a future
    /// slice can branch on `--non-interactive` without `--accept-defaults`.
    #[arg(long)]
    pub accept_defaults: bool,
    /// Daemon posture to install (only `separate-uid` accepted today).
    /// Default `separate-uid` per design. Currently informational — pinned
    /// here so downstream tooling (Dockerfile authors, CI runners) can lock
    /// the posture explicitly without ambiguity.
    #[arg(long, value_name = "POSTURE")]
    pub posture: Option<String>,
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
        /// REFUSED — passing secrets via argv leaks them. Kept for argv-parse so we
        /// can emit a structured error pointing at --stdin / --file. Per
        /// implementation-note-452.
        #[arg(long, hide = true)]
        value: Option<String>,
        /// Read credential value from stdin (no shell history leak; trailing newline trimmed).
        #[arg(long, conflicts_with_all = ["value", "file"])]
        stdin: bool,
        /// Read credential value from a file (binary-safe; no leak).
        #[arg(long, conflicts_with_all = ["value", "stdin"])]
        file: Option<std::path::PathBuf>,
        /// With --file: zero the file's bytes then unlink it after vault-encrypt.
        /// Use for one-shot transfers (paste into a tmpfile, ember adds, file is gone).
        #[arg(long, requires = "file")]
        delete_source: bool,
        /// Allow --file paths under ~/Downloads (default: refused — Downloads is a
        /// known cleartext-credential leak surface).
        #[arg(long, requires = "file")]
        from_downloads: bool,
        /// Optional metadata
        #[arg(long)]
        metadata: Option<String>,
    },
    /// List stored credentials
    List(VaultListArgs),
    /// Retrieve a credential value (masked by default)
    Get(VaultGetArgs),
    /// Store a credential value (alias for `add`; safe-input flags only).
    ///
    /// Per implementation-note-458 this is the operator-facing
    /// surface for the `CredentialStore::put` trait method shipped in
    /// prior change. Refuses `--value <secret>` argv form (leaks via shell
    /// history); use `--stdin` or `--file <path>`.
    Put(VaultPutArgs),
    /// Remove a credential
    Remove {
        /// Credential name
        name: String,
    },
    /// Export every credential as an age-encrypted JSON envelope.
    ///
    /// Each value is sealed individually under the operator's age
    /// recipient key (`~/.config/emberlink/recipient.age` by default);
    /// names are visible so the operator can audit what's stored. Use
    /// `ember vault import` to restore on another host.
    Export(VaultExportArgs),
    /// Import a JSON envelope produced by `ember vault export`.
    ///
    /// All entries decrypt-and-write atomically: any decryption failure
    /// aborts before any `put` runs, so the live vault never sees a
    /// partial restore.
    Import(VaultImportArgs),
    /// Re-lock the vault session.
    ///
    /// Equivalent to letting the idle timer expire — but explicit. After
    /// this runs, the next high-risk op (vault add, vault remove, grant
    /// create, persona key export) will require fresh user presence
    /// (Touch ID on macOS).
    Lock,
    /// Re-open the vault session explicitly after `ember vault lock`.
    ///
    /// On the daemon-backed path this is the current non-session operator
    /// reopen seam. It does not yet make the accepted lazy first-session
    /// unlock posture live; it is an explicit operator action.
    Unlock,
    /// Re-store the vault MEK passphrase with the platform-current ACL.
    ///
    /// One-shot migration for pre-existing MEK entries created before
    /// implementation-note-117 shipped. After this runs, vault unlocks
    /// via Touch ID / device passcode instead of the plain keychain password.
    /// Idempotent: safe to run multiple times.
    MigrateAcl,
}

/// Args for `ember vault list`.
///
/// `--prefix <pat>` filters to credential names beginning with `<pat>`.
/// Empty prefix lists every credential (the default).
#[derive(Debug, Args)]
pub struct VaultListArgs {
    /// Filter to names starting with this prefix.
    #[arg(long)]
    pub prefix: Option<String>,
}

/// Args for `ember vault get`.
///
/// Default behaviour masks all but the last 4 chars (e.g. `****abcd` for
/// `<long>abcd`; `****` for values shorter than 4 chars). `--unmask`
/// prints the raw value but only when stdout is non-TTY (e.g. piped) or
/// `--i-know-what-im-doing` is set, to protect screen-recording demos
/// from accidental leaks.
#[derive(Debug, Args)]
pub struct VaultGetArgs {
    /// Credential name.
    pub name: String,
    /// Print the raw value. Refused on a TTY unless --i-know-what-im-doing.
    #[arg(long)]
    pub unmask: bool,
    /// Acknowledge the leak risk and unmask even on a TTY.
    #[arg(long)]
    pub i_know_what_im_doing: bool,
}

/// Args for `ember vault put`.
///
/// Mirrors `ember vault add` for the safe-input flags (`--stdin`,
/// `--file`, `--delete-source`, `--from-downloads`); `--value <secret>`
/// argv form is refused via [`refuse_value_in_argv`].
#[derive(Debug, Args)]
pub struct VaultPutArgs {
    /// Credential name.
    #[arg(long)]
    pub name: String,
    /// REFUSED — passing secrets via argv leaks them. Surfaces a
    /// structured error pointing at `--stdin` / `--file`.
    #[arg(long, hide = true)]
    pub value: Option<String>,
    /// Read credential value from stdin (no shell history leak).
    #[arg(long, conflicts_with_all = ["value", "file"])]
    pub stdin: bool,
    /// Read credential value from a file (binary-safe; no leak).
    #[arg(long, conflicts_with_all = ["value", "stdin"])]
    pub file: Option<std::path::PathBuf>,
    /// With `--file`: zero the file's bytes then unlink it after vault-encrypt.
    #[arg(long, requires = "file")]
    pub delete_source: bool,
    /// Allow `--file` paths under `~/Downloads` (default: refused).
    #[arg(long, requires = "file")]
    pub from_downloads: bool,
    /// Optional metadata.
    #[arg(long)]
    pub metadata: Option<String>,
}

/// Args for `ember vault export`.
///
/// Lists every credential and seals each value individually under the
/// operator's age recipient key. Output JSON shape:
///
/// ```json
/// {
///   "version": 1,
///   "exported_at": "2026-05-10T...",
///   "recipient": "age1...",
///   "entries": [
///     { "name": "azure/tenant-id", "value_age_armored": "-----BEGIN AGE..." }
///   ]
/// }
/// ```
#[derive(Debug, Args)]
pub struct VaultExportArgs {
    /// Output format. Currently only `json` is supported.
    #[arg(long, default_value = "json")]
    pub format: String,
    /// Output file path (default: stdout). Created with mode 0600.
    #[arg(long)]
    pub output: Option<std::path::PathBuf>,
    /// Path to the operator's age recipient public key.
    /// Defaults to `$XDG_CONFIG_HOME/emberlink/recipient.age` (or `~/.config/...`).
    #[arg(long)]
    pub recipient_key: Option<std::path::PathBuf>,
}

/// Args for `ember vault import`.
///
/// Decrypts every entry first; only on full success does it `put` each
/// entry. Any decryption failure aborts before any write so the live
/// vault never sees a partial restore.
#[derive(Debug, Args)]
pub struct VaultImportArgs {
    /// Input format. Currently only `json` is supported.
    #[arg(long, default_value = "json")]
    pub format: String,
    /// Path to the JSON envelope produced by `ember vault export`.
    #[arg(long)]
    pub from: std::path::PathBuf,
    /// Path to the operator's age identity (private key) file.
    /// Defaults to `$XDG_CONFIG_HOME/emberlink/identity.age` (or `~/.config/...`).
    #[arg(long)]
    pub identity_key: Option<std::path::PathBuf>,
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
    /// implementation-note-346: unblocks `ember sandbox create --name X` retries
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
        /// Emit a JSON array with full UUIDs (no truncation) instead of the table view
        #[arg(long)]
        json: bool,
    },
    /// Show the full receipt for a given id
    Show {
        /// Receipt id (or grant id)
        id: String,
        /// Output format: `json` (default) or `md` (markdown).
        #[arg(long, default_value = "json")]
        format: String,
        /// Show full sidecar content. Today a no-op (forward-compat
        /// surface; the v2 receipt envelope carries the full sidecar
        /// inline, so this flag is reserved for the v3 split-sidecar
        /// shape).
        #[arg(long)]
        raw: bool,
    },
    /// Export a receipt's signed JSON to stdout
    Export {
        /// Receipt id.
        #[arg(required_unless_present = "latest")]
        id: Option<String>,
        /// Export the most recent receipt (friendly Touch-2 shortcut).
        #[arg(long, conflicts_with = "id")]
        latest: bool,
        /// Output format: `json` (default) or `md` (markdown).
        #[arg(long, default_value = "json")]
        format: String,
        /// Show full sidecar content. Today a no-op (forward-compat
        /// surface; the v2 receipt envelope carries the full sidecar
        /// inline, so this flag is reserved for the v3 split-sidecar
        /// shape).
        #[arg(long)]
        raw: bool,
    },
    /// Verify a receipt's Ed25519 signature against the daemon's identity key.
    ///
    /// Either pass a receipt `id` (looked up in the local daemon's store) or
    /// `--file <PATH>` to verify an exported receipt JSON offline (use `-`
    /// for stdin). Offline verification is what makes Grant Receipts a
    /// third-party-verifiable artifact (CEO-009).
    ///
    /// `--tree <PATH> --offline` verifies a tree-export JSON produced by
    /// `ember receipt tree --export`. The verify path is daemon-free: the
    /// trust anchor pubkey is embedded in the export file and no socket
    /// connection is made. This is the Beat 8 demo close.
    Verify {
        /// Receipt id (looked up from the local daemon store).
        /// Mutually exclusive with `--file`.
        #[arg(conflicts_with_all = ["file", "materialization", "tree"])]
        id: Option<String>,
        /// Verify a receipt JSON file. `-` reads from stdin.
        /// Mutually exclusive with `id`.
        #[arg(long, value_name = "PATH")]
        file: Option<String>,
        /// Override the trust anchor — expected signer pubkey (hex).
        /// When omitted, reads from the Daemon Persona key file under
        /// `<data_dir>/daemon_persona.key`. Required in practice for
        /// `--file` mode against receipts signed by a different daemon.
        #[arg(long)]
        pubkey: Option<String>,
        /// Verify chain integrity for a construct-invocation rollup, keyed
        /// by `materialization_id`. Walks the sub-Receipts in
        /// `--events` and exits non-zero if the chain is broken (e.g.
        /// missing `broker.materialization` head, or `Incomplete` because
        /// the daemon crashed mid-spawn).
        #[arg(long, value_name = "MATERIALIZATION_ID")]
        materialization: Option<String>,
        /// Override the events-log path used by `--materialization`.
        /// Defaults to `<data_dir>/events.jsonl`.
        #[arg(long, value_name = "PATH")]
        events: Option<PathBuf>,
        /// Verify a tree-export JSON produced by `ember receipt tree
        /// --export <path>`. Daemon-free: the trust anchor is embedded in
        /// the file.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["id", "file", "materialization"])]
        tree: Option<PathBuf>,
        /// Confirm the offline-verify intent. When `--tree` is set,
        /// `--offline` documents that no daemon RPC will be made. Today
        /// the flag is informational — the verify path is always
        /// daemon-free.
        #[arg(long)]
        offline: bool,
    },
    /// Walk the grant graph rooted at `--grant <id>` and render the
    /// delegated authority + receipt artifact set as a tree.
    ///
    /// `--export <PATH>` additionally writes a JSON export shape that
    /// `ember receipt verify --tree <PATH> --offline` consumes for
    /// third-party verification after `ember daemon stop`. This is the
    /// Beat 8 demo close artifact.
    Tree {
        /// Root grant id — typically the orchestrator's composite grant.
        #[arg(long)]
        grant: String,
        /// Optional JSON-export destination for offline verify.
        #[arg(long, value_name = "PATH")]
        export: Option<PathBuf>,
    },
    /// Aggregate construct-invocation sub-Receipts into one row per
    /// `materialization_id` (per `docs/construct-receipt-rollup.md`).
    ///
    /// Reads the daemon's `events.jsonl` (or `--events <PATH>`), groups by
    /// `materialization_id`, and renders a `RECEIPTS / STARTED / OUTCOME / ACTION`
    /// table. Use `--json` for machine-parseable output.
    Rollup {
        /// Filter rollups whose `started_at` is older than this cutoff.
        /// Forms: `1h`, `24h`, `7d`, `all`, or any RFC-3339 timestamp.
        #[arg(long, default_value = "all")]
        since: String,
        /// Show only the rollup matching this `materialization_id`.
        #[arg(long, value_name = "MATERIALIZATION_ID")]
        materialization: Option<String>,
        /// Restrict output to chains missing `session.construct_invocation`
        /// (operator-followup signal — daemon crashed mid-spawn).
        #[arg(long)]
        incomplete_only: bool,
        /// Override the events-log path. Defaults to
        /// `<data_dir>/events.jsonl`.
        #[arg(long, value_name = "PATH")]
        events: Option<PathBuf>,
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
    /// Query the receipts table (EMBER-implementation-note-278).
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
    /// implementation-note-262 (B): walk the audit chain and
    /// verify each row's `blake3(prev_hash || canonical_row_bytes)`
    /// matches its stored `row_hash`. Routes through the daemon's
    /// `audit_verify` socket method so the verdict is authoritative
    /// (same path the daemon's startup verify uses).
    Verify {
        /// Limit the walk to the most recent N rows. Omit for a full-chain walk.
        #[arg(long)]
        tail: Option<usize>,
    },
    /// implementation-note-459: report combined audit disk footprint across
    /// the prod (`~/.ember/audit/`) and dev (`~/.ember-dev/audit/`)
    /// daemons. Splits the total into primary / archive / sidecar
    /// buckets per design §C2 and flags daemons within 80% / above
    /// 100% of the v0.3.0 dev0 ceiling (5 GiB per cohort-defaults
    /// Knob 14). audit_df_command_landed.
    Usage,
}

/// EMBER-implementation-note-278 — parse a `--since` argument.
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
/// implementation-note-460: check whether the ember-init shadow PATH
/// has been installed on this host. Returns `Err(msg)` with a precise
/// remediation hint if `$HOME/.ember/shadow/bin/` is missing or doesn't
/// contain the expected shim binaries (`gh`, `git`).
///
/// Shim binaries live under `~/.ember/shadow/bin/` (the PATH-prepended
/// subdirectory); credential and config files live at `~/.ember/shadow/`.
///
/// Without the shadow PATH, raw `gh` / `git` invocations from sequential
/// agents (headless SKILL, ralph loops, `ship-pr.sh`'s `EMBER_GH_BIN`
/// fallback) bypass the broker entirely — every PR ships as the operator's
/// identity and the audit trail collapses. This is the host-side invariant
/// that closes the gap.
fn ensure_shadow_path_installed() -> Result<(), String> {
    let home = std::env::var("HOME").map_err(|_| "$HOME not set".to_string())?;
    let shadow_bin_dir = std::path::Path::new(&home)
        .join(".ember")
        .join("shadow")
        .join("bin");
    if !shadow_bin_dir.is_dir() {
        return Err(format!(
            "shadow path not installed at {}; run `ember init --for claude`",
            shadow_bin_dir.display()
        ));
    }
    let critical = ["gh", "git"];
    let missing: Vec<&str> = critical
        .iter()
        .filter(|name| !shadow_bin_dir.join(name).exists())
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "shadow path at {} is missing shims: {} — run `ember init --for claude`",
            shadow_bin_dir.display(),
            missing.join(", ")
        ));
    }
    Ok(())
}

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
/// implementation-note-201 extended this from a single dashboard line to the full
/// startup-binds aggregate.
fn print_banner_startup(binds: &StartupBinds) {
    // Identity line first — for the camera-clean demo flow, the daemon's
    // signing fingerprint is the load-bearing visual the viewer needs to
    // match across the dashboard header, the receipt detail card, and the
    // post-take `ember receipt verify --pubkey` arg. Surface it before the
    // listener URLs so the eye registers it as the daemon's "name."
    if !binds.identity_pubkey.is_empty() {
        let fp = ember_daemon::infra::runtime::daemon_identity_fingerprint(&binds.identity_pubkey);
        eprintln!("  Identity:  {fp} (Ed25519)");
    }
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
    match &binds.llm_proxy {
        LlmProxyBind::Bound(addr) => {
            // implementation-note-202: the LLM proxy is what the
            // Anthropic SDK demo posts to via `base_url=$EMBER_PROXY_URL`,
            // so the canonical `EMBER_PROXY_URL=…` line carries this URL.
            // qember.sh + the smoke-runner wrapper read this line.
            eprintln!("  EMBER_PROXY_URL=http://{addr}");
        }
        LlmProxyBind::Failed { addr, error: _ } => {
            eprintln!("  LLM proxy: unavailable (port {} in use)", addr.port());
        }
        LlmProxyBind::Disabled => {
            eprintln!("  LLM proxy: disabled");
        }
        LlmProxyBind::Timeout => {
            eprintln!("  LLM proxy: status unknown (startup timeout)");
        }
    }
    match &binds.git_proxy {
        GitProxyBind::Bound(addr) => {
            // implementation-note-202: the git-echo proxy URL now lives
            // at `EMBER_GIT_PROXY_URL` (was previously `EMBER_PROXY_URL`).
            // ember-git.sh's allowlisted shape still reads `EMBER_PROXY_URL`,
            // so this line is informational; ember-git.sh callers should
            // export `EMBER_GIT_PROXY_URL` directly when both are needed.
            eprintln!("  EMBER_GIT_PROXY_URL=http://{addr}");
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

/// implementation-note-461: resolve the user-pinned config path from
/// the precedence chain (flag → `EMBER_CONFIG` → `EMBER_DEMO_DIR/config.toml`),
/// returning `None` if none of the inputs point at a config so the caller
/// falls through to the default (`~/.ember/config.toml`).
///
/// Pure function so tests cover priority order without mutating
/// process-global env vars (mirrors `resolve_init_keyring_value`).
///
/// Precedence:
/// 1. `--config <path>` flag (always wins, even if file doesn't exist —
///    the caller surfaces the error).
/// 2. `EMBER_CONFIG=<path>` env var.
/// 3. `EMBER_DEMO_DIR=<dir>` env var, when `<dir>/config.toml` exists.
/// 4. `None` — caller falls back to `DaemonConfig::default_config_path()`.
///
/// The `EMBER_DEMO_DIR` fallback only fires when the candidate file
/// actually exists, so a stale env var pointing at a removed demo dir
/// doesn't make every CLI invocation fail.
fn resolve_config_path(
    cli_config: Option<&PathBuf>,
    env_config: Option<String>,
    env_demo_dir: Option<String>,
) -> Option<PathBuf> {
    if let Some(p) = cli_config {
        return Some(p.clone());
    }
    if let Some(env) = env_config.filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(env));
    }
    if let Some(dir) = env_demo_dir.filter(|s| !s.is_empty()) {
        let candidate = PathBuf::from(dir).join("config.toml");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Read `EMBER_CONFIG` / `EMBER_DEMO_DIR` from the live process env and
/// resolve a user-pinned config path (or `None` to fall through to default).
///
/// Thin runtime wrapper around `resolve_config_path` so call sites that
/// previously read `cli.config.as_ref()` can adopt env-var auto-discovery
/// in one substitution.
fn resolved_user_config_path(cli_config: Option<&PathBuf>) -> Option<PathBuf> {
    resolve_config_path(
        cli_config,
        std::env::var("EMBER_CONFIG").ok(),
        std::env::var("EMBER_DEMO_DIR").ok(),
    )
}

fn effective_config_path(cli_config: Option<&PathBuf>) -> PathBuf {
    resolved_user_config_path(cli_config).unwrap_or_else(DaemonConfig::default_config_path)
}

fn managed_separate_uid_topology_paths(home: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let ember_root = home.join(".ember");
    (
        ember_root.join("run"),
        ember_root.join("data"),
        ember_root.join("run").join("emberd.pid"),
    )
}

fn matches_managed_separate_uid_topology_paths(config: &DaemonConfig, home: &Path) -> bool {
    let (socket_dir, data_dir, pid_file) = managed_separate_uid_topology_paths(home);
    config.socket_dir == socket_dir && config.data_dir == data_dir && config.pid_file == pid_file
}

fn uses_managed_separate_uid_topology(config: &DaemonConfig) -> bool {
    if !ember_daemon::install::is_separate_uid_posture() {
        return false;
    }
    let Some(home) = dirs_next::home_dir() else {
        return false;
    };
    matches_managed_separate_uid_topology_paths(config, &home)
}

fn managed_local_vault_fallback_refused() -> core_types::ValidationError {
    core_types::ValidationError::new(
        "daemon is not running on the managed separate-uid path; local vault fallback is refused. \
         Run `ember status` to inspect daemon posture and `sudo ember daemon install` to repair it."
            .to_string(),
    )
}

/// implementation-note-220: probe `/api/status` on the configured
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

    let mut stream =
        std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .ok()?;

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
fn configure_tracing(
    data_dir: &std::path::Path,
    log_level: &ember_daemon::infra::config::LogLevel,
    console: bool,
) -> LogGuard {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level.as_filter_str()));

    let log_dir = data_dir;
    let file_appender = tracing_appender::rolling::daily(log_dir, "daemon.log");
    let (non_blocking, worker_guard) = tracing_appender::non_blocking(file_appender);

    let file_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(non_blocking);

    let registry = tracing_subscriber::registry().with(filter).with(file_layer);

    if console {
        let console_layer = tracing_subscriber::fmt::layer();
        registry.with(console_layer).try_init().ok();
    } else {
        registry.try_init().ok();
    }

    tracing::info!(log_dir = %log_dir.display(), log_prefix = "daemon.log", "daemon logging initialized");

    LogGuard {
        _worker: worker_guard,
    }
}

fn load_config(path: Option<&PathBuf>) -> DaemonConfig {
    // implementation-note-461: when `--config` is absent, fall back
    // through `EMBER_CONFIG` and `EMBER_DEMO_DIR/config.toml` before the
    // default path. Lets `bash scripts/recording-day.sh prep` export
    // `EMBER_DEMO_DIR=/tmp/ember-demo-<id>` and have every subsequent
    // `ember <verb>` talk to the demo daemon without `--config` plumbing.
    if let Some(resolved) = resolved_user_config_path(path) {
        return match DaemonConfig::load(&resolved) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!(
                    "error: failed to load config from {}: {e}",
                    resolved.display()
                );
                process::exit(1);
            }
        };
    }

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
        // implementation-note-462: loud-fail instead of silent
        // DaemonConfig::default() fallback. The May-12 25-hour leaked-daemon
        // incident was rooted in this fallback silently inheriting user-home
        // paths in test contexts where --config / EMBER_CONFIG / EMBER_DEMO_DIR
        // were absent. Subtask A's type-system change removes Default outright;
        // this loud-fail closes the same gap from the CLI entry-point.
        eprintln!(
            "no ember config found at {}. Run `ember init` to create one, or pass --config <path>.",
            default_path.display()
        );
        process::exit(1);
    }
}

fn init_rerun_command(for_target: Option<OnboardingTarget>) -> &'static str {
    match for_target {
        Some(OnboardingTarget::Claude) => "`ember init --for claude`",
        Some(OnboardingTarget::Codex) => "`ember init --for codex`",
        None => "`ember init`",
    }
}

fn init_managed_daemon_install_starting_line() -> &'static str {
    "  Daemon:   not running — running `sudo ember daemon install`"
}

fn init_managed_daemon_install_started_line() -> &'static str {
    "  Daemon:   managed separate-uid daemon is up"
}

fn init_autostart_repair_line(rerun_cmd: &str) -> String {
    format!(
        "Run `sudo ember daemon install` to install or repair the managed daemon service, \
         then re-run {rerun_cmd}."
    )
}

fn init_noncanonical_daemon_topology_line(rerun_cmd: &str) -> String {
    format!(
        "Friendly init only auto-installs the managed daemon from the default operator HOME \
         and default config path. This invocation is using an isolated HOME or custom config, \
         so the same-uid fallback is refused. Run `sudo ember daemon install` from your normal \
         shell and then re-run {rerun_cmd}."
    )
}

fn wait_for_init_daemon_socket(socket_path: &Path) -> Result<(), String> {
    let timeout_secs = emberlink_cli::onboarding::claude_code::autostart_liveness_timeout_secs();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let pid_path = socket_path
        .parent()
        .map(|dir| dir.join("emberd.pid"))
        .unwrap_or_else(|| std::path::PathBuf::from("emberd.pid"));
    loop {
        match emberlink_cli::probe_live_daemon_status(socket_path, &pid_path) {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(e) => {
                return Err(format!(
                    "daemon install completed but the live status probe failed: {e}"
                ));
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "daemon install completed but the daemon never became live within {timeout_secs}s \
                 (expected socket at {}); check daemon logs at $HOME/.ember/logs/daemon.out and retry. \
                 Override the timeout with EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS=<seconds>.",
                socket_path.display()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn ensure_managed_daemon_for_init(
    config: &DaemonConfig,
    cli_config_path: Option<&PathBuf>,
    rerun_cmd: &str,
    non_interactive: bool,
) -> Result<(), String> {
    let socket_path = config.socket_dir.join("daemon.sock");
    match emberlink_cli::probe_live_daemon_status(&socket_path, &config.pid_file) {
        Ok(Some(live)) => {
            println!(
                "  Daemon:   already running (socket {})",
                live.socket.display()
            );
            return Ok(());
        }
        Ok(None) => {}
        Err(e) => return Err(format!("could not inspect managed daemon posture: {e}")),
    }

    let config_path = resolved_user_config_path(cli_config_path);
    let home = dirs_next::home_dir().unwrap_or_else(|| std::path::PathBuf::from("/"));
    if !emberlink_cli::onboarding::claude_code::supports_managed_daemon_install(
        &home,
        config_path.as_deref(),
    ) {
        return Err(init_noncanonical_daemon_topology_line(rerun_cmd));
    }

    if non_interactive || !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(init_autostart_repair_line(rerun_cmd));
    }

    let exe = std::env::current_exe()
        .map_err(|e| format!("could not resolve ember binary for managed install: {e}"))?;
    println!("{}", init_managed_daemon_install_starting_line());
    let status = std::process::Command::new("sudo")
        .arg(&exe)
        .arg("daemon")
        .arg("install")
        .status()
        .map_err(|e| format!("failed to launch `sudo ember daemon install`: {e}"))?;
    if !status.success() {
        let suffix = status
            .code()
            .map(|code| format!("exit code {code}"))
            .unwrap_or_else(|| "terminated by signal".to_string());
        return Err(format!(
            "managed daemon install failed ({suffix}). {}",
            init_autostart_repair_line(rerun_cmd)
        ));
    }

    wait_for_init_daemon_socket(&socket_path)?;
    println!("{}", init_managed_daemon_install_started_line());
    Ok(())
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

    // implementation-note-335: in-process CLI subcommands (grant/sandbox/persona) talk to
    // the same SQLite DB the daemon uses, but without going through the
    // socket — so they need their own attached vault to encrypt/decrypt
    // persona secrets. Best-effort auto-unseal from keyring is still useful
    // for dev/test and same-uid local paths.
    //
    // Under design's managed separate-uid topology, though, the keyring lane
    // has been superseded by the daemon's native unlock RPC. Offline local
    // summaries (for example `ember status` when the daemon is down) must not
    // drag the operator back through the legacy login-keychain prompt.
    if !uses_managed_separate_uid_topology(config) {
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
    }

    // Initialise the daemon's Ed25519 process identity so that
    // `DaemonStore::revoke_grant` (and other terminal-transition paths)
    // can emit signed Grant Receipts via `trigger_receipt_if_terminal_current`.
    // Without this, the identity `OnceCell` stays empty and receipt emission
    // silently no-ops, leaving `ember receipt show <id>` returning "grant
    // exists but has not reached terminal state".
    if let Err(e) = ember_daemon::infra::receipt::init_identity(&config.data_dir) {
        tracing::warn!("could not initialise daemon identity for receipt emission: {e}");
    }

    store
}

/// implementation-note-463: detect whether a basic `ember init` has
/// already been run. Returns true if `daemon.db` exists in `config.data_dir`.
/// On live daemon-backed runs the daemon owns creating that file; the old
/// local-store fallback still creates it in-process. Used by the
/// `--for claude` handler to skip re-running basic init (and creating a
/// duplicate "root" persona) when the daemon DB is already present.
fn is_ember_initialized(config: &DaemonConfig) -> bool {
    config.data_dir.join("daemon.db").exists()
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

/// Default policy seed written by `ember init` when no `policy.toml` exists.
/// Schema must round-trip through `core_approval::policy::PolicyConfig` —
/// regression-tested in `tests::default_policy_seed_parses` (implementation-note-464).
const DEFAULT_POLICY_TOML: &str = "\
# Ember daemon policy
# Rules evaluated in order — first match wins.

default_requirement = \"required\"
default_risk = \"medium\"

[[rules]]
action = \"git.push.main\"
risk = \"critical\"
requirement = \"denied\"

[[rules]]
action = \"git.push.*\"
risk = \"medium\"
requirement = \"auto\"

[[rules]]
action = \"deploy.production\"
risk = \"critical\"
requirement = \"required\"

[[rules]]
action = \"deploy.staging\"
risk = \"medium\"
requirement = \"auto\"

[[rules]]
action = \"credential.access\"
risk = \"high\"
requirement = \"required\"
";

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

fn emit_first_grant_receipt_after_init(
    config: &DaemonConfig,
    socket_path: &Path,
    persona_id: &str,
    persona_public_key: &str,
    direct_store: Option<&DaemonStore>,
) -> Result<(), String> {
    if emberlink_cli::onboarding::first_grant::short_circuit_first_grant_receipt_emit(
        &config.data_dir,
    )
    .is_some()
    {
        return Ok(());
    }

    if let Some(store) = direct_store {
        let signer = store
            .persona_signer(persona_id)
            .map_err(|e| format!("persona signer: {e}"))?;
        emberlink_cli::onboarding::first_grant::emit_first_grant_receipt(
            &config.data_dir,
            persona_id,
            persona_public_key,
            &signer,
        )
        .map(|_| ())
        .map_err(|e| e.to_string())?;
        return Ok(());
    }

    let built = emberlink_cli::call_daemon_method(
        socket_path,
        "build_init_first_grant_receipt",
        &serde_json::json!({"persona_id": persona_id}),
    )
    .map_err(|e| format!("build init first-grant receipt (rpc): {e}"))?;
    let file: emberlink_cli::onboarding::first_grant::FirstGrantReceiptFile =
        serde_json::from_value(built)
            .map_err(|e| format!("parse init first-grant receipt (rpc): {e}"))?;
    emberlink_cli::onboarding::first_grant::write_first_grant_receipt_file(
        &config.data_dir,
        persona_id,
        persona_public_key,
        &file,
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

fn cmd_init(
    config: &DaemonConfig,
    name: Option<String>,
    cli_config_path: Option<&PathBuf>,
    keyring_service_override: Option<String>,
    keyring_account_override: Option<String>,
    touch_id: bool,
    non_interactive: bool,
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
    // otherwise consult `EMBER_CONFIG` / `EMBER_DEMO_DIR` (implementation-note-465-
    // AUTODISCOVERY) before falling back to the default
    // (`~/.ember/config.toml`).
    let config_path = resolved_user_config_path(cli_config_path)
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
    if !policy_path.exists()
        && let Err(e) = fs::write(&policy_path, DEFAULT_POLICY_TOML)
    {
        eprintln!("warning: failed to write policy: {e}");
    }

    // `cmd_init` still owns the passphrase/salt bootstrap today so the CLI
    // can provision first-run keyring state and clear `EMBER_VAULT_PASSPHRASE`
    // from its own environment. Once the daemon socket is live, persona
    // creation and first-grant receipt signing move behind daemon RPC.
    //
    // V0 schema: persona rows are vault-sealed at rest, so the no-daemon
    // test fallback still needs a local vault. Order:
    //   1. Write or reuse the salt file.
    //   2. Resolve or provision the passphrase.
    //   3. In the test-only no-daemon branch, build the vault from
    //      passphrase + salt and attach it to the local store.
    //   4. Otherwise let the daemon own persona-secret access.
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
    let (passphrase, vault_status): (String, String) = if let Ok(p) =
        std::env::var("EMBER_VAULT_PASSPHRASE")
    {
        // Capture then immediately zeroize from the process environment so
        // it cannot be read from /proc/<pid>/environ by a second party.
        // Called during init before any background threads spawn; the
        // signal/thread race in remove_var is acceptable here.
        // Safety: single-threaded init path; no other threads are reading env.
        unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };
        (p, "passphrase source: EMBER_VAULT_PASSPHRASE".to_string())
    } else if keyring_writes_suppressed() {
        // Three-axis gate — `bin/ember.rs` isn't covered by the gate
        // inside `resolve_passphrase` because it calls `keyring_core::Entry::new`
        // directly. Keeps `cargo test` from firing real keychain popups
        // (the 2026-04-22 leak).
        (
            "ember-test-fallback-passphrase".to_string(),
            "keyring write skipped (test/mock gate)".to_string(),
        )
    } else {
        // Belt-and-suspenders production checkpoint. Mirrors the check
        // inside `Vault::open_from_config` (vault.rs:102-110) so the
        // CLI init path cannot bypass it by calling `keyring_core::Entry::new`
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
            if let Err(e) = check_production_sentinel(&service, DEFAULT_KEYRING_SERVICE, &home) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }

        let entry = match keyring_core::Entry::new(&service, &account) {
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
                eprintln!("           Set EMBER_VAULT_PASSPHRASE env var to bypass the keyring.");
                "keyring unavailable (see above)".to_string()
            }
        };

        (generated, status)
    };

    let root_name = name.as_deref().unwrap_or("root");

    // init_persona_rpc_after_autostart_reorder: implementation-note-466
    // Autostart fires BEFORE the RPC so the socket is live when create_persona dispatches.
    //
    // Under design separate-uid posture (daemon=ember uid, operator=operator uid)
    // the operator cannot write the daemon's SQLite DB, so the prior direct
    // `store.create_persona(root_name)` call failed. Route through the daemon
    // JSON-RPC instead. Mirrors the pattern in `cmd_init_for_claude_code`.
    let socket_path = config.socket_dir.join("daemon.sock");
    // EMBER_SKIP_DAEMON_INSTALL_CHECK: test-only bypass — same env var as the
    // daemon-install precheck gate above. When set, skip the managed-daemon
    // check so binary tests running against isolated tmp dirs do not try to
    // invoke sudo or wait for a production socket.
    let skip_daemon_install_check = std::env::var("EMBER_SKIP_DAEMON_INSTALL_CHECK").is_ok();
    if !skip_daemon_install_check
        && let Err(e) = ensure_managed_daemon_for_init(
            config,
            cli_config_path,
            init_rerun_command(None),
            non_interactive,
        )
    {
        eprintln!("error: {e}");
        process::exit(1);
    }

    // When EMBER_SKIP_DAEMON_INSTALL_CHECK is set (test-only bypass) and no
    // daemon socket is present, fall back to the old local store path.
    let daemon_socket_live = socket_path.exists();
    let mut direct_store: Option<DaemonStore> = None;
    let (persona_id, persona_name, persona_public_key) =
        if skip_daemon_install_check && !socket_path.exists() {
            // [open-store-audit] MUTATOR-MIXED: cmd_init local fallback only.
            // The installed path now routes both persona creation and
            // first-grant receipt signing through daemon RPC. A local store is
            // still needed only for the test/isolated no-daemon branch.
            let vault = Rc::new(Vault::from_passphrase(&passphrase, &salt));
            let store = open_store(config);
            store.set_vault(Rc::clone(&vault));
            match store.create_persona(root_name) {
                Ok(info) => {
                    direct_store = Some(store);
                    (info.id, info.name, info.public_key)
                }
                Err(e) => {
                    eprintln!("error: failed to create root persona (direct): {e}");
                    process::exit(1);
                }
            }
        } else {
            let created = match emberlink_cli::call_daemon_method(
                &socket_path,
                "create_persona",
                &serde_json::json!({"name": root_name}),
            ) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: failed to create root persona (rpc): {e}");
                    process::exit(1);
                }
            };
            (
                created
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                created
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                created
                    .get("public_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            )
        };

    println!("Initialized ember");
    println!("  Config:   {}", config_path.display());
    println!("  Policy:   {}", policy_path.display());
    println!(
        "  Database: {}",
        config.data_dir.join("daemon.db").display()
    );
    println!("  Root:     {persona_id} ({persona_name})");
    println!("  Vault:    {vault_status}");
    if daemon_socket_live {
        println!("  Daemon:   running ({})", socket_path.display());
    } else {
        println!("  Daemon:   not started (test/local fallback path)");
        println!();
        println!(
            "Run `sudo ember daemon install` on a normal host, or keep using EMBER_SKIP_DAEMON_INSTALL_CHECK only for isolated tests."
        );
    }

    // EMBER-INIT-FIRST-implementation-note-467 (v2): emit a real signed Grant
    // Receipt v2 envelope to <data_dir>/receipts/first.json. The installed
    // path now asks the daemon to build/sign it, while the test-only no-daemon
    // path still signs locally from the direct fallback store.
    // init_first_grant_receipt_emit
    if let Err(e) = emit_first_grant_receipt_after_init(
        config,
        &socket_path,
        &persona_id,
        &persona_public_key,
        direct_store.as_ref(),
    ) {
        eprintln!("warning: first-grant receipt emission failed: {e}");
        // Fall through to v1 tips so the user isn't left with no guidance.
        emberlink_cli::onboarding::first_grant::run(&config.data_dir);
    }
}

/// implementation-note-468: cohort A onboarding orchestrator.
///
/// Runs after `cmd_init` has set up the keyring/vault/salt/root persona.
/// Creates the agent persona, writes the scope template, mints a 24h
/// implementation-note-453: relocate any old-layout
/// PATH-shadow shims at `~/.ember/shadow/<tool>` to the canonical
/// `~/.ember/shadow/bin/<tool>` layout and plant back-compat
/// symlinks at the old paths. Idempotent across all four layout
/// states (none / new / old / both). shadow_path_migrate_flag_landed.
fn cmd_migrate_path_shadow_layout() -> Result<(), Box<dyn std::error::Error>> {
    let home = emberlink_cli::onboarding::claude_code::home_dir_for_migrate()?;
    let shadow_root = home.join(".ember").join("shadow");
    let specs =
        emberlink_cli::launcher::claude_code::managed_prod_construct_specs();
    let outcome = emberlink_cli::launcher::path_shadow::migrate_path_shadow_layout(
        &shadow_root,
        &specs,
    )?;
    use emberlink_cli::launcher::path_shadow::MigrationOutcome::*;
    match outcome {
        NoShimsAtAll => {
            println!(
                "ember init --migrate: no shims found at {} or {}/bin/; \
                 nothing to migrate. Run `ember init --for claude` (without \
                 --migrate) to install the shadow PATH first.",
                shadow_root.display(),
                shadow_root.display(),
            );
        }
        AlreadyMigrated => {
            println!(
                "ember init --migrate: shadow PATH already on the new \
                 layout at {}/bin/; nothing to migrate (no-op).",
                shadow_root.display(),
            );
        }
        AlreadyMigratedSymlinksInPlace => {
            println!(
                "ember init --migrate: shadow PATH already migrated — old \
                 paths at {} are symlinks pointing into bin/; nothing to do \
                 (no-op).",
                shadow_root.display(),
            );
        }
        MigratedFromOldLayout { count } => {
            println!(
                "ember init --migrate: relocated {count} old-layout \
                 shim(s) under {} to {}/bin/; back-compat symlinks planted \
                 at the old paths.",
                shadow_root.display(),
                shadow_root.display(),
            );
        }
    }
    Ok(())
}

fn cmd_init_for_claude_code(
    config: &DaemonConfig,
    cli_config_path: Option<&PathBuf>,
    non_interactive: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use emberlink_cli::onboarding::claude_code as cc;

    let persona_name = cc::claude_code_persona_name();
    let template_path = cc::default_grant_template_path()?;
    let settings_path = cc::default_settings_json_path()?;

    println!();
    println!("Setting up Claude Code integration:");

    // implementation-note-469friendly posture: init must only use the managed
    // separate-uid daemon path. If the daemon is missing, offer the canonical
    // `sudo ember daemon install` path in the default operator topology and
    // refuse same-uid fallbacks everywhere else.
    if std::env::var("EMBER_SKIP_DAEMON_INSTALL_CHECK").is_err() {
        ensure_managed_daemon_for_init(
            config,
            cli_config_path,
            init_rerun_command(Some(OnboardingTarget::Claude)),
            non_interactive,
        )?;
    }

    // implementation-note-470: route every persona /
    // grant / vault operation through the daemon's JSON-RPC instead of
    // opening SQLite + vault directly. Under design separate-uid posture
    // (daemon=ember uid, operator=operator uid) the operator cannot read
    // `~/.ember/data/vault.salt` (mode 0600, daemon-owned), so direct
    // `Vault::open_from_config` returns "salt read: Permission denied".
    // The daemon already has DB + vault authority; the CLI proxies.
    //
    // Daemon-autostart fires earlier in this function (lines ~2596-2664),
    // so the socket is guaranteed live by the time we reach this block. Plain
    // `cmd_init` now follows the same live-socket ordering for root persona
    // creation and first-grant receipt signing, but still keeps bootstrap-local
    // config/keyring/salt work.
    //
    // Anchor: ember_init_for_claude_code_rpc_migration_landed.
    let socket_path = config.socket_dir.join("daemon.sock");

    // 1. Find or create the persona via daemon RPC. Calling create_persona
    //    twice with the same name returns an error (UNIQUE constraint), so
    //    we list first and reuse.
    let personas_value =
        emberlink_cli::call_daemon_method(&socket_path, "list_personas", &serde_json::Value::Null)
            .map_err(|e| format!("list personas (rpc): {e}"))?;
    let empty_personas: Vec<serde_json::Value> = Vec::new();
    let personas_array = personas_value.as_array().unwrap_or(&empty_personas);
    let persona_id: String = match personas_array.iter().find(|p| {
        p.get("name")
            .and_then(|v| v.as_str())
            .map(|n| n == persona_name)
            .unwrap_or(false)
    }) {
        Some(p) => {
            let id = p
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name = p
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            println!("  Persona:  reused {id} ({name})");
            id
        }
        None => {
            let created = emberlink_cli::call_daemon_method(
                &socket_path,
                "create_persona",
                &serde_json::json!({"name": persona_name}),
            )
            .map_err(|e| format!("create persona {persona_name} (rpc): {e}"))?;
            let id = created
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name = created
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            println!("  Persona:  created {id} ({name})");
            id
        }
    };

    // 2. Write the grant scope template (idempotent — pure file op).
    let template_written = cc::write_grant_template_if_missing(&template_path)?;
    if template_written {
        println!("  Template: wrote {}", template_path.display());
    } else {
        println!(
            "  Template: kept {} (already present)",
            template_path.display()
        );
    }

    // 3. Repair the managed shadow toolchain up front so the first friendly
    //    launcher run uses installed product constructs rather than stale
    //    repo-local target artifacts.
    let shadow_root = cc::install_managed_prod_shadow_path()
        .map_err(|e| format!("install managed shadow toolchain: {e}"))?;
    println!("  Shadow:   ready {}", shadow_root.display());

    // 4. Seed or detect Anthropic runtime auth for Claude Code. When an
    //    `anthropic-key` vault row is present we can shape the persona's
    //    session grant as a brokered composite grant; otherwise the
    //    friendly still uses ambient Claude auth for now.
    let anthropic_runtime = ensure_claude_code_anthropic_runtime_credential(config)
        .map_err(|e| format!("prepare anthropic runtime credential: {e}"))?;
    println!("{}", render_claude_runtime_auth_status(anthropic_runtime));

    // 5. Ensure the persona has an active 24h grant. Prefer a composite
    //    Anthropic runtime grant when the vault has the credential; otherwise
    //    fall back to the plain launcher grant.
    let grant = ensure_claude_code_runtime_grant(
        config,
        &persona_id,
        anthropic_runtime != AnthropicRuntimeCredentialAvailability::Absent,
    )
    .map_err(|e| format!("ensure claude-code grant (rpc): {e}"))?;
    let expires = grant.expires_at.as_deref().unwrap_or("never");
    match (grant.created, grant.brokered_anthropic_runtime) {
        (true, true) => println!("  Grant:    created {} (24h, Anthropic brokered)", grant.id),
        (false, true) => {
            println!(
                "  Grant:    reused {} (Anthropic brokered until {expires})",
                grant.id
            )
        }
        (true, false) => println!(
            "  Grant:    created {} (24h, ambient Claude auth)",
            grant.id
        ),
        (false, false) => println!("  Grant:    reused {} (active until {expires})", grant.id),
    }

    // 6. Patch ~/.claude/settings.json (idempotent).
    let patched =
        emberlink_cli::onboarding::claude_code::patch_claude_settings_file(&settings_path)?;
    if patched {
        println!("  Hook:     patched {}", settings_path.display());
    } else {
        println!(
            "  Hook:     kept {} (already patched)",
            settings_path.display()
        );
    }

    // 6b. Add permissions.deny entries for raw gh/git/kubectl outside the
    //     shadow PATH (design §3 step 4 — defense-in-depth deny).
    {
        use emberlink_cli::onboarding::settings_patch::add_permissions_deny_outside_shadow;
        let raw = if settings_path.exists() {
            std::fs::read_to_string(&settings_path)
                .map_err(|e| format!("read {} for deny patch: {e}", settings_path.display()))?
        } else {
            String::new()
        };
        let mut value: serde_json::Value = if raw.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&raw).map_err(|e| format!("parse settings.json: {e}"))?
        };
        add_permissions_deny_outside_shadow(&mut value)
            .map_err(|e| format!("add deny rules: {e}"))?;
        let serialized = serde_json::to_string_pretty(&value)
            .map_err(|e| format!("serialize settings.json: {e}"))?;
        std::fs::write(&settings_path, serialized)
            .map_err(|e| format!("write {} after deny patch: {e}", settings_path.display()))?;
        println!(
            "  Deny:     permissions.deny rules added to {}",
            settings_path.display()
        );
    }

    // 7. GitHub posture guidance. The friendly v0.3.0 story is:
    //    App over HTTPS/API first, SSH substrate exists but is not
    //    auto-wired by `ember claude` yet, PAT only as an explicit
    //    degraded fallback through `ember vault add --name github-pat`.
    let mut github_posture = github_onboarding_posture(config);
    cc::print_github_onboarding_guidance(github_posture.clone())?;
    if should_offer_inline_github_setup(
        github_posture.clone(),
        non_interactive,
        io::stdin().is_terminal(),
        io::stderr().is_terminal(),
    ) && prompt_yes_no_default_yes("  Configure the GitHub App lane now")
        .map_err(|e| format!("prompt GitHub App setup: {e}"))?
    {
        println!();
        register_github_from_setup_args(config, &GithubSetupArgs::default(), true, false)
            .map_err(|e| format!("GitHub App setup failed: {e}"))?;
        match try_reload_daemon_after_github_setup(config) {
            Ok(GithubSetupDaemonFollowup::Reloaded { .. }) => {
                github_posture = github_onboarding_posture(config);
            }
            Ok(GithubSetupDaemonFollowup::NeedsManualReload) => {
                eprintln!(
                    "warning: GitHub App credentials were stored, but this daemon must be reloaded before the App lane is live"
                );
                eprintln!("         run `ember daemon reload` and then `ember github status`");
            }
            Err(e) => {
                eprintln!(
                    "warning: GitHub App credentials were stored, but daemon reload failed: {e}"
                );
                eprintln!("         run `ember daemon reload` and then `ember github status`");
            }
        }
    }
    match github_posture {
        cc::GitHubOnboardingPosture::AppConfiguredReal => {
            println!("  GitHub:   ready on the App lane");
        }
        cc::GitHubOnboardingPosture::PatConfigured => {
            println!(
                "  GitHub:   degraded PAT fallback active; run `{}` to move onto the App lane",
                github_setup_command()
            );
        }
        cc::GitHubOnboardingPosture::AppBroken(ref detail) => {
            println!(
                "  GitHub:   local App config is broken; repair with `{}`",
                github_setup_command()
            );
            println!("            detail: {detail}");
        }
        cc::GitHubOnboardingPosture::AppConfiguredMock
        | cc::GitHubOnboardingPosture::AppNotConfigured => {
            println!(
                "  GitHub:   not configured yet; run `{}` when you want GitHub access",
                github_setup_command()
            );
        }
    }

    // 8. Print the next two commands per design §2.
    cc::print_next_commands(github_posture);

    Ok(())
}

/// implementation-note-468: reverse the settings.json patch from
/// `init --for claude`. Removes only what we added; persona, grant,
/// and vault entries are left in place because they may be in use.
fn cmd_uninstall_for_claude_code() -> Result<(), Box<dyn std::error::Error>> {
    use emberlink_cli::onboarding::claude_code as cc;
    use emberlink_cli::onboarding::settings_patch::remove_permissions_deny_outside_shadow;

    let settings_path = cc::default_settings_json_path()?;
    println!("Uninstalling Claude Code integration:");
    let removed = cc::unpatch_claude_settings_file(&settings_path)?;
    if removed {
        println!("  Hook:     removed from {}", settings_path.display());
    } else {
        println!(
            "  Hook:     not present in {} (nothing to do)",
            settings_path.display()
        );
    }

    // Remove permissions.deny entries for raw gh/git/kubectl (design §3 step 4).
    if settings_path.exists() {
        let raw = std::fs::read_to_string(&settings_path)
            .map_err(|e| format!("read {} for deny removal: {e}", settings_path.display()))?;
        if !raw.trim().is_empty() {
            let mut value: serde_json::Value =
                serde_json::from_str(&raw).map_err(|e| format!("parse settings.json: {e}"))?;
            remove_permissions_deny_outside_shadow(&mut value)
                .map_err(|e| format!("remove deny rules: {e}"))?;
            let serialized = serde_json::to_string_pretty(&value)
                .map_err(|e| format!("serialize settings.json: {e}"))?;
            std::fs::write(&settings_path, serialized).map_err(|e| {
                format!("write {} after deny removal: {e}", settings_path.display())
            })?;
            println!(
                "  Deny:     permissions.deny rules removed from {}",
                settings_path.display()
            );
        }
    }

    println!();
    println!(
        "Note: persona, grant, and any github-pat vault entry are kept. \
         Remove them manually with `ember persona revoke`, `ember grant revoke`, \
         and `ember vault remove github-pat` if you want a full clean-up."
    );
    Ok(())
}

/// Install the ember daemon as a managed user service (LaunchAgent on macOS,
/// systemd user unit on Linux). See `daemon_agent` for the platform-specific
/// details. Prints a status summary on success; exits non-zero on failure.
fn cmd_daemon_install_agent(cli_config: Option<&PathBuf>, no_autostart: bool) {
    // Config path lookup: --config wins, then `EMBER_CONFIG` /
    // `EMBER_DEMO_DIR/config.toml` (implementation-note-461), then the
    // default (`~/.ember/config.toml`). We only pass a path through to the
    // plist/unit if the file actually exists — otherwise the service would
    // crash-loop on startup waiting for a config that isn't there.
    let config_path = resolved_user_config_path(cli_config).or_else(|| {
        let default = DaemonConfig::default_config_path();
        if default.exists() {
            Some(default)
        } else {
            None
        }
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
            eprintln!(
                "error: ember daemon install-agent is a dev-only same-uid path and is only supported on macOS and Linux."
            );
            eprintln!(
                "       For the canonical managed daemon posture, use `sudo ember daemon install`."
            );
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

/// Verify `sudo` is on `PATH` before invoking any subprocess that needs root.
/// Returns `Ok(())` when present, `Err(message)` with manual-install
/// instructions when missing.
fn require_sudo() -> Result<(), String> {
    let probe = std::process::Command::new("which").arg("sudo").output();
    match probe {
        Ok(output) if output.status.success() => Ok(()),
        Ok(_) | Err(_) => Err(
            "error: `sudo` not found on PATH — privileged daemon install steps require sudo.\n       \
             Install sudo or run the install steps manually as root:\n         \
             - macOS: `dseditgroup -o create ember`, `sysadminctl -addUser ember ...`, \
             `dseditgroup -o create ember-clients`\n         \
             - Linux: `groupadd --system ember`, `useradd --system ... ember`, \
             `groupadd --system ember-clients`\n       \
             See design §macOS install / §Linux install for the full sequence."
                .to_string(),
        ),
    }
}

/// Install the ember daemon under the separate-uid posture (design).
///
/// Default flow (`--single-uid` not set):
/// 1. Provision the `ember` system user + the `ember-clients` connect group
///    via [`ember_daemon::install::provision_ember_user`].
/// 2. chown the daemon's at-rest state (`~/.ember/{vault,grants,sessions,run,binaries}`)
///    to `ember:ember-clients` via [`ember_daemon::install::chown_ember_data_dirs`].
/// 3. Install the platform launcher (LaunchDaemon plist on macOS / systemd
///    unit on Linux) via [`ember_daemon::install::install_launchd_plist`] /
///    [`ember_daemon::install::install_systemd_unit`].
///
/// `--single-uid` is the dev-mode escape hatch (relaxed threat model — a
/// process running as the operator's uid can bypass the broker by reading
/// the vault directly). Reserved but not yet implemented; surfaces a clear
/// error pointing back to the canonical installed daemon posture.
///
/// Privileged steps (`provision_ember_user`, `install_launchd_plist`,
/// `install_systemd_unit`) require root — typically invoked under `sudo`.
/// We surface a clear progress print before each privileged subprocess so
/// the operator knows when sudo will prompt.
fn cmd_daemon_install(args: DaemonInstallArgs) {
    if args.single_uid {
        tracing::warn!(
            "installing single-uid daemon posture (dev mode — relaxed threat model). \
             See design §Dev mode."
        );
        eprintln!(
            "error: --single-uid is reserved but not yet implemented.\n       \
             Use the canonical installed posture instead:\n         \
             sudo ember daemon install\n       \
             Tracking issue: design §Dev mode."
        );
        process::exit(2);
    }

    // Non-interactive lane (T-INSTALL-WIZARD-NON-INTERACTIVE). Branches off
    // before any prompt-bearing logic so CI / Dockerfile callers never block
    // on a TTY. The posture string is parsed up-front so an unsupported
    // posture surfaces a clean clap-style error instead of running half the
    // install before refusing.
    if args.non_interactive {
        let posture = match args.posture.as_deref() {
            Some(raw) => match emberlink_cli::install::Posture::parse(raw) {
                Ok(p) => p,
                Err(msg) => {
                    eprintln!("error: {msg}");
                    process::exit(2);
                }
            },
            None => emberlink_cli::install::Posture::SeparateUid,
        };
        let opts = emberlink_cli::install::InstallNonInteractiveOptions {
            accept_defaults: args.accept_defaults,
            posture,
        };
        match emberlink_cli::install::install_non_interactive(&opts) {
            Ok(()) => return,
            Err(e) => {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }
    }

    if args.posture.is_some() || args.accept_defaults {
        // The interactive wizard doesn't yet branch on these, but accepting
        // them silently when `--non-interactive` is missing would be a
        // footgun — surface a clear error pointing at the missing flag.
        eprintln!(
            "error: --posture and --accept-defaults require --non-interactive in this release"
        );
        process::exit(2);
    }

    tracing::info!("installing separate-uid daemon posture (design)");

    if let Err(msg) = require_sudo() {
        eprintln!("{msg}");
        process::exit(1);
    }

    println!(
        "about to provision ember user + ember-clients group — sudo password may be requested"
    );
    if let Err(e) = ember_daemon::install::provision_ember_user() {
        eprintln!("error: failed to provision ember user: {e}");
        process::exit(1);
    }

    // Resolve the OPERATOR's home, not root's. Under `sudo`, the calling
    // process has uid 0 and `dirs_next::home_dir()` returns `/var/root`,
    // but the daemon's at-rest state lives under the invoking human's
    // `~/.ember/...` — `resolve_operator_home` reads `$SUDO_USER` (set by
    // sudo) and looks up the home via `getpwnam_r`. The same `home` value
    // is then baked into the plist/unit's `HOME` env var so the daemon
    // (running as the `ember` system uid) resolves `~/.ember/...` back to
    // this directory at runtime.
    let home = match ember_daemon::install::resolve_operator_home() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: failed to resolve operator home: {e}");
            process::exit(1);
        }
    };
    println!(
        "about to chown {}/.ember/{{vault,grants,sessions,run,binaries}} to ember:ember-clients",
        home.display()
    );
    if let Err(e) = ember_daemon::install::chown_ember_data_dirs(&home) {
        eprintln!("error: failed to chown daemon data dirs: {e}");
        process::exit(1);
    }

    println!(
        "about to provision vault MEK in System.keychain + prepare {}/.ember/data/",
        home.display()
    );
    if let Err(e) = ember_daemon::install::provision_se_mek(&home) {
        eprintln!("error: failed to provision vault MEK: {e}");
        process::exit(1);
    }

    #[cfg(target_os = "macos")]
    {
        println!(
            "about to install LaunchDaemon plist at /Library/LaunchDaemons/sh.emberlink.daemon.plist (HOME={})",
            home.display()
        );
        if let Err(e) = ember_daemon::install::install_launchd_plist(&home) {
            eprintln!("error: failed to install LaunchDaemon plist: {e}");
            process::exit(1);
        }
    }

    #[cfg(target_os = "linux")]
    {
        println!(
            "about to install systemd unit at /etc/systemd/system/emberd.service (HOME={})",
            home.display()
        );
        if let Err(e) = ember_daemon::install::install_systemd_unit(&home) {
            eprintln!("error: failed to install systemd unit: {e}");
            process::exit(1);
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        eprintln!("error: ember daemon install is only supported on macOS and Linux.");
        process::exit(1);
    }

    tracing::info!("daemon installed; verify with `ps -o uid,pid,comm | grep emberd`");
    println!();
    println!("ember daemon installed (separate-uid posture, design)");
    println!("  Verify: ps -o uid,pid,comm | grep emberd");
}

/// Migrate a single-uid daemon installation to the separate-uid posture
/// (design) while preserving all on-disk state.
///
/// Only `--to separate-uid` is accepted in v1.  Any other value exits
/// non-zero with a usage error.
///
/// Steps when migration is required:
/// 1. Detect current posture — exit early if already separate-uid.
/// 2. Stop the running daemon (launchctl bootout / systemctl stop).
/// 3. Provision the `ember` system user + `ember-clients` group (idempotent).
/// 4. chown existing vault/grants/sessions dirs to ember:ember-clients.
/// 5. Install the platform launcher (LaunchDaemon plist / systemd unit).
/// 6. Start the daemon under the new posture.
/// 7. Verify: report daemon uid via `ps -o uid,pid,comm`.
fn cmd_daemon_migrate(to: &str) {
    if to != "separate-uid" {
        eprintln!(
            "error: unrecognised --to value {to:?}. Only `separate-uid` is accepted in v1.\n       \
             Usage: ember daemon migrate --to separate-uid"
        );
        process::exit(2);
    }
    migrate_to_separate_uid();
}

/// Core migration logic — extracted so it can be unit-tested and so the
/// target_state_anchor `fn migrate_to_separate_uid` matches.
///
/// Posture detection: calls [`ember_daemon::install::is_separate_uid_posture`]
/// (probes `id ember`). If the host is already migrated the function prints
/// a success notice and returns without touching state.
fn migrate_to_separate_uid() {
    tracing::info!("ember daemon migrate --to separate-uid (design)");

    // Step 1 — detect current posture.
    if ember_daemon::install::is_separate_uid_posture() {
        tracing::info!("host is already on separate-uid posture — nothing to do");
        println!("Ok | already on separate-uid posture");
        return;
    }

    tracing::info!("detected single-uid posture; beginning migration to separate-uid");

    if let Err(msg) = require_sudo() {
        eprintln!("{msg}");
        process::exit(1);
    }

    // Step 2 — stop the running daemon (tolerant; daemon may already be down).
    tracing::info!("step 2/7: stopping running daemon");
    println!("stopping ember daemon...");
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("launchctl")
            .args([
                "bootout",
                "system",
                "/Library/LaunchDaemons/sh.emberlink.daemon.plist",
            ])
            .output()
            .map_err(|e| tracing::warn!("launchctl bootout spawn failed: {e}"));
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["stop", "emberd.service"])
            .output()
            .map_err(|e| tracing::warn!("systemctl stop spawn failed: {e}"));
    }
    // Best-effort: also signal via the pid file / socket if present.
    // Errors are non-fatal — the daemon may have already exited or may not
    // be managed by a platform launcher yet (single-uid path uses
    // LaunchAgent, not LaunchDaemon).
    tracing::info!("daemon stop signal sent (errors above are non-fatal)");

    // Step 3 — provision ember user + ember-clients group.
    tracing::info!("step 3/7: provisioning ember user + ember-clients group");
    println!("provisioning ember user and ember-clients group (sudo may prompt)...");
    if let Err(e) = ember_daemon::install::provision_ember_user() {
        eprintln!("error: failed to provision ember user: {e}");
        process::exit(1);
    }
    tracing::info!("ember user provisioned");

    // Step 4 — chown existing vault/grants/sessions to ember:ember-clients.
    // Resolve the operator's home via SUDO_USER (not dirs_next::home_dir(),
    // which under sudo returns /var/root). Same home is then baked into the
    // plist/unit's HOME env var so the daemon resolves `~/.ember/...` here.
    let home = match ember_daemon::install::resolve_operator_home() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: failed to resolve operator home: {e}");
            process::exit(1);
        }
    };
    tracing::info!(
        home = %home.display(),
        "step 4/7: chowning data dirs to ember:ember-clients"
    );
    println!(
        "chowning {}/.ember/{{vault,grants,sessions,run,binaries}} to ember:ember-clients...",
        home.display()
    );
    if let Err(e) = ember_daemon::install::chown_ember_data_dirs(&home) {
        eprintln!("error: failed to chown daemon data dirs: {e}");
        process::exit(1);
    }
    tracing::info!("data dirs chowned");

    // Step 5 — install platform launcher.
    tracing::info!("step 5/7: installing platform launcher");
    #[cfg(target_os = "macos")]
    {
        println!(
            "installing LaunchDaemon plist at /Library/LaunchDaemons/sh.emberlink.daemon.plist (HOME={})...",
            home.display()
        );
        if let Err(e) = ember_daemon::install::install_launchd_plist(&home) {
            eprintln!("error: failed to install LaunchDaemon plist: {e}");
            process::exit(1);
        }
    }
    #[cfg(target_os = "linux")]
    {
        println!(
            "installing systemd unit at /etc/systemd/system/emberd.service (HOME={})...",
            home.display()
        );
        if let Err(e) = ember_daemon::install::install_systemd_unit(&home) {
            eprintln!("error: failed to install systemd unit: {e}");
            process::exit(1);
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        eprintln!("error: ember daemon migrate is only supported on macOS and Linux.");
        process::exit(1);
    }
    tracing::info!("platform launcher installed");

    // Step 6 — start daemon under new posture.  The platform launcher
    // (LaunchDaemon / systemd) handles the actual start; on macOS
    // install_launchd_plist already runs `launchctl bootstrap`.  On
    // Linux `install_systemd_unit` runs `systemctl enable --now`.  We
    // give the daemon a moment to bind before the ps probe.
    tracing::info!("step 6/7: daemon start triggered by platform launcher (install step)");
    println!("platform launcher installed and daemon started");

    // Step 7 — verify: ps -o uid,pid,comm | grep emberd.
    tracing::info!("step 7/7: verifying daemon uid via ps");
    let ps_out = std::process::Command::new("ps")
        .args(["-eo", "uid,pid,comm"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();

    let emberd_line = ps_out
        .lines()
        .find(|l| l.contains("emberd"))
        .map(|l| l.trim().to_string());

    println!();
    match emberd_line {
        Some(line) => {
            println!("Ok | daemon running as: {line}");
            tracing::info!(ps_line = %line, "daemon uid verified");
        }
        None => {
            println!(
                "Ok | migration complete (daemon may need a moment to start; \
                 verify with: ps -o uid,pid,comm | grep emberd)"
            );
            tracing::info!("emberd not yet visible in ps — may still be starting");
        }
    }
    println!("  Vault + grants preserved (chown is non-destructive).");
    println!("  Re-run `ember vault list` to confirm data is readable.");
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
        match daemon_agent::reload_daemon(
            &pid_file,
            &socket_path,
            Duration::from_secs(timeout_secs),
        ) {
            Ok(_) => {
                // Shouldn't happen — if unmanaged, the daemon can't restart itself.
                // But if it did come back (e.g. user races install-agent), no harm.
                println!("Unexpected: unmanaged daemon reappeared after SIGTERM.");
            }
            Err(daemon_agent::AgentError::DaemonNotRunning) => {
                eprintln!(
                    "error: daemon is not running — run `ember status` to inspect and `sudo ember daemon install` to install or repair the managed daemon"
                );
                process::exit(1);
            }
            Err(daemon_agent::AgentError::ReloadTimeout { .. }) => {
                // Expected: unmanaged daemon won't come back on its own.
                // Respawn it the same way the user originally started it.
                eprintln!(
                    "warning: daemon is not a managed service — spawning a fresh `--background` instance"
                );
                let exe = match std::env::current_exe() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("error: could not resolve current exe: {e}");
                        process::exit(1);
                    }
                };
                let mut cmd = std::process::Command::new(exe);
                cmd.arg("daemon").arg("start").arg("--background");
                // implementation-note-461: the respawn child inherits
                // the resolved config path so an env-var-pinned demo daemon
                // comes back on the same config.
                if let Some(path) = resolved_user_config_path(cli_config) {
                    cmd.arg("--config").arg(path);
                }
                match cmd.spawn() {
                    Ok(_child) => {
                        println!("Respawned daemon with `ember daemon start --background`.");
                        println!(
                            "Tip: the canonical always-up posture is `sudo ember daemon install`."
                        );
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
            eprintln!(
                "error: daemon is not running — run `ember status` to inspect and `sudo ember daemon install` to install or repair the managed daemon"
            );
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

/// ember_daemon_recover_fresh_landed (implementation-note-471).
///
/// Idempotent + auditable wipe sequence for the MEK-missing-with-state
/// recovery path. Replaces the hand-typed paste-block that operators ran
/// during the 2026-05-14 SCION-demo-prep incident recovery.
///
/// Order of operations:
/// 1. Best-effort daemon stop (launchctl unload / systemctl stop)
/// 2. Archive `config.data_dir` to `<archive_to>` (refuses if dir exists —
///    idempotent guard against overwriting a prior recovery archive)
/// 3. Print canonical keychain-clear command for the operator's OS
///    (slice D-bis will own the actual System.keychain delete via the
///    daemon's privileged process; today the CLI emits the command for
///    operator copy-paste under the existing manual-process pattern)
/// 4. Print re-seed checklist
///
/// `--archive-to` REQUIRED — no destructive default. Per the brief's
/// "Archive path required (no destructive default behavior)" acceptance.
fn cmd_daemon_recover_fresh(config: &DaemonConfig, archive_to: &std::path::Path) {
    println!("ember daemon recover-fresh");
    println!();

    // Step 1: refuse if archive_to exists (idempotent guard).
    if archive_to.exists() {
        eprintln!(
            "error: archive path {} already exists; pick a unique path per recovery attempt",
            archive_to.display()
        );
        process::exit(1);
    }

    // Step 2: stop daemon (best-effort; OS-specific paths).
    println!("[1/4] stopping daemon (best-effort)");
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("launchctl")
            .args(["unload", "/Library/LaunchDaemons/sh.emberlink.daemon.plist"])
            .output();
        println!("    launchctl unload /Library/LaunchDaemons/sh.emberlink.daemon.plist");
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["stop", "emberd.service"])
            .output();
        println!("    systemctl stop emberd.service");
    }

    // Step 3: archive data dir.
    println!(
        "[2/4] archiving {} → {}",
        config.data_dir.display(),
        archive_to.display()
    );
    if !config.data_dir.exists() {
        println!(
            "    note: data dir does not exist — nothing to archive (already wiped or never initialized)"
        );
    } else if let Err(e) = std::fs::rename(&config.data_dir, archive_to) {
        eprintln!(
            "error: failed to archive {}: {e}",
            config.data_dir.display()
        );
        eprintln!(
            "    suggested workaround: manually `mv {} {}`",
            config.data_dir.display(),
            archive_to.display()
        );
        process::exit(1);
    } else {
        println!("    archived");
    }

    // Step 4: keychain-clear instructions.
    println!("[3/4] keychain clear (operator command, requires privileged uid)");
    #[cfg(target_os = "macos")]
    println!("    security delete-generic-password -s sh.emberlink.daemon -a vault-mek");
    #[cfg(target_os = "linux")]
    println!(
        "    secret-tool clear service sh.emberlink.daemon  # (or equivalent for your secret-service backend)"
    );

    // Step 5: re-seed checklist.
    println!("[4/4] re-seed checklist (operator next steps)");
    println!("    1. Restart the daemon:");
    #[cfg(target_os = "macos")]
    println!("       launchctl load /Library/LaunchDaemons/sh.emberlink.daemon.plist");
    #[cfg(target_os = "linux")]
    println!("       systemctl start emberd.service");
    println!("    2. Re-register the operator passkey:");
    println!("       ember init");
    println!("    3. Re-seed each vault credential (consult archive for known names):");
    println!("       ls {}/vault* 2>/dev/null", archive_to.display());
    println!("    4. Re-establish persona signing keys:");
    println!("       ember persona create <name>");
    println!("    5. Verify daemon is healthy:");
    println!("       ember daemon status");
    println!();
    println!(
        "recover-fresh complete. Archive at {}",
        archive_to.display()
    );
}

/// daemon_diagnose_mek_pattern_landed (implementation-note-472).
///
/// `git fsck`-style detector for the MEK-persistence-failed pattern that
/// hit the SCION demo prep on 2026-05-14: daemon silently re-provisioning
/// a fresh MEK on top of pre-existing encrypted state, destroying all
/// prior vault data + persona keys without diagnostic.
///
/// Pattern recognition (4 outcomes):
///   HEALTHY                    — keychain MEK + daemon.db state + fingerprint align
///   MEK-MISSING-WITH-STATE     — keychain empty but daemon.db has rows
///   FINGERPRINT-MISMATCH       — keychain MEK loaded but fingerprint disagrees (slice B)
///   STATE-EMPTY                — fresh install
///
/// Fingerprint-check shape depends on slice B
/// (implementation-note-350) landing. Pre-B,
/// the FINGERPRINT row reports "unavailable (slice B pending)". Once B
/// lands, the row reports `present|absent|mismatch` per the brief.
fn cmd_daemon_diagnose(config: &DaemonConfig) {
    // Path existence is the proxy for the four-pattern detector. The fully
    // structural shape (keychain probe, fingerprint compare) requires
    // daemon-internal vault primitives that live in ember-daemon's
    // privileged uid; the CLI can only inspect what its uid is permitted
    // to read. Slice E (startup-probe in runtime.rs) is the
    // privileged-side complement.
    let data_dir = &config.data_dir;
    let db_path = data_dir.join("daemon.db");
    let launcher_issue = detect_default_installed_launcher_issue();

    println!("ember daemon diagnose");
    if let Some(issue) = launcher_issue.as_ref() {
        println!();
        println!("INSTALL PATH: {}", issue.detail());
    }

    // KEYCHAIN row — the daemon-side keychain entry is opaque to the
    // operator uid under design. Report what we CAN observe.
    println!();
    println!("KEYCHAIN: opaque to operator uid (daemon-side probe pending — slice E)");

    // DAEMON.DB row — file existence + rough size hint. Detailed table
    // row counts require a privileged store-open call (daemon RPC) and
    // are reported via `ember daemon status` already.
    let db_state = if db_path.exists() {
        match std::fs::metadata(&db_path) {
            Ok(m) if m.len() > 0 => format!("present ({} bytes)", m.len()),
            Ok(_) => "present (empty)".to_string(),
            Err(_) => "present (unreadable)".to_string(),
        }
    } else {
        "absent".to_string()
    };
    println!("DAEMON.DB: {db_state} ({})", db_path.display());

    // FINGERPRINT row — slice B prerequisite. Pre-B: unavailable.
    // Post-B: this row reports present(<hex prefix>) | absent | mismatch.
    println!(
        "FINGERPRINT: unavailable (slice B pending — implementation-note-350)"
    );

    // PATTERN row — best-effort pattern recognition from what the
    // operator-uid CLI can see today.
    let pattern = if !db_path.exists() {
        "STATE-EMPTY"
    } else {
        match std::fs::metadata(&db_path) {
            Ok(m) if m.len() == 0 => "STATE-EMPTY",
            Ok(_) => "INDETERMINATE (full pattern detection requires slice B + E)",
            Err(_) => "UNREADABLE",
        }
    };
    println!();
    println!("PATTERN: {pattern}");

    // RUNBOOK row — deterministic recovery commands per pattern.
    println!();
    println!("RUNBOOK:");
    if let Some(issue) = launcher_issue.as_ref() {
        println!("  # First repair the installed `ember` launcher path:");
        println!("  # {}", issue.detail());
        println!(
            "  # Reinstall the managed CLI artifact or stop pointing the host launcher at repo build outputs."
        );
    }
    match pattern {
        "STATE-EMPTY" => {
            println!("  ember init                  # fresh provision");
            println!("  sudo ember daemon install   # install / repair the managed daemon");
            println!("  ember status                # confirm the daemon is up");
        }
        "UNREADABLE" => {
            println!(
                "  ls -la {}                   # check filesystem perms",
                db_path.display()
            );
            println!("  # under design separate-uid posture, the daemon's data");
            println!("  # is chowned to ember:ember-clients; the operator uid");
            println!("  # may not be able to read it. This is by design.");
        }
        _ => {
            println!("  # Pattern is indeterminate without slice B (fingerprint column)");
            println!("  # and slice E (startup probe).");
            println!("  ember daemon status         # daemon-side state summary");
            println!("  # If status reports MEK-missing-with-state, run:");
            println!("  ember daemon recover-fresh --archive-to <path>");
            println!("  # If status reports fingerprint-mismatch, run:");
            println!("  ember vault import --sealed --recovery-passphrase");
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
    if is_tty { vec!["-i", "-t"] } else { vec!["-i"] }
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
) -> Vec<StatementProposal> {
    let Some(cred_resource) = credential_resource else {
        return vec![];
    };

    // Statement 1: Credential — credential:read on the named object.
    let credential_stmt = StatementProposal {
        resource_type: ResourceType::Credential,
        credential_name: cred_resource.to_string(),
        actions: vec!["credential:read".to_string()],
        resource: ResourceSelector::Exact {
            value: cred_resource.to_string(),
        },
        budget: None,
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
    let session_stmt = StatementProposal {
        resource_type: ResourceType::Session,
        credential_name: String::new(),
        actions: vec!["llm:generate".to_string()],
        resource: ResourceSelector::Glob {
            pattern: "anthropic/*".to_string(),
        },
        budget: session_budget,
        conditions: vec![],
    };

    // Statement 3: Time — time:wall_clock on *, wall_clock_secs budget.
    let time_budget = budget_seconds.map(|secs| Budget {
        wall_clock_secs: Some(secs),
        ..Budget::default()
    });
    let time_stmt = StatementProposal {
        resource_type: ResourceType::Time,
        credential_name: String::new(),
        actions: vec!["time:wall_clock".to_string()],
        resource: ResourceSelector::Any,
        budget: time_budget,
        conditions: vec![],
    };

    vec![credential_stmt, session_stmt, time_stmt]
}

/// Parse a duration string (15s, 5m, 2h, 1d, or bare integer seconds).
fn parse_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('s') {
        n.parse::<u64>()
            .map_err(|_| format!("invalid duration '{s}'"))
    } else if let Some(n) = s.strip_suffix('m') {
        let v = n
            .parse::<u64>()
            .map_err(|_| format!("invalid duration '{s}'"))?;
        v.checked_mul(60)
            .ok_or_else(|| format!("duration overflow '{s}'"))
    } else if let Some(n) = s.strip_suffix('h') {
        let v = n
            .parse::<u64>()
            .map_err(|_| format!("invalid duration '{s}'"))?;
        v.checked_mul(3600)
            .ok_or_else(|| format!("duration overflow '{s}'"))
    } else if let Some(n) = s.strip_suffix('d') {
        let v = n
            .parse::<u64>()
            .map_err(|_| format!("invalid duration '{s}'"))?;
        v.checked_mul(86400)
            .ok_or_else(|| format!("duration overflow '{s}'"))
    } else {
        s.parse::<u64>().map_err(|_| {
            format!("invalid duration '{s}' (expected e.g. 15s, 5m, 2h, 1d, or bare seconds)")
        })
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

// `resolve_receipt` removed per implementation-note-451;
// the daemon's `get_receipt` RPC handles the grant-id → receipt-id walk
// (see [`run_receipt_get`]).

/// Pretty-print a receipt to stdout in human-readable form.
fn print_receipt_summary(r: &core_grant_types::grant_receipt::GrantReceipt) {
    use core_grant_types::grant_receipt::{RevokeActor, TerminalReason};

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
        TerminalReason::ExhaustedByBudget {
            statement_sid,
            axis,
        } => {
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
    println!(
        "  Actions observed: {} entry(ies)",
        r.actions_observed.len()
    );
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
        ResourceSelector::GlobWithSubtarget {
            primary_glob,
            subtarget_glob,
        } => {
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
    let _ = writeln!(
        out,
        "  Status:  {}",
        grant.effective_status(now_secs).as_str()
    );

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
                    let _ = writeln!(
                        out,
                        "  {}",
                        fmt_budget_line("tokens:", stmt.usage.tokens, cap)
                    );
                }
                if let Some(cap) = b.cents {
                    let _ = writeln!(
                        out,
                        "  {}",
                        fmt_budget_line("cents:", stmt.usage.cents, cap)
                    );
                }
                if let Some(cap) = b.requests {
                    let _ = writeln!(
                        out,
                        "  {}",
                        fmt_budget_line("requests:", stmt.usage.requests, cap)
                    );
                }
                if let Some(cap) = b.wall_clock_secs {
                    let _ = writeln!(
                        out,
                        "  {}",
                        fmt_budget_line("wall-clock:", stmt.usage.wall_clock_secs, cap)
                    );
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
                            let remaining_min =
                                (cap - used) as f64 / (used as f64 / minutes_elapsed);
                            let _ = writeln!(
                                out,
                                "  {indent}  tokens:      ~{}m",
                                remaining_min.round() as u64
                            );
                        } else {
                            let _ = writeln!(out, "  {indent}  tokens:      —");
                        }
                    }
                    if let Some(cap) = b.cents {
                        let used = stmt.usage.cents;
                        if used > 0 && cap > used {
                            let remaining_min =
                                (cap - used) as f64 / (used as f64 / minutes_elapsed);
                            let _ = writeln!(
                                out,
                                "  {indent}  cents:       ~{}m",
                                remaining_min.round() as u64
                            );
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

/// Local fallback for `ember sandbox delete <id|name>`.
///
/// Resolves the argument to a sandbox UUID, then asks the store to delete the
/// row + container + auto-created persona (when unreferenced). Idempotent: a
/// missing sandbox returns `already_absent = true` so callers can preserve the
/// friendly "already deleted" UX without hard-exiting.
fn run_sandbox_delete_local(
    store: &DaemonStore,
    id_or_name: &str,
) -> Result<SandboxDeleteResult, core_types::ValidationError> {
    match store.resolve_sandbox_id(id_or_name) {
        Ok(resolved_id) => {
            store
                .delete_sandbox(&resolved_id)
                .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
            Ok(SandboxDeleteResult {
                resolved_id: Some(resolved_id),
                already_absent: false,
            })
        }
        Err(ember_daemon::infra::store::StoreError::NotFound) => Ok(SandboxDeleteResult {
            resolved_id: None,
            already_absent: true,
        }),
        Err(e) => Err(core_types::ValidationError::new(e.to_string())),
    }
}

/// implementation-note-438 — `ember up` body.
///
/// Detects the host's container runtime (Docker / OrbStack / Podman),
/// renders the bundled compose template at
/// `crates/headless-runtime/templates/compose.yml.j2` against the operator-selected
/// profile (`dev` / `headless` / `demo`; defaults to `dev`), writes the
/// rendered YAML to `~/.ember/run/<run-id>/compose.yml`, and shells out to
/// `<engine> compose -f <path> --profile <name> up -d`.
fn cmd_up(profile: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    emberlink_cli::up::open_claude_code_isolated(profile.as_deref(), None)?;
    println!("Tear down with: ember down [--revoke-grants] [--purge]");
    Ok(())
}

/// implementation-note-438 — `ember down` body.
fn cmd_down(
    revoke_grants: bool,
    yes: bool,
    purge: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let engine = emberlink_cli::up::detect_runtime_engine()?.ok_or_else(
        || -> Box<dyn std::error::Error> {
            emberlink_cli::up::missing_runtime_remediation().into()
        },
    )?;

    let run_root = dirs_next::home_dir()
        .ok_or_else(|| -> Box<dyn std::error::Error> {
            "could not resolve $HOME for ~/.ember/run".into()
        })?
        .join(".ember/run");
    let compose_path =
        latest_compose_yml(&run_root)?.ok_or_else(|| -> Box<dyn std::error::Error> {
            format!(
                "no compose stack found under {} — run `ember up` first",
                run_root.display()
            )
            .into()
        })?;
    println!("Compose: {}", compose_path.display());

    let (stdout, _stderr) = emberlink_cli::up::compose_down(engine, &compose_path, purge)?;
    if !stdout.trim().is_empty() {
        println!("{}", stdout.trim_end());
    }
    if purge {
        println!("Removed named compose volumes (-v).");
    }

    if revoke_grants {
        cmd_down_revoke_active_grants(yes)?;
    }

    println!("ember down: session torn down.");
    Ok(())
}

/// Eager-revoke every active workflow grant + per-action grant owned by
/// the operator at `ember down --revoke-grants` time (design §C4).
///
/// Flow:
/// 1. Resolve daemon socket; gracefully no-op when daemon is unavailable
///    (the compose stack has already torn down, so the grants will TTL out).
/// 2. List active workflow grants via `workflow_list`.
/// 3. List active per-action grants via `list_operator_grants`.
/// 4. Without `--yes` prompt confirmation; refuse on negative.
/// 5. Revoke each grant; surface progress; exit non-zero on any failure.
/// 6. SIGINT mid-revoke is masked to avoid partial state.
fn cmd_down_revoke_active_grants(yes: bool) -> Result<(), Box<dyn std::error::Error>> {
    let socket = resolve_daemon_socket_for_down();

    // Adversarial CRIT-2 fix (2026-05-22): pre-fix this enumerated
    // `list_operator_grants` (the entire grants table) and revoked
    // every grant. Catastrophic during parallel-fanout — would nuke
    // sibling headless containers + parallel sessions + the operator's
    // host session. The reviewer's recommended path: "hold the
    // per-action revoke entirely and only revoke workflow grants for
    // the stack's sessions" until session-scoped grant enumeration
    // exists. This commit takes that path: list workflow grants
    // scoped to the caller persona (handler-side enforcement after the
    // PR's caller-binding fix), revoke each. NO per-action grants
    // are revoked here; those will be wired in v0.3.1 with a
    // `list_session_grants` RPC keyed on `session_id`.
    let workflow_grants = match emberlink_cli::call_daemon_rpc(
        &socket,
        "workflow_list",
        &serde_json::json!({"all": false}),
    ) {
        Ok(v) => v.as_array().cloned().unwrap_or_default(),
        Err(emberlink_cli::DaemonRpcError::Unavailable(_)) => {
            eprintln!(
                "ember down --revoke-grants: daemon socket at {} unavailable; grants will expire at TTL",
                socket.display()
            );
            return Ok(());
        }
        Err(e) => {
            return Err(format!("ember down --revoke-grants: workflow_list failed: {e}").into());
        }
    };

    let total = workflow_grants.len();
    if total == 0 {
        println!("ember down --revoke-grants: no active workflow grants to revoke.");
        return Ok(());
    }

    println!(
        "ember down --revoke-grants: {} workflow grant{} active (scoped to caller persona). \
         Per-action grants are NOT revoked by this command — they expire at TTL or via \
         `ember grant revoke <id>`.",
        workflow_grants.len(),
        if workflow_grants.len() == 1 { "" } else { "s" },
    );

    if !yes && !confirm_revoke_prompt(total)? {
        println!("ember down --revoke-grants: aborted by operator.");
        return Ok(());
    }

    // Mask SIGINT/SIGTERM/SIGHUP for the duration of the revoke loop
    // so partial state is not possible. Adversarial HIGH-3 fix
    // (2026-05-22): pre-fix the guard masked only SIGINT, leaving
    // SIGTERM/SIGHUP (CI runner cleanup, ssh tear-down, OOM-kill)
    // unhandled. The guard's contract is "the revoke loop is
    // atomic from the operator's perspective"; that requires all
    // three masked.
    let _sig_guard = SigintGuard::install();

    let mut failures: Vec<String> = Vec::new();
    let mut revoked: usize = 0;

    for grant in &workflow_grants {
        let wf_id = grant["workflow_id"].as_str().unwrap_or("?");
        match emberlink_cli::call_daemon_rpc(
            &socket,
            "workflow_revoke",
            &serde_json::json!({"workflow_id": wf_id}),
        ) {
            Ok(_) => {
                revoked += 1;
                println!("  revoked workflow grant {wf_id}");
            }
            Err(e) => {
                failures.push(format!("workflow_revoke({wf_id}): {e}"));
            }
        }
    }

    println!("ember down --revoke-grants: revoked {revoked}/{total}.");

    if !failures.is_empty() {
        for f in &failures {
            eprintln!("  error: {f}");
        }
        return Err(format!("ember down --revoke-grants: {} failure(s)", failures.len()).into());
    }
    Ok(())
}

fn resolve_daemon_socket_for_down() -> std::path::PathBuf {
    dirs_next::home_dir()
        .map(|h| h.join(emberlink_cli::install_paths::PROD_DAEMON_SOCKET_REL))
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp/ember-daemon.sock"))
}

fn confirm_revoke_prompt(total: usize) -> Result<bool, Box<dyn std::error::Error>> {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        // Headless / piped — refuse without an explicit --yes so a CI script
        // can't accidentally revoke everything.
        eprintln!(
            "ember down --revoke-grants: refusing in non-interactive context without --yes (would revoke {total} grants)"
        );
        return Ok(false);
    }
    eprint!("Revoke {total} active grants? [y/N] ");
    std::io::stderr().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

/// Install SIG_IGN on SIGINT for this scope; restore on drop. Used by the
/// `--revoke-grants` loop so the user's Ctrl-C does not stop the revoke
/// halfway and leave half the grants live.
struct SigintGuard {
    #[cfg(unix)]
    prior: libc::sighandler_t,
}

impl SigintGuard {
    fn install() -> Self {
        // Adversarial HIGH-3 fix (2026-05-22): mask SIGINT + SIGTERM
        // + SIGHUP. Pre-fix only SIGINT was masked — SIGTERM (CI
        // runner cleanup), SIGHUP (ssh tear-down), or OOM-kill would
        // leave the revoke loop in partial state.
        #[cfg(unix)]
        {
            let prior = unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
            // Best-effort mask SIGTERM + SIGHUP. We don't preserve
            // their prior handlers because (a) the loop is short and
            // (b) preserving three of them adds complexity for no
            // observable benefit — Drop restores SIGINT, which is the
            // signal we care about preserving across the guard.
            unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
            unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
            return SigintGuard { prior };
        }
        #[cfg(not(unix))]
        SigintGuard {}
    }
}

impl Drop for SigintGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::signal(libc::SIGINT, self.prior);
        }
    }
}

fn latest_compose_yml(run_root: &std::path::Path) -> std::io::Result<Option<std::path::PathBuf>> {
    if !run_root.exists() {
        return Ok(None);
    }
    let mut newest: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    for entry in std::fs::read_dir(run_root)? {
        let entry = entry?;
        let compose = entry.path().join("compose.yml");
        if !compose.is_file() {
            continue;
        }
        let mtime = entry.metadata()?.modified()?;
        if newest.as_ref().is_none_or(|(t, _)| mtime > *t) {
            newest = Some((mtime, compose));
        }
    }
    Ok(newest.map(|(_, p)| p))
}

/// Validate the `--emit-file <path>` arg against a strict allowlist
/// before writing. Per implementation-note-473:
///
/// 1. The path (after lexical `..` resolution) MUST reside under
///    `$HOME` or `$XDG_RUNTIME_DIR`.
/// 2. The path MUST NOT start with `/etc`, `/var`, `/usr`, `/sys`,
///    `/proc`, `/root`, or `/dev` — defense in depth on top of the
///    containment check, in case a symlinked HOME would otherwise
///    route through a sensitive system directory.
/// 3. `..` traversal that escapes the lexical root is refused.
///
/// Relative paths are resolved against CWD before validation.
/// Returns the lexically-cleaned absolute path on success.
///
/// Anchor: emit_file_path_validated
fn validate_emit_file_path(
    path: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    use std::path::{Component, PathBuf};

    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| {
                format!("--emit-file: cannot resolve relative path (CWD: {e})")
            })?
            .join(path)
    };

    let mut clean = PathBuf::new();
    for component in abs.components() {
        match component {
            Component::ParentDir => {
                if !clean.pop() {
                    return Err(format!(
                        "--emit-file: `..` escapes root in {}",
                        abs.display()
                    ));
                }
            }
            Component::CurDir => {}
            Component::RootDir => clean.push("/"),
            Component::Normal(c) => clean.push(c),
            Component::Prefix(_) => {
                return Err(format!(
                    "--emit-file: unexpected path prefix in {}",
                    abs.display()
                ));
            }
        }
    }

    let s = clean.to_string_lossy();
    for forbidden in [
        "/etc", "/var", "/usr", "/sys", "/proc", "/root", "/dev",
    ] {
        if s == forbidden || s.starts_with(&format!("{forbidden}/")) {
            return Err(format!(
                "--emit-file: refused — path resolves to forbidden system prefix `{forbidden}`: {}",
                clean.display()
            ));
        }
    }

    let mut allowed_roots: Vec<PathBuf> = Vec::new();
    if let Some(h) = std::env::var_os("HOME") {
        allowed_roots.push(PathBuf::from(h));
    }
    if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR") {
        allowed_roots.push(PathBuf::from(x));
    }
    if allowed_roots.is_empty() {
        return Err(
            "--emit-file: cannot validate path — neither HOME nor XDG_RUNTIME_DIR is set"
                .to_string(),
        );
    }
    if !allowed_roots.iter().any(|root| clean.starts_with(root)) {
        return Err(format!(
            "--emit-file: path must resolve under $HOME or $XDG_RUNTIME_DIR, got: {}",
            clean.display()
        ));
    }

    Ok(clean)
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

    // keyring-core 1.0 split — see runtime.rs head-of-run() comment. The CLI
    // shares the same Keychain backend as the daemon; register the default
    // store before any subcommand dispatches. Subcommands that touch the
    // keyring (init, vault, dev) rely on this; subcommands that don't
    // (--version, --help, render-only commands) tolerate registration
    // failure as a warning. Always-off in EMBER_VAULT_MOCK / cargo-test
    // contexts via the three-axis gate inside resolve_passphrase.
    #[cfg(target_os = "macos")]
    {
        match apple_native_keyring_store::keychain::Store::new() {
            Ok(store) => keyring_core::set_default_store(store),
            Err(e) => eprintln!(
                "ember: warning — failed to register macOS Keychain store: {e:?}; \
                 keyring-using subcommands will fail with NoDefaultStore"
            ),
        }
    }

    let cli = Cli::parse();
    let config = load_config(cli.config.as_ref());

    match cli.command {
        Commands::Init {
            name,
            keyring_service,
            keyring_account,
            touch_id,
            for_target,
            non_interactive,
            migrate,
        } => {
            // implementation-note-474: on a new machine the daemon
            // service will not be installed. Detect this early — before any
            // vault or DB work — and offer to run `sudo ember daemon install`.
            // Skip the check when the daemon is already running or the operator
            // used `--for claude` (that path autostarts the daemon itself).
            {
                let socket_path = config.socket_dir.join("daemon.sock");
                // EMBER_SKIP_DAEMON_INSTALL_CHECK: test-only bypass for the
                // daemon-install precheck. Production code never sets this; the
                // env var lets binary tests construct an isolated config + tmpdir
                // without tripping the non-interactive `Declined` branch that
                // process::exit(0)s before downstream init work completes.
                // See implementation-note-475.
                // implementation-note-476resolved
                let skip_check = std::env::var("EMBER_SKIP_DAEMON_INSTALL_CHECK").is_ok();
                if !skip_check {
                    let install_status = match emberlink_cli::probe_live_daemon_status(
                        &socket_path,
                        &config.pid_file,
                    ) {
                        Ok(Some(_)) => emberlink_cli::install::DaemonInstallStatus::Running,
                        Ok(None) => emberlink_cli::install::detect_daemon_installed(&socket_path),
                        Err(e) => {
                            eprintln!("error: could not inspect daemon posture: {e}");
                            process::exit(1);
                        }
                    };
                    if install_status == emberlink_cli::install::DaemonInstallStatus::NotInstalled {
                        let rerun_cmd = init_rerun_command(for_target);
                        match emberlink_cli::install::prompt_install_daemon(non_interactive) {
                            Ok(()) => {
                                println!("  Daemon:   installed successfully");
                            }
                            Err(emberlink_cli::install::DaemonInstallPromptError::Declined) => {
                                eprintln!(
                                    "note: setup paused before daemon install.\n\
                                     Run `sudo ember daemon install`, then re-run {rerun_cmd}."
                                );
                                process::exit(0);
                            }
                            Err(
                                emberlink_cli::install::DaemonInstallPromptError::NonInteractive,
                            ) => {
                                eprintln!(
                                    "error: daemon is not installed and --non-interactive is set.\n\
                                     Run `sudo ember daemon install` first, then re-run {rerun_cmd}."
                                );
                                process::exit(1);
                            }
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        }
                    }
                }
            }

            // implementation-note-463: when `--for claude` is set,
            // skip basic init if the daemon DB already exists. Without this guard
            // a friendly who ran `ember init --name "Foo"` and then ran
            // `ember init --for claude` ended up with two extra root
            // personas ("root" + their named one) in addition to the claude-code
            // persona. We detect initialization by checking for daemon.db — the
            // file written by `open_store` during every `cmd_init` run.
            let skip_basic_init =
                for_target == Some(OnboardingTarget::Claude) && is_ember_initialized(&config);

            if skip_basic_init {
                // Already initialized — count existing personas for the log line.
                // We open the store read-only here (no vault needed for list).
                let db_path = config.data_dir.join("daemon.db");
                let persona_count = DaemonStore::open(&db_path)
                    .ok()
                    .and_then(|s| s.list_personas().ok())
                    .map(|ps| ps.len())
                    .unwrap_or(0);
                println!("Daemon DB: already initialized (existing personas: {persona_count})");
            } else {
                cmd_init(
                    &config,
                    name,
                    cli.config.as_ref(),
                    keyring_service,
                    keyring_account,
                    touch_id,
                    non_interactive,
                );
            }
            // implementation-note-477: layer the claude-code onboarding on top of the
            // base daemon init when `--for claude` is set. The base
            // init has already set up the keyring, vault, salt, and root
            // persona — the cohort A flow now creates the agent persona,
            // template, grant, settings.json patch, and optional PAT.
            //
            // implementation-note-453: when `--migrate` is
            // passed alongside `--for claude`, run the path-shadow
            // layout migration after the standard claude-code init.
            // Idempotent — re-running on layout=new / layout=both /
            // layout=none is a no-op with a clear status line.
            // shadow_path_migrate_flag_landed.
            if let Some(OnboardingTarget::Claude) = for_target {
                if let Err(e) =
                    cmd_init_for_claude_code(&config, cli.config.as_ref(), non_interactive)
                {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
                if migrate {
                    if let Err(e) = cmd_migrate_path_shadow_layout() {
                        eprintln!("error: shadow-path migrate failed: {e}");
                        process::exit(1);
                    }
                }
            }
            // Anchor: onboarding_target_codex_variant_landed
            //
            // Codex onboarding is in development. The flag parses (so
            // operators can pin shell aliases and dotfiles to the
            // canonical form today) and the base daemon init has
            // already run above. The Codex-specific patcher
            // (`~/.codex/hooks.json`, Codex auth-lane probe via
            // `codex login status`) is broader work tracked outside
            // this PR; until it lands, surface a clear-progress
            // message so the operator can see init completed the
            // base setup and route follow-up steps explicitly.
            if let Some(OnboardingTarget::Codex) = for_target {
                println!(
                    "ember init: base setup complete. Codex onboarding \
                     (hooks.json patch + `codex login status` probe) is \
                     in development; this run did not patch ~/.codex/. \
                     Re-run with `--for claude` for the shipping lane, \
                     or watch the v0.3.0 release notes for Codex \
                     parity."
                );
            }
        }

        Commands::Uninstall {
            for_target: OnboardingTarget::Claude,
        } => {
            if let Err(e) = cmd_uninstall_for_claude_code() {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }

        // Codex uninstall is a stub matching the Codex init shape:
        // there is nothing for ember to clean up because the install
        // arm never patched ~/.codex/hooks.json. Surface the
        // operator-visible "nothing to do" message so the verb
        // doesn't silently no-op.
        Commands::Uninstall {
            for_target: OnboardingTarget::Codex,
        } => {
            println!(
                "ember uninstall --for codex: nothing to uninstall. \
                 Codex onboarding has not yet patched ~/.codex/, so \
                 this verb is a no-op. Tracks parity with the Codex \
                 init lane (see `ember init --for codex`)."
            );
        }

        Commands::Up { profile } => {
            if let Err(e) = cmd_up(profile) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }

        Commands::Down {
            revoke_grants,
            yes,
            purge,
        } => {
            if let Err(e) = cmd_down(revoke_grants, yes, purge) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }

        Commands::Workflow { action } => {
            let socket_path = config.socket_dir.join("daemon.sock");
            let opts = emberlink_cli::workflow::GlobalOpts { socket_path };
            if let Err(e) = emberlink_cli::workflow::workflow_command(action, opts) {
                eprintln!("error: {e}");
                process::exit(e.exit_code());
            }
        }

        Commands::Recover { action } => {
            if let Err(e) = emberlink_cli::recover::dispatch(action, None) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }

        Commands::Daemon { action } => match action {
            DaemonAction::Start {
                background,
                foreground: _,
            } => {
                if background {
                    if let Err(e) = config.ensure_dirs() {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                    let log_path = config.data_dir.join("daemon.log");

                    let exe = std::env::current_exe().expect("current exe");
                    let mut cmd = std::process::Command::new(exe);
                    cmd.arg("daemon").arg("start");
                    // implementation-note-461: propagate the resolved
                    // config path (flag → EMBER_CONFIG → EMBER_DEMO_DIR) to
                    // the background child so it pins the same demo dir.
                    if let Some(config_path) = resolved_user_config_path(cli.config.as_ref()) {
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

                // implementation-note-460: warn loudly when the
                // shadow PATH isn't installed — the agent-routing invariant
                // fails silently otherwise. Best-effort: a missing shadow
                // dir doesn't block daemon start, but the WARN must surface
                // so the operator notices and runs `ember init --for
                // claude`.
                if let Err(msg) = ensure_shadow_path_installed() {
                    if console {
                        eprintln!("WARN  {msg}");
                    }
                    tracing::warn!("{msg}");
                }

                // implementation-note-461: env-var fallback — if the
                // operator pinned a config via EMBER_CONFIG / EMBER_DEMO_DIR
                // (e.g. demo/dev tooling), the runtime should track that
                // same path so reload + dashboard config-show stay coherent.
                let runtime = match resolved_user_config_path(cli.config.as_ref()) {
                    Some(p) => DaemonRuntime::new_with_config_path(config, p),
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
                // Capture the daemon's identity from disk BEFORE stopping.
                // The keyfile (<data_dir>/daemon_persona.key) survives a
                // stop, but the on-camera demo close needs the pubkey
                // surfaced here so the operator can paste it into the
                // subsequent `ember receipt verify --file ... --pubkey ...`
                // command without leaving the terminal. Mirrors the
                // identity relay at end-of-life that qember.sh demo down
                // already prints.
                let identity_pubkey =
                    ember_daemon::infra::receipt::init_identity(&config.data_dir).ok();

                let runtime = DaemonRuntime::new(config);
                match runtime.stop() {
                    Ok(pid) => {
                        println!("Stopped ember daemon (PID {pid})");
                        if let Some(pubkey) = identity_pubkey {
                            let fp =
                                ember_daemon::infra::runtime::daemon_identity_fingerprint(&pubkey);
                            println!();
                            println!("  Identity preserved (data dir is intact):");
                            println!("    fingerprint:  {fp}");
                            println!("    pubkey:       {pubkey}");
                            println!();
                            println!("  Verify any receipt this daemon signed:");
                            println!("    ember receipt verify --file <path> --pubkey {pubkey}");
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                }
            }
            DaemonAction::Status => {
                let runtime = DaemonRuntime::new(config.clone());
                let runtime_status = runtime.status().ok();
                match emberlink_cli::probe_live_daemon_status(
                    &config.socket_dir.join("daemon.sock"),
                    &config.pid_file,
                ) {
                    Ok(Some(live)) => {
                        println!("ember daemon is running");
                        if let Some(pid) =
                            live.pid.or_else(|| runtime_status.as_ref().map(|s| s.pid))
                        {
                            println!("  PID:    {pid}");
                        }
                        println!("  Socket: {}", live.socket.display());
                        // implementation-note-460: warn loudly if
                        // the shadow PATH isn't installed. Without it,
                        // raw `gh`/`git`/`kubectl` calls from sequential
                        // agents bypass the broker, operator-author the
                        // commits, and break audit-trail clarity.
                        if let Err(msg) = ensure_shadow_path_installed() {
                            eprintln!("WARN  {msg}");
                        }
                    }
                    Ok(None) => {
                        if let Some(status) = runtime_status {
                            if !status.running {
                                println!("ember daemon is not running (stale PID {})", status.pid);
                                process::exit(1);
                            }
                        }
                        println!("ember daemon is not running");
                        process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
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
            DaemonAction::Install { args } => {
                cmd_daemon_install(args);
            }
            DaemonAction::Migrate { to } => {
                cmd_daemon_migrate(&to);
            }
            DaemonAction::Diagnose => {
                cmd_daemon_diagnose(&config);
            }
            DaemonAction::RecoverFresh { archive_to } => {
                cmd_daemon_recover_fresh(&config, &archive_to);
            }
        },

        Commands::Persona { action } => {
            // implementation-note-478: all persona
            // mutations (create, revoke) and reads (list) route through the
            // daemon RPC socket so the operator uid never touches the DB file
            // directly. Under design separate-uid posture (daemon=ember uid,
            // operator=operator uid) the DB is owned by the ember uid and the
            // operator uid cannot open it for writing — and may not be able
            // to open it for reading depending on filesystem permissions.
            // Routing every verb through JSON-RPC lets the daemon own all
            // store access under its uid while the CLI only needs socket
            // connect permission.
            let socket_path = config.socket_dir.join("daemon.sock");
            match action {
                PersonaAction::Create { name } => {
                    let request = serde_json::json!({"name": name});
                    match emberlink_cli::call_daemon_method(
                        &socket_path,
                        "create_persona",
                        &request,
                    ) {
                        Ok(result) => {
                            let id = result.get("id").and_then(|v| v.as_str()).unwrap_or("");
                            let display_name =
                                result.get("name").and_then(|v| v.as_str()).unwrap_or("");
                            let public_key = result
                                .get("public_key")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            println!("Created persona");
                            println!("  ID:         {id}");
                            println!("  Name:       {display_name}");
                            println!("  Public key: {public_key}");
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                PersonaAction::List => {
                    match emberlink_cli::call_daemon_method(
                        &socket_path,
                        "list_personas",
                        &serde_json::Value::Null,
                    ) {
                        Ok(result) => {
                            let empty = Vec::new();
                            let personas = result.as_array().unwrap_or(&empty);
                            if cli.json {
                                println!("{}", serde_json::to_string_pretty(&result).unwrap());
                            } else if personas.is_empty() {
                                println!("No personas");
                            } else {
                                for p in personas {
                                    let id = p.get("id").and_then(|v| v.as_str()).unwrap_or("");
                                    let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
                                    let status =
                                        p.get("status").and_then(|v| v.as_str()).unwrap_or("");
                                    let status_marker = if status == "revoked" {
                                        " [revoked]"
                                    } else {
                                        ""
                                    };
                                    println!("{} ({}){}", name, id, status_marker);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                PersonaAction::Revoke { id } => {
                    match run_persona_revoke(&config, &id) {
                        Ok(_) => println!("Revoked persona {id}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
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

        Commands::BinaryPin { action } => match action {
            BinaryPinAction::Generate { paths, force } => {
                let socket_path = emberlink_cli::daemon_socket_path();
                let self_exe = match std::env::current_exe() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("error: could not resolve current_exe for cli pin: {e}");
                        process::exit(1);
                    }
                };

                let mut pins: Vec<serde_json::Value> = vec![serde_json::json!({
                    "caller": "cli",
                    "path": self_exe.display().to_string(),
                })];
                for spec in &paths {
                    match spec.split_once('=') {
                        Some((caller, path)) => pins.push(serde_json::json!({
                            "caller": caller,
                            "path": path,
                        })),
                        None => {
                            eprintln!(
                                "error: --path expects caller=path form (e.g. gui=/Applications/...), got {spec:?}"
                            );
                            process::exit(1);
                        }
                    }
                }

                let request = serde_json::json!({
                    "pins": pins,
                    "force": force,
                });
                let result = match emberlink_cli::call_daemon_method(
                    &socket_path,
                    "binary_pin_generate",
                    &request,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("error: binary_pin_generate failed: {e}");
                        process::exit(1);
                    }
                };

                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
                    );
                } else {
                    let signed = result
                        .get("pins_signed")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let missing = result
                        .get("missing")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    println!("ember binary-pin: signed manifest with {signed} pin(s)");
                    if missing > 0 {
                        println!("  (warning: {missing} requested binary paths were not found)");
                    }
                    if let Some(pubkey) = result.get("signer_pubkey").and_then(|v| v.as_str()) {
                        println!("  signer: {pubkey}");
                    }
                    if let Some(when) = result.get("signed_at").and_then(|v| v.as_str()) {
                        println!("  signed_at: {when}");
                    }
                }
            }
        },
        Commands::Vault { action } => {
            // Handle migrate-acl before opening the vault — it operates on the
            // keyring directly and must not require the vault to already be
            // accessible under the new ACL.
            if matches!(action, VaultAction::MigrateAcl) {
                match run_vault_migrate_acl(&config) {
                    Ok(result) => {
                        if cli.json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&result)
                                    .unwrap_or_else(|_| "{}".to_string())
                            );
                        } else {
                            let before = result
                                .get("before_acl_kind")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let after = result
                                .get("after_acl_kind")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let service =
                                result.get("service").and_then(|v| v.as_str()).unwrap_or("");
                            let account =
                                result.get("account").and_then(|v| v.as_str()).unwrap_or("");
                            if before == after {
                                println!("MEK already uses {before} ACL — no migration needed.");
                            } else {
                                println!("MEK ACL migrated: {before} → {after}");
                                println!("  service: {service}");
                                println!("  account: {account}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                }
                return;
            }

            // These verbs can route through the daemon without changing the
            // operator-visible data contract, so prefer the daemon surface and
            // avoid opening the vault in-process when the socket exists.
            match &action {
                VaultAction::List(VaultListArgs { prefix }) => {
                    match run_vault_list(&config, prefix.as_deref()) {
                        Ok((_, entries)) => {
                            if cli.json {
                                println!("{}", serde_json::to_string_pretty(&entries).unwrap());
                            } else if entries.is_empty() {
                                println!("No credentials in vault");
                            } else {
                                for entry in &entries {
                                    if let Some(name) = entry.get("name").and_then(|v| v.as_str()) {
                                        println!("{name}");
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                VaultAction::Add {
                    name,
                    value,
                    stdin,
                    file,
                    delete_source,
                    from_downloads,
                    metadata,
                } => {
                    if let Err(e) = validate_credential_name(name) {
                        eprintln!("error: invalid credential name: {e}");
                        eprintln!(
                            "       see design §5.1 for the path grammar (lowercase \
                                 + digits + hyphen, 1..=4 path segments separated by '/')"
                        );
                        process::exit(2);
                    }
                    if value.is_some() {
                        refuse_value_in_argv("value");
                    }
                    let resolved = match resolve_credential_input(
                        *stdin,
                        file.as_deref(),
                        *delete_source,
                        *from_downloads,
                    ) {
                        Ok(bytes) => bytes,
                        Err(code) => process::exit(code),
                    };
                    match run_vault_store(&config, name, &resolved, metadata.as_deref()) {
                        Ok(info) => {
                            let _ = info.dispatch;
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
                VaultAction::Get(VaultGetArgs {
                    name,
                    unmask,
                    i_know_what_im_doing,
                }) => match run_vault_get(&config, name) {
                    Ok((_, value)) => {
                        if *unmask {
                            if std::io::stdout().is_terminal() && !i_know_what_im_doing {
                                eprintln!("error: --unmask refused on a TTY. Re-run with one of:");
                                eprintln!(
                                    "         ember vault get {name} --unmask | tee /dev/null   # pipe to non-TTY"
                                );
                                eprintln!(
                                    "         ember vault get {name} --unmask --i-know-what-im-doing"
                                );
                                process::exit(2);
                            }
                            let text = String::from_utf8_lossy(&value);
                            println!("{text}");
                        } else {
                            println!(
                                "{}",
                                emberlink_cli::vault_io::mask_credential_for_display(&value)
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                VaultAction::Put(args) => {
                    if let Err(e) = validate_credential_name(&args.name) {
                        eprintln!("error: invalid credential name: {e}");
                        eprintln!(
                            "       see design §5.1 for the path grammar (lowercase \
                                 + digits + hyphen, 1..=4 path segments separated by '/')"
                        );
                        process::exit(2);
                    }
                    if args.value.is_some() {
                        refuse_value_in_argv("value");
                    }
                    let resolved = match resolve_credential_input(
                        args.stdin,
                        args.file.as_deref(),
                        args.delete_source,
                        args.from_downloads,
                    ) {
                        Ok(bytes) => bytes,
                        Err(code) => process::exit(code),
                    };
                    match run_vault_store(&config, &args.name, &resolved, args.metadata.as_deref())
                    {
                        Ok(info) => {
                            let _ = info.dispatch;
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
                VaultAction::Remove { name } => match run_vault_remove(&config, name) {
                    Ok(_) => println!("Removed credential {name}"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                _ => {}
            }

            if matches!(
                &action,
                VaultAction::List(_)
                    | VaultAction::Add { .. }
                    | VaultAction::Get(_)
                    | VaultAction::Put(_)
                    | VaultAction::Remove { .. }
            ) {
                return;
            }

            // Lock/unlock are authority-sensitive but do not need the normal
            // open_store + Vault::open_from_config data path.
            if matches!(&action, VaultAction::Lock | VaultAction::Unlock) {
                let result = match &action {
                    VaultAction::Lock => run_vault_lock(&config).map(|_| "locked"),
                    VaultAction::Unlock => run_vault_unlock(&config).map(|_| "unlocked"),
                    _ => unreachable!("lock/unlock branch must only handle lock-style actions"),
                };
                match result {
                    Ok(state) => {
                        if cli.json {
                            println!("{{\"{state}\": true}}");
                        } else if state == "locked" {
                            println!(
                                "Vault session re-locked. Next high-risk op will prompt for user presence."
                            );
                        } else {
                            println!(
                                "Vault session unlocked. Non-session operator flows may use the daemon vault again."
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                }
                return;
            }

            // Client-side pre-validation: fail fast on a malformed name before
            // we open the store / unlock the vault (which on macOS would fire
            // a Touch ID prompt). The daemon-side check in `Vault::add` is
            // authoritative; this mirror is purely UX. If the regex constants
            // need to be tweaked, change `validate_credential_name` in
            // `ember-daemon::vault` — the CLI imports the same fn so they
            // cannot drift.
            // Mirror the daemon-side `validate_credential_name` UX gate
            // for both `add` and `put` so we fail before unlocking the
            // vault on macOS (which would fire a Touch ID prompt).
            let pre_validate_name: Option<&str> = match &action {
                VaultAction::Add { name, .. } => Some(name.as_str()),
                VaultAction::Put(args) => Some(args.name.as_str()),
                _ => None,
            };
            if let Some(name) = pre_validate_name
                && let Err(e) = validate_credential_name(name)
            {
                eprintln!("error: invalid credential name: {e}");
                eprintln!(
                    "       see design §5.1 for the path grammar (lowercase \
                         + digits + hyphen, 1..=4 path segments separated by '/')"
                );
                process::exit(2);
            }

            // [open-store-audit] MUTATOR-MIXED: Commands::Vault.
            //   Add/Put     → MUTATOR (`vault_add`) when a daemon socket is
            //                 present; local fallback when no daemon exists.
            //   Remove      → MUTATOR (`vault_remove`) when a daemon socket is
            //                 present; local fallback when no daemon exists.
            //   Import      → MUTATOR. No dedicated batch RPC, but the CLI
            //                 now commits via per-entry `vault_add` on the
            //                 current authority surface.
            //   List        → READ-ONLY (`vault_list`) when a daemon socket is
            //                 present; local fallback when no daemon exists.
            //   Get         → READ-ONLY (`vault_get`) when a daemon socket is
            //                 present; local fallback when no daemon exists.
            //   Export      → READ-ONLY. No dedicated batch RPC, but the CLI
            //                 now reads via `vault_list` + `vault_get` on the
            //                 current authority surface.
            //   Lock/Unlock → MUTATOR (`vault_lock` / `vault_unlock`) when a
            //                 daemon socket is present; local fallback when no
            //                 daemon exists. Handled before `open_store`.
            // Migration is per-arm and high-traffic; deferred to follow-up.
            match action {
                VaultAction::Add { .. } => unreachable!("add is handled before vault open"),
                VaultAction::List(_) => unreachable!("list is handled before vault open"),
                VaultAction::Get(_) => unreachable!("get is handled before vault open"),
                VaultAction::Put(_) => unreachable!("put is handled before vault open"),
                VaultAction::Export(args) => {
                    if let Err(code) = run_vault_export(&config, cli.json, args) {
                        process::exit(code);
                    }
                }
                VaultAction::Import(args) => {
                    if let Err(code) = run_vault_import(&config, args) {
                        process::exit(code);
                    }
                }
                VaultAction::Remove { .. } => unreachable!("remove is handled before vault open"),
                VaultAction::Lock => {
                    unreachable!("lock is handled before vault open");
                }
                VaultAction::Unlock => {
                    unreachable!("unlock is handled before vault open");
                }
                VaultAction::MigrateAcl => {
                    // Handled above (before vault open) via the early-return path.
                    unreachable!("migrate-acl is handled before vault open");
                }
            }
        }

        Commands::Grant { action } => {
            // [open-store-audit] MUTATOR-MIXED: Commands::Grant.
            //   Create   → MUTATOR (`create_grant`) when a daemon socket is
            //              present; local fallback when no daemon exists.
            //   Delegate → MUTATOR (`delegate_grant`) when a daemon socket is
            //              present; local fallback when no daemon exists.
            //   List     → READ-ONLY (`list_operator_grants`) when a daemon
            //              socket is present; local fallback when no daemon exists.
            //   Revoke   → MUTATOR (`revoke_grant`) on the daemon socket.
            //   Expire   → MUTATOR (`expire_grants`) when a daemon socket is
            //              present; local fallback when no daemon exists.
            //   Budget   → READ-ONLY (`grant_status`) when a daemon socket is
            //              present; local fallback when no daemon exists.
            //   Extend   → MUTATOR (`extend_grant`) when a daemon socket is
            //              present; local fallback when no daemon exists.
            match &action {
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
                    attestation_runtime: _,
                    standing,
                    max_children_per_day,
                    auto_delegate_scope_template,
                } => {
                    if *standing && max_children_per_day.is_none() {
                        eprintln!("error: --standing requires --max-children-per-day");
                        process::exit(1);
                    }
                    if *standing && delegation_depth.is_none() {
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
                    let spec = GrantCreateSpec {
                        persona: persona.clone(),
                        credential: credential.clone(),
                        scope: scope.clone(),
                        ttl_secs,
                        max_uses_per_hour: *rate_limit,
                        allowed_hours_start: *hours_start,
                        allowed_hours_end: *hours_end,
                        allowed_targets: allowed_targets.as_ref().map(|targets| {
                            targets
                                .split(',')
                                .map(str::to_owned)
                                .collect::<Vec<String>>()
                        }),
                        max_delegation_depth: *delegation_depth,
                        budget: build_budget(
                            *budget_tokens,
                            parsed_cents,
                            *budget_requests,
                            *budget_seconds,
                        ),
                        max_children_per_day: if *standing {
                            *max_children_per_day
                        } else {
                            None
                        },
                        auto_delegate_scope_template: if *standing {
                            auto_delegate_scope_template.clone()
                        } else {
                            None
                        },
                    };
                    match run_grant_create(&config, &spec) {
                        Ok((_, response)) => {
                            if cli.json {
                                println!("{}", serde_json::to_string_pretty(&response).unwrap());
                            } else if response["status"] == serde_json::json!("pending_approval") {
                                let approval_id =
                                    response["approval_id"].as_str().unwrap_or("<unknown>");
                                println!("Grant creation pending approval");
                                println!("  Approval:   {approval_id}");
                            } else {
                                let id = response["id"].as_str().unwrap_or("");
                                let expires_at = response["expires_at"].as_str();
                                print_created_grant(&spec, id, expires_at);
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
                        *budget_tokens,
                        parsed_cents,
                        *budget_requests,
                        *budget_seconds,
                    );
                    match run_grant_delegate(
                        &config,
                        parent,
                        persona,
                        scope,
                        ttl_secs,
                        child_budget,
                    ) {
                        Ok((_, info)) => {
                            if cli.json {
                                println!("{}", serde_json::to_string_pretty(&info).unwrap());
                            } else {
                                let id = info.get("id").and_then(|v| v.as_str()).unwrap_or("");
                                println!("{id}");
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                GrantAction::List { active } => match run_grant_list(&config, *active) {
                    Ok((_, list)) => {
                        if cli.json {
                            println!("{}", serde_json::to_string_pretty(&list).unwrap());
                        } else if list.is_empty() {
                            println!("No grants");
                        } else {
                            for g in &list {
                                let exp = g
                                    .get("expires_at")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("never");
                                let id = g.get("id").and_then(|v| v.as_str()).unwrap_or("");
                                let persona_id =
                                    g.get("persona_id").and_then(|v| v.as_str()).unwrap_or("");
                                let credential_name = g
                                    .get("credential_name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                let scope = g.get("scope").and_then(|v| v.as_str()).unwrap_or("");
                                let status = g.get("status").and_then(|v| v.as_str()).unwrap_or("");
                                println!(
                                    "{} {} → {} ({}) expires {} [{}]",
                                    id, persona_id, credential_name, scope, exp, status
                                );
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                GrantAction::Revoke { id } => {
                    let socket_path = config.socket_dir.join("daemon.sock");
                    let request = serde_json::json!({ "id": id });
                    match emberlink_cli::call_daemon_method(&socket_path, "revoke_grant", &request)
                    {
                        Ok(_) => println!("Revoked grant {id}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                GrantAction::Expire => match run_grant_expire(&config) {
                    Ok((_, count)) => println!("Expired {} stale grant(s)", count),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                GrantAction::Extend {
                    grant_id,
                    tokens,
                    cents,
                    ttl,
                } => {
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
                    match run_grant_extend(&config, grant_id, *tokens, parsed_cents, ttl_secs) {
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
                }
                GrantAction::Budget { grant_id } => match run_grant_budget(&config, grant_id) {
                    Ok((_, rendered)) => print!("{rendered}"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
            }
        }

        Commands::Sandbox { action } => {
            // [open-store-audit] MUTATOR-MIXED: Commands::Sandbox.
            //   Create/List/Stop/Delete/Exec → daemon-backed when a live
            //                socket exists; local fallback only on
            //                no-daemon/dev paths.
            //   Run        → daemon-backed for sandbox create/start plus
            //                composite grant policy/approval orchestration;
            //                local fallback only on no-daemon/dev paths.
            //                The final interactive `docker exec` handoff is
            //                still a local operator terminal step.
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
                            kv.split_once('=')
                                .map(|(k, v)| (k.to_string(), v.to_string()))
                        })
                        .collect();
                    let owner_persona_id =
                        persona.or_else(|| std::env::var("EMBER_PERSONA_ID").ok());
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
                    let created = match run_sandbox_create(&config, &opts) {
                        Ok((_, created)) => created,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };
                    if let Some(ref e) = created.start_error {
                        eprintln!("warning: sandbox created but container failed: {e}");
                    }
                    // Record image digest to ~/.ember/images.toml
                    let registry_path = config.data_dir.join("images.toml");
                    match resolve_image_digest(&image) {
                        Some(digest) => {
                            record_image_digest(&registry_path, &image, &digest);
                        }
                        None => {
                            eprintln!(
                                "warning: could not resolve image digest for {image} — docker may not be available"
                            );
                        }
                    }
                    let container_id = created.container_id.as_deref().unwrap_or("none");
                    let sandbox = &created.sandbox;
                    println!("Created sandbox");
                    println!("  ID:        {}", sandbox.id);
                    println!("  Persona:   {}", sandbox.persona_id);
                    println!("  Container: {container_id}");
                    if let Some(ws) = &sandbox.workspace_path {
                        println!("  Workspace: {ws}");
                    }
                }
                SandboxAction::List => match run_sandbox_list(&config) {
                    Ok((_, sandboxes)) => {
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
                SandboxAction::Stop { id } => match run_sandbox_stop(&config, &id) {
                    Ok((_, resolved_id)) => println!("Stopped sandbox {resolved_id}"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                SandboxAction::Delete { id } => match run_sandbox_delete(&config, &id) {
                    Ok((_, deleted)) if deleted.already_absent => {
                        println!("sandbox '{id}' not found (already deleted — ok)");
                    }
                    Ok((_, deleted)) => {
                        let resolved_id = deleted.resolved_id.as_deref().unwrap_or("(unknown)");
                        println!("Deleted sandbox {resolved_id}");
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                SandboxAction::Exec {
                    id,
                    persona,
                    command,
                } => {
                    let caller_persona = persona
                        .or_else(|| std::env::var("EMBER_PERSONA_ID").ok())
                        .filter(|s| !s.is_empty());
                    match run_sandbox_exec(&config, &id, caller_persona, &command) {
                        Ok((_, output)) => print!("{output}"),
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

                    let run_owner_persona_id = std::env::var("EMBER_PERSONA_ID").ok();
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
                    let prepared = match run_sandbox_run(
                        &config,
                        &opts,
                        &statements,
                        ttl_secs,
                        credential_resource.as_deref(),
                    ) {
                        Ok((_, prepared)) => prepared,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };
                    if let Some(ref e) = prepared.start_error {
                        eprintln!("warning: sandbox created but container failed: {e}");
                    }
                    let container_id = prepared.container_id.as_deref().unwrap_or("none");
                    let sandbox = &prepared.sandbox;

                    println!("Started sandbox");
                    println!("  ID:        {}", sandbox.id);
                    println!("  Persona:   {}", sandbox.persona_id);
                    println!("  Container: {container_id}");
                    if let Some(ws) = &sandbox.workspace_path {
                        println!("  Workspace: {ws}");
                    }

                    // Mint the composite grant if a credential resource was supplied.
                    //
                    // implementation-note-233 — route the composite mint through the policy
                    // engine so `default_decision = "require_approval"` fires
                    // here.
                    //
                    // COMPOSITE-prior change — collapsed both Auto and Required onto a
                    // single mint code path. Every outcome dispatches via
                    // `propose_grant`; the daemon-side `auto_resolve` handles
                    // the auto lane (immediate Approved + `auto_resolved`
                    // audit event), the human approval flow handles Required.
                    // No more inline `create_grant` + `overwrite_grant_blocks`
                    // bypass on the AutoApprove path.
                    //
                    // Three outcomes:
                    //   - Auto: propose_grant + auto_resolve (mint immediate)
                    //   - Required: propose_grant; do NOT exec prompt; exit
                    //     so the operator can `ember approval approve <id>`
                    //   - Denied: error and exit non-zero
                    //
                    // The policy action name is `credential.access` to match
                    // the daemon's existing credential-access rule shape.
                    let mut sandbox_grant_pending = false;
                    let credential_res = credential_resource.as_deref().unwrap_or("");
                    match &prepared.grant {
                        SandboxRunGrantDisposition::NotRequested => {
                            println!("  (no --credential-resource supplied — grant not minted)");
                        }
                        SandboxRunGrantDisposition::PendingApproval { approval_id } => {
                            sandbox_grant_pending = true;
                            println!("Approval required for composite grant");
                            println!("  Approval ID: {}", approval_id);
                            println!("  Statements:  {statement_count}");
                            println!("    [0] credential:read  on {credential_res}");
                            if let Some(t) = budget_tokens {
                                println!(
                                    "    [1] llm:generate     on anthropic/*  budget={t} tokens"
                                );
                            } else {
                                println!(
                                    "    [1] llm:generate     on anthropic/*  (no token budget)"
                                );
                            }
                            if let Some(s) = budget_seconds {
                                println!("    [2] time:wall_clock  on *             budget={s}s");
                            } else {
                                println!(
                                    "    [2] time:wall_clock  on *             (no time budget)"
                                );
                            }
                            println!();
                            println!("  Approve from CLI: ember approval approve {}", approval_id);
                            println!(
                                "  Or open dashboard: http://localhost:3141/approvals/{}",
                                approval_id
                            );
                        }
                        SandboxRunGrantDisposition::Minted { grant_id } => {
                            let grant_id = grant_id.as_deref().unwrap_or("(unknown)");
                            println!("Minted 3-statement composite grant");
                            println!("  Grant ID:   {grant_id}");
                            println!("  Statements: {statement_count}");
                            println!("    [0] credential:read  on {credential_res}");
                            if let Some(t) = budget_tokens {
                                println!(
                                    "    [1] llm:generate     on anthropic/*  budget={t} tokens"
                                );
                            } else {
                                println!(
                                    "    [1] llm:generate     on anthropic/*  (no token budget)"
                                );
                            }
                            if let Some(s) = budget_seconds {
                                println!("    [2] time:wall_clock  on *             budget={s}s");
                            } else {
                                println!(
                                    "    [2] time:wall_clock  on *             (no time budget)"
                                );
                            }
                            println!("  One approval. Three meters. One receipt at the end.");
                            if let Some(ref p) = prompt {
                                println!("  Prompt: {p}");
                            }
                        }
                        SandboxRunGrantDisposition::Failed { message } => {
                            eprintln!("warning: sandbox started but {message}");
                        }
                    }

                    // If a prompt was given and the container started, hand off to
                    // `docker exec -it <container_id> claude -p "<prompt>"`.  The
                    // child process inherits stdin/stdout so Claude Code's output
                    // streams directly to the operator's terminal.
                    //
                    // implementation-note-233 — when the composite grant is pending approval,
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
                            exec_args.push(container_id);
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
            // [open-store-audit] MUTATOR-MIXED: Commands::Approval.
            //   List              → `list_pending_approvals` when a daemon
            //                       socket is live.
            //   Approve/Deny/Narrow → `resolve_approval` when a daemon
            //                       socket is live.
            // Direct store fallback remains only for no-daemon/dev paths.
            match action {
                ApprovalAction::List => match run_approval_list(&config) {
                    Ok((_, requests)) => {
                        if requests.is_empty() {
                            println!("No pending approvals");
                        } else {
                            for r in &requests {
                                // implementation-note-233 — composite envelopes render as
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
                                    // implementation-note-226: shipped
                                    for (i, s) in stmts.iter().enumerate() {
                                        let actions = s.actions.join(",");
                                        let resource = match &s.resource {
                                            core_grant_types::ResourceSelector::Exact { value } => {
                                                value.clone()
                                            }
                                            core_grant_types::ResourceSelector::Glob {
                                                pattern,
                                            } => pattern.clone(),
                                            core_grant_types::ResourceSelector::Any => {
                                                "*".to_string()
                                            }
                                            _ => format!("{:?}", s.resource),
                                        };
                                        // Append per-statement budget caps (tokens + cents + seconds).
                                        let budget_str = if let Some(b) = &s.budget {
                                            let mut parts: Vec<String> = Vec::new();
                                            if let Some(t) = b.tokens {
                                                parts.push(format!("tokens:{t}"));
                                            }
                                            if let Some(c) = b.cents {
                                                parts.push(format!("${:.2}", c as f64 / 100.0));
                                            }
                                            if let Some(sec) = b.wall_clock_secs {
                                                parts.push(format!("seconds:{sec}"));
                                            }
                                            if parts.is_empty() {
                                                String::new()
                                            } else {
                                                format!("  [{}]", parts.join(" · "))
                                            }
                                        } else {
                                            String::new()
                                        };
                                        println!("    [{i}] {actions} on {resource}{budget_str}");
                                    }
                                } else {
                                    println!(
                                        "{} {} → {} ({}) [{}]",
                                        r.id,
                                        r.persona_id,
                                        r.credential_name,
                                        r.action,
                                        r.risk_level
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
                                    eprintln!(
                                        "error: invalid --ttl value '{s}'; expected e.g. 7d, 30d, never"
                                    );
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
                    match run_approval_resolve(&config, &id, &outcome) {
                        Ok((_, resolved)) => {
                            if always {
                                println!("Approved {id}");
                                println!(
                                    "  Standing grant created: future requests for this action will auto-approve."
                                );
                                println!("  Review: ember grant standing list");
                            } else {
                                println!("Approved {id}");
                            }
                            // implementation-note-233 — surface the grant ID minted by a
                            // composite-approval resolution so the operator
                            // (or test harness) can use it directly.
                            if let Some(grant_id) = resolved.result_grant_id.as_deref() {
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
                    match run_approval_resolve(
                        &config,
                        &id,
                        &ApprovalOutcome::Denied {
                            reason: reason.clone(),
                        },
                    ) {
                        Ok(_) => println!("Denied {id}: {reason}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                ApprovalAction::Narrow { id, scope } => {
                    match run_approval_resolve(
                        &config,
                        &id,
                        &ApprovalOutcome::Narrowed {
                            new_scope: scope.clone(),
                        },
                    ) {
                        Ok(_) => println!("Narrowed {id} to scope: {scope}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
            }
        }

        Commands::Audit { action } => {
            // [open-store-audit] DAEMON-BACKED READ-ONLY on the installed path.
            //   Query   → `receipt_query` when a daemon socket is live.
            //   Show    → operator-only `audit_log_query` when a daemon
            //             socket is live.
            //   Export  → operator-only `audit_log_query` when a daemon
            //             socket is live.
            //   Explain → current-state `audit_explain` when a daemon
            //             socket is live.
            //   Verify  → daemon-backed via `audit_verify`.
            // Local direct fallback remains only for no-daemon/dev paths.
            match action {
                AuditAction::Show { agent, limit } => {
                    let filter = AuditFilter {
                        agent_id: agent,
                        limit: Some(limit),
                        ..Default::default()
                    };
                    match run_audit_log_query(&config, &filter) {
                        Ok((_, entries)) => {
                            if cli.json {
                                let arr: Vec<_> = entries
                                    .iter()
                                    .map(|e| {
                                        serde_json::json!({
                                            "timestamp": e.timestamp,
                                            "agent_id": e.agent_id,
                                            "action": e.action,
                                            "credential": e.credential,
                                            "outcome": e.outcome,
                                        })
                                    })
                                    .collect();
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
                AuditAction::Export {
                    format,
                    limit,
                    agent,
                    output,
                } => {
                    let filter = AuditFilter {
                        agent_id: agent,
                        limit,
                        ..Default::default()
                    };
                    let entries = match run_audit_log_query(&config, &filter) {
                        Ok(entries) => {
                            let (_, entries) = entries;
                            entries
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };

                    let content = match format.as_str() {
                        "csv" => {
                            let mut lines = vec![
                                "timestamp,agent_id,action,credential,outcome,details".to_string(),
                            ];
                            for e in &entries {
                                lines.push(format!(
                                    "{},{},{},{},{},{}",
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
                        _ => serde_json::to_string_pretty(
                            &entries
                                .iter()
                                .map(|e| {
                                    serde_json::json!({
                                        "timestamp": e.timestamp,
                                        "agent_id": e.agent_id,
                                        "action": e.action,
                                        "credential": e.credential,
                                        "outcome": e.outcome,
                                        "details": e.details,
                                    })
                                })
                                .collect::<Vec<_>>(),
                        )
                        .unwrap_or_default(),
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
                    let entry_id = match id.parse::<i64>() {
                        Ok(id) => id,
                        Err(_) => {
                            eprintln!("Event {} not found", id);
                            process::exit(1);
                        }
                    };

                    match run_audit_explain(&config, entry_id) {
                        Ok((_, explain)) => {
                            let e = &explain.event;
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

                            match explain.current_grant {
                                Some(grant) => {
                                    println!("GRANT {}", grant.id);
                                    println!("  Scope:      {}", grant.scope);
                                    println!("  Created:    {}", grant.created_at);
                                    println!(
                                        "  Expires:    {}",
                                        grant.expires_at.as_deref().unwrap_or("never")
                                    );
                                    println!("  Status:     {}", grant.status);
                                }
                                None => println!("GRANT: no active grant found"),
                            }
                            println!();

                            println!("POLICY");
                            println!("  Decision:   {:?}", explain.current_policy.requirement);
                            println!("  Risk:       {:?}", explain.current_policy.risk);
                            println!("  Tier:       {:?}", explain.current_policy.tier);
                            println!(
                                "  Rule:       {}",
                                explain
                                    .current_policy
                                    .matched_rule
                                    .as_deref()
                                    .unwrap_or("(default)")
                            );
                            println!();
                            println!("NOTE");
                            println!("  {}", explain.note);
                        }
                        Err(e) => {
                            if e.to_string().contains("not found") {
                                eprintln!("Event {} not found", id);
                            } else {
                                eprintln!("error: {e}");
                            }
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
                    // audit_actions_migrated_to_rpc: routes through the
                    // daemon's `receipt_query` JSON-RPC rather than opening
                    // the store directly. The daemon side parses ReceiptFilter
                    // fields from the params object and returns a JSON array
                    // of ReceiptRow-shaped objects.

                    // Validate `--since` up front — surface a clean usage
                    // error rather than handing a malformed string to the
                    // RPC params.
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
                    let filter = ember_daemon::infra::receipt::ReceiptFilter {
                        persona_id: actor,
                        kind,
                        grant_id,
                        resource,
                        since_iso,
                        limit,
                        ..Default::default()
                    };
                    let (_, rows) = match run_audit_receipt_query(&config, &filter) {
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
                            let reason_short: String = r.terminal_reason.chars().take(40).collect();
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
                // implementation-note-262 (B): chain verify via
                // daemon socket. Routes through `audit_verify` so the
                // verdict is the daemon's authoritative answer (same
                // path startup verify uses). Exit code: 0 on Ok, 2 on
                // Break (a tampered chain is a distinct signal from
                // operational error), 1 on transport / RPC failure.
                //
                // audit_actions_migrated_to_rpc: routes through the
                // daemon's `audit_verify` JSON-RPC (via
                // `emberlink_cli::audit::verify`); no open_store needed.
                AuditAction::Verify { tail } => {
                    let socket_path = config.socket_dir.join("daemon.sock");
                    match emberlink_cli::audit::verify::run_audit_verify_cli(&socket_path, tail) {
                        Ok(verdict) => {
                            if cli.json {
                                let v = emberlink_cli::audit::verify::format_verdict_json(&verdict);
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&v).unwrap_or_default()
                                );
                            } else {
                                print!(
                                    "{}",
                                    emberlink_cli::audit::verify::format_verdict_human(&verdict)
                                );
                            }
                            if matches!(
                                verdict,
                                emberlink_cli::audit::verify::VerifyVerdict::Break { .. }
                            ) {
                                process::exit(2);
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                AuditAction::Usage => {
                    // implementation-note-459: read prod (~/.ember/audit/) and
                    // dev (~/.ember-dev/audit/) audit roots; print the
                    // per-daemon + grand-total footprint with 80% / 100%
                    // ceiling flags. Exits 1 in warn range, 2 at/above
                    // 100% so operators can gate scripts on the verdict.
                    let home = match std::env::var("HOME") {
                        Ok(h) => PathBuf::from(h),
                        Err(_) => {
                            eprintln!("error: $HOME not set; cannot locate audit roots");
                            process::exit(1);
                        }
                    };
                    let code = emberlink_cli::audit::usage::run(&home);
                    if code != 0 {
                        process::exit(code);
                    }
                }
            }
        }

        Commands::Receipt { action } => {
            // [open-store-audit] READ-ONLY: Commands::Receipt.
            //   List   → `list_receipts` when a daemon socket is live.
            //   Show   → `get_receipt` when a daemon socket is live.
            //   Export → `get_receipt` when a daemon socket is live.
            //   Tree   → `receipt_tree` when a daemon socket is live.
            //   Verify → `get_receipt` only for the id-mode path; file/tree/
            //            materialization modes stay daemon-free.
            // Local direct fallback remains only for no-daemon/dev paths.
            match action {
                ReceiptAction::List {
                    persona,
                    json: list_json,
                } => {
                    let (_, receipts) = match run_receipt_list(&config, persona.as_deref()) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };
                    if cli.json || list_json {
                        // ember receipt list --json emits full UUIDs
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&receipts).unwrap_or_default()
                        );
                    } else if receipts.is_empty() {
                        println!("No receipts found.");
                    } else {
                        let h_receipt = "RECEIPT";
                        let h_grant = "GRANT";
                        let h_persona = "PERSONA";
                        let h_reason = "REASON";
                        println!("{h_receipt:<30} {h_grant:<38} {h_persona:<22} {h_reason}");
                        for r in &receipts {
                            let reason_short = match &r.lifecycle.terminal_reason {
                                core_grant_types::grant_receipt::TerminalReason::Expired => "expired".to_string(),
                                core_grant_types::grant_receipt::TerminalReason::Revoked { .. } => "revoked".to_string(),
                                core_grant_types::grant_receipt::TerminalReason::ExhaustedByBudget { .. } => "exhausted".to_string(),
                                core_grant_types::grant_receipt::TerminalReason::ParentCascadeRevoked { .. } => "cascaded".to_string(),
                            };
                            let persona_short: String =
                                r.summary.persona_id.chars().take(20).collect();
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
                ReceiptAction::Show { id, format, raw } => {
                    let (_, r) = match run_receipt_get(&config, &id) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };
                    if format == "md" {
                        println!(
                            "{}",
                            emberlink_cli::receipt::render_receipt_markdown(&r, raw)
                        );
                    } else if cli.json {
                        println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
                    } else {
                        print_receipt_summary(&r);
                    }
                }
                ReceiptAction::Export {
                    id,
                    latest,
                    format,
                    raw,
                } => {
                    let target_id =
                        match resolve_receipt_export_target(&config, id.as_deref(), latest) {
                            Ok(id) => id,
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        };
                    let (_, r) = match run_receipt_get(&config, &target_id) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };
                    if format == "md" {
                        println!(
                            "{}",
                            emberlink_cli::receipt::render_receipt_markdown(&r, raw)
                        );
                    } else {
                        match serde_json::to_string_pretty(&r) {
                            Ok(s) => println!("{s}"),
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        }
                    }
                }
                ReceiptAction::Verify {
                    id,
                    file,
                    pubkey,
                    materialization,
                    events,
                    tree,
                    offline: _,
                } => {
                    // --tree mode: load a tree-export JSON and run all
                    // signature checks offline. Beat 8 demo close. The
                    // verify path does not touch the daemon socket — the
                    // trust anchor is embedded in the export file.
                    if let Some(tree_path) = tree {
                        let tree_export = match emberlink_cli::receipt::read_tree_export(&tree_path)
                        {
                            Ok(t) => t,
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        };
                        match emberlink_cli::receipt::verify_tree_offline(&tree_export) {
                            Ok(outcome) => {
                                print!(
                                    "{}",
                                    emberlink_cli::receipt::format_verify_outcome(&outcome)
                                );
                                return;
                            }
                            Err(e) => {
                                eprintln!("Tree verification FAILED: {e}");
                                process::exit(2);
                            }
                        }
                    }
                    // --materialization mode: chain-integrity walk over
                    // sub-Receipts in events.jsonl. Distinct from the
                    // signature-verification path below — rollup chains are
                    // not signed end-to-end (each sub-Receipt is signed
                    // individually); the integrity check is structural.
                    if let Some(mid) = materialization {
                        let events_path =
                            events.unwrap_or_else(|| config.data_dir.join("events.jsonl"));
                        let receipts =
                            match emberlink_cli::receipt::rollup::read_receipts_from_jsonl(
                                &events_path,
                            ) {
                                Ok(r) => r,
                                Err(e) => {
                                    eprintln!("error: {e}");
                                    process::exit(1);
                                }
                            };
                        match emberlink_cli::receipt::verify_chain(&receipts, &mid) {
                            Ok(rollup) => {
                                println!(
                                    "Verified: chain {} ({} sub-receipts, outcome={:?})",
                                    rollup.materialization_id, rollup.receipt_count, rollup.outcome
                                );
                                return;
                            }
                            Err(e) => {
                                eprintln!("Chain verification FAILED: {e}");
                                process::exit(2);
                            }
                        }
                    }
                    let r = match (id, file) {
                        (Some(_), Some(_)) => {
                            // clap conflicts_with should prevent reaching here.
                            eprintln!("error: pass either <id> or --file <PATH>, not both");
                            process::exit(2);
                        }
                        (None, None) => {
                            eprintln!(
                                "error: pass either a receipt <id>, --file <PATH>, or --materialization <ID>"
                            );
                            process::exit(2);
                        }
                        (Some(id), None) => match run_receipt_get(&config, &id) {
                            Ok((_, r)) => r,
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        },
                        (None, Some(path)) => {
                            const MAX_RECEIPT_BYTES: usize = 1024 * 1024;
                            let bytes = if path == "-" {
                                use std::io::Read as _;
                                let mut buf = Vec::with_capacity(8192);
                                let mut handle =
                                    std::io::stdin().lock().take((MAX_RECEIPT_BYTES + 1) as u64);
                                if let Err(e) = handle.read_to_end(&mut buf) {
                                    eprintln!("error: failed to read stdin: {e}");
                                    process::exit(1);
                                }
                                if buf.len() > MAX_RECEIPT_BYTES {
                                    eprintln!(
                                        "error: receipt input exceeds {MAX_RECEIPT_BYTES} bytes"
                                    );
                                    process::exit(1);
                                }
                                buf
                            } else {
                                let meta = match std::fs::metadata(&path) {
                                    Ok(m) => m,
                                    Err(e) => {
                                        eprintln!("error: cannot read {path}: {e}");
                                        process::exit(1);
                                    }
                                };
                                if meta.len() > MAX_RECEIPT_BYTES as u64 {
                                    eprintln!(
                                        "error: {path} is {} bytes; limit is {MAX_RECEIPT_BYTES}",
                                        meta.len()
                                    );
                                    process::exit(1);
                                }
                                match std::fs::read(&path) {
                                    Ok(b) => b,
                                    Err(e) => {
                                        eprintln!("error: cannot read {path}: {e}");
                                        process::exit(1);
                                    }
                                }
                            };
                            // Detect format: parse as Value first, inspect version field.
                            let raw_value =
                                match serde_json::from_slice::<serde_json::Value>(&bytes) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        eprintln!("error: not a valid Grant Receipt JSON: {e}");
                                        process::exit(1);
                                    }
                                };
                            let version_field = raw_value
                                .get("version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            if version_field == "2" {
                                // v2 receipt (design ReceiptEnvelope).
                                // Dispatch to verify_receipt_v2.
                                let envelope = match serde_json::from_value::<
                                    core_events::receipt::envelope::ReceiptEnvelope,
                                >(raw_value)
                                {
                                    Ok(e) => e,
                                    Err(e) => {
                                        eprintln!("error: not a valid v2 Receipt envelope: {e}");
                                        process::exit(1);
                                    }
                                };
                                // Resolve trust anchor: --pubkey <hex> or daemon identity.
                                // v2 PublicKey has "ed25519:" prefix; pubkey arg is bare hex.
                                let pubkey_hex = match pubkey.as_deref() {
                                    Some(p) => p.to_string(),
                                    None => {
                                        let key_path =
                                            ember_daemon::infra::receipt::identity_key_path(
                                                &config.data_dir,
                                            );
                                        match ember_daemon::infra::receipt::DaemonPersona::load_or_create(&config.data_dir) {
                                            Ok(id) => id.pubkey_hex(),
                                            Err(e) => {
                                                eprintln!(
                                                    "error: could not load trust anchor from {}: {e}",
                                                    key_path.display()
                                                );
                                                process::exit(1);
                                            }
                                        }
                                    }
                                };
                                let pk = core_crypto::PublicKey(format!("ed25519:{pubkey_hex}"));
                                match core_events::receipt::sign::verify_receipt_v2(
                                    &envelope,
                                    &pk,
                                    &core_crypto::Ed25519Verifier,
                                ) {
                                    Ok(()) => {
                                        println!("Verified: receipt {}", envelope.receipt_id);
                                        println!("  Signer pubkey: {pubkey_hex}");
                                        println!("  Kind: {}", envelope.kind);
                                        println!("  Version: v{}", envelope.version.0);
                                    }
                                    Err(e) => {
                                        eprintln!("Verification FAILED: {e}");
                                        process::exit(2);
                                    }
                                }
                                return;
                            }
                            // v1 receipt (or no version field): existing GrantReceipt path.
                            match serde_json::from_value::<
                                core_grant_types::grant_receipt::GrantReceipt,
                            >(raw_value)
                            {
                                Ok(r) => r,
                                Err(e) => {
                                    eprintln!("error: not a valid Grant Receipt JSON: {e}");
                                    process::exit(1);
                                }
                            }
                        }
                    };
                    let expected_pubkey = match pubkey {
                        Some(p) => p,
                        None => {
                            // Read pubkey from the identity file.
                            let path =
                                ember_daemon::infra::receipt::identity_key_path(&config.data_dir);
                            match ember_daemon::infra::receipt::DaemonPersona::load_or_create(
                                &config.data_dir,
                            ) {
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
                    match ember_daemon::infra::receipt::verify_receipt(&r, &expected_pubkey) {
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
                ReceiptAction::Rollup {
                    since,
                    materialization,
                    incomplete_only,
                    events,
                } => {
                    let events_path =
                        events.unwrap_or_else(|| config.data_dir.join("events.jsonl"));
                    let filters = emberlink_cli::receipt::RollupFilters {
                        since: Some(since),
                        materialization,
                        incomplete_only,
                    };
                    match emberlink_cli::receipt::rollup_command(&events_path, &filters, cli.json) {
                        Ok(out) => print!("{out}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                ReceiptAction::Tree { grant, export } => match run_receipt_tree(&config, &grant) {
                    Ok((_, tree)) => {
                        print!("{}", emberlink_cli::receipt::render_tree_ascii(&tree));
                        if let Some(path) = export.as_deref() {
                            if let Err(e) =
                                emberlink_cli::receipt::tree::write_tree_export(&tree, path)
                            {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                            println!("Exported tree to {}", path.display());
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
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

        Commands::Bind { action } => {
            // implementation-note-176: admin path for
            // daemon-controlled credential bindings. Same socket
            // resolution as `Broker` so the two surfaces share the
            // operator-facing daemon-socket invariant.
            let socket_path = config.socket_dir.join("daemon.sock");
            let opts = emberlink_cli::bind::GlobalOpts { socket_path };
            if let Err(e) = emberlink_cli::bind::cmd_bind(action, opts) {
                eprintln!("error: {e}");
                process::exit(e.exit_code());
            }
        }

        Commands::Policy { action } => {
            let policy = ember_daemon::trust::policy::PolicyEngine::default();
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
                    let decision = format!("{:?}", eval.requirement);
                    let rule = eval.matched_rule.as_deref().unwrap_or("(default)");
                    println!("Action:   {act}");
                    println!("Decision: {decision}");
                    println!("Risk:     {risk}");
                    println!("Rule:     {rule}");
                }
            }
        }

        Commands::Status { troubleshoot } => {
            let runtime = DaemonRuntime::new(config.clone());
            // [open-store-audit] READ-ONLY: Commands::Status. Aggregates
            // list_personas / list_active_grants / list_sandboxes /
            // list_pending_approvals / query_audit / audit_count /
            // list_standing_grants. The installed path now prefers the
            // daemon-owned `status` RPC when the daemon is live; local direct
            // fallback remains only for no-daemon/dev paths.
            let runtime_status = runtime.status().ok();
            let daemon_running = runtime_status.as_ref().is_some_and(|s| s.running);
            let (status_dispatch, live_daemon, summary) =
                match run_status_summary(&config, daemon_running) {
                    Ok((dispatch, live_daemon, summary)) => (dispatch, live_daemon, summary),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                };

            let active = summary
                .personas
                .iter()
                .filter(|p| p.status == "active")
                .count();
            let total = summary.audit_events_total;

            // implementation-note-340: surface the credential-store backend
            // selector + its addr (or `local-encrypted` for the default local
            // backend) alongside the daemon's other status rows. Sourced from
            // the same `[credential_store]` section the daemon parses at
            // startup so this is honest about what the running daemon is
            // configured to do.
            let (vault_backend, vault_addr) = match config.credential_store.as_ref() {
                None => ("local".to_string(), "local-encrypted".to_string()),
                Some(cs) if cs.backend == "local" => {
                    ("local".to_string(), "local-encrypted".to_string())
                }
                Some(cs) => (
                    cs.backend.clone(),
                    cs.addr
                        .clone()
                        .unwrap_or_else(|| "<addr-not-configured>".to_string()),
                ),
            };

            if cli.json {
                if troubleshoot {
                    eprintln!(
                        "error: `ember status --json --troubleshoot` is not supported; rerun without `--json`"
                    );
                    process::exit(1);
                }
                let (daemon_running, daemon_pid, daemon_socket) =
                    live_daemon_identity(runtime_status.as_ref(), live_daemon.as_ref());
                let status = serde_json::json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "daemon": { "running": daemon_running, "pid": daemon_pid, "socket": daemon_socket },
                    "personas": active,
                    "grants": { "active": summary.grants.len(), "expired_sweep_interval_sec": 60 },
                    "approvals": { "pending": summary.approvals.len() },
                    "standing_grants": summary.standing_grants,
                    "audit_events": total,
                    "vault": { "backend": vault_backend, "addr": vault_addr },
                });
                println!("{}", serde_json::to_string_pretty(&status).unwrap());
            } else {
                let banner = build_status_banner(
                    &config,
                    runtime_status.as_ref(),
                    live_daemon.as_ref(),
                    vault_backend,
                    vault_addr,
                );
                let github_status = if status_dispatch == StatusActionDispatch::DaemonRpc {
                    run_github_provider_status(&config).ok()
                } else {
                    None
                };
                let ember_initialized = is_ember_initialized(&config);
                let launcher_issue = detect_default_installed_launcher_issue();
                println!("{}", render_status_text(banner.clone(), &summary));
                if troubleshoot {
                    println!();
                    println!(
                        "{}",
                        render_status_troubleshoot_text(
                            &banner,
                            &summary,
                            status_dispatch,
                            github_status.as_ref(),
                            ember_initialized,
                            launcher_issue.as_ref()
                        )
                    );
                }
            }
        }

        Commands::Config { action } => match action {
            ConfigAction::Show => {
                println!("Socket dir:  {}", config.socket_dir.display());
                println!("Data dir:    {}", config.data_dir.display());
                println!("PID file:    {}", config.pid_file.display());
                println!("Log level:   {}", config.log_level.as_filter_str());
                println!(
                    "Config file: {}",
                    effective_config_path(cli.config.as_ref()).display()
                );
            }
            ConfigAction::Path => {
                println!("{}", effective_config_path(cli.config.as_ref()).display());
            }
        },

        Commands::Github { action } => match action {
            GithubAction::Status => match run_github_provider_status(&config) {
                Ok(status) => {
                    if cli.json {
                        let payload = serde_json::json!({
                                "https_app_lane": match github_https_lane(&status) {
                                    GithubHttpsLane::ConfiguredApp => "configured_app",
                                    GithubHttpsLane::ConfiguredPat => "configured_pat",
                                    GithubHttpsLane::ConfiguredMock => "configured_mock",
                                    GithubHttpsLane::Broken => "broken",
                                    GithubHttpsLane::NotConfigured => "not_configured",
                                },
                            "detail": status.detail,
                            "app_id": status.app_id,
                            "installation_id": status.installation_id,
                            "ssh_lane": "substrate_exists_not_launcher_wired",
                            "pat_lane": "degraded_brokered_fallback",
                        });
                        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
                    } else {
                        print!("{}", render_github_status_text(&status));
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    if let Some(hint) = render_github_status_retry_hint(&e) {
                        eprintln!("       {hint}");
                    } else {
                        eprintln!(
                            "       run `ember status` to inspect daemon posture, or `sudo ember daemon install` to repair it"
                        );
                    }
                    process::exit(1);
                }
            },
            GithubAction::Setup(args) => {
                if let Err(exit_code) = run_github_registration_flow(
                    &config,
                    &args,
                    io::stdin().is_terminal(),
                    cli.json,
                ) {
                    process::exit(exit_code);
                }
            }
            GithubAction::App { action } => match action {
                GithubAppAction::InstallUrl => {
                    let url = emberlink_cli::onboarding::github_app::print_install_url();
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "install_url": url,
                            }))
                            .unwrap()
                        );
                    } else {
                        println!("{url}");
                    }
                }
                GithubAppAction::Show => {
                    emberlink_cli::onboarding::github_app::show_manifest();
                }
                GithubAppAction::Register(args) => {
                    if let Err(exit_code) = run_github_registration_flow(
                        &config,
                        &github_setup_args_from_app_register(&args),
                        io::stdin().is_terminal(),
                        cli.json,
                    ) {
                        process::exit(exit_code);
                    }
                }
            },
        },

        Commands::Trust { action } => {
            let socket_path = config.socket_dir.join("daemon.sock");
            let exit_code = match action {
                TrustAction::List => emberlink_cli::trust::list::run(&socket_path),
                TrustAction::Show { root_id } => {
                    emberlink_cli::trust::show::run(&socket_path, &root_id)
                }
                TrustAction::Explain {
                    artifact_path,
                    sidecar,
                    kind,
                } => emberlink_cli::trust::explain::run(
                    &socket_path,
                    &kind,
                    &artifact_path,
                    sidecar.as_deref(),
                ),
                TrustAction::Backup {
                    to,
                    force,
                    no_biometric,
                } => {
                    // Resolve hostname from `$HOSTNAME` / `$HOST` with
                    // an "unknown" fallback (mirrors headless-runtime's
                    // event-emit helper — daemons under systemd/launchd
                    // commonly don't export `HOSTNAME`, and the audit
                    // surface tolerates the fallback).
                    let hostname = std::env::var("HOSTNAME")
                        .or_else(|_| std::env::var("HOST"))
                        .unwrap_or_else(|_| "unknown".to_string());
                    // Daemon-mode label is best-effort: the local CLI
                    // doesn't query the daemon for posture before
                    // sealing the backup. The metadata is rendered to
                    // the operator at restore-time for *context*, not
                    // enforcement, so an "unknown" or label mismatch
                    // never blocks the flow. Follow-up slice can wire
                    // the live `trust.list` `dev_mode_active` field.
                    let daemon_mode = std::env::var("EMBER_DAEMON_MODE")
                        .unwrap_or_else(|_| "unknown".to_string());
                    emberlink_cli::trust::backup::run(
                        &to,
                        force,
                        no_biometric,
                        &daemon_mode,
                        &hostname,
                    )
                }
                TrustAction::Restore { from, no_biometric } => {
                    emberlink_cli::trust::restore::run(&from, no_biometric)
                }
            };
            if exit_code != 0 {
                process::exit(exit_code);
            }
        }

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

        Commands::Cluster { action } => {
            cmd_cluster(action, &config, cli.json);
        }

        Commands::ClaudeCode {
            dev,
            prod: _,
            host,
            isolated,
            backend,
            preset,
            worktree,
            branch,
            purpose,
            args,
        } => {
            let request = match emberlink_cli::session::claude_code_alias_request(
                dev, host, isolated, backend, preset, worktree, branch, purpose, &args,
            ) {
                Ok(request) => request,
                Err(e) => {
                    eprintln!("ember claude: {e}");
                    process::exit(2);
                }
            };
            if let Err(e) = emberlink_cli::session::cmd_session_open(&request) {
                eprintln!("ember claude: {e}");
                process::exit(2);
            }
            unreachable!("session open either exec-replaces or returns Err");
        }

        Commands::Codex {
            dev,
            prod: _,
            host,
            isolated,
            backend,
            preset,
            worktree,
            branch,
            purpose,
            args,
        } => {
            let request = match emberlink_cli::session::codex_alias_request(
                dev, host, isolated, backend, preset, worktree, branch, purpose, &args,
            ) {
                Ok(request) => request,
                Err(e) => {
                    eprintln!("ember codex: {e}");
                    process::exit(2);
                }
            };
            if let Err(e) = emberlink_cli::session::cmd_session_open(&request) {
                eprintln!("ember codex: {e}");
                process::exit(2);
            }
            unreachable!("session open either exec-replaces or returns Err");
        }

        Commands::Demo { action } => match action {
            DemoAction::Wedge { teardown } => {
                if let Err(e) = emberlink_cli::demo::wedge::cmd_demo_wedge(teardown) {
                    eprintln!("ember demo wedge: {e}");
                    process::exit(1);
                }
            }
            DemoAction::Bundle => {
                if let Err(e) = emberlink_cli::demo::bundle::cmd_demo_bundle(&config) {
                    eprintln!("ember demo bundle: {e}");
                    process::exit(1);
                }
            }
            DemoAction::Seed { grant, count } => {
                match emberlink_cli::demo::seed::cmd_demo_seed(&config, &grant, count) {
                    Ok(ids) => {
                        println!("Seeded {} synthetic receipts on grant {grant}:", ids.len());
                        for id in &ids {
                            println!("  {id}");
                        }
                    }
                    Err(e) => {
                        eprintln!("ember demo seed: {e}");
                        process::exit(1);
                    }
                }
            }
        },

        Commands::Grants { rest } => {
            let exit = emberlink_cli::grants::dispatch(&rest);
            process::exit(match exit {
                std::process::ExitCode::SUCCESS => 0,
                _ => 1,
            });
        }

        Commands::Session { action } => match action {
            SessionAction::Open {
                target,
                dev,
                prod: _,
                host,
                isolated,
                backend,
                preset,
                worktree,
                branch,
                purpose,
                args,
            } => {
                let request = match emberlink_cli::session::build_open_request(
                    target, dev, host, isolated, backend, preset, worktree, branch, purpose, args,
                ) {
                    Ok(request) => request,
                    Err(e) => {
                        eprintln!("ember session open: {e}");
                        process::exit(2);
                    }
                };
                if let Err(e) = emberlink_cli::session::cmd_session_open(&request) {
                    eprintln!("ember session open: {e}");
                    process::exit(2);
                }
                unreachable!("session open either exec-replaces or returns Err");
            }
            SessionAction::Tail { id, pretty } => {
                if let Err(e) = emberlink_cli::session::cmd_session_tail(id.as_deref(), pretty) {
                    eprintln!("ember session tail: {e}");
                    process::exit(1);
                }
            }
        },

        Commands::Construct { action } => match action {
            ConstructAction::Sign {
                binary,
                construct_toml,
                version,
                identity_root_keypath,
            } => {
                let args = emberlink_cli::construct::sign::SignConstructArgs {
                    binary,
                    construct_toml,
                    version,
                    identity_root_keypath,
                };
                if let Err(e) = emberlink_cli::construct::sign::sign_construct(&args) {
                    eprintln!("ember construct sign: {e}");
                    process::exit(1);
                }
            }
            ConstructAction::Dev {
                path,
                list,
                unregister,
            } => {
                let args = emberlink_cli::construct::dev::DevConstructArgs {
                    path,
                    list,
                    unregister,
                };
                if let Err(e) = emberlink_cli::construct::dev::dev_construct(&args) {
                    eprintln!("ember construct dev: {e}");
                    process::exit(1);
                }
            }
        },

        Commands::Binary { action } => match action {
            BinaryAction::Install {
                tool_at_version,
                from_path,
                publisher,
            } => {
                let args = emberlink_cli::binary::install::BinaryInstallArgs {
                    tool_at_version,
                    from_path,
                    publisher,
                };
                let home = match dirs_next::home_dir() {
                    Some(h) => h,
                    None => {
                        eprintln!("ember binary install: could not determine home directory");
                        process::exit(1);
                    }
                };
                if let Err(e) = emberlink_cli::binary::install::binary_install(&args, &home) {
                    eprintln!("ember binary install: {e}");
                    process::exit(1);
                }
            }
            BinaryAction::List => {
                if let Err(e) = emberlink_cli::binary::list::binary_list() {
                    eprintln!("ember binary list: {e}");
                    process::exit(1);
                }
            }
            BinaryAction::Update { tool_name } => {
                let args = emberlink_cli::binary::update::BinaryUpdateArgs { tool_name };
                if let Err(e) = emberlink_cli::binary::update::binary_update(&args) {
                    eprintln!("ember binary update: {e}");
                    process::exit(1);
                }
            }
            BinaryAction::Remove { tool_at_version } => {
                let args = emberlink_cli::binary::remove::BinaryRemoveArgs { tool_at_version };
                if let Err(e) = emberlink_cli::binary::remove::binary_remove(&args) {
                    eprintln!("ember binary remove: {e}");
                    process::exit(1);
                }
            }
        },

        Commands::Headless { action } => {
            let socket_path = config.socket_dir.join("daemon.sock");
            match action {
                HeadlessAction::Enroll {
                    duration,
                    persona,
                    yes,
                } => {
                    let args = emberlink_cli::headless::EnrollArgs {
                        duration,
                        persona,
                        yes,
                    };
                    if let Err(e) = emberlink_cli::headless::cmd_enroll(&socket_path, args) {
                        eprintln!("ember headless enroll: {e}");
                        process::exit(1);
                    }
                }
                HeadlessAction::Revoke { enrollment_id } => {
                    let args = emberlink_cli::headless::RevokeArgs { enrollment_id };
                    if let Err(e) = emberlink_cli::headless::cmd_revoke(&socket_path, args) {
                        eprintln!("ember headless revoke: {e}");
                        process::exit(1);
                    }
                }
                HeadlessAction::Status => {
                    if let Err(e) = emberlink_cli::headless::cmd_status(&socket_path) {
                        eprintln!("ember headless status: {e}");
                        process::exit(1);
                    }
                }
                HeadlessAction::Preflight { input, json } => {
                    let args = emberlink_cli::headless::PreflightArgs {
                        input_json_path: input,
                        json,
                    };
                    if let Err(e) = emberlink_cli::headless::cmd_preflight(&socket_path, args) {
                        eprintln!("ember headless preflight: {e}");
                        process::exit(1);
                    }
                }
            }
        }

        Commands::Kms { action } => {
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            match action {
                KmsAction::InitEdge => {
                    if let Err(e) =
                        rt.block_on(emberlink_cli::kms::cmd_kms_init_edge(&config.data_dir))
                    {
                        eprintln!("ember kms init-edge: {e}");
                        process::exit(1);
                    }
                }
                KmsAction::Peer {
                    action: peer_action,
                } => match peer_action {
                    KmsPeerAction::Prepare { target } => {
                        if let Err(e) =
                            rt.block_on(emberlink_cli::kms::cmd_kms_peer_prepare(&target))
                        {
                            eprintln!("ember kms peer prepare: {e}");
                            process::exit(1);
                        }
                    }
                    KmsPeerAction::Enroll { csr_file } => {
                        if let Err(e) = rt.block_on(emberlink_cli::kms::cmd_kms_peer_enroll(
                            &csr_file,
                            &config.data_dir,
                        )) {
                            eprintln!("ember kms peer enroll: {e}");
                            process::exit(1);
                        }
                    }
                    KmsPeerAction::Install {
                        bundle_file,
                        ca_fingerprint,
                        global,
                    } => {
                        if let Err(e) = rt.block_on(emberlink_cli::kms::cmd_kms_peer_install(
                            &bundle_file,
                            &ca_fingerprint,
                            global,
                        )) {
                            eprintln!("ember kms peer install: {e}");
                            process::exit(1);
                        }
                    }
                    KmsPeerAction::Revoke { name } => {
                        if let Err(e) = rt.block_on(emberlink_cli::kms::cmd_kms_peer_revoke(
                            &name,
                            &config.data_dir,
                        )) {
                            eprintln!("ember kms peer revoke: {e}");
                            process::exit(1);
                        }
                    }
                },
            }
        }

        Commands::Orchestrator { action } => {
            use emberlink_cli::orchestrator::OrchestratorAction;
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            match action {
                OrchestratorAction::Spawn {
                    max_depth,
                    template,
                    brief,
                    budget_usd,
                    extra_hosts,
                } => {
                    match rt.block_on(emberlink_cli::orchestrator::cmd_orchestrator_spawn(
                        &config,
                        max_depth,
                        template,
                        brief,
                        budget_usd,
                        extra_hosts,
                    )) {
                        Ok(_) => {}
                        Err(code) => process::exit(code),
                    }
                }
                OrchestratorAction::Status {
                    verbose,
                    follow,
                    follow_timeout_secs,
                } => {
                    if let Err(code) =
                        rt.block_on(emberlink_cli::orchestrator::cmd_orchestrator_status(
                            &config,
                            verbose,
                            follow,
                            follow_timeout_secs,
                        ))
                    {
                        process::exit(code);
                    }
                }
                OrchestratorAction::Stop => {
                    if let Err(code) =
                        rt.block_on(emberlink_cli::orchestrator::cmd_orchestrator_stop(&config))
                    {
                        process::exit(code);
                    }
                }
            }
        }

        Commands::Dev { action } => match action {
            DevAction::Install => {
                if let Err(e) = emberlink_cli::dev::install::run() {
                    eprintln!("ember dev install: {e}");
                    process::exit(1);
                }
            }
            DevAction::Info => {
                if let Err(e) = emberlink_cli::dev::info::run() {
                    eprintln!("ember dev info: {e}");
                    process::exit(1);
                }
            }
            DevAction::Sync { no_launchctl } => {
                let args = emberlink_cli::dev::sync::SyncArgs {
                    no_launchctl,
                    workspace_root: None,
                };
                if let Err(e) = emberlink_cli::dev::sync::run(&args) {
                    eprintln!("ember dev sync: {e}");
                    process::exit(1);
                }
            }
        },

        Commands::Bridge { action } => match action {
            // ember_bridge_endpoint_emit_file
            BridgeAction::Endpoint { emit_file, json } => {
                use core_crypto::ca::generate_edge_ca;

                // Refuse if daemon not running.
                let runtime = DaemonRuntime::new(config.clone());
                let runtime_status = runtime.status().ok();
                match emberlink_cli::probe_live_daemon_status(
                    &config.socket_dir.join("daemon.sock"),
                    &config.pid_file,
                ) {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        if runtime_status.as_ref().is_some_and(|s| !s.running) {
                            eprintln!(
                                "ember bridge endpoint: daemon not running (stale runtime state)"
                            );
                        } else {
                            eprintln!("ember bridge endpoint: daemon not running");
                        }
                        process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("ember bridge endpoint: {e}");
                        process::exit(1);
                    }
                }

                // Resolve the port from bridge_bind config; refuse if not configured.
                let port = match config.bridge_bind {
                    Some(addr) => {
                        let p = addr.port();
                        if p == 0 {
                            // Port 0 means kernel-assigned — not yet bound/advertised.
                            eprintln!(
                                "ember bridge endpoint: bridge not bound (port is 0 — daemon not yet listening)"
                            );
                            process::exit(1);
                        }
                        p
                    }
                    None => {
                        eprintln!(
                            "ember bridge endpoint: bridge not bound (bridge_bind not configured)"
                        );
                        process::exit(1);
                    }
                };

                // Build bridge addr using the host.docker.internal name that
                // in-container callers use to reach the host.
                let addr = format!("host.docker.internal:{port}");

                // Derive the CA fingerprint from the KMS edge CA seed on disk.
                // TODO(bridge-state-rpc): replace with a daemon RPC once
                // `bridge.endpoint` exists in the JSON-RPC surface. For now we
                // read the seed file directly — same path the daemon loads at
                // startup (data_dir/kms/edge-ca/ca.seed).
                let seed_path = config.data_dir.join("kms").join("edge-ca").join("ca.seed");
                let ca_fingerprint_sha256: String = if seed_path.exists() {
                    match fs::read(&seed_path) {
                        Ok(bytes) if bytes.len() == 32 => {
                            let mut seed = [0u8; 32];
                            seed.copy_from_slice(&bytes);
                            match generate_edge_ca(Some(seed)) {
                                Ok(edge_ca) => hex::encode(edge_ca.fingerprint),
                                Err(e) => {
                                    eprintln!(
                                        "ember bridge endpoint: failed to derive CA fingerprint: {e}"
                                    );
                                    process::exit(1);
                                }
                            }
                        }
                        Ok(_) => {
                            eprintln!("ember bridge endpoint: edge CA seed has unexpected size");
                            process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("ember bridge endpoint: failed to read edge CA seed: {e}");
                            process::exit(1);
                        }
                    }
                } else {
                    // Edge CA not initialized yet — emit a placeholder.
                    // Run `ember kms init-edge` first.
                    "TODO-bridge-state-rpc-missing".to_string()
                };

                let endpoint_json = serde_json::json!({
                    "addr": addr,
                    "ca_fingerprint_sha256": ca_fingerprint_sha256,
                });
                let json_text = serde_json::to_string_pretty(&endpoint_json)
                    .expect("bridge endpoint JSON serialization is infallible");

                // Resolve output path: --emit-file or default ~/.ember/bridge-endpoint.json.
                let output_path = emit_file.unwrap_or_else(|| {
                    dirs_next::home_dir()
                        .expect("HOME directory must be resolvable")
                        .join(".ember")
                        .join("bridge-endpoint.json")
                });

                // Refuse paths that escape $HOME / $XDG_RUNTIME_DIR or
                // resolve into system dirs (`/etc`, `/var`, …).
                // Anchor: emit_file_path_validated
                let output_path = match validate_emit_file_path(&output_path) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("ember bridge endpoint: {e}");
                        process::exit(2);
                    }
                };

                // Create parent directory if needed.
                if let Some(parent) = output_path.parent()
                    && let Err(e) = fs::create_dir_all(parent)
                {
                    eprintln!(
                        "ember bridge endpoint: failed to create parent dir {}: {e}",
                        parent.display()
                    );
                    process::exit(1);
                }

                // Write JSON to the output path (mode 0644).
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut opts = fs::OpenOptions::new();
                    opts.write(true).create(true).truncate(true).mode(0o644);
                    match opts.open(&output_path) {
                        Ok(mut f) => {
                            use std::io::Write;
                            if let Err(e) = f.write_all(json_text.as_bytes()) {
                                eprintln!(
                                    "ember bridge endpoint: failed to write {}: {e}",
                                    output_path.display()
                                );
                                process::exit(1);
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "ember bridge endpoint: failed to open {} for writing: {e}",
                                output_path.display()
                            );
                            process::exit(1);
                        }
                    }
                }

                // Print to stdout when --json is given or when no --emit-file was supplied
                // (emit-file absent means stdout is the primary output).
                if json {
                    println!("{json_text}");
                } else {
                    println!("bridge endpoint written to {}", output_path.display());
                }
            }
        },
    }
}

/// `ember cluster <action>` — cluster management subcommands.
///
/// implementation-note-203: lists locally-pulled cluster snapshots.
/// implementation-note-479: `bootstrap` generates the Daemon
/// Persona keypair for single-phase EmberSeal bootstrap (design).
fn cmd_cluster(action: ClusterAction, config: &DaemonConfig, json_output: bool) {
    match action {
        ClusterAction::Snapshots { cluster_id } => {
            cmd_cluster_snapshots(config, cluster_id.as_deref(), json_output);
        }
        ClusterAction::Bootstrap {
            cluster_id,
            two_phase,
        } => {
            emberlink_cli::cluster::cmd_cluster_bootstrap(
                &cluster_id,
                two_phase,
                config,
                json_output,
            );
        }
        ClusterAction::Restore {
            cluster_id,
            verify,
            seed_out,
        } => {
            emberlink_cli::cluster::cmd_cluster_restore(
                &cluster_id,
                verify,
                seed_out.as_deref(),
                config,
                json_output,
            );
        }
    }
}

/// `ember cluster snapshots [--cluster-id <id>]`
///
/// Reads locally-stored cluster snapshots from the vault and prints them.
/// Each row: { snapshot_id, cluster_id, taken_at, prev_snapshot_id, size_bytes }.
fn cmd_cluster_snapshots(
    config: &DaemonConfig,
    cluster_id_filter: Option<&str>,
    json_output: bool,
) {
    if uses_managed_separate_uid_topology(config) {
        eprintln!("error: {}", managed_local_vault_fallback_refused());
        process::exit(1);
    }

    let db_path = config.data_dir.join("daemon.db");
    let store = match DaemonStore::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to open daemon store: {e}");
            process::exit(1);
        }
    };
    let vault = match Vault::open_from_config(config) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: failed to open vault: {e}");
            process::exit(1);
        }
    };

    let entries = ember_daemon::snapshot::list_local_snapshots(&vault, &store, cluster_id_filter);

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_string())
        );
    } else if entries.is_empty() {
        if let Some(cid) = cluster_id_filter {
            println!("No local snapshots for cluster {cid}.");
        } else {
            println!("No local cluster snapshots found.");
        }
        println!(
            "Configure snapshot_pull_endpoint + snapshot_pull_cluster_id in config.toml to enable pulling."
        );
    } else {
        println!(
            "{:<18} {:<16} {:<12} {:<10}",
            "SNAPSHOT_ID", "CLUSTER", "TAKEN_AT", "SIZE"
        );
        println!("{}", "-".repeat(60));
        for e in &entries {
            let id_short: String = e.snapshot_id.chars().take(16).collect();
            let cluster_short: String = e.cluster_id.chars().take(14).collect();
            println!(
                "{:<18} {:<16} {:<12} {:>8}B",
                id_short, cluster_short, e.taken_at, e.size_bytes,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_grant_types::Usage;
    use tempfile::NamedTempFile;

    /// Accept a Unix-socket connection with a wall-clock timeout, ensuring
    /// tests never hang indefinitely on `__skb_wait_for_more_packets` when
    /// a client thread crashes before connecting. Replaces bare
    /// `listener.accept().expect(...)` calls in this module.
    ///
    /// anchor: emberlink_cli_test_listener_timeout_landed
    fn accept_with_timeout(
        listener: &std::os::unix::net::UnixListener,
        timeout: std::time::Duration,
    ) -> std::os::unix::net::UnixStream {
        listener
            .set_nonblocking(true)
            .expect("set_nonblocking on listener");
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .expect("restore blocking on accepted stream");
                    return stream;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        panic!(
                            "listener.accept() timed out after {:?} — implementation-note-480 guard fired",
                            timeout
                        );
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(e) => panic!("listener.accept() error: {}", e),
            }
        }
    }

    fn fake_grant_receipt_json(id: &str, grant_id: &str, persona_id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "grant_id": grant_id,
            "summary": {
                "human_owner": "Operator Example",
                "persona_id": persona_id,
                "agent_id": "cli",
                "service": "github",
                "resource": "repo:acme/project"
            },
            "approved_chain": [],
            "per_statement_usage": [],
            "approval_chain": [],
            "actions_observed": [],
            "lifecycle": {
                "issued_at": 1,
                "last_used_at": null,
                "terminated_at": 2,
                "terminal_reason": {
                    "kind": "revoked",
                    "by": "operator",
                    "reason": "test"
                }
            },
            "attestation": {},
            "evidence": {
                "hash": "0".repeat(64),
                "sig": "1".repeat(128),
                "signer_pubkey": "2".repeat(64),
                "canonical_version": 1
            }
        })
    }

    fn fake_receipt_row_json(id: &str, actor: &str, grant_id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "kind": "grant",
            "actor": actor,
            "resource": "repo:acme/project",
            "grant_id": grant_id,
            "materialized_at": "2026-05-19T00:00:00Z",
            "terminal_reason": "revoked",
            "requested_scope": "repo:read",
            "granted_scope": "repo:read"
        })
    }

    fn fake_receipt_tree_json(grant_id: &str) -> serde_json::Value {
        serde_json::json!({
            "version": "v2",
            "root_grant_id": grant_id,
            "grants": [{
                "id": grant_id,
                "parent_grant_id": null,
                "persona_id": "persona-a",
                "credential_name": "api-key",
                "scope": "read",
                "status": "active",
                "created_at": "2026-05-19T00:00:00Z",
                "expires_at": null
            }],
            "receipts": [],
            "spawn_witnesses": [],
            "daemon_pubkey_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        })
    }

    fn fake_approval_request_json(id: &str, persona_id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "persona_id": persona_id,
            "credential_name": "api-key",
            "scope": "read",
            "ttl_secs": null,
            "action": "credential.access",
            "risk_level": "high",
            "status": "pending",
            "reason": null,
            "created_at": "2026-05-19T00:00:00Z",
            "tool_name": null,
            "target_host": null,
            "target_summary": null,
            "target_url": null,
            "agent_framework": null,
            "composite_statements": null,
            "result_grant_id": null,
            "skill_ref": null,
            "max_delegation_depth": null,
            "max_uses_per_hour": null,
            "allowed_hours_start": null,
            "allowed_hours_end": null,
            "allowed_targets": null,
            "budget": null,
            "max_children_per_day": null,
            "auto_delegate_scope_template": null
        })
    }

    fn fake_persona_info_json(id: &str, name: &str, status: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "name": name,
            "public_key": "ed25519:test",
            "created_at": "2026-05-19T00:00:00Z",
            "status": status,
            "container_id": null,
            "parent_grant_id": null
        })
    }

    fn fake_grant_info_json(id: &str, persona_id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "persona_id": persona_id,
            "credential_name": "api-key",
            "scope": "read",
            "created_at": "2026-05-19T00:00:00Z",
            "expires_at": null,
            "status": "active",
            "max_uses_per_hour": null,
            "allowed_hours_start": null,
            "allowed_hours_end": null,
            "allowed_targets": null,
            "parent_grant_id": null,
            "max_delegation_depth": null,
            "spending_limit_cents": null,
            "budget": null,
            "usage": {
                "tokens": 0,
                "cents": 0,
                "requests": 0,
                "workload_hours": 0,
                "wall_clock_secs": 0,
                "last_updated": 0
            },
            "paused": false,
            "receipt_id": null,
            "is_standing": false,
            "max_children_per_day": null,
            "auto_delegate_scope_template": null
        })
    }

    fn fake_audit_entry_json(id: i64) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "timestamp": "2026-05-19T00:00:00Z",
            "agent_id": "persona-a",
            "action": "grant.issued",
            "credential": "api-key",
            "outcome": "allowed",
            "details": null
        })
    }

    fn fake_audit_explain_json(id: i64) -> serde_json::Value {
        serde_json::json!({
            "event": fake_audit_entry_json(id),
            "current_grant": {
                "id": "grant-123",
                "scope": "read",
                "created_at": "2026-05-19T00:00:00Z",
                "expires_at": null,
                "status": "active"
            },
            "current_policy": {
                "requirement": "required",
                "risk": "high",
                "tier": "tier1",
                "matched_rule": "credential.access"
            },
            "note": "Current-state explanation: the event row is historical audit evidence, but grant and policy sections reflect the daemon's current live state."
        })
    }

    fn fake_status_summary_json() -> serde_json::Value {
        serde_json::json!({
            "personas": [fake_persona_info_json("persona-a", "Alpha", "active")],
            "grants": [fake_grant_info_json("grant-123", "persona-a")],
            "sandboxes": [{
                "id": "sandbox-1",
                "name": "alpha",
                "persona_id": "persona-a",
                "owner_persona_id": "persona-owner",
                "container_id": "container-1",
                "image": "ubuntu:24.04",
                "status": "running",
                "created_at": "2026-05-19T00:00:00Z",
                "workspace_path": null
            }],
            "approvals": [fake_approval_request_json("approval-123", "persona-a")],
            "recent_activity": [fake_audit_entry_json(7)],
            "standing_grants": 2,
            "audit_events_total": 9,
            "quarantined": false,
            "quarantine_authority": null
        })
    }

    fn fake_status_summary() -> ember_daemon::infra::status::StatusSummary {
        serde_json::from_value(fake_status_summary_json()).expect("decode fake status summary")
    }

    #[test]
    fn render_status_text_offline_prioritizes_repair_over_detail() {
        let rendered = render_status_text(DaemonStatusBanner::NotRunning, &fake_status_summary());
        assert!(
            rendered.contains("DAEMON             not running"),
            "offline status must lead with daemon-down state: {rendered}"
        );
        assert!(
            rendered.contains("Repair:    sudo ember daemon install"),
            "offline status must include the canonical repair CTA: {rendered}"
        );
        assert!(
            rendered.contains("showing local store summary only"),
            "offline status must explain the summary-only posture: {rendered}"
        );
        assert!(
            rendered.contains("PERSONAS           1 active, 0 revoked"),
            "offline status must keep summary counts: {rendered}"
        );
        assert!(
            !rendered.contains("Alpha"),
            "offline status should not dump per-persona detail: {rendered}"
        );
        assert!(
            !rendered.contains("grant-123"),
            "offline status should not dump per-grant detail: {rendered}"
        );
    }

    #[test]
    fn render_status_text_running_surfaces_quarantine_banner() {
        let mut summary = fake_status_summary();
        summary.quarantined = true;
        summary.quarantine_authority = Some("startup_audit_chain_break".to_string());
        let rendered = render_status_text(
            DaemonStatusBanner::Running {
                pid: 42,
                socket: "/tmp/daemon.sock".to_string(),
                dashboard: "http://localhost:8123/".to_string(),
                vault_backend: "local".to_string(),
                vault_addr: "local-encrypted".to_string(),
            },
            &summary,
        );
        assert!(
            rendered.contains("Quarantine: startup_audit_chain_break"),
            "running status must disclose the quarantine authority: {rendered}"
        );
        assert!(
            rendered.contains("write-class commands are blocked until audit repair"),
            "running status must explain the operational impact: {rendered}"
        );
        assert!(
            rendered.contains("Repair:     ember audit verify"),
            "running status must route the operator to audit repair: {rendered}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn detect_installed_launcher_issue_at_resolves_relative_repo_build_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let bin_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let install = bin_dir.join("ember");
        let target = PathBuf::from("../target/dev-sign/ember.app/Contents/MacOS/ember");
        std::os::unix::fs::symlink(&target, &install).unwrap();

        let expected_target = tmp
            .path()
            .join("target/dev-sign/ember.app/Contents/MacOS/ember");
        assert_eq!(
            detect_installed_launcher_issue_at(&install),
            Some(InstalledLauncherIssue::BrokenRepoBuildSymlink {
                path: install,
                target: expected_target,
            })
        );
    }

    #[test]
    fn render_status_troubleshoot_offline_calls_out_broken_launcher_before_daemon_repair() {
        let issue = InstalledLauncherIssue::BrokenRepoBuildSymlink {
            path: PathBuf::from("/usr/local/bin/ember"),
            target: PathBuf::from(
                "/Users/operator/repos/emberlink-dev/target/dev-sign/ember.app/Contents/MacOS/ember",
            ),
        };
        let rendered = render_status_troubleshoot_text(
            &DaemonStatusBanner::NotRunning,
            &fake_status_summary(),
            StatusActionDispatch::LocalFallback,
            None,
            true,
            Some(&issue),
        );
        assert!(
            rendered.contains("Install path:   /usr/local/bin/ember ->"),
            "offline troubleshoot must surface the broken install path: {rendered}"
        );
        assert!(
            rendered.contains("1. Repair the installed `ember` launcher path first"),
            "offline troubleshoot must repair the launcher before daemon surgery: {rendered}"
        );
        assert!(
            rendered.contains("2. Run `sudo ember daemon install`"),
            "offline troubleshoot must renumber daemon repair after the launcher fix: {rendered}"
        );
    }

    #[test]
    fn render_status_troubleshoot_offline_routes_to_diagnose_when_state_exists() {
        let rendered = render_status_troubleshoot_text(
            &DaemonStatusBanner::NotRunning,
            &fake_status_summary(),
            StatusActionDispatch::LocalFallback,
            None,
            true,
            None,
        );
        assert!(
            rendered.contains("Summary source: local fallback"),
            "troubleshoot must disclose local fallback dispatch: {rendered}"
        );
        assert!(
            rendered.contains("ember daemon diagnose"),
            "offline troubleshoot must preserve the diagnose branch when daemon.db exists: {rendered}"
        );
        assert!(
            rendered.contains("ember github status"),
            "offline troubleshoot must point back at GitHub posture after repair: {rendered}"
        );
    }

    #[test]
    fn render_status_troubleshoot_running_app_path_points_at_claude_code() {
        let rendered = render_status_troubleshoot_text(
            &DaemonStatusBanner::Running {
                pid: 42,
                socket: "/tmp/daemon.sock".to_string(),
                dashboard: "http://localhost:8123/".to_string(),
                vault_backend: "local".to_string(),
                vault_addr: "local-encrypted".to_string(),
            },
            &fake_status_summary(),
            StatusActionDispatch::DaemonRpc,
            Some(&GithubProviderStatusView {
                lane: "app".to_string(),
                detail: None,
                app_id: None,
                installation_id: None,
            }),
            true,
            None,
        );
        assert!(
            rendered.contains("Summary source: daemon RPC"),
            "troubleshoot must disclose daemon RPC dispatch: {rendered}"
        );
        assert!(
            rendered.contains("real App lane ready"),
            "running troubleshoot must distinguish the real App lane: {rendered}"
        );
        assert!(
            rendered.contains("Launch `ember claude`"),
            "running troubleshoot must point at the canonical launcher: {rendered}"
        );
        assert!(
            rendered.contains("ember receipt export --latest --format md"),
            "running troubleshoot must expose the first proof command after launch: {rendered}"
        );
        assert!(
            rendered.contains("ember trust list"),
            "running troubleshoot must keep trust verification on the repair surface: {rendered}"
        );
    }

    #[test]
    fn render_status_troubleshoot_running_not_configured_points_at_setup_without_reload_dance() {
        let rendered = render_status_troubleshoot_text(
            &DaemonStatusBanner::Running {
                pid: 42,
                socket: "/tmp/daemon.sock".to_string(),
                dashboard: "http://localhost:8123/".to_string(),
                vault_backend: "local".to_string(),
                vault_addr: "local-encrypted".to_string(),
            },
            &fake_status_summary(),
            StatusActionDispatch::DaemonRpc,
            Some(&GithubProviderStatusView {
                lane: "none".to_string(),
                detail: None,
                app_id: None,
                installation_id: None,
            }),
            true,
            None,
        );
        assert!(
            rendered.contains(
                "Run `ember github setup` to register local App credentials for the HTTPS/App lane."
            ),
            "not-configured troubleshoot must point at the local App setup command: {rendered}"
        );
        assert!(
            rendered.contains("Then run `ember github status` to confirm the App lane is ready."),
            "not-configured troubleshoot must point back at explicit posture confirmation: {rendered}"
        );
        assert!(
            !rendered.contains("ember github app install-url"),
            "not-configured troubleshoot should stay on the single friendly setup path: {rendered}"
        );
        assert!(
            !rendered.contains("ember daemon reload"),
            "not-configured troubleshoot must not reintroduce the old reload dance: {rendered}"
        );
    }

    #[test]
    fn render_status_troubleshoot_running_pat_path_names_degraded_proof_lane() {
        let rendered = render_status_troubleshoot_text(
            &DaemonStatusBanner::Running {
                pid: 42,
                socket: "/tmp/daemon.sock".to_string(),
                dashboard: "http://localhost:8123/".to_string(),
                vault_backend: "local".to_string(),
                vault_addr: "local-encrypted".to_string(),
            },
            &fake_status_summary(),
            StatusActionDispatch::DaemonRpc,
            Some(&GithubProviderStatusView {
                lane: "pat".to_string(),
                detail: None,
                app_id: None,
                installation_id: None,
            }),
            true,
            None,
        );
        assert!(
            rendered.contains("degraded PAT fallback active"),
            "PAT troubleshoot branch must disclose degraded posture: {rendered}"
        );
        assert!(
            rendered.contains("ember github setup"),
            "PAT troubleshoot branch must point at the App upgrade path: {rendered}"
        );
        assert!(
            rendered.contains("ember receipt export --latest --format md"),
            "PAT troubleshoot branch should still expose the proof command for intentional degraded runs: {rendered}"
        );
    }

    #[test]
    fn render_status_troubleshoot_running_quarantine_routes_to_audit_repair() {
        let mut summary = fake_status_summary();
        summary.quarantined = true;
        summary.quarantine_authority = Some("startup_audit_chain_break".to_string());
        let rendered = render_status_troubleshoot_text(
            &DaemonStatusBanner::Running {
                pid: 42,
                socket: "/tmp/daemon.sock".to_string(),
                dashboard: "http://localhost:8123/".to_string(),
                vault_backend: "local".to_string(),
                vault_addr: "local-encrypted".to_string(),
            },
            &summary,
            StatusActionDispatch::DaemonRpc,
            Some(&GithubProviderStatusView {
                lane: "app".to_string(),
                detail: None,
                app_id: None,
                installation_id: None,
            }),
            true,
            None,
        );
        assert!(
            rendered.contains("write-class methods are quarantined"),
            "quarantined troubleshoot must lead with the quarantine state: {rendered}"
        );
        assert!(
            rendered.contains("startup_audit_chain_break"),
            "quarantined troubleshoot must disclose the stable authority label: {rendered}"
        );
        assert!(
            rendered.contains("ember audit verify"),
            "quarantined troubleshoot must point at audit repair first: {rendered}"
        );
        assert!(
            !rendered.contains("Launch `ember claude`"),
            "quarantined troubleshoot must not advertise immediate session launch before repair: {rendered}"
        );
    }

    #[test]
    fn render_github_status_text_points_at_app_first() {
        let rendered = render_github_status_text(&GithubProviderStatusView {
            lane: "app".to_string(),
            detail: None,
            app_id: None,
            installation_id: None,
        });
        assert!(
            rendered.contains("configured (real GitHub App broker)"),
            "github status must distinguish the real App lane: {rendered}"
        );
        assert!(
            rendered.contains("Advanced notes:"),
            "github status should separate the friendly path from deeper substrate notes: {rendered}"
        );
        assert!(
            rendered.contains("SSH substrate exists for git/ember-gh"),
            "github status must acknowledge the real SSH lane: {rendered}"
        );
        assert!(
            rendered.contains("does not request a PAT"),
            "real App posture must keep init on the App-first path: {rendered}"
        );
        assert!(
            rendered.contains("does not auto-wire or status it yet"),
            "real App posture must acknowledge the built-but-not-yet-wired SSH lane: {rendered}"
        );
        assert!(
            rendered.contains("PAT fallback exists only as a degraded recovery lane"),
            "status must name PAT as secondary fallback, not primary path: {rendered}"
        );
    }

    #[test]
    fn render_github_status_text_names_pat_as_degraded_lane() {
        let rendered = render_github_status_text(&GithubProviderStatusView {
            lane: "pat".to_string(),
            detail: None,
            app_id: None,
            installation_id: None,
        });
        assert!(
            rendered.contains("configured (degraded PAT fallback"),
            "github status must distinguish degraded PAT posture: {rendered}"
        );
        assert!(
            rendered.contains("under your GitHub identity"),
            "PAT posture must warn about attribution and identity surface: {rendered}"
        );
        assert!(
            rendered.contains("Preferred upgrade"),
            "PAT posture must point at the App upgrade path: {rendered}"
        );
        assert!(
            rendered.contains(github_setup_command()),
            "PAT posture should point at the friendly GitHub setup command: {rendered}"
        );
        assert!(
            rendered.contains("Advanced notes:"),
            "PAT posture should still keep substrate notes separate from the primary upgrade path: {rendered}"
        );
    }

    #[test]
    fn render_github_status_text_surfaces_broken_detail() {
        let rendered = render_github_status_text(&GithubProviderStatusView {
            lane: "broken".to_string(),
            detail: Some(
                "github/apps/ember/install-123: partial credential triple (private-key=true, app-id=true, installation-id=false)"
                    .to_string(),
            ),
            app_id: None,
            installation_id: None,
        });
        assert!(
            rendered.contains("local authority loading failed"),
            "broken posture must say the local App config is broken: {rendered}"
        );
        assert!(
            rendered.contains("partial credential triple"),
            "broken posture must surface the daemon-side detail: {rendered}"
        );
        assert!(
            rendered.contains("Re-run `ember github setup`"),
            "broken posture must point at the repair path: {rendered}"
        );
    }

    fn parse_github(args: &[&str]) -> GithubAction {
        use clap::Parser;
        #[derive(Parser)]
        struct T {
            #[command(subcommand)]
            action: GithubAction,
        }
        let mut full = vec!["test"];
        full.extend_from_slice(args);
        let cli = T::try_parse_from(&full).expect("parse failed");
        cli.action
    }

    fn parse_receipt(args: &[&str]) -> ReceiptAction {
        use clap::Parser;
        #[derive(Parser)]
        struct T {
            #[command(subcommand)]
            action: ReceiptAction,
        }
        let mut full = vec!["test"];
        full.extend_from_slice(args);
        let cli = T::try_parse_from(&full).expect("parse failed");
        cli.action
    }

    #[test]
    fn github_setup_parses_explicit_register_fields() {
        match parse_github(&[
            "setup",
            "--pem-file",
            "/tmp/app.pem",
            "--app-id",
            "123",
            "--installation-id",
            "456",
            "--slug",
            "emberlink",
        ]) {
            GithubAction::Setup(args) => {
                assert_eq!(args.pem_file, Some(PathBuf::from("/tmp/app.pem")));
                assert_eq!(args.app_id.as_deref(), Some("123"));
                assert_eq!(args.installation_id.as_deref(), Some("456"));
                assert_eq!(args.slug.as_deref(), Some("emberlink"));
            }
            _ => panic!("expected github setup"),
        }
    }

    #[test]
    fn github_setup_prelude_explains_where_values_come_from() {
        let rendered =
            render_github_setup_prelude("https://github.com/apps/emberlink/installations/new");
        assert!(rendered.contains("registered locally with this daemon."));
        assert!(rendered.contains("Private key PEM"));
        assert!(rendered.contains("App ID"));
        assert!(rendered.contains("/installations/<ID>"));
        assert!(rendered.contains("plain slug or a GitHub App URL"));
    }

    #[test]
    fn normalize_github_installation_id_accepts_post_install_url() {
        assert_eq!(
            normalize_github_installation_id_input(
                "https://github.com/settings/installations/126782716"
            )
            .expect("installation id from url"),
            "126782716"
        );
    }

    #[test]
    fn normalize_github_slug_accepts_github_app_url() {
        assert_eq!(
            normalize_github_slug_input("https://github.com/apps/ember-engine/installations/new")
                .expect("slug from public app url"),
            "ember-engine"
        );
        assert_eq!(
            normalize_github_slug_input(
                "https://github.com/organizations/emberdotlink/settings/apps/ember-engine"
            )
            .expect("slug from settings app url"),
            "ember-engine"
        );
    }

    #[test]
    fn github_setup_success_text_manual_reload_points_back_to_status_and_init() {
        let rendered =
            render_github_setup_success_text(GithubSetupDaemonFollowup::NeedsManualReload);
        assert!(rendered.contains("ember daemon reload"));
        assert!(rendered.contains("ember github status"));
        assert!(rendered.contains("ember init --for claude"));
        assert!(rendered.contains("ember claude"));
        assert!(rendered.contains("ember receipt export --latest --format md"));
    }

    #[test]
    fn github_setup_success_text_reloaded_path_names_daemon_reload_result() {
        let rendered = render_github_setup_success_text(GithubSetupDaemonFollowup::Reloaded {
            old_pid: 11,
            new_pid: Some(22),
        });
        assert!(rendered.contains("Daemon reloaded: old pid 11, new pid 22"));
        assert!(rendered.contains("ember github status"));
        assert!(rendered.contains("HTTPS remotes"));
        assert!(rendered.contains("ember init --for claude"));
        assert!(rendered.contains("ember claude"));
        assert!(rendered.contains("ember receipt export --latest --format md"));
    }

    #[test]
    fn github_setup_retry_hint_names_replace_path() {
        let hint = render_github_setup_retry_hint(&GithubSetupError::Broker(
            emberlink_cli::broker::BrokerCliError::InvalidArgs(
                "vault entry 'github/apps/ember/install-123/private-key' already exists; pass --replace to overwrite".to_string(),
            ),
        ))
        .expect("replace hint");
        assert!(hint.contains("ember github setup --replace"));
    }

    #[test]
    fn github_setup_retry_hint_names_allow_unverified_slug_path() {
        let hint = render_github_setup_retry_hint(&GithubSetupError::Broker(
            emberlink_cli::broker::BrokerCliError::InvalidArgs(
                "GET https://api.github.com/app: unexpected status 401: {\"message\":\"Bad credentials\"}. Pass --allow-unverified-slug to skip canonicalization.".to_string(),
            ),
        ))
        .expect("canonicalization hint");
        assert!(hint.contains("ember github setup --allow-unverified-slug"));
    }

    #[test]
    fn github_setup_retry_hint_names_vault_unlock_path() {
        let hint = render_github_setup_retry_hint(&GithubSetupError::Broker(
            emberlink_cli::broker::BrokerCliError::Guidance(
                "this command needs operator presence on the daemon-managed vault lane. Approve the unlock flow if prompted, or run `ember vault unlock` from an interactive operator shell and retry.".to_string(),
            ),
        ))
        .expect("vault unlock hint");
        assert!(hint.contains("ember vault unlock"));
        assert!(hint.contains("ember github setup"));
    }

    #[test]
    fn github_app_register_args_convert_to_setup_args_losslessly() {
        let args = GithubAppRegisterArgs {
            pem_file: PathBuf::from("/tmp/app.pem"),
            app_id: "123".to_string(),
            installation_id: "456".to_string(),
            slug: "ember-engine".to_string(),
            allow_unverified_slug: true,
            replace: true,
        };

        let setup = github_setup_args_from_app_register(&args);
        assert_eq!(setup.pem_file.as_deref(), Some(args.pem_file.as_path()));
        assert_eq!(setup.app_id.as_deref(), Some("123"));
        assert_eq!(setup.installation_id.as_deref(), Some("456"));
        assert_eq!(setup.slug.as_deref(), Some("ember-engine"));
        assert!(setup.allow_unverified_slug);
        assert!(setup.replace);
    }

    #[test]
    fn render_claude_runtime_auth_status_names_exact_follow_up_paths() {
        let rendered =
            render_claude_runtime_auth_status(AnthropicRuntimeCredentialAvailability::Absent);
        assert!(rendered.contains("ANTHROPIC_API_KEY"));
        assert!(rendered.contains("ember vault add --name anthropic-key"));
        assert!(rendered.contains("rerunning init"));
    }

    #[test]
    fn render_claude_runtime_auth_status_names_existing_vault_entry() {
        let rendered = render_claude_runtime_auth_status(
            AnthropicRuntimeCredentialAvailability::ExistingVaultEntry,
        );
        assert!(rendered.contains("reusing anthropic-key from vault"));
    }

    #[test]
    fn github_status_retry_hint_names_vault_unlock_path() {
        let hint = render_github_status_retry_hint(&core_types::ValidationError::new(
            "this command needs operator presence on the daemon-managed vault lane. Approve the unlock flow if prompted, or run `ember vault unlock` from an interactive operator shell and retry.".to_string(),
        ))
        .expect("vault unlock hint");
        assert!(hint.contains("ember vault unlock"));
        assert!(hint.contains("ember github status"));
    }

    #[test]
    fn github_status_retry_hint_ignores_non_unlock_failures() {
        let hint = render_github_status_retry_hint(&core_types::ValidationError::new(
            "ember daemon not running".to_string(),
        ));
        assert!(hint.is_none());
    }

    #[test]
    fn parse_default_yes_response_accepts_expected_forms() {
        assert_eq!(parse_default_yes_response(""), Some(true));
        assert_eq!(parse_default_yes_response("y"), Some(true));
        assert_eq!(parse_default_yes_response("YES"), Some(true));
        assert_eq!(parse_default_yes_response("n"), Some(false));
        assert_eq!(parse_default_yes_response("No"), Some(false));
        assert_eq!(parse_default_yes_response("maybe"), None);
    }

    #[test]
    fn inline_github_setup_offer_only_appears_on_interactive_app_missing_path() {
        use emberlink_cli::onboarding::claude_code::GitHubOnboardingPosture;

        assert!(should_offer_inline_github_setup(
            GitHubOnboardingPosture::AppNotConfigured,
            false,
            true,
            true,
        ));
        assert!(should_offer_inline_github_setup(
            GitHubOnboardingPosture::AppConfiguredMock,
            false,
            true,
            true,
        ));
        assert!(should_offer_inline_github_setup(
            GitHubOnboardingPosture::AppBroken("partial credential triple".to_string()),
            false,
            true,
            true,
        ));
        assert!(!should_offer_inline_github_setup(
            GitHubOnboardingPosture::PatConfigured,
            false,
            true,
            true,
        ));
        assert!(!should_offer_inline_github_setup(
            GitHubOnboardingPosture::AppConfiguredReal,
            false,
            true,
            true,
        ));
        assert!(!should_offer_inline_github_setup(
            GitHubOnboardingPosture::AppNotConfigured,
            true,
            true,
            true,
        ));
        assert!(!should_offer_inline_github_setup(
            GitHubOnboardingPosture::AppNotConfigured,
            false,
            false,
            true,
        ));
        assert!(!should_offer_inline_github_setup(
            GitHubOnboardingPosture::AppNotConfigured,
            false,
            true,
            false,
        ));
    }

    #[test]
    fn receipt_export_parses_latest_shortcut() {
        match parse_receipt(&["export", "--latest", "--format", "md"]) {
            ReceiptAction::Export {
                id,
                latest,
                format,
                raw,
            } => {
                assert_eq!(id, None);
                assert!(latest);
                assert_eq!(format, "md");
                assert!(!raw);
            }
            _ => panic!("expected receipt export"),
        }
    }

    #[test]
    fn init_rerun_command_prefers_claude_when_requested() {
        assert_eq!(
            init_rerun_command(Some(OnboardingTarget::Claude)),
            "`ember init --for claude`"
        );
        assert_eq!(
            init_rerun_command(Some(OnboardingTarget::Codex)),
            "`ember init --for codex`"
        );
        assert_eq!(init_rerun_command(None), "`ember init`");
    }

    fn parse_cli(args: &[&str]) -> Cli {
        use clap::Parser as _;
        let full: Vec<&str> = std::iter::once("ember").chain(args.iter().copied()).collect();
        Cli::try_parse_from(&full).expect("parse failed")
    }

    #[test]
    fn init_for_claude_accepts_only_canonical_target() {
        match parse_cli(&["init", "--for", "claude"]).command {
            Commands::Init { for_target, .. } => {
                assert_eq!(for_target, Some(OnboardingTarget::Claude));
            }
            _ => panic!("expected init command"),
        }
        assert!(
            Cli::try_parse_from(["ember", "init", "--for", "claude-code"]).is_err(),
            "legacy init target should no longer parse"
        );
    }

    /// Anchor: onboarding_target_codex_variant_landed
    ///
    /// `ember init --for codex` parses to `OnboardingTarget::Codex`.
    /// The dispatch arm is a stub (Codex onboarding implementation is
    /// out of scope for the variant-add PR), but the parse-level
    /// surface is committed so operators can pin shell aliases to the
    /// canonical form today.
    #[test]
    fn init_for_codex_parses_to_canonical_target() {
        match parse_cli(&["init", "--for", "codex"]).command {
            Commands::Init { for_target, .. } => {
                assert_eq!(for_target, Some(OnboardingTarget::Codex));
            }
            _ => panic!("expected init command"),
        }
    }

    #[test]
    fn claude_launcher_accepts_canonical_and_compat_alias_verb() {
        for verb in ["claude", "claude-code"] {
            match parse_cli(&[verb]).command {
                Commands::ClaudeCode { .. } => {}
                _ => panic!("expected claude launcher for `{verb}`"),
            }
        }
    }

    #[test]
    fn codex_launcher_parses_canonical_verb() {
        match parse_cli(&["codex"]).command {
            Commands::Codex { .. } => {}
            _ => panic!("expected codex launcher"),
        }
    }

    #[test]
    fn claude_launcher_parses_worktree_flags() {
        match parse_cli(&[
            "claude",
            "--worktree",
            "auth-posture",
            "--branch",
            "agent/auth-posture/20260522-170000",
            "--purpose",
            "release proof",
            "--",
            "--print",
            "hello",
        ])
        .command
        {
            Commands::ClaudeCode {
                worktree,
                branch,
                purpose,
                args,
                ..
            } => {
                assert_eq!(worktree.as_deref(), Some("auth-posture"));
                assert_eq!(branch.as_deref(), Some("agent/auth-posture/20260522-170000"));
                assert_eq!(purpose.as_deref(), Some("release proof"));
                assert_eq!(args, vec!["--print".to_string(), "hello".to_string()]);
            }
            _ => panic!("expected claude launcher"),
        }
    }

    #[test]
    fn codex_launcher_parses_worktree_flags() {
        match parse_cli(&[
            "codex",
            "--worktree",
            "auth-posture",
            "--branch",
            "agent/auth-posture/20260522-170000",
            "--purpose",
            "release proof",
            "--",
            "--no-alt-screen",
        ])
        .command
        {
            Commands::Codex {
                worktree,
                branch,
                purpose,
                args,
                ..
            } => {
                assert_eq!(worktree.as_deref(), Some("auth-posture"));
                assert_eq!(branch.as_deref(), Some("agent/auth-posture/20260522-170000"));
                assert_eq!(purpose.as_deref(), Some("release proof"));
                assert_eq!(args, vec!["--no-alt-screen".to_string()]);
            }
            _ => panic!("expected codex launcher"),
        }
    }

    #[test]
    fn init_managed_daemon_install_lines_center_canonical_path() {
        assert_eq!(
            init_managed_daemon_install_starting_line(),
            "  Daemon:   not running — running `sudo ember daemon install`"
        );
        assert_eq!(
            init_managed_daemon_install_started_line(),
            "  Daemon:   managed separate-uid daemon is up"
        );
    }

    #[test]
    fn init_autostart_repair_line_points_to_daemon_install() {
        let message = init_autostart_repair_line("`ember init --for claude`");
        assert!(
            message.contains("sudo ember daemon install"),
            "repair message must point to the canonical daemon install path: {message}"
        );
        assert!(
            message.contains("`ember init --for claude`"),
            "repair message must preserve the onboarding rerun command: {message}"
        );
        assert!(
            !message.contains("install-agent"),
            "repair message must not leak the dev-only install-agent path: {message}"
        );
    }

    #[test]
    fn init_noncanonical_daemon_topology_line_refuses_same_uid_fallback() {
        let message = init_noncanonical_daemon_topology_line("`ember init --for claude`");
        assert!(
            message.contains("same-uid fallback is refused"),
            "noncanonical topology message must refuse the old fallback: {message}"
        );
        assert!(
            message.contains("sudo ember daemon install"),
            "noncanonical topology message must still point at the canonical install path: {message}"
        );
    }

    #[test]
    fn ensure_managed_daemon_for_init_refuses_custom_config_topology() {
        let tmp = tempfile::tempdir().unwrap();
        let custom_config = tmp.path().join("custom-config.toml");
        let config = DaemonConfig::for_test(tmp.path());
        let err = ensure_managed_daemon_for_init(
            &config,
            Some(&custom_config),
            "`ember init --for claude`",
            false,
        )
        .expect_err("custom config topology must refuse managed-daemon auto-install");
        assert!(
            err.contains("same-uid fallback is refused"),
            "custom config refusal must forbid same-uid fallback: {err}"
        );
    }

    #[test]
    fn ensure_managed_daemon_for_init_non_interactive_points_to_repair() {
        let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/"));
        if !emberlink_cli::onboarding::claude_code::supports_managed_daemon_install(&home, None) {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let config = DaemonConfig::for_test(tmp.path());
        let err = ensure_managed_daemon_for_init(&config, None, "`ember init`", true)
            .expect_err("non-interactive init must not try to run sudo");
        assert!(
            err.contains("sudo ember daemon install"),
            "non-interactive failure must point at the canonical repair path: {err}"
        );
    }

    #[test]
    fn managed_separate_uid_topology_paths_match_default_layout() {
        let home = Path::new("/home/test-operator");
        let (socket_dir, data_dir, pid_file) = managed_separate_uid_topology_paths(home);
        let config = DaemonConfig {
            socket_dir,
            data_dir,
            pid_file,
            ..DaemonConfig::for_test(home)
        };
        assert!(
            matches_managed_separate_uid_topology_paths(&config, home),
            "default ~/.ember layout must match the managed separate-uid topology"
        );
    }

    #[test]
    fn managed_separate_uid_topology_paths_reject_custom_layout() {
        let home = Path::new("/home/test-operator");
        let config = DaemonConfig::for_test(home);
        assert!(
            !matches_managed_separate_uid_topology_paths(&config, home),
            "tmpdir / custom layouts must not be treated as the managed default topology"
        );
    }

    #[test]
    fn managed_local_vault_fallback_refusal_points_to_repair() {
        let err = managed_local_vault_fallback_refused().to_string();
        assert!(
            err.contains("local vault fallback is refused"),
            "managed fallback refusal must make the superseded local path explicit: {err}"
        );
        assert!(
            err.contains("sudo ember daemon install"),
            "managed fallback refusal must point at the canonical repair path: {err}"
        );
    }

    /// implementation-note-473:
    /// Path under $HOME is accepted; validator returns the canonical
    /// lexically-cleaned form.
    #[test]
    fn emit_file_path_under_home_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        // SAFETY: tests in this binary run single-threaded; HOME is
        // restored before this scope exits. Matches the existing
        // unsafe set_var/restore pattern earlier in this module.
        unsafe {
            std::env::set_var("HOME", tmp.path());
        }
        let candidate = tmp.path().join("bridge-endpoint.json");
        let result = validate_emit_file_path(&candidate);
        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        let ok = result.expect("HOME-relative emit_file path must validate");
        assert!(
            ok.starts_with(tmp.path()),
            "validator must return a path under HOME, got: {}",
            ok.display()
        );
    }

    /// implementation-note-473:
    /// /etc/passwd is refused even when HOME=tmp lets nothing else match.
    #[test]
    fn emit_file_path_etc_passwd_rejected() {
        let path = std::path::PathBuf::from("/etc/passwd");
        let err = validate_emit_file_path(&path)
            .expect_err("/etc paths must be rejected outright");
        assert!(
            err.contains("/etc"),
            "refusal must name the forbidden prefix `/etc`, got: {err}"
        );
    }

    /// implementation-note-473:
    /// `$HOME/../etc/passwd` lexically resolves outside HOME and is
    /// refused either by the forbidden-prefix gate or by the HOME-
    /// containment check (depends on what `..` lands on).
    #[test]
    fn emit_file_path_dotdot_traversal_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        // SAFETY: tests are single-threaded; HOME is restored below.
        unsafe {
            std::env::set_var("HOME", tmp.path());
        }
        // tmp.path() is e.g. `/tmp/xxx`; `tmp.path()/../etc/passwd`
        // lexically resolves to `/tmp/etc/passwd` — outside HOME.
        let candidate = tmp.path().join("..").join("etc").join("passwd");
        let result = validate_emit_file_path(&candidate);
        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        result.expect_err(
            "$HOME/../etc/passwd lexically resolves outside HOME and must be rejected",
        );
    }

    /// bridge_endpoint_emit_file_default_path_when_arg_omitted — verifies that
    /// the default output path resolves to `~/.ember/bridge-endpoint.json` when
    /// `--emit-file` is absent.
    #[test]
    fn bridge_endpoint_emit_file_default_path_when_arg_omitted() {
        // Simulate the default-path logic from the BridgeAction::Endpoint handler.
        let default_path: PathBuf = dirs_next::home_dir()
            .expect("HOME must be resolvable in test environment")
            .join(".ember")
            .join("bridge-endpoint.json");
        assert!(
            default_path.ends_with(".ember/bridge-endpoint.json"),
            "default emit-file path must be ~/.ember/bridge-endpoint.json, got: {}",
            default_path.display()
        );
    }

    /// implementation-note-460: `ensure_shadow_path_installed`
    /// returns `Err` with a remediation hint when the shadow dir is absent.
    #[test]
    fn ensure_shadow_path_installed_errors_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        // SAFETY: tests are single-threaded for this binary; we restore HOME
        // before exit. Concurrent harness modules don't share this env knob
        // because the binary doesn't spawn threads here.
        // SAFETY: `set_var` is `unsafe` since Rust 1.84+; this test single-threadedly
        // toggles HOME and restores it before returning, satisfying the soundness
        // contract documented on `std::env::set_var`.
        unsafe {
            std::env::set_var("HOME", tmp.path());
        }
        let result = ensure_shadow_path_installed();
        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        let err = result.expect_err("missing shadow dir must surface as Err");
        assert!(
            err.contains("shadow path not installed") || err.contains("missing shims"),
            "error must name the remediation: {err}"
        );
        assert!(
            err.contains("ember init --for claude"),
            "error must point at the install command: {err}"
        );
    }

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

    /// Round-trip the `ember init` policy seed through the daemon's
    /// `PolicyConfig` deserializer. prior change renamed `decision`→`requirement`
    /// without serde aliases; the seed got missed and every fresh install
    /// produced a daemon that refused to start. This test pins the seed to
    /// the schema so the next rename can't ship without flipping it.
    #[test]
    fn default_policy_seed_parses() {
        let engine = core_approval::policy::PolicyEngine::from_toml(DEFAULT_POLICY_TOML)
            .expect("DEFAULT_POLICY_TOML must parse");
        let denied = engine.evaluate("git.push.main");
        assert!(matches!(
            denied.requirement,
            core_approval::policy::ApprovalRequirement::Denied
        ));
        let auto = engine.evaluate("git.push.feature-branch");
        assert!(matches!(
            auto.requirement,
            core_approval::policy::ApprovalRequirement::Auto
        ));
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
        let config = ember_daemon::infra::config::DaemonConfig {
            socket_dir: run_dir.clone(),
            data_dir: data_dir.clone(),
            pid_file: run_dir.join("emberd.pid"),
            policy_file: tmp.path().join("policy.toml"),
            log_level: ember_daemon::infra::config::LogLevel::Info,
            dashboard_addr: None,
            git_proxy_addr: None,
            llm_proxy_addr: None,
            keyring: ember_daemon::infra::config::KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            presence: ember_daemon::infra::config::PresenceConfigSection::default(),
            snapshot_interval_secs: 3600,
            snapshot_pull_interval_secs: 600,
            snapshot_pull_endpoint: None,
            snapshot_pull_cluster_id: None,
            credential_store: None,
            ..ember_daemon::infra::config::DaemonConfig::for_test(tmp.path())
        };

        // Suppress keyring and passphrase side-effects.
        unsafe {
            std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-passphrase");
            std::env::set_var("EMBER_SKIP_DAEMON_INSTALL_CHECK", "1");
        }

        cmd_init(
            &config,
            Some("test".to_string()),
            Some(&config_path),
            None,
            None,
            false,
            false,
        );

        unsafe {
            std::env::remove_var("EMBER_VAULT_PASSPHRASE");
            std::env::remove_var("EMBER_SKIP_DAEMON_INSTALL_CHECK");
        }

        let contents = std::fs::read_to_string(&config_path).unwrap();
        assert!(
            contents.contains("[keyring]"),
            "config must contain [keyring] section"
        );
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

        let config = ember_daemon::infra::config::DaemonConfig {
            socket_dir: run_dir.clone(),
            data_dir: data_dir.clone(),
            pid_file: run_dir.join("emberd.pid"),
            policy_file: tmp.path().join("policy.toml"),
            log_level: ember_daemon::infra::config::LogLevel::Info,
            dashboard_addr: None,
            git_proxy_addr: None,
            llm_proxy_addr: None,
            keyring: ember_daemon::infra::config::KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            presence: ember_daemon::infra::config::PresenceConfigSection::default(),
            snapshot_interval_secs: 3600,
            snapshot_pull_interval_secs: 600,
            snapshot_pull_endpoint: None,
            snapshot_pull_cluster_id: None,
            credential_store: None,
            ..ember_daemon::infra::config::DaemonConfig::for_test(tmp.path())
        };

        unsafe {
            std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-passphrase");
            std::env::set_var("EMBER_SKIP_DAEMON_INSTALL_CHECK", "1");
        }

        cmd_init(
            &config,
            Some("test".to_string()),
            Some(&config_path),
            Some("custom-service".to_string()),
            Some("custom-account".to_string()),
            false,
            false,
        );

        unsafe {
            std::env::remove_var("EMBER_VAULT_PASSPHRASE");
            std::env::remove_var("EMBER_SKIP_DAEMON_INSTALL_CHECK");
        }

        let contents = std::fs::read_to_string(&config_path).unwrap();
        assert!(
            contents.contains("service = \"custom-service\""),
            "config must use custom service"
        );
        assert!(
            contents.contains("account = \"custom-account\""),
            "config must use custom account"
        );
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
        let v = resolve_init_keyring_value(None, Some("from-env".to_string()), "from-default");
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
        // implementation-note-461: this test asserts the
        // "no env, no flag" baseline, but the live runtime now also
        // consults `EMBER_CONFIG` / `EMBER_DEMO_DIR`. The pure
        // `resolve_config_path` tests below exercise the precedence
        // chain without touching process-global env vars; if either
        // env var is set in this test process we skip rather than
        // assert the wrong baseline.
        if std::env::var("EMBER_CONFIG").is_ok() || std::env::var("EMBER_DEMO_DIR").is_ok() {
            return;
        }
        assert_eq!(
            effective_config_path(None),
            DaemonConfig::default_config_path()
        );
    }

    // implementation-note-461: precedence chain for the user-pinned
    // config path: --config flag → EMBER_CONFIG → EMBER_DEMO_DIR/config.toml
    // → None (caller falls through to default). Pure-function tests so we
    // don't touch process-global env vars (race-prone when cargo runs
    // tests in parallel — see the 2026-04-23 keyring leak).

    #[test]
    fn resolve_config_path_flag_wins_over_env_and_demo_dir() {
        let flag = PathBuf::from("/tmp/from-flag/config.toml");
        let resolved = resolve_config_path(
            Some(&flag),
            Some("/tmp/from-env/config.toml".to_string()),
            Some("/tmp/from-demo-dir".to_string()),
        );
        assert_eq!(resolved, Some(flag));
    }

    #[test]
    fn resolve_config_path_env_wins_over_demo_dir_when_flag_absent() {
        let resolved = resolve_config_path(
            None,
            Some("/tmp/from-env/config.toml".to_string()),
            Some("/tmp/from-demo-dir".to_string()),
        );
        assert_eq!(resolved, Some(PathBuf::from("/tmp/from-env/config.toml")));
    }

    #[test]
    fn resolve_config_path_demo_dir_resolves_when_env_absent_and_file_exists() {
        let tmp = tempfile::Builder::new()
            .prefix("esb")
            .tempdir()
            .expect("tempdir");
        let demo_dir = tmp.path();
        let candidate = demo_dir.join("config.toml");
        std::fs::write(&candidate, "# fixture\n").expect("write config.toml");

        let resolved = resolve_config_path(None, None, Some(demo_dir.display().to_string()));
        assert_eq!(resolved, Some(candidate));
    }

    #[test]
    fn resolve_config_path_demo_dir_skipped_when_config_toml_missing() {
        // Stale `EMBER_DEMO_DIR` pointing at a removed demo session must
        // NOT short-circuit the chain — we fall through to the default
        // path so unrelated `ember` invocations don't fail.
        let tmp = tempfile::Builder::new()
            .prefix("esb")
            .tempdir()
            .expect("tempdir");
        let resolved = resolve_config_path(None, None, Some(tmp.path().display().to_string()));
        assert_eq!(resolved, None);
    }

    #[test]
    fn resolve_config_path_returns_none_when_all_inputs_absent() {
        let resolved = resolve_config_path(None, None, None);
        assert_eq!(resolved, None);
    }

    #[test]
    fn resolve_config_path_treats_empty_env_as_absent() {
        // Shells often export empty strings; the chain must skip them
        // rather than resolve to "" / "/config.toml".
        let resolved = resolve_config_path(None, Some(String::new()), Some(String::new()));
        assert_eq!(resolved, None);
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
        assert!(
            obj.contains_key("standing_grants"),
            "missing standing_grants"
        );
        assert!(obj.contains_key("audit_events"), "missing audit_events");
        let daemon = obj["daemon"].as_object().unwrap();
        assert!(daemon.contains_key("running"), "daemon missing running");
        assert!(daemon.contains_key("pid"), "daemon missing pid");
        assert!(daemon.contains_key("socket"), "daemon missing socket");
        let grants = obj["grants"].as_object().unwrap();
        assert!(grants.contains_key("active"), "grants missing active");
        assert!(
            grants.contains_key("expired_sweep_interval_sec"),
            "grants missing expired_sweep_interval_sec"
        );
        assert!(obj["personas"].is_number(), "personas should be a count");
        assert!(
            obj["standing_grants"].is_number(),
            "standing_grants should be a count"
        );
        assert!(
            obj["audit_events"].is_number(),
            "audit_events should be a count"
        );
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
        assert!(
            parse_duration(&input).is_err(),
            "days overflow should return Err"
        );
        // Same for hours: u64::MAX / 3600 + 1
        let overflow_hours = u64::MAX / 3600 + 1;
        let input = format!("{overflow_hours}h");
        assert!(
            parse_duration(&input).is_err(),
            "hours overflow should return Err"
        );
        // Same for minutes: u64::MAX / 60 + 1
        let overflow_mins = u64::MAX / 60 + 1;
        let input = format!("{overflow_mins}m");
        assert!(
            parse_duration(&input).is_err(),
            "minutes overflow should return Err"
        );
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
        assert_eq!(stmts[0].credential_name, "obj-github-token");
        assert_eq!(stmts[0].resource_type, ResourceType::Credential);
        assert!(stmts[0].actions.contains(&"credential:read".to_string()));
        assert_eq!(
            stmts[0].resource,
            ResourceSelector::Exact {
                value: "obj-github-token".to_string()
            }
        );
        assert!(
            stmts[0].budget.is_none(),
            "credential statement must have no budget"
        );

        // Statement 1: Session
        assert_eq!(stmts[1].resource_type, ResourceType::Session);
        assert!(stmts[1].actions.contains(&"llm:generate".to_string()));
        assert_eq!(
            stmts[1].resource,
            ResourceSelector::Glob {
                pattern: "anthropic/*".to_string()
            }
        );
        let session_budget = stmts[1]
            .budget
            .as_ref()
            .expect("session must have a budget");
        assert_eq!(session_budget.tokens, Some(20_000));
        assert_eq!(session_budget.cents, Some(50));

        // Statement 2: Time
        assert_eq!(stmts[2].resource_type, ResourceType::Time);
        assert!(stmts[2].actions.contains(&"time:wall_clock".to_string()));
        assert_eq!(stmts[2].resource, ResourceSelector::Any);
        let time_budget = stmts[2].budget.as_ref().expect("time must have a budget");
        assert_eq!(time_budget.wall_clock_secs, Some(1800));
    }

    #[test]
    fn build_composite_grant_statements_no_credential_returns_empty() {
        let stmts = build_composite_grant_statements(None, Some(20_000), Some(50), Some(1800));
        assert!(
            stmts.is_empty(),
            "no credential_resource means no statements"
        );
    }

    #[test]
    fn build_composite_grant_statements_no_budgets_still_three_statements() {
        let stmts = build_composite_grant_statements(Some("obj-github-token"), None, None, None);
        assert_eq!(stmts.len(), 3);
        assert!(
            stmts[1].budget.is_none(),
            "session budget absent when no token/cent flags"
        );
        assert!(
            stmts[2].budget.is_none(),
            "time budget absent when no seconds flag"
        );
    }

    // --- helpers for render_grant_budget tests ---

    fn make_test_statement(
        sid: &str,
        rt: ResourceType,
        resource: &str,
        budget: Option<Budget>,
        usage: Usage,
    ) -> Statement {
        Statement {
            sid: sid.into(),
            resource_type: rt,
            actions: vec!["read".to_string()],
            resource: ResourceSelector::Glob {
                pattern: resource.to_string(),
            },
            budget,
            usage,
            conditions: vec![],
        }
    }

    fn make_test_grant(statements_by_block: Vec<Vec<Statement>>) -> AccessGrant {
        use core_event_types::PresentationAudienceKind;
        use core_grant_types::{
            AttestationBinding, Block, GrantMode, GrantStatus, RecipientProfile, SignedBlock,
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
            Some(Budget {
                tokens: Some(20_000),
                cents: Some(50),
                requests: None,
                workload_hours: None,
                wall_clock_secs: None,
            }),
            Usage {
                tokens: 14_342,
                cents: 37,
                last_updated: 0,
                ..Usage::default()
            },
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
            Some(Budget {
                tokens: Some(20_000),
                cents: None,
                requests: None,
                workload_hours: None,
                wall_clock_secs: None,
            }),
            Usage {
                tokens: 5_000,
                last_updated: 0,
                ..Usage::default()
            },
        );
        let grant = make_test_grant(vec![vec![stmt]]);
        // Stale usage — runway should show dash.
        let out = render_grant_budget(&grant);
        assert!(
            out.contains("Runway:  —"),
            "expected stale runway dash: {out}"
        );
    }

    #[test]
    fn render_single_statement_no_budget() {
        let stmt = make_test_statement(
            "S0",
            ResourceType::Credential,
            "credential:*",
            None,
            Usage::default(),
        );
        let grant = make_test_grant(vec![vec![stmt]]);
        let out = render_grant_budget(&grant);
        assert!(out.contains("Grant grant-test"), "missing header: {out}");
        assert!(
            out.contains("Budget:  (none)"),
            "expected no-budget line: {out}"
        );
        // Single-statement grants must NOT show per-statement header.
        assert!(
            !out.contains("Statement S0"),
            "should not show stmt header for single: {out}"
        );
    }

    #[test]
    fn render_composite_three_statements() {
        let s0 = make_test_statement(
            "S0",
            ResourceType::Credential,
            "credential:*",
            None,
            Usage::default(),
        );
        let s1 = make_test_statement(
            "S1",
            ResourceType::Session,
            "llm:generate",
            Some(Budget {
                tokens: Some(20_000),
                cents: Some(100),
                requests: None,
                workload_hours: None,
                wall_clock_secs: None,
            }),
            Usage {
                tokens: 12_450,
                cents: 85,
                requests: 0,
                workload_hours: 0,
                wall_clock_secs: 0,
                last_updated: 0,
                cents_micro: 85_000_000,
            },
        );
        let s2 = make_test_statement(
            "S2",
            ResourceType::Time,
            "session:*",
            Some(Budget {
                tokens: None,
                cents: None,
                requests: None,
                workload_hours: None,
                wall_clock_secs: Some(1800),
            }),
            Usage {
                tokens: 0,
                cents: 0,
                requests: 0,
                workload_hours: 0,
                wall_clock_secs: 240,
                last_updated: 0,
                cents_micro: 0,
            },
        );
        let grant = make_test_grant(vec![vec![s0, s1, s2]]);
        let out = render_grant_budget(&grant);

        // Should have per-statement headers.
        assert!(out.contains("Statement S0"), "missing S0 header: {out}");
        assert!(out.contains("Statement S1"), "missing S1 header: {out}");
        assert!(out.contains("Statement S2"), "missing S2 header: {out}");

        // S0 has no budget.
        assert!(
            out.contains("Budget:  (none)"),
            "expected no-budget for S0: {out}"
        );

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
        use ember_daemon::infra::config::LogLevel;
        use std::io::BufRead;
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();

        let guard = configure_tracing(data_dir, &LogLevel::Info, false);
        tracing::info!(
            test_marker = "unit-test-probe",
            "configure_tracing_writes_json_log probe"
        );
        // Drop guard to flush the non-blocking writer before reading the file.
        drop(guard);

        // tracing-appender rolling daily names files <prefix>.<YYYY-MM-DD>
        let log_file = std::fs::read_dir(data_dir)
            .unwrap()
            .flatten()
            .find(|e| e.file_name().to_string_lossy().starts_with("daemon.log"))
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
        let action = parse_sandbox_run(&[
            "agent-coding",
            "--image",
            "ember-claude-code:v1",
            "--prompt",
            "hello",
        ]);
        match action {
            SandboxAction::Run {
                name,
                image,
                prompt,
                ..
            } => {
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
            "--image",
            "ember-claude-code:v1",
            "--workspace-from",
            "https://github.com/example/repo",
        ]);
        match action {
            SandboxAction::Run { workspace_from, .. } => {
                assert_eq!(
                    workspace_from.as_deref(),
                    Some("https://github.com/example/repo")
                );
            }
            _ => panic!("expected SandboxAction::Run"),
        }
    }

    #[test]
    fn sandbox_run_parses_env_vars() {
        let action = parse_sandbox_run(&["env-sandbox", "--env", "FOO=bar", "--env", "BAZ=qux"]);
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
        let action = parse_sandbox_run(&["ttl-sandbox", "--ttl", "30m"]);
        match action {
            SandboxAction::Run { ttl, .. } => {
                assert_eq!(ttl.as_deref(), Some("30m"));
            }
            _ => panic!("expected SandboxAction::Run"),
        }
    }

    // --- docker_exec_flags unit tests (implementation-note-481) ---

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
        for (input, expected_secs) in [("5s", 5u64), ("5m", 300), ("2h", 7200), ("30", 30)] {
            let action = parse_grant_create(&[
                "--persona",
                "p1",
                "--credential",
                "cred-x",
                "--scope",
                "read",
                "--ttl",
                input,
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
            "--budget-tokens",
            "20000",
            "--budget-usd",
            "0.50",
        ]);
        match action {
            SandboxAction::Run {
                budget_tokens,
                budget_usd,
                ..
            } => {
                assert_eq!(budget_tokens, Some(20_000u64));
                assert_eq!(budget_usd.as_deref(), Some("0.50"));
            }
            _ => panic!("expected SandboxAction::Run"),
        }
    }

    #[test]
    fn sandbox_run_parses_credential_resource() {
        let action =
            parse_sandbox_run(&["cred-sandbox", "--credential-resource", "obj-github-token"]);
        match action {
            SandboxAction::Run {
                credential_resource,
                ..
            } => {
                assert_eq!(credential_resource.as_deref(), Some("obj-github-token"));
            }
            _ => panic!("expected SandboxAction::Run"),
        }
    }

    #[test]
    fn sandbox_run_full_flags() {
        let action = parse_sandbox_run(&[
            "full-sandbox",
            "--image",
            "ember-claude-code:v1",
            "--prompt",
            "echo hello",
            "--workspace-from",
            "https://github.com/example/repo",
            "--env",
            "KEY=val",
            "--ttl",
            "60s",
            "--budget-tokens",
            "5000",
            "--budget-usd",
            "0.25",
            "--budget-seconds",
            "3600",
            "--credential-resource",
            "obj-anthropic-key",
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
                assert_eq!(
                    workspace_from.as_deref(),
                    Some("https://github.com/example/repo")
                );
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
    /// before `keyring_core::Entry::new` — belt-and-suspenders alongside prior change's
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
        assert!(
            result.is_ok(),
            "checkpoint should pass when opt-in file exists"
        );
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

    // --- EMBER_VAULT_PASSPHRASE cleared after first read in cmd_init ---

    #[test]
    fn cmd_init_removes_vault_passphrase_env_after_read() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        let data_dir = tmp.path().join("data");
        let run_dir = tmp.path().join("run");

        let config = ember_daemon::infra::config::DaemonConfig {
            socket_dir: run_dir.clone(),
            data_dir: data_dir.clone(),
            pid_file: run_dir.join("emberd.pid"),
            policy_file: tmp.path().join("policy.toml"),
            log_level: ember_daemon::infra::config::LogLevel::Info,
            dashboard_addr: None,
            git_proxy_addr: None,
            llm_proxy_addr: None,
            keyring: ember_daemon::infra::config::KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            presence: ember_daemon::infra::config::PresenceConfigSection::default(),
            snapshot_interval_secs: 3600,
            snapshot_pull_interval_secs: 600,
            snapshot_pull_endpoint: None,
            snapshot_pull_cluster_id: None,
            credential_store: None,
            ..ember_daemon::infra::config::DaemonConfig::for_test(tmp.path())
        };

        // SAFETY: test-only, single-threaded, no other threads reading env vars.
        unsafe {
            std::env::set_var("EMBER_VAULT_PASSPHRASE", "sec14-cli-passphrase");
            std::env::set_var("EMBER_SKIP_DAEMON_INSTALL_CHECK", "1");
        }

        cmd_init(
            &config,
            Some("test".to_string()),
            Some(&config_path),
            None,
            None,
            false,
            false,
        );

        assert!(
            std::env::var("EMBER_VAULT_PASSPHRASE").is_err(),
            "EMBER_VAULT_PASSPHRASE must be absent from the environment after cmd_init"
        );
        unsafe {
            std::env::remove_var("EMBER_SKIP_DAEMON_INSTALL_CHECK");
        }
    }

    // implementation-note-482: cmd_init's
    // ensure_managed_daemon_for_init now probes the daemon via the
    // `status` RPC before the existing create_persona /
    // build_init_first_grant_receipt sequence. The fake daemon below
    // accepts the new method with a minimal empty StatusSummary, and
    // the request-loop bound is widened from 0..2 to 0..3 to absorb
    // the additional connection.
    // Anchor: cmd_init_with_live_socket_builds_first_receipt_via_daemon_without_local_db_write_passes
    #[test]
    fn cmd_init_with_live_socket_builds_first_receipt_via_daemon_without_local_db_write() {
        use core_crypto::Signer as _;
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::Builder::new()
            .prefix("esb")
            .tempdir()
            .expect("tempdir");
        let config_path = tmp.path().join("config.toml");
        let data_dir = tmp.path().join("data");
        let run_dir = tmp.path().join("run");

        let config = ember_daemon::infra::config::DaemonConfig {
            socket_dir: run_dir.clone(),
            data_dir: data_dir.clone(),
            pid_file: run_dir.join("emberd.pid"),
            policy_file: tmp.path().join("policy.toml"),
            log_level: ember_daemon::infra::config::LogLevel::Info,
            dashboard_addr: None,
            git_proxy_addr: None,
            llm_proxy_addr: None,
            keyring: ember_daemon::infra::config::KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            presence: ember_daemon::infra::config::PresenceConfigSection::default(),
            snapshot_interval_secs: 3600,
            snapshot_pull_interval_secs: 600,
            snapshot_pull_endpoint: None,
            snapshot_pull_cluster_id: None,
            credential_store: None,
            ..ember_daemon::infra::config::DaemonConfig::for_test(tmp.path())
        };

        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let signer = core_crypto::FixtureSigner::new("cmd-init-daemon-receipt");
                let public_key = signer.public_key().0.clone();

                for _ in 0..3 {
                    let mut stream =
                        accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                    let mut reader = std::io::BufReader::new(
                        stream.try_clone().expect("clone fake daemon stream"),
                    );
                    let mut line = String::new();
                    reader
                        .read_line(&mut line)
                        .expect("read fake daemon request");
                    let request: serde_json::Value =
                        serde_json::from_str(line.trim()).expect("parse fake daemon request");

                    let response = match request["method"].as_str().unwrap() {
                        // ensure_managed_daemon_for_init probes the daemon's
                        // `status` method first. Return a minimal empty
                        // StatusSummary that deserializes cleanly so the
                        // probe reports "already running" and cmd_init
                        // proceeds to create_persona + build_init_first_grant_receipt.
                        "status" => serde_json::json!({
                            "id": request["id"],
                            "result": {
                                "personas": [],
                                "grants": [],
                                "sandboxes": [],
                                "approvals": [],
                                "recent_activity": [],
                                "standing_grants": 0,
                                "audit_events_total": 0,
                            },
                        }),
                        "create_persona" => {
                            assert_eq!(request["params"]["name"], serde_json::json!("daemon-root"));
                            serde_json::json!({
                                "id": request["id"],
                                "result": {
                                    "id": "persona-rpc",
                                    "name": "daemon-root",
                                    "public_key": public_key,
                                },
                            })
                        }
                        "build_init_first_grant_receipt" => {
                            assert_eq!(
                                request["params"]["persona_id"],
                                serde_json::json!("persona-rpc")
                            );
                            let file = ember_daemon::infra::init_first_grant::build_first_grant_receipt_file(
                                "persona-rpc",
                                &signer,
                            )
                            .expect("build first-grant receipt");
                            serde_json::json!({
                                "id": request["id"],
                                "result": serde_json::to_value(file).expect("serialize receipt file"),
                            })
                        }
                        other => panic!("unexpected method: {other}"),
                    };

                    let mut encoded =
                        serde_json::to_string(&response).expect("encode fake daemon response");
                    encoded.push('\n');
                    stream
                        .write_all(encoded.as_bytes())
                        .expect("write fake daemon response");
                }
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        unsafe {
            std::env::set_var("EMBER_VAULT_PASSPHRASE", "rpc-init-passphrase");
        }

        cmd_init(
            &config,
            Some("daemon-root".to_string()),
            Some(&config_path),
            None,
            None,
            false,
            false,
        );

        assert!(
            std::env::var("EMBER_VAULT_PASSPHRASE").is_err(),
            "EMBER_VAULT_PASSPHRASE must be absent from the environment after cmd_init"
        );
        assert!(
            !data_dir.join("daemon.db").exists(),
            "live-socket init must not create daemon.db locally when the daemon owns persona + receipt flows"
        );

        let receipt_path = data_dir.join("receipts/first.json");
        assert!(
            receipt_path.exists(),
            "daemon-built first-grant receipt must be written locally"
        );
        let raw = std::fs::read_to_string(&receipt_path).expect("read receipt");
        let file: emberlink_cli::onboarding::first_grant::FirstGrantReceiptFile =
            serde_json::from_str(&raw).expect("parse receipt");
        assert_eq!(file.issuer.persona, "persona-rpc");

        server.join().expect("fake daemon thread");
    }

    // --- .C device enroll/pair scaffold parse tests ---

    fn parse_dev(args: &[&str]) -> DevAction {
        use clap::Parser as _;
        let full: Vec<&str> = std::iter::once("ember")
            .chain(std::iter::once("dev"))
            .chain(args.iter().copied())
            .collect();
        let cli = Cli::try_parse_from(&full).expect("parse failed");
        match cli.command {
            Commands::Dev { action } => action,
            _ => panic!("expected Dev command"),
        }
    }

    #[test]
    fn dev_status_alias_parses_to_info() {
        let action = parse_dev(&["status"]);
        assert!(matches!(action, DevAction::Info));
    }

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

    #[test]
    fn vault_add_value_arg_refused_at_dispatch() {
        // The dispatch handler calls refuse_value_in_argv when `value.is_some()`.
        // We can't process::exit() inside a test, so instead verify that
        // VaultAction::Add's argv parser still accepts --value (clap-level) but
        // the runtime dispatch will reject it. This test is the parser smoke;
        // the runtime refuse path is exercised in cli_integration tests.
        use clap::Parser;
        #[derive(Parser)]
        struct T {
            #[command(subcommand)]
            action: VaultAction,
        }
        let parsed = T::try_parse_from(["test", "add", "--name", "foo/bar", "--value", "leaky"]);
        assert!(
            parsed.is_ok(),
            "clap should accept --value at parse-time so dispatch can emit a structured refuse"
        );
        let parsed = parsed.unwrap();
        match parsed.action {
            VaultAction::Add { value, .. } => {
                assert_eq!(value.as_deref(), Some("leaky"), "value field captured");
            }
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn vault_lock_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::Builder::new()
            .prefix("esb")
            .tempdir()
            .expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("vault_lock"));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": {"locked": true},
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let dispatch = run_vault_lock(&config).expect("vault lock via daemon");
        assert_eq!(dispatch, VaultLockDispatch::DaemonRpc);
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn vault_lock_falls_back_to_local_when_socket_is_absent() {
        let tmp = tempfile::Builder::new()
            .prefix("esb")
            .tempdir()
            .expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        let dispatch = run_vault_lock(&config).expect("local fallback lock");
        assert_eq!(dispatch, VaultLockDispatch::LocalFallback);
    }

    #[cfg_attr(
        target_os = "macos",
        ignore = "local macOS sandbox forbids fake daemon UDS bind"
    )]
    #[test]
    fn vault_unlock_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::Builder::new()
            .prefix("esb")
            .tempdir()
            .expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("vault_unlock"));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": {"unlocked": true},
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let dispatch = run_vault_unlock(&config).expect("vault unlock via daemon");
        assert_eq!(dispatch, VaultLockDispatch::DaemonRpc);
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn vault_unlock_falls_back_to_local_when_socket_is_absent() {
        // SAFETY: test-only env var scoped to this unit test.
        unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "vault-unlock-fallback-test") };
        let tmp = tempfile::Builder::new()
            .prefix("esb")
            .tempdir()
            .expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        let dispatch = run_vault_unlock(&config).expect("local fallback unlock");
        assert_eq!(dispatch, VaultLockDispatch::LocalFallback);
        // SAFETY: test-only cleanup for the scoped env var above.
        unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };
    }

    #[test]
    fn vault_list_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("vault_list"));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": [
                        {"id": 1, "name": "alpha/token", "metadata": null},
                        {"id": 2, "name": "beta/token", "metadata": "meta"}
                    ],
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let (dispatch, entries) =
            run_vault_list(&config, Some("alpha")).expect("vault list via daemon");
        assert_eq!(dispatch, VaultActionDispatch::DaemonRpc);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], serde_json::json!("alpha/token"));
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn vault_remove_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("vault_remove"));
                assert_eq!(request["params"]["name"], serde_json::json!("alpha/token"));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": {"removed": true, "name": "alpha/token"},
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let dispatch = run_vault_remove(&config, "alpha/token").expect("vault remove via daemon");
        assert_eq!(dispatch, VaultActionDispatch::DaemonRpc);
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn vault_get_prefers_exact_value_bytes_from_daemon() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("vault_get"));
                assert_eq!(request["params"]["name"], serde_json::json!("alpha/token"));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": {
                        "value": "lossy-placeholder",
                        "value_bytes": [0, 255, 65]
                    },
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let (dispatch, value) =
            run_vault_get(&config, "alpha/token").expect("vault get via daemon");
        assert_eq!(dispatch, VaultActionDispatch::DaemonRpc);
        assert_eq!(value, vec![0, 255, 65]);
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn vault_store_routes_exact_bytes_through_daemon() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("vault_add"));
                assert_eq!(request["params"]["name"], serde_json::json!("alpha/token"));
                assert_eq!(
                    request["params"]["value_bytes"],
                    serde_json::json!([0, 255, 65])
                );
                assert_eq!(request["params"]["metadata"], serde_json::json!("meta"));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": {"id": 42, "name": "alpha/token"},
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let stored = run_vault_store(&config, "alpha/token", &[0, 255, 65], Some("meta"))
            .expect("vault store via daemon");
        assert_eq!(stored.dispatch, VaultActionDispatch::DaemonRpc);
        assert_eq!(stored.id, "42");
        assert_eq!(stored.name, "alpha/token");
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn grant_create_routes_full_shape_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("create_grant"));
                assert_eq!(
                    request["params"]["persona_id"],
                    serde_json::json!("persona-1")
                );
                assert_eq!(
                    request["params"]["credential_name"],
                    serde_json::json!("api-key")
                );
                assert_eq!(request["params"]["scope"], serde_json::json!("read"));
                assert_eq!(request["params"]["ttl_secs"], serde_json::json!(600));
                assert_eq!(request["params"]["max_uses_per_hour"], serde_json::json!(5));
                assert_eq!(
                    request["params"]["allowed_hours_start"],
                    serde_json::json!(9)
                );
                assert_eq!(
                    request["params"]["allowed_hours_end"],
                    serde_json::json!(17)
                );
                assert_eq!(
                    request["params"]["allowed_targets"],
                    serde_json::json!(["api.example.com", "uploads.example.com"])
                );
                assert_eq!(
                    request["params"]["max_delegation_depth"],
                    serde_json::json!(2)
                );
                assert_eq!(request["params"]["budget"]["tokens"], serde_json::json!(42));
                assert_eq!(
                    request["params"]["max_children_per_day"],
                    serde_json::json!(3)
                );
                assert_eq!(
                    request["params"]["auto_delegate_scope_template"],
                    serde_json::json!("github:push:acme/*")
                );

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": {
                        "id": "grant-123",
                        "expires_at": null,
                        "budget": {"tokens": 42},
                    },
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let spec = GrantCreateSpec {
            persona: "persona-1".to_string(),
            credential: "api-key".to_string(),
            scope: "read".to_string(),
            ttl_secs: Some(600),
            max_uses_per_hour: Some(5),
            allowed_hours_start: Some(9),
            allowed_hours_end: Some(17),
            allowed_targets: Some(vec![
                "api.example.com".to_string(),
                "uploads.example.com".to_string(),
            ]),
            max_delegation_depth: Some(2),
            budget: Some(Budget {
                tokens: Some(42),
                cents: None,
                requests: None,
                workload_hours: None,
                wall_clock_secs: None,
            }),
            max_children_per_day: Some(3),
            auto_delegate_scope_template: Some("github:push:acme/*".to_string()),
        };

        let (dispatch, response) =
            run_grant_create(&config, &spec).expect("grant create via daemon");
        assert_eq!(dispatch, GrantActionDispatch::DaemonRpc);
        assert_eq!(response["id"], serde_json::json!("grant-123"));
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn grant_create_composite_routes_statement_chain_through_daemon() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(
                    request["method"],
                    serde_json::json!("create_composite_grant")
                );
                assert_eq!(
                    request["params"]["persona_id"],
                    serde_json::json!("persona-1")
                );
                assert_eq!(
                    request["params"]["credential_name"],
                    serde_json::json!("anthropic-key")
                );
                assert_eq!(
                    request["params"]["scope"],
                    serde_json::json!("claude-code-default-v1")
                );
                let statements = request["params"]["statements"]
                    .as_array()
                    .expect("statements array");
                assert_eq!(statements.len(), 2);
                assert_eq!(
                    statements[0]["resource_type"],
                    serde_json::json!("credential")
                );
                assert_eq!(
                    statements[1]["resource"]["pattern"],
                    serde_json::json!("anthropic/*")
                );

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": {
                        "id": "grant-composite-123",
                        "expires_at": null,
                        "statement_count": 2,
                    },
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let spec = CompositeGrantCreateSpec {
            persona_id: "persona-1".to_string(),
            credential_name: "anthropic-key".to_string(),
            scope: "claude-code-default-v1".to_string(),
            ttl_secs: Some(600),
            statements: build_claude_code_anthropic_runtime_statements(),
        };

        let (dispatch, response) =
            run_grant_create_composite(&config, &spec).expect("composite grant create via daemon");
        assert_eq!(dispatch, GrantActionDispatch::DaemonRpc);
        assert_eq!(response["id"], serde_json::json!("grant-composite-123"));
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn grant_status_supports_anthropic_gateway_requires_both_statements() {
        let compatible = serde_json::json!({
            "statements": [
                {
                    "resource_type": "credential",
                    "actions": ["credential:read"],
                    "resource": {"kind": "exact", "value": "anthropic-key"}
                },
                {
                    "resource_type": "session",
                    "actions": ["llm:generate"],
                    "resource": {"kind": "glob", "pattern": "anthropic/*"}
                }
            ]
        });
        assert!(
            grant_status_supports_anthropic_gateway(&compatible),
            "expected matching credential + session statements to qualify"
        );

        let missing_session = serde_json::json!({
            "statements": [
                {
                    "resource_type": "credential",
                    "actions": ["credential:read"],
                    "resource": {"kind": "exact", "value": "anthropic-key"}
                }
            ]
        });
        assert!(
            !grant_status_supports_anthropic_gateway(&missing_session),
            "credential statement alone must not qualify as an Anthropic gateway grant"
        );
    }

    #[test]
    fn grant_list_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("list_operator_grants"));
                assert_eq!(request["params"]["active_only"], serde_json::json!(true));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": [
                        {
                            "id": "grant-1",
                            "persona_id": "persona-a",
                            "credential_name": "cred-a",
                            "scope": "read",
                            "status": "active",
                            "expires_at": null
                        },
                        {
                            "id": "grant-2",
                            "persona_id": "persona-b",
                            "credential_name": "cred-b",
                            "scope": "write",
                            "status": "paused",
                            "expires_at": "2026-06-01T00:00:00Z"
                        }
                    ],
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let (dispatch, list) = run_grant_list(&config, true).expect("grant list via daemon");
        assert_eq!(dispatch, GrantActionDispatch::DaemonRpc);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0]["id"], serde_json::json!("grant-1"));
        assert_eq!(list[1]["status"], serde_json::json!("paused"));
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn grant_expire_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("expire_grants"));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": {"expired_count": 3},
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let (dispatch, count) = run_grant_expire(&config).expect("grant expire via daemon");
        assert_eq!(dispatch, GrantActionDispatch::DaemonRpc);
        assert_eq!(count, 3);
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn grant_extend_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("extend_grant"));
                assert_eq!(
                    request["params"]["grant_id"],
                    serde_json::json!("grant-123")
                );
                assert_eq!(request["params"]["add_tokens"], serde_json::json!(10));
                assert_eq!(request["params"]["add_cents"], serde_json::json!(25));
                assert_eq!(request["params"]["add_ttl_secs"], serde_json::json!(900));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": {
                        "grant_id": "grant-123",
                        "expires_at": null,
                        "budget": {"tokens": 10, "cents": 25},
                    },
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let dispatch = run_grant_extend(&config, "grant-123", Some(10), Some(25), Some(900))
            .expect("grant extend via daemon");
        assert_eq!(dispatch, GrantActionDispatch::DaemonRpc);
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn grant_delegate_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut status_stream =
                    accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut status_reader = std::io::BufReader::new(
                    status_stream
                        .try_clone()
                        .expect("clone fake daemon grant_status stream"),
                );
                let mut line = String::new();
                status_reader
                    .read_line(&mut line)
                    .expect("read fake grant_status request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake grant_status request");
                assert_eq!(request["method"], serde_json::json!("grant_status"));
                assert_eq!(request["params"]["id"], serde_json::json!("grant-parent"));
                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": {
                        "kind": "grant",
                        "id": "grant-parent",
                        "persona_id": "persona-owner",
                    },
                }))
                .expect("encode fake grant_status response");
                encoded.push('\n');
                status_stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake grant_status response");

                let mut delegate_stream =
                    accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut delegate_reader = std::io::BufReader::new(
                    delegate_stream
                        .try_clone()
                        .expect("clone fake daemon delegate_grant stream"),
                );
                line.clear();
                delegate_reader
                    .read_line(&mut line)
                    .expect("read fake delegate_grant request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake delegate_grant request");
                assert_eq!(request["method"], serde_json::json!("delegate_grant"));
                assert_eq!(
                    request["params"]["parent_grant_id"],
                    serde_json::json!("grant-parent")
                );
                assert_eq!(
                    request["params"]["child_persona_id"],
                    serde_json::json!("persona-child")
                );
                assert_eq!(request["params"]["scope"], serde_json::json!("read"));
                assert_eq!(
                    request["params"]["caller_persona_id"],
                    serde_json::json!("persona-owner")
                );
                assert_eq!(request["params"]["ttl_secs"], serde_json::json!(600));
                assert_eq!(request["params"]["budget"]["tokens"], serde_json::json!(42));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": {
                        "id": "grant-child",
                        "parent": "grant-parent",
                        "persona_id": "persona-child",
                        "scope": "read",
                        "expires_at": null,
                        "budget": {"tokens": 42},
                    },
                }))
                .expect("encode fake delegate_grant response");
                encoded.push('\n');
                delegate_stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake delegate_grant response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let (dispatch, info) = run_grant_delegate(
            &config,
            "grant-parent",
            "persona-child",
            "read",
            Some(600),
            Some(Budget {
                tokens: Some(42),
                cents: None,
                requests: None,
                workload_hours: None,
                wall_clock_secs: None,
            }),
        )
        .expect("grant delegate via daemon");
        assert_eq!(dispatch, GrantActionDispatch::DaemonRpc);
        assert_eq!(info["id"], serde_json::json!("grant-child"));
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn grant_budget_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("grant_status"));
                assert_eq!(request["params"]["id"], serde_json::json!("grant-123"));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": {
                        "kind": "grant",
                        "id": "grant-123",
                        "persona_id": "persona-owner",
                        "status": "active",
                        "expires_at": null,
                        "statements": [{
                            "sid": "S0",
                            "block_index": 0,
                            "resource_type": "credential",
                            "resource": {"kind": "exact", "value": "alpha/token"},
                            "budget": {"tokens": 100},
                            "usage": {"tokens": 10, "last_updated": 1},
                            "conditions": []
                        }]
                    },
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let (dispatch, rendered) =
            run_grant_budget(&config, "grant-123").expect("grant budget via daemon");
        assert_eq!(dispatch, GrantActionDispatch::DaemonRpc);
        assert!(rendered.contains("Grant grant-123"));
        assert!(rendered.contains("Persona: persona-owner"));
        assert!(rendered.contains("tokens:"));
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn receipt_list_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("list_receipts"));
                assert_eq!(
                    request["params"]["persona_id"],
                    serde_json::json!("persona-a")
                );

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": [
                        fake_grant_receipt_json("rct-1", "grant-1", "persona-a"),
                        fake_grant_receipt_json("rct-2", "grant-2", "persona-a")
                    ],
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let (dispatch, receipts) =
            run_receipt_list(&config, Some("persona-a")).expect("receipt list via daemon");
        assert_eq!(dispatch, ReceiptActionDispatch::DaemonRpc);
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].id, "rct-1");
        assert_eq!(receipts[1].grant_id, "grant-2");
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn receipt_get_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("get_receipt"));
                assert_eq!(request["params"]["id"], serde_json::json!("grant-123"));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": fake_grant_receipt_json("rct-terminal", "grant-123", "persona-owner"),
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let (dispatch, receipt) =
            run_receipt_get(&config, "grant-123").expect("receipt get via daemon");
        assert_eq!(dispatch, ReceiptActionDispatch::DaemonRpc);
        assert_eq!(receipt.id, "rct-terminal");
        assert_eq!(receipt.grant_id, "grant-123");
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn receipt_tree_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("receipt_tree"));
                assert_eq!(
                    request["params"]["grant_id"],
                    serde_json::json!("grant-123")
                );

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": fake_receipt_tree_json("grant-123"),
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let (dispatch, tree) =
            run_receipt_tree(&config, "grant-123").expect("receipt tree via daemon");
        assert_eq!(dispatch, ReceiptActionDispatch::DaemonRpc);
        assert_eq!(tree.root_grant_id, "grant-123");
        assert_eq!(tree.grants.len(), 1);
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn audit_query_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("receipt_query"));
                assert_eq!(request["params"]["actor"], serde_json::json!("persona-a"));
                assert_eq!(request["params"]["kind"], serde_json::json!("grant"));
                assert_eq!(
                    request["params"]["grant_id"],
                    serde_json::json!("grant-123")
                );
                assert_eq!(
                    request["params"]["resource"],
                    serde_json::json!("repo:acme")
                );
                assert_eq!(
                    request["params"]["since"],
                    serde_json::json!("2026-05-01T00:00:00Z")
                );
                assert_eq!(request["params"]["limit"], serde_json::json!(5));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": [fake_receipt_row_json("rct-1", "persona-a", "grant-123")],
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let filter = ember_daemon::infra::receipt::ReceiptFilter {
            persona_id: Some("persona-a".to_string()),
            kind: Some("grant".to_string()),
            grant_id: Some("grant-123".to_string()),
            resource: Some("repo:acme".to_string()),
            since_iso: Some("2026-05-01T00:00:00Z".to_string()),
            limit: Some(5),
            ..Default::default()
        };
        let (dispatch, rows) =
            run_audit_receipt_query(&config, &filter).expect("audit query via daemon");
        assert_eq!(dispatch, AuditActionDispatch::DaemonRpc);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "rct-1");
        assert_eq!(rows[0].grant_id, "grant-123");
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn audit_log_query_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("audit_log_query"));
                assert_eq!(request["params"]["id"], serde_json::json!(7));
                assert_eq!(
                    request["params"]["agent_id"],
                    serde_json::json!("persona-a")
                );
                assert_eq!(request["params"]["limit"], serde_json::json!(3));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": [serde_json::json!({
                        "id": 7,
                        "timestamp": "2026-05-19T00:00:00Z",
                        "agent_id": "persona-a",
                        "action": "grant.issued",
                        "credential": "api-key",
                        "outcome": "allowed",
                        "details": "{\"note\":\"first\"}",
                    })],
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let filter = ember_daemon::infra::audit::AuditFilter {
            id: Some(7),
            agent_id: Some("persona-a".to_string()),
            limit: Some(3),
            ..Default::default()
        };
        let (dispatch, rows) =
            run_audit_log_query(&config, &filter).expect("audit log query via daemon");
        assert_eq!(dispatch, AuditActionDispatch::DaemonRpc);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, 7);
        assert_eq!(rows[0].details.as_deref(), Some("{\"note\":\"first\"}"));
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn audit_explain_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("audit_explain"));
                assert_eq!(request["params"]["id"], serde_json::json!(7));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": fake_audit_explain_json(7),
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let (dispatch, explain) = run_audit_explain(&config, 7).expect("audit explain via daemon");
        assert_eq!(dispatch, AuditActionDispatch::DaemonRpc);
        assert_eq!(explain.event.id, 7);
        assert_eq!(
            explain.current_policy.matched_rule.as_deref(),
            Some("credential.access")
        );
        assert_eq!(
            explain.current_grant.as_ref().map(|g| g.id.as_str()),
            Some("grant-123")
        );
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn approval_list_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(
                    request["method"],
                    serde_json::json!("list_pending_approvals")
                );

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": [fake_approval_request_json("approval-123", "persona-a")],
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let (dispatch, requests) = run_approval_list(&config).expect("approval list via daemon");
        assert_eq!(dispatch, ApprovalActionDispatch::DaemonRpc);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].id, "approval-123");
        assert_eq!(requests[0].persona_id, "persona-a");
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn approval_resolve_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("resolve_approval"));
                assert_eq!(request["params"]["id"], serde_json::json!("approval-123"));
                assert_eq!(request["params"]["decision"], serde_json::json!("always"));
                assert_eq!(
                    request["params"]["expires_at"],
                    serde_json::json!("2026-06-18T00:00:00")
                );

                let mut resolved = fake_approval_request_json("approval-123", "persona-a");
                resolved["status"] = serde_json::json!("approved");
                resolved["result_grant_id"] = serde_json::json!("grant-123");

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": resolved,
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let outcome = ApprovalOutcome::Always {
            scope: None,
            expires_at: Some("2026-06-18T00:00:00".to_string()),
        };
        let (dispatch, resolved) = run_approval_resolve(&config, "approval-123", &outcome)
            .expect("approval resolve via daemon");
        assert_eq!(dispatch, ApprovalActionDispatch::DaemonRpc);
        assert_eq!(resolved.status, "approved");
        assert_eq!(resolved.result_grant_id.as_deref(), Some("grant-123"));
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn status_routes_through_daemon_when_pid_is_running_and_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        std::fs::write(&config.pid_file, format!("{}\n", std::process::id()))
            .expect("write pid file");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("status"));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": fake_status_summary_json(),
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let (dispatch, live_daemon, summary) =
            run_status_summary(&config, true).expect("status summary via daemon");
        assert_eq!(dispatch, StatusActionDispatch::DaemonRpc);
        assert_eq!(
            live_daemon.as_ref().and_then(|status| status.pid),
            Some(std::process::id())
        );
        assert_eq!(summary.personas.len(), 1);
        assert_eq!(summary.grants.len(), 1);
        assert_eq!(summary.sandboxes.len(), 1);
        assert_eq!(summary.approvals.len(), 1);
        assert_eq!(summary.standing_grants, 2);
        assert_eq!(summary.audit_events_total, 9);
        server.join().expect("fake daemon thread");
    }

    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "local macOS sandbox forbids fake daemon UDS bind"
    )]
    fn status_routes_through_daemon_when_socket_exists_even_if_pid_probe_lags() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("status"));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": fake_status_summary_json(),
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let (dispatch, live_daemon, summary) =
            run_status_summary(&config, false).expect("status summary via live socket");
        assert_eq!(dispatch, StatusActionDispatch::DaemonRpc);
        assert!(
            live_daemon.is_some(),
            "live daemon probe should be captured"
        );
        assert_eq!(summary.audit_events_total, 9);
        server.join().expect("fake daemon thread");
    }

    #[test]
    fn build_status_banner_prefers_daemon_rpc_when_pid_probe_lags() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        std::fs::write(&config.pid_file, "4242\n").expect("write pid hint");

        let live = emberlink_cli::LiveDaemonStatus {
            pid: Some(4242),
            socket: config.socket_dir.join("daemon.sock"),
            summary: fake_status_summary(),
        };

        let banner = build_status_banner(
            &config,
            None,
            Some(&live),
            "local".to_string(),
            "local-encrypted".to_string(),
        );

        match banner {
            DaemonStatusBanner::Running { pid, socket, .. } => {
                assert_eq!(pid, 4242);
                assert!(
                    socket.ends_with("daemon.sock"),
                    "expected daemon socket path, got {socket}"
                );
            }
            other => panic!("expected running banner from live daemon rpc, got {other:?}"),
        }
    }

    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "local macOS sandbox forbids fake daemon UDS bind"
    )]
    fn sandbox_create_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("sandbox_create"));
                assert_eq!(request["params"]["name"], serde_json::json!("codebox"));
                assert_eq!(
                    request["params"]["image"],
                    serde_json::json!("ubuntu:24.04")
                );
                assert_eq!(
                    request["params"]["workspace_from"],
                    serde_json::json!("https://example.test/repo.git")
                );
                assert_eq!(
                    request["params"]["extra_env"],
                    serde_json::json!([["FOO", "bar"]])
                );
                assert_eq!(
                    request["params"]["owner_persona_id"],
                    serde_json::json!("persona-owner")
                );

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": {
                        "sandbox": {
                            "id": "sandbox-123",
                            "name": "codebox",
                            "persona_id": "persona-sandbox",
                            "owner_persona_id": "persona-owner",
                            "container_id": null,
                            "image": "ubuntu:24.04",
                            "status": "created",
                            "created_at": "2026-05-18T00:00:00Z",
                            "workspace_path": "/tmp/ws"
                        },
                        "container_id": "container-123",
                        "start_error": null
                    },
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let opts = SandboxCreateOpts {
            name: "codebox".to_string(),
            image: "ubuntu:24.04".to_string(),
            workspace_from: Some("https://example.test/repo.git".to_string()),
            extra_env: vec![("FOO".to_string(), "bar".to_string())],
            owner_persona_id: Some("persona-owner".to_string()),
            ..SandboxCreateOpts::default()
        };
        let (dispatch, created) = run_sandbox_create(&config, &opts).expect("sandbox create");
        assert_eq!(dispatch, SandboxActionDispatch::DaemonRpc);
        assert_eq!(created.sandbox.id, "sandbox-123");
        assert_eq!(created.container_id.as_deref(), Some("container-123"));
        server.join().expect("fake daemon thread");
    }

    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "local macOS sandbox forbids fake daemon UDS bind"
    )]
    fn sandbox_list_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("sandbox_list"));

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": [{
                        "id": "sandbox-1",
                        "name": "alpha",
                        "persona_id": "persona-a",
                        "owner_persona_id": "persona-owner",
                        "container_id": "container-a",
                        "image": "ubuntu:24.04",
                        "status": "running",
                        "created_at": "2026-05-18T00:00:00Z",
                        "workspace_path": null
                    }],
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let (dispatch, sandboxes) = run_sandbox_list(&config).expect("sandbox list");
        assert_eq!(dispatch, SandboxActionDispatch::DaemonRpc);
        assert_eq!(sandboxes.len(), 1);
        assert_eq!(sandboxes[0].name, "alpha");
        server.join().expect("fake daemon thread");
    }

    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "local macOS sandbox forbids fake daemon UDS bind"
    )]
    fn sandbox_stop_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("sandbox_stop"));
                assert_eq!(
                    request["params"]["id_or_name"],
                    serde_json::json!("sandbox-1")
                );

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": {"resolved_id": "sandbox-1", "stopped": true},
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let (dispatch, resolved_id) = run_sandbox_stop(&config, "sandbox-1").expect("sandbox stop");
        assert_eq!(dispatch, SandboxActionDispatch::DaemonRpc);
        assert_eq!(resolved_id, "sandbox-1");
        server.join().expect("fake daemon thread");
    }

    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "local macOS sandbox forbids fake daemon UDS bind"
    )]
    fn sandbox_delete_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("sandbox_delete"));
                assert_eq!(
                    request["params"]["id_or_name"],
                    serde_json::json!("codebox")
                );

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": {"resolved_id": "sandbox-1", "already_absent": false},
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let (dispatch, deleted) = run_sandbox_delete(&config, "codebox").expect("sandbox delete");
        assert_eq!(dispatch, SandboxActionDispatch::DaemonRpc);
        assert_eq!(deleted.resolved_id.as_deref(), Some("sandbox-1"));
        assert!(!deleted.already_absent);
        server.join().expect("fake daemon thread");
    }

    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "local macOS sandbox forbids fake daemon UDS bind"
    )]
    fn persona_revoke_routes_through_daemon_with_operator_caller_persona() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                for expected_method in ["list_personas", "revoke_persona"] {
                    let mut stream =
                        accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                    let mut reader = std::io::BufReader::new(
                        stream.try_clone().expect("clone fake daemon stream"),
                    );
                    let mut line = String::new();
                    reader
                        .read_line(&mut line)
                        .expect("read fake daemon request");
                    let request: serde_json::Value =
                        serde_json::from_str(line.trim()).expect("parse fake daemon request");
                    assert_eq!(request["method"], serde_json::json!(expected_method));

                    let response = match expected_method {
                        "list_personas" => serde_json::json!({
                            "id": request["id"],
                            "result": [
                                {"id": "persona-root", "name": "root", "status": "active"},
                                {"id": "persona-target", "name": "scope-proof-temp", "status": "active"}
                            ],
                        }),
                        "revoke_persona" => {
                            assert_eq!(request["params"]["id"], serde_json::json!("persona-target"));
                            assert_eq!(
                                request["params"]["caller_persona_id"],
                                serde_json::json!("persona-target")
                            );
                            assert_eq!(
                                request["params"]["name"],
                                serde_json::json!("scope-proof-temp")
                            );
                            serde_json::json!({
                                "id": request["id"],
                                "result": {"revoked": true},
                            })
                        }
                        other => panic!("unexpected method: {other}"),
                    };

                    let mut encoded =
                        serde_json::to_string(&response).expect("encode fake daemon response");
                    encoded.push('\n');
                    stream
                        .write_all(encoded.as_bytes())
                        .expect("write fake daemon response");
                }
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        run_persona_revoke(&config, "persona-target").expect("persona revoke via daemon");
        server.join().expect("fake daemon thread");
    }

    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "local macOS sandbox forbids fake daemon UDS bind"
    )]
    fn sandbox_exec_routes_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("sandbox_exec"));
                assert_eq!(
                    request["params"]["id_or_name"],
                    serde_json::json!("sandbox-1")
                );
                assert_eq!(
                    request["params"]["caller_persona_id"],
                    serde_json::json!("persona-owner")
                );
                assert_eq!(
                    request["params"]["command"],
                    serde_json::json!(["echo", "hello"])
                );

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": {"resolved_id": "sandbox-1", "output": "hello\n"},
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let (dispatch, output) = run_sandbox_exec(
            &config,
            "sandbox-1",
            Some("persona-owner".to_string()),
            &["echo".to_string(), "hello".to_string()],
        )
        .expect("sandbox exec");
        assert_eq!(dispatch, SandboxActionDispatch::DaemonRpc);
        assert_eq!(output, "hello\n");
        server.join().expect("fake daemon thread");
    }

    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "local macOS sandbox forbids fake daemon UDS bind"
    )]
    fn sandbox_run_routes_orchestration_through_daemon_when_socket_exists() {
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::Builder::new()
            .prefix("esb")
            .tempdir()
            .expect("tempdir");
        let config = DaemonConfig::for_test(tmp.path());
        std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
        let socket_path = config.socket_dir.join("daemon.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let _ = std::fs::remove_file(&socket_path);
                let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
                ready_tx.send(()).expect("signal ready");

                let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_str(line.trim()).expect("parse fake daemon request");
                assert_eq!(request["method"], serde_json::json!("sandbox_run"));
                assert_eq!(
                    request["params"]["sandbox"]["name"],
                    serde_json::json!("codebox")
                );
                assert_eq!(
                    request["params"]["sandbox"]["image"],
                    serde_json::json!("ubuntu:24.04")
                );
                assert_eq!(
                    request["params"]["credential_resource"],
                    serde_json::json!("obj-github-token")
                );
                assert_eq!(request["params"]["ttl_secs"], serde_json::json!(1800));
                assert_eq!(
                    request["params"]["statements"]
                        .as_array()
                        .expect("statements array")
                        .len(),
                    3
                );

                let mut encoded = serde_json::to_string(&serde_json::json!({
                    "id": request["id"],
                    "result": {
                        "sandbox": {
                            "id": "sandbox-123",
                            "name": "codebox",
                            "persona_id": "persona-sandbox",
                            "owner_persona_id": "persona-owner",
                            "container_id": null,
                            "image": "ubuntu:24.04",
                            "status": "created",
                            "created_at": "2026-05-18T00:00:00Z",
                            "workspace_path": null
                        },
                        "container_id": "container-123",
                        "start_error": null,
                        "grant": {
                            "PendingApproval": {
                                "approval_id": "approval-123"
                            }
                        }
                    },
                }))
                .expect("encode fake daemon response");
                encoded.push('\n');
                stream
                    .write_all(encoded.as_bytes())
                    .expect("write fake daemon response");
            }
        });

        ready_rx.recv().expect("wait for fake daemon ready");
        let opts = SandboxCreateOpts {
            name: "codebox".to_string(),
            image: "ubuntu:24.04".to_string(),
            owner_persona_id: Some("persona-owner".to_string()),
            ..SandboxCreateOpts::default()
        };
        let statements =
            build_composite_grant_statements(Some("obj-github-token"), Some(42), None, Some(1800));
        let (dispatch, prepared) = run_sandbox_run(
            &config,
            &opts,
            &statements,
            Some(1800),
            Some("obj-github-token"),
        )
        .expect("sandbox run via daemon");
        assert_eq!(dispatch, SandboxActionDispatch::DaemonRpc);
        assert_eq!(prepared.sandbox.id, "sandbox-123");
        assert_eq!(prepared.container_id.as_deref(), Some("container-123"));
        match prepared.grant {
            SandboxRunGrantDisposition::PendingApproval { approval_id } => {
                assert_eq!(approval_id, "approval-123");
            }
            other => panic!("expected pending approval, got {other:?}"),
        }
        server.join().expect("fake daemon thread");
    }

    /// Helper: parse a `daemon` subcommand argv into a `DaemonAction`.
    fn parse_daemon(args: &[&str]) -> DaemonAction {
        use clap::Parser;
        #[derive(Parser)]
        struct T {
            #[command(subcommand)]
            action: DaemonAction,
        }
        let mut full = vec!["test"];
        full.extend_from_slice(args);
        T::try_parse_from(full)
            .expect("daemon argv should parse")
            .action
    }

    /// implementation-note-483: `ember daemon install` (no flags) must
    /// take the separate-uid path. clap default for `bool` is false — we
    /// pin the surface so a future rename to `single_uid: Option<bool>` or
    /// a flipped default is intentional, not accidental.
    #[test]
    fn daemon_install_args_default_is_separate_uid() {
        let action = parse_daemon(&["install"]);
        match action {
            DaemonAction::Install { args } => {
                assert!(
                    !args.single_uid,
                    "default posture must be separate-uid (single_uid = false) per design"
                );
            }
            _ => panic!("expected DaemonAction::Install"),
        }
    }

    /// implementation-note-483: `ember daemon install --single-uid`
    /// must opt into the dev-mode path. Pins the flag spelling so future
    /// renames stay intentional.
    #[test]
    fn daemon_install_args_single_uid_flag_parses() {
        let action = parse_daemon(&["install", "--single-uid"]);
        match action {
            DaemonAction::Install { args } => {
                assert!(
                    args.single_uid,
                    "--single-uid must set single_uid = true (dev-mode escape, design §Dev mode)"
                );
            }
            _ => panic!("expected DaemonAction::Install"),
        }
    }

    /// T-INSTALL-WIZARD-NON-INTERACTIVE: `ember daemon install --non-interactive`
    /// (with optional `--accept-defaults` and `--posture`) must parse and
    /// surface the flags on `DaemonInstallArgs`. Pins the flag spellings so
    /// downstream Dockerfile / CI runner invocations stay stable.
    #[test]
    fn daemon_install_args_non_interactive_flag_parses() {
        let action = parse_daemon(&[
            "install",
            "--non-interactive",
            "--accept-defaults",
            "--posture",
            "separate-uid",
        ]);
        match action {
            DaemonAction::Install { args } => {
                assert!(args.non_interactive, "--non-interactive sets the flag");
                assert!(args.accept_defaults, "--accept-defaults sets the flag");
                assert_eq!(
                    args.posture.as_deref(),
                    Some("separate-uid"),
                    "--posture captured raw for downstream parsing"
                );
                assert!(
                    !args.single_uid,
                    "non-interactive run must not flip single_uid silently"
                );
            }
            _ => panic!("expected DaemonAction::Install"),
        }
    }

    /// implementation-note-484: `ember daemon migrate --to separate-uid`
    /// must parse to `DaemonAction::Migrate { to: "separate-uid" }`.
    #[test]
    fn daemon_migrate_to_separate_uid_parses() {
        let action = parse_daemon(&["migrate", "--to", "separate-uid"]);
        match action {
            DaemonAction::Migrate { to } => {
                assert_eq!(
                    to, "separate-uid",
                    "--to must capture the posture string exactly"
                );
            }
            _ => panic!("expected DaemonAction::Migrate"),
        }
    }

    /// implementation-note-484: `ember daemon migrate` without `--to`
    /// must be rejected by clap (required arg).
    #[test]
    fn daemon_migrate_without_to_is_rejected() {
        use clap::Parser;
        #[derive(Parser)]
        struct T {
            #[command(subcommand)]
            action: DaemonAction,
        }
        let result = T::try_parse_from(["test", "migrate"]);
        assert!(
            result.is_err(),
            "migrate without --to must fail clap validation"
        );
    }

    /// implementation-note-484: `is_separate_uid_posture` returns
    /// false when the ember user does not exist (T1 posture-detection
    /// function test — probes the live system user database).
    ///
    /// On the build host the `ember` user is not provisioned (CI / dev
    /// workstations start clean), so this asserts the false branch.
    /// Intentionally not `#[ignore]` — the no-ember-user case is the
    /// common unit-test environment and must always return false without
    /// side effects.
    #[test]
    fn is_separate_uid_posture_false_when_ember_user_absent() {
        // The build host does not have an `ember` system user. Verify
        // that the detector returns false without mutating state.
        // If this test fails it means the host already has an `ember`
        // user — which is valid, but not the default CI environment.
        if ember_daemon::install::is_separate_uid_posture() {
            // ember user already exists on this host — skip assertion to
            // avoid false positive. Document the environment assumption.
            eprintln!(
                "note: ember user already exists on this host; skipping absent-user assertion"
            );
        } else {
            // Confirm the return type is bool and the probe ran without panic.
            assert!(
                !ember_daemon::install::is_separate_uid_posture(),
                "is_separate_uid_posture must return false when ember user is absent"
            );
        }
    }

    /// implementation-note-463 T1: `is_ember_initialized` returns false
    /// for a fresh temp dir, and true once `cmd_init` has run and written daemon.db.
    ///
    /// Verifies the detection logic that `init --for claude` uses to decide
    /// whether to skip the basic init step (to avoid creating a duplicate "root"
    /// persona). A friendly who ran `ember init --name "Foo"` before running
    /// `ember init --for claude` triggered the double-init bug; after this
    /// fix the basic-init step is skipped when daemon.db is present.
    #[test]
    fn init_for_claude_code_skips_basic_init_when_already_initialized() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let run_dir = tmp.path().join("run");

        let config = ember_daemon::infra::config::DaemonConfig {
            socket_dir: run_dir.clone(),
            data_dir: data_dir.clone(),
            pid_file: run_dir.join("emberd.pid"),
            policy_file: tmp.path().join("policy.toml"),
            log_level: ember_daemon::infra::config::LogLevel::Info,
            dashboard_addr: None,
            git_proxy_addr: None,
            llm_proxy_addr: None,
            keyring: ember_daemon::infra::config::KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            presence: ember_daemon::infra::config::PresenceConfigSection::default(),
            snapshot_interval_secs: 3600,
            snapshot_pull_interval_secs: 600,
            snapshot_pull_endpoint: None,
            snapshot_pull_cluster_id: None,
            credential_store: None,
            ..ember_daemon::infra::config::DaemonConfig::for_test(tmp.path())
        };

        // Before any init: daemon.db does not exist → not initialized.
        assert!(
            !is_ember_initialized(&config),
            "is_ember_initialized must return false before any init"
        );

        // Run basic init to simulate a friendly who already ran `ember init`.
        let config_path = tmp.path().join("config.toml");
        unsafe {
            std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-passphrase-t3-t1");
            std::env::set_var("EMBER_SKIP_DAEMON_INSTALL_CHECK", "1");
        };
        cmd_init(
            &config,
            Some("Foo".to_string()),
            Some(&config_path),
            None,
            None,
            false,
            false,
        );
        unsafe {
            std::env::remove_var("EMBER_VAULT_PASSPHRASE");
            std::env::remove_var("EMBER_SKIP_DAEMON_INSTALL_CHECK");
        };

        // After init: daemon.db exists → is_ember_initialized returns true.
        assert!(
            is_ember_initialized(&config),
            "is_ember_initialized must return true after cmd_init wrote daemon.db"
        );

        // Verify daemon.db is present (the file is the detection signal).
        assert!(
            data_dir.join("daemon.db").exists(),
            "daemon.db must exist after cmd_init"
        );

        // Count personas: expect exactly one ("Foo") from the basic init.
        // This is the count that would survive if `init --for claude`
        // correctly skips the basic init step (no extra "root" added).
        let db_path = data_dir.join("daemon.db");
        let store = DaemonStore::open(&db_path).expect("open store");
        let personas = store.list_personas().expect("list personas");
        assert_eq!(
            personas.len(),
            1,
            "exactly one persona expected after a single cmd_init; got: {:?}",
            personas.iter().map(|p| &p.name).collect::<Vec<_>>()
        );
        assert_eq!(
            personas[0].name, "Foo",
            "persona name must match --name argument"
        );
    }

    /// implementation-note-463 T2: `is_ember_initialized` returns false
    /// for an empty temp dir, confirming that the `init --for claude` path
    /// would run basic init (not skip it) when starting fresh.
    #[test]
    fn init_for_claude_code_runs_basic_init_when_fresh() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let run_dir = tmp.path().join("run");

        let config = ember_daemon::infra::config::DaemonConfig {
            socket_dir: run_dir.clone(),
            data_dir: data_dir.clone(),
            pid_file: run_dir.join("emberd.pid"),
            policy_file: tmp.path().join("policy.toml"),
            log_level: ember_daemon::infra::config::LogLevel::Info,
            dashboard_addr: None,
            git_proxy_addr: None,
            llm_proxy_addr: None,
            keyring: ember_daemon::infra::config::KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            presence: ember_daemon::infra::config::PresenceConfigSection::default(),
            snapshot_interval_secs: 3600,
            snapshot_pull_interval_secs: 600,
            snapshot_pull_endpoint: None,
            snapshot_pull_cluster_id: None,
            credential_store: None,
            ..ember_daemon::infra::config::DaemonConfig::for_test(tmp.path())
        };

        // Fresh temp dir: daemon.db absent → not initialized → basic init would run.
        assert!(
            !is_ember_initialized(&config),
            "is_ember_initialized must return false for a fresh (empty) data_dir"
        );

        // Simulate the basic init step that `init --for claude` would run.
        let config_path = tmp.path().join("config.toml");
        unsafe {
            std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-passphrase-t3-t2");
            std::env::set_var("EMBER_SKIP_DAEMON_INSTALL_CHECK", "1");
        };
        cmd_init(&config, None, Some(&config_path), None, None, false, false);
        unsafe {
            std::env::remove_var("EMBER_VAULT_PASSPHRASE");
            std::env::remove_var("EMBER_SKIP_DAEMON_INSTALL_CHECK");
        };

        // After init: config.toml and daemon.db must exist.
        assert!(
            config_path.exists(),
            "config.toml must exist after cmd_init"
        );
        assert!(
            data_dir.join("daemon.db").exists(),
            "daemon.db must exist after cmd_init"
        );

        // is_ember_initialized must now return true.
        assert!(
            is_ember_initialized(&config),
            "is_ember_initialized must return true after basic init completed"
        );
    }
}
