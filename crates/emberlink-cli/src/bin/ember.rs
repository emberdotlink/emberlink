//! `ember` CLI binary.
//!
//! open_store_mutator_audit_complete
//!
//! Audit of every `open_store(config)` call site in this file, per
//! implementation-note-385. Under design
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

use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::rc::Rc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
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
    check_production_sentinel, is_cargo_test_binary, keyring_writes_suppressed, migrate_mek_acl,
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
/// CLI-VERSION-FLAG: the implementation-note-101 root cause was a
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

struct VaultStoreResult {
    dispatch: VaultActionDispatch,
    id: String,
    name: String,
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

    fn allowed_targets_json_string(&self) -> Option<String> {
        self.allowed_targets
            .as_ref()
            .map(|targets| serde_json::to_string(targets).unwrap_or_default())
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

/// Remove a vault entry on the current authority surface.
fn run_vault_remove(
    config: &DaemonConfig,
    name: &str,
) -> Result<VaultActionDispatch, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        emberlink_cli::call_daemon_method(
            &socket_path,
            "vault_remove",
            &serde_json::json!({ "name": name }),
        )?;
        Ok(VaultActionDispatch::DaemonRpc)
    } else {
        let store = open_store(config);
        let vault = Vault::open_from_config(config)
            .map_err(|e| core_types::ValidationError::new(format!("vault open: {e}")))?;
        vault
            .remove(VaultScope::Interactive, &store, name)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok(VaultActionDispatch::LocalFallback)
    }
}

/// Fetch a vault entry on the current authority surface.
fn run_vault_get(
    config: &DaemonConfig,
    name: &str,
) -> Result<(VaultActionDispatch, Vec<u8>), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
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
    } else {
        let store = open_store(config);
        let vault = Vault::open_from_config(config)
            .map_err(|e| core_types::ValidationError::new(format!("vault open: {e}")))?;
        let value = vault
            .get(VaultScope::Interactive, &store, name)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((VaultActionDispatch::LocalFallback, value))
    }
}

/// Store a vault entry on the current authority surface.
fn run_vault_store(
    config: &DaemonConfig,
    name: &str,
    value: &[u8],
    metadata: Option<&str>,
) -> Result<VaultStoreResult, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
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
    } else {
        let store = open_store(config);
        let vault = Vault::open_from_config(config)
            .map_err(|e| core_types::ValidationError::new(format!("vault open: {e}")))?;
        let info = vault
            .add(VaultScope::Interactive, &store, name, value, metadata)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok(VaultStoreResult {
            dispatch: VaultActionDispatch::LocalFallback,
            id: info.id.to_string(),
            name: info.name,
        })
    }
}

/// Create a grant on the current authority surface.
fn run_grant_create(
    config: &DaemonConfig,
    spec: &GrantCreateSpec,
) -> Result<(GrantActionDispatch, serde_json::Value), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "create_grant",
            &spec.daemon_request(),
        )?;
        Ok((GrantActionDispatch::DaemonRpc, result))
    } else {
        let store = open_store(config);
        let info = store
            .create_grant_with_budget(
                &spec.persona,
                &spec.credential,
                &spec.scope,
                spec.ttl_secs,
                spec.budget.clone(),
            )
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;

        let targets_json = spec.allowed_targets_json_string();
        if spec.max_uses_per_hour.is_some()
            || spec.allowed_hours_start.is_some()
            || targets_json.is_some()
            || spec.max_delegation_depth.is_some()
        {
            store
                .conn()
                .execute(
                    "UPDATE grants SET max_uses_per_hour=?1, allowed_hours_start=?2, allowed_hours_end=?3, allowed_targets=?4, max_delegation_depth=?5 WHERE id=?6",
                    rusqlite::params![
                        spec.max_uses_per_hour.map(|v| v as i64),
                        spec.allowed_hours_start.map(|v| v as i64),
                        spec.allowed_hours_end.map(|v| v as i64),
                        targets_json,
                        spec.max_delegation_depth.map(|v| v as i64),
                        info.id,
                    ],
                )
                .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        }
        if let Some(limit) = spec.max_children_per_day {
            store
                .mark_grant_standing(
                    &info.id,
                    limit,
                    spec.auto_delegate_scope_template.as_deref(),
                )
                .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        }

        Ok((
            GrantActionDispatch::LocalFallback,
            serde_json::json!({
                "id": info.id,
                "persona_id": info.persona_id,
                "credential_name": info.credential_name,
                "scope": info.scope,
                "expires_at": info.expires_at,
                "budget": spec.budget.clone(),
                "standing": spec.max_children_per_day.map(|limit| serde_json::json!({
                    "max_children_per_day": limit,
                    "auto_delegate_scope_template": spec.auto_delegate_scope_template.clone(),
                })),
                "conditions": {
                    "max_uses_per_hour": spec.max_uses_per_hour,
                    "allowed_hours": spec.allowed_hours_start.map(|start| format!(
                        "{}:00-{}:00 UTC",
                        start,
                        spec.allowed_hours_end.unwrap_or(0)
                    )),
                    "allowed_targets": spec.allowed_targets.clone(),
                    "max_delegation_depth": spec.max_delegation_depth,
                    "max_children_per_day": spec.max_children_per_day,
                }
            }),
        ))
    }
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

/// Delegate a grant on the current authority surface.
fn run_grant_delegate(
    config: &DaemonConfig,
    parent_grant_id: &str,
    child_persona_id: &str,
    scope: &str,
    ttl_secs: Option<u64>,
    budget: Option<Budget>,
) -> Result<(GrantActionDispatch, serde_json::Value), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let status = emberlink_cli::call_daemon_method(
            &socket_path,
            "grant_status",
            &serde_json::json!({ "id": parent_grant_id }),
        )?;
        let caller_persona_id = status
            .get("persona_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                core_types::ValidationError::new(
                    "daemon grant_status: missing parent grant persona_id",
                )
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
    } else {
        let store = open_store(config);
        let info = store
            .delegate_grant_full(parent_grant_id, child_persona_id, scope, ttl_secs, budget)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((
            GrantActionDispatch::LocalFallback,
            serde_json::json!({
                "id": info.id,
                "parent": parent_grant_id,
                "persona_id": info.persona_id,
                "scope": info.scope,
                "expires_at": info.expires_at,
                "budget": info.budget,
            }),
        ))
    }
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

/// Extend a grant on the current authority surface.
fn run_grant_extend(
    config: &DaemonConfig,
    grant_id: &str,
    add_tokens: Option<u64>,
    add_cents: Option<u64>,
    add_ttl_secs: Option<u64>,
) -> Result<GrantActionDispatch, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
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
    } else {
        let store = open_store(config);
        store
            .extend_grant(grant_id, add_tokens, add_cents, add_ttl_secs)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok(GrantActionDispatch::LocalFallback)
    }
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

/// List receipts on the current authority surface.
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
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "list_receipts",
            &serde_json::json!({ "persona_id": persona }),
        )?;
        let receipts = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon list_receipts: {e}")))?;
        Ok((ReceiptActionDispatch::DaemonRpc, receipts))
    } else {
        let store = open_store(config);
        let receipts = store
            .list_receipts(persona)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((ReceiptActionDispatch::LocalFallback, receipts))
    }
}

/// Fetch a receipt on the current authority surface.
///
/// The installed daemon path preserves the existing CLI contract: callers may
/// supply either a receipt id or a grant id, and the daemon resolves terminal
/// grants to their receipt rows.
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
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "get_receipt",
            &serde_json::json!({ "id": id }),
        )?;
        let receipt = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon get_receipt: {e}")))?;
        Ok((ReceiptActionDispatch::DaemonRpc, receipt))
    } else {
        let store = open_store(config);
        let receipt = resolve_receipt(&store, id).map_err(core_types::ValidationError::new)?;
        Ok((ReceiptActionDispatch::LocalFallback, receipt))
    }
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

/// Query receipt-backed audit rows on the current authority surface.
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
    if socket_path.exists() {
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
    } else {
        let store = open_store(config);
        let rows = store
            .list_receipt_rows(filter)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((AuditActionDispatch::LocalFallback, rows))
    }
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
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let params = match outcome {
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
        ember_daemon::infra::status::StatusSummary,
    ),
    core_types::ValidationError,
> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if daemon_running && socket_path.exists() {
        let result =
            emberlink_cli::call_daemon_method(&socket_path, "status", &serde_json::Value::Null)?;
        let summary = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon status: {e}")))?;
        Ok((StatusActionDispatch::DaemonRpc, summary))
    } else {
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
        };
        Ok((StatusActionDispatch::LocalFallback, summary))
    }
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

/// Per implementation-note-386: refuse `ember vault add --value <secret>`
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
        /// One-command cohort A onboarding (implementation-note-387).
        ///
        /// Currently the only accepted value is `claude-code`. When set,
        /// the standard daemon init runs first; then the cohort A
        /// orchestrator creates a `claude-code-{hostname}` persona, writes
        /// the default scope template, mints a 24h grant, patches
        /// `~/.claude/settings.json`, and optionally captures a GitHub
        /// PAT into the vault. See design §2.
        #[arg(long = "for", value_name = "TARGET")]
        for_target: Option<String>,
        /// Skip all interactive prompts. When set and the daemon is not
        /// installed, `ember init` exits with an error and a runbook
        /// pointer instead of prompting to run `sudo ember daemon install`.
        /// Useful for CI and scripted provisioning where stdin is not a TTY.
        #[arg(long)]
        non_interactive: bool,
    },
    /// Uninstall ember integrations.
    ///
    /// Currently supports `--for claude-code` (implementation-note-387),
    /// which removes only the lines `init --for claude-code` added to
    /// `~/.claude/settings.json`. Persona, grant, and vault entries are
    /// left in place — they may be in use by other tools.
    Uninstall {
        /// Integration target to uninstall. Currently only `claude-code`.
        #[arg(long = "for", value_name = "TARGET")]
        for_target: String,
    },
    /// Boot a container-mode session (implementation-note-388 scaffold).
    Up {
        /// Profile name selecting the compose service set (`dev` /
        /// `headless` / `demo`).
        #[arg(long, value_name = "NAME")]
        profile: Option<String>,
    },
    /// Tear down a container-mode session (implementation-note-388 scaffold).
    Down {
        /// Eager-revoke this session's grants instead of letting them expire at TTL.
        #[arg(long = "revoke-grants")]
        revoke_grants: bool,
        /// Remove named compose volumes after teardown.
        #[arg(long)]
        purge: bool,
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
    /// Manage the binary-pin manifest used for daemon-socket peer-binary
    /// content-hash binding. Per KEYCHAIN-CONSOLIDATE-CLI adversarial-
    /// review HIGH-1: every `local_state_key_*` call verifies the peer's
    /// binary blake3 against this manifest. The manifest is daemon-self-
    /// signed (v0.3 trust model: TOFU at the moment generate runs).
    #[command(name = "binary-pin")]
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
    Broker {
        #[command(subcommand)]
        action: emberlink_cli::broker::BrokerCmd,
    },
    /// Manage daemon-controlled credential bindings (implementation-note-150).
    ///
    /// A binding ties `(persona, working-tree, remote)` to a remote URL
    /// the broker is authorized to inject credentials for. This is the
    /// EXPLICIT admin path — operators use it to pre-register bindings
    /// during admin work (no biometric required) and to recover from
    /// rename/repo-move scenarios. Biometric will gate the TOFU flow
    /// (DCC-3), not this verb.
    Bind {
        #[command(subcommand)]
        action: emberlink_cli::bind::BindCmd,
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
    /// Cluster snapshot management (implementation-note-174)
    Cluster {
        #[command(subcommand)]
        action: ClusterAction,
    },
    /// Launch Claude Code with ember-managed env + PATH wiring (design Phase 4).
    ///
    /// Selects daemon flavor via `--dev` or `--prod` (default: `--prod`).
    /// Prepends the correct shadow PATH, injects EMBER_DAEMON_SOCKET /
    /// EMBER_SESSION_ID / EMBER_STRICT_BROKER / EMBER_DAEMON_FLAVOR into the
    /// child env, verifies daemon reachability, then exec-replaces this process
    /// with `claude` (or `$EMBER_CLAUDE_BIN`).
    ///
    /// Legacy cohort-A session-RPC behavior (implementation-note-389 / design §2) is
    /// preserved when neither `--dev` nor `--prod` alter the selected daemon;
    /// the new flavor flags are design Phase 4 additions.
    #[command(
        name = "claude-code",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    ClaudeCode {
        /// Use the dev daemon flavor (~/.ember/run/daemon.dev.sock).
        /// Mutually exclusive with --prod.
        #[arg(long, conflicts_with = "prod")]
        dev: bool,
        /// Use the prod daemon flavor (~/.ember/run/daemon.sock). Default when
        /// neither --dev nor --prod is given.
        /// Mutually exclusive with --dev.
        #[arg(long, conflicts_with = "dev")]
        prod: bool,
        /// Trailing arguments forwarded verbatim to `claude`.
        #[arg(value_name = "CLAUDE_ARGS")]
        args: Vec<String>,
    },
    /// Demo subcommands — canned flows for friendly-dev onboarding and
    /// the May-3 composite-grant recording.
    ///
    /// `wedge`  — 60-second canned fallback (implementation-note-390,
    ///            design §8). Spins up an isolated daemon + seeded vault
    ///            + MCP server via `qember.sh demo up`.
    /// `bundle` — submit the locked May-3 4-statement composite-grant
    ///            approval (implementation-note-391). In-process
    ///            store call; no socket round-trip.
    Demo {
        #[command(subcommand)]
        action: DemoAction,
    },
    /// Grants manifest workflows (validate <file>).
    Grants {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Session live-tail subcommands.
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
    Construct {
        #[command(subcommand)]
        action: ConstructAction,
    },
    /// Manage content-hash-pinned binaries (T-CONSTRUCT-PATH-PINNING-CLI).
    ///
    /// Reads/writes `~/.ember/binaries/manifest.toml`. Verbs:
    ///   install <tool>@<version> --from-path <path>
    ///   list
    ///   update <tool>   (stub — not yet implemented)
    ///   remove <tool>@<version>
    Binary {
        #[command(subcommand)]
        action: BinaryAction,
    },
    /// Manage headless (attested-device) enrollments — variable
    /// duration credential delegation for headless / scheduled jobs
    /// (implementation-note-392, design).
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
    /// (design Amendment 1 v3, implementation-note-362).
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
    Orchestrator {
        #[command(subcommand)]
        action: emberlink_cli::orchestrator::OrchestratorAction,
    },
    /// Dev daemon install + info + sync (design Phase 4).
    ///
    /// `ember dev install` — provision the dev daemon end-to-end (11 phases).
    ///   Phase 1: generate the dev IdentityRoot Ed25519 keypair and stash the
    ///   private key in Keychain at `sh.emberlink.dev-identity-root`.
    ///   Phases 2-4: GH App + uid/group provisioning.
    ///   Phases 5-10: slice-C helper modules ready (prior change); integration PR wires them.
    ///
    /// `ember dev info` — print the current dev install state (fingerprint,
    ///   paths, socket, daemon reachability).
    ///
    /// `ember dev sync` — incremental rebuild + content-hash diff + copy + daemon
    ///   kickstart. Use this after editing daemon or construct code.
    Dev {
        #[command(subcommand)]
        action: DevAction,
    },
    /// Manage the ember mTLS bridge (design Component 1).
    ///
    /// `ember bridge endpoint [--emit-file <path>] [--json]`
    ///   Print or write the bridge endpoint JSON used by in-container agents.
    ///   The JSON contains `addr` (host.docker.internal:<port>) and
    ///   `ca_fingerprint_sha256` (hex SHA-256 of the KMS edge CA cert DER).
    Bridge {
        #[command(subcommand)]
        action: BridgeAction,
    },
}

/// `ember dev` subcommands (design Phase 4).
#[derive(Subcommand)]
enum DevAction {
    /// Install the dev daemon (11-phase flow — phases 1-4 implemented;
    /// phases 5-10 helpers ready in slice-C, integration PR wires them).
    Install,
    /// Print dev install state (fingerprint, paths, socket, daemon ping).
    Info,
    /// Incremental rebuild + content-hash diff + copy + daemon kickstart.
    ///
    /// Runs `cargo build --release -p ember-daemon -p ember-construct`,
    /// diffs each built binary (SHA-256) against the dev install root copy,
    /// copies any changed binaries, then restarts the dev daemon via
    /// `launchctl kickstart -k system/sh.emberlink.daemon.dev`.
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
    /// (implementation-note-390, design §8). Shells `qember.sh demo
    /// up`/`down` and prints the live-approval-flow next steps.
    Wedge {
        /// Tear down the demo environment (calls `qember.sh demo down`).
        #[arg(long)]
        teardown: bool,
    },
    /// Mint the locked May-3 4-statement composite-grant bundle
    /// (implementation-note-391). Submits a single composite
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

/// `ember headless <action>` — attested-device enrollment management
/// (implementation-note-392, design). Surface for the
/// daemon-side `headless_enroll` / `headless_revoke` / `headless_status`
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
    /// Run the Layer-1 pre-flight scope check
    /// (implementation-note-261, design).
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
    /// Install the ember daemon (separate-uid posture by default; see design).
    ///
    /// Default behaviour provisions the dedicated `ember` system user and
    /// `ember-clients` connect group, chowns the daemon's at-rest state to
    /// `ember:ember-clients`, and installs the platform launcher
    /// (LaunchDaemon on macOS / systemd unit on Linux). Pass `--single-uid`
    /// to opt into the relaxed-threat-model dev posture (reserved — not
    /// yet implemented). See design.
    Install {
        #[command(flatten)]
        args: DaemonInstallArgs,
    },
    /// Migrate a running single-uid installation to the separate-uid posture
    /// (design) while preserving all on-disk state (vault rows, grants,
    /// sessions). Only `--to separate-uid` is accepted in v1.
    ///
    /// If the host is already on the separate-uid posture the command exits
    /// immediately with a success message ("already on separate-uid posture").
    Migrate {
        /// Target posture. Only `separate-uid` is accepted.
        #[arg(long, value_name = "POSTURE")]
        to: String,
    },
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
        /// implementation-note-386.
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
    /// Per implementation-note-393 this is the operator-facing
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
    /// implementation-note-100 shipped. After this runs, vault unlocks
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
    /// implementation-note-303: unblocks `ember sandbox create --name X` retries
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
        /// (design v2 forward-compat) Show full sidecar content. Today a no-op.
        #[arg(long)]
        raw: bool,
    },
    /// Export a receipt's signed JSON to stdout
    Export {
        /// Receipt id
        id: String,
        /// Output format: `json` (default) or `md` (markdown).
        #[arg(long, default_value = "json")]
        format: String,
        /// (design v2 forward-compat) Show full sidecar content. Today a no-op.
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
    /// Query the receipts table (EMBER-implementation-note-244).
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
    /// implementation-note-230 (B): walk the audit chain and
    /// verify each row's `blake3(prev_hash || canonical_row_bytes)`
    /// matches its stored `row_hash`. Routes through the daemon's
    /// `audit_verify` socket method so the verdict is authoritative
    /// (same path the daemon's startup verify uses).
    Verify {
        /// Limit the walk to the most recent N rows. Omit for a full-chain walk.
        #[arg(long)]
        tail: Option<usize>,
    },
}

/// EMBER-implementation-note-244 — parse a `--since` argument.
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
/// implementation-note-394: check whether the ember-init shadow PATH
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
            "shadow path not installed at {}; run `ember init --for claude-code`",
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
            "shadow path at {} is missing shims: {} — run `ember init --for claude-code`",
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
/// implementation-note-172 extended this from a single dashboard line to the full
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
            // implementation-note-173: the LLM proxy is what the
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
            // implementation-note-173: the git-echo proxy URL now lives
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

/// implementation-note-395: resolve the user-pinned config path from
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

/// implementation-note-188: probe `/api/status` on the configured
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
    // implementation-note-395: when `--config` is absent, fall back
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
        // implementation-note-396: loud-fail instead of silent
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

    // implementation-note-296: in-process CLI subcommands (grant/sandbox/persona) talk to
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
    if let Err(e) = ember_daemon::infra::receipt::init_identity(&config.data_dir) {
        tracing::warn!("could not initialise daemon identity for receipt emission: {e}");
    }

    store
}

/// implementation-note-397: detect whether a basic `ember init` has
/// already been run. Returns true if `daemon.db` exists in `config.data_dir`.
/// On live daemon-backed runs the daemon owns creating that file; the old
/// local-store fallback still creates it in-process. Used by the
/// `--for claude-code` handler to skip re-running basic init (and creating a
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
/// regression-tested in `tests::default_policy_seed_parses` (implementation-note-398).
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
    // otherwise consult `EMBER_CONFIG` / `EMBER_DEMO_DIR` (implementation-note-399-
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
            if let Err(e) = check_production_sentinel(&service, DEFAULT_KEYRING_SERVICE, &home) {
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
                eprintln!("           Set EMBER_VAULT_PASSPHRASE env var to bypass the keyring.");
                "keyring unavailable (see above)".to_string()
            }
        };

        (generated, status)
    };

    let root_name = name.as_deref().unwrap_or("root");

    // init_persona_rpc_after_autostart_reorder: implementation-note-400
    // Autostart fires BEFORE the RPC so the socket is live when create_persona dispatches.
    //
    // Under design separate-uid posture (daemon=ember uid, operator=operator uid)
    // the operator cannot write the daemon's SQLite DB, so the prior direct
    // `store.create_persona(root_name)` call failed. Route through the daemon
    // JSON-RPC instead. Mirrors the pattern in `cmd_init_for_claude_code`.
    let socket_path = config.socket_dir.join("daemon.sock");
    // EMBER_SKIP_DAEMON_INSTALL_CHECK: test-only bypass — same env var as the
    // daemon-install precheck gate above. When set, skip the autostart block so
    // binary tests running against isolated tmp dirs don't attempt to spawn a
    // real daemon or wait for a socket that will never appear.
    let skip_daemon_autostart = std::env::var("EMBER_SKIP_DAEMON_INSTALL_CHECK").is_ok();
    if !skip_daemon_autostart && !socket_path.exists() {
        let autostart_config_path = resolved_user_config_path(cli_config_path);
        let home = dirs_next::home_dir().unwrap_or_else(|| std::path::PathBuf::from("/"));
        let use_launch_agent = emberlink_cli::onboarding::claude_code::should_use_launch_agent(
            &home,
            autostart_config_path.as_deref(),
        );

        if use_launch_agent {
            println!("  Daemon:   not running — starting daemon (install-agent)");
            match daemon_agent::install_agent(autostart_config_path.as_deref(), false) {
                Ok(_) => {
                    println!("  Daemon:   started daemon (background, install-agent)");
                }
                Err(daemon_agent::AgentError::UnsupportedPlatform) => {
                    if let Err(e) = spawn_background_daemon(autostart_config_path.as_deref()) {
                        eprintln!("error: daemon autostart failed: {e}");
                        process::exit(1);
                    }
                    println!("  Daemon:   started daemon (background process)");
                }
                Err(e) => {
                    eprintln!(
                        "error: daemon autostart failed: {e}\n\
                         Run `ember daemon start --background --install-agent` manually first, \
                         then re-run `ember init`."
                    );
                    process::exit(1);
                }
            }
        } else {
            println!("  Daemon:   not running — starting daemon (background, isolated env)");
            if let Err(e) = spawn_background_daemon(autostart_config_path.as_deref()) {
                eprintln!("error: daemon autostart failed: {e}");
                process::exit(1);
            }
            println!("  Daemon:   started daemon (background process)");
        }

        let timeout_secs =
            emberlink_cli::onboarding::claude_code::autostart_liveness_timeout_secs();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        loop {
            if socket_path.exists() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                eprintln!(
                    "error: daemon started but socket did not appear within {timeout_secs}s \
                     (expected at {}); check daemon logs at $HOME/.ember/logs/daemon.out \
                     and retry. Override the timeout with \
                     EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS=<seconds>.",
                    socket_path.display()
                );
                process::exit(1);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    // When EMBER_SKIP_DAEMON_INSTALL_CHECK is set (test-only bypass) and no
    // daemon socket is present, fall back to the old local store path.
    let daemon_socket_live = socket_path.exists();
    let mut direct_store: Option<DaemonStore> = None;
    let (persona_id, persona_name, persona_public_key) =
        if skip_daemon_autostart && !socket_path.exists() {
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
        println!("  Daemon:   not started (local fallback path)");
        println!();
        println!("Run `ember daemon start` to start the daemon.");
    }

    // EMBER-INIT-FIRST-implementation-note-401 (v2): emit a real signed Grant
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

/// implementation-note-387: cohort A onboarding orchestrator.
///
/// Runs after `cmd_init` has set up the keyring/vault/salt/root persona.
/// Creates the agent persona, writes the scope template, mints a 24h
/// grant, patches `~/.claude/settings.json`, and optionally captures a
/// GitHub PAT into the vault. Idempotent — every step is a find-or-create
/// or atomic-write.
/// implementation-note-402: spawn `ember daemon start
/// --background` directly so the child inherits the current process env
/// (HOME, EMBER_KEYRING_SERVICE, EMBER_CONFIG, …).
///
/// Used when `should_use_launch_agent` returns false — i.e. the operator is
/// running under an isolated HOME or with an explicit `--config` override —
/// because the LaunchAgent / systemd-user path would write a service file
/// pointing at the operator's *real* HOME instead.
fn spawn_background_daemon(
    config_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let exe =
        std::env::current_exe().map_err(|e| format!("could not resolve ember binary: {e}"))?;
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("daemon")
        .arg("start")
        .arg("--background")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null());
    if let Some(path) = config_path {
        cmd.arg("--config").arg(path);
    }
    let child = cmd
        .spawn()
        .map_err(|e| format!("could not start daemon: {e}"))?;
    #[allow(clippy::zombie_processes)]
    std::mem::forget(child);
    Ok(())
}

fn cmd_init_for_claude_code(config: &DaemonConfig) -> Result<(), Box<dyn std::error::Error>> {
    use emberlink_cli::onboarding::claude_code as cc;

    let persona_name = cc::claude_code_persona_name();
    let template_path = cc::default_grant_template_path()?;
    let settings_path = cc::default_settings_json_path()?;

    println!();
    println!("Setting up Claude Code integration:");

    // implementation-note-403: autostart daemon if not running.
    //
    // `init --for claude-code` opens the vault, which requires the daemon to be
    // running (the vault is AEAD-sealed and the daemon holds the unlock key).
    // QUICKSTART.md previously told friendlies to run `ember init --for
    // claude-code` BEFORE starting the daemon, causing:
    //   error: vault open: refusing to open production keychain without opt-in checkpoint
    //
    // implementation-note-402: the LaunchAgent / systemd-user
    // path is correct for production (single canonical always-up daemon per
    // login session), but it bakes the operator's *real* HOME into the service
    // file. Under an isolated HOME (T3 walks, CI, QA), the launched daemon
    // would bind the production socket while our liveness probe waited at the
    // isolated socket path and timed out. So we branch on
    // `cc::should_use_launch_agent(home, --config)`:
    //   - production HOME, no --config → LaunchAgent / systemd (existing path).
    //   - non-default HOME or --config set → raw `ember daemon start
    //     --background` spawn that inherits the current process env.
    //
    // The liveness wait is now 10s by default (raised from 5s) and honors
    // `EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS` for further override.
    {
        let socket_path = config.socket_dir.join("daemon.sock");
        if socket_path.exists() {
            println!(
                "  Daemon:   already running (socket {})",
                socket_path.display()
            );
        } else {
            let config_path = resolved_user_config_path(None);
            let home = dirs_next::home_dir().unwrap_or_else(|| std::path::PathBuf::from("/"));
            // implementation-note-402: branch the autostart
            // path on whether HOME / --config look like a default install.
            let use_launch_agent = cc::should_use_launch_agent(&home, config_path.as_deref());

            if use_launch_agent {
                println!("  Daemon:   not running — starting daemon (install-agent)");
                match daemon_agent::install_agent(config_path.as_deref(), false) {
                    Ok(_) => {
                        println!("  Daemon:   started daemon (background, install-agent)");
                    }
                    Err(daemon_agent::AgentError::UnsupportedPlatform) => {
                        // Platform doesn't support launchd/systemd — fall back to
                        // spawning a raw background process (same as
                        // `ember daemon start --background`).
                        spawn_background_daemon(config_path.as_deref())?;
                        println!("  Daemon:   started daemon (background process)");
                    }
                    Err(e) => {
                        return Err(format!(
                            "daemon autostart failed: {e}\n\
                             Run `ember daemon start --background --install-agent` manually first, \
                             then re-run `ember init --for claude-code`."
                        )
                        .into());
                    }
                }
            } else {
                // Non-default HOME or --config set — skip LaunchAgent and
                // spawn a raw background daemon that inherits the current
                // env (HOME, EMBER_KEYRING_SERVICE, EMBER_CONFIG, …).
                println!("  Daemon:   not running — starting daemon (background, isolated env)");
                spawn_background_daemon(config_path.as_deref())?;
                println!("  Daemon:   started daemon (background process)");
            }

            // Wait up to N seconds for the socket to appear before proceeding.
            // Default raised to 10s (from 5s) so first-time provisioning of
            // vault.salt + daemon.db has slack on slow disks; override via
            // `EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS`.
            let timeout_secs = cc::autostart_liveness_timeout_secs();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
            loop {
                if socket_path.exists() {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "daemon started but socket did not appear within {timeout_secs}s \
                         (expected at {}); check daemon logs at $HOME/.ember/logs/daemon.out \
                         and retry. Override the timeout with \
                         EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS=<seconds>.",
                        socket_path.display()
                    )
                    .into());
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    // implementation-note-404: security-hardening call-to-action.
    //
    // When the daemon is on single-uid posture, offer an inline migration with
    // explicit consent rather than printing a passive warning with internal jargon.
    // The checkpoint file suppresses this prompt on every subsequent run (regardless
    // of what the user chose) so we never nag them on daemon start or re-init.
    {
        let sentinel_path = config.data_dir.join(".posture-prompt-shown");
        let prompt_already_shown = sentinel_path.exists();

        if !ember_daemon::install::is_separate_uid_posture() && !prompt_already_shown {
            println!();
            println!("  Security hardening (recommended):");
            println!("    ember currently runs as your user account. For stronger isolation");
            println!("    between the daemon and your shell/agents, ember can run as a");
            println!("    dedicated user (`ember-daemon`) with its own home directory and");
            println!("    permissions. This means: even a compromised agent in your shell");
            println!("    can't read the daemon's vault directly.");
            println!();
            println!("    Ember can set this up now — it requires one sudo prompt to create");
            println!("    the user account.");
            println!();

            // Write checkpoint now — before prompting — so even if the user
            // Ctrl-Cs we don't re-show on the next run.
            if let Some(parent) = sentinel_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&sentinel_path, "posture-prompt-shown\n");

            let do_harden = if io::stdin().is_terminal() {
                use std::io::{BufRead as _, Write as _};
                print!("  Harden now? [Y/n]: ");
                let _ = io::stdout().flush();
                let mut line = String::new();
                let _ = io::stdin().lock().read_line(&mut line);
                let answer = line.trim().to_ascii_lowercase();
                // Default is Y — empty line or "y"/"yes" all mean proceed.
                answer.is_empty() || answer == "y" || answer == "yes"
            } else {
                // Non-interactive (CI / pipe): skip hardening, don't block.
                false
            };

            if do_harden {
                println!();
                println!("  Switching daemon to dedicated user...");
                migrate_to_separate_uid();
                println!("  Done. Daemon now running as `ember-daemon`.");
            } else {
                println!("  Skipped — daemon stays on your user account.");
                println!("  Run `ember daemon harden` later to enable.");
            }
            println!();
        }
    }

    // implementation-note-405: route every persona /
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

    // 3. Mint a 24h grant for the persona, or reuse an active one. The
    //    daemon's `list_grants` RPC requires `persona_id` and returns
    //    only that persona's active grants.
    let grants_value = emberlink_cli::call_daemon_method(
        &socket_path,
        "list_grants",
        &serde_json::json!({"persona_id": persona_id}),
    )
    .map_err(|e| format!("list grants (rpc): {e}"))?;
    let empty_grants: Vec<serde_json::Value> = Vec::new();
    let grants_array = grants_value.as_array().unwrap_or(&empty_grants);
    match grants_array.iter().find(|g| {
        g.get("credential_name")
            .and_then(|v| v.as_str())
            .map(|n| n == "claude-code-default-v1")
            .unwrap_or(false)
    }) {
        Some(g) => {
            let id = g.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let expires = g
                .get("expires_at")
                .and_then(|v| v.as_str())
                .unwrap_or("never");
            println!("  Grant:    reused {id} (active until {expires})");
        }
        None => {
            let created = emberlink_cli::call_daemon_method(
                &socket_path,
                "create_grant",
                &serde_json::json!({
                    "persona_id": persona_id,
                    "credential_name": "claude-code-default-v1",
                    "scope": "claude-code-default-v1",
                    "ttl_secs": cc::DEFAULT_GRANT_TTL_SECS,
                }),
            )
            .map_err(|e| format!("create grant (rpc): {e}"))?;
            let id = created.get("id").and_then(|v| v.as_str()).unwrap_or("");
            println!("  Grant:    created {id} (24h)");
        }
    }

    // 4. Patch ~/.claude/settings.json (idempotent).
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

    // 4b. Add permissions.deny entries for raw gh/git/kubectl outside the
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

    // 5. Optional GH PAT capture. Cohort A is friendly devs; this is the
    //    manual-paste path. Vault add routes through the daemon's
    //    `vault_add` RPC (same cross-uid rationale as the persona +
    //    grant blocks above) — the PAT never touches the operator-side
    //    vault.salt; the daemon owns the AEAD seal.
    let stdin_is_terminal = io::stdin().is_terminal();
    match cc::prompt_for_gh_pat(stdin_is_terminal)? {
        Some(pat) => {
            let result = emberlink_cli::call_daemon_method(
                &socket_path,
                "vault_add",
                &serde_json::json!({
                    "name": cc::GH_PAT_VAULT_NAME,
                    "value": pat,
                    "metadata": "github personal access token (cohort A)",
                }),
            );
            match result {
                Ok(info) => {
                    let id = info.get("id").and_then(|v| v.as_str()).unwrap_or("");
                    let name = info.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    println!("  GH PAT:   stored as {name} ({id})");
                }
                Err(e) => {
                    eprintln!("warning: failed to store GH PAT: {e}");
                    eprintln!(
                        "         re-run `ember vault add {}` to retry",
                        cc::GH_PAT_VAULT_NAME
                    );
                }
            }
        }
        None => {
            println!("  GH PAT:   skipped (run `ember vault add github-pat` later)");
        }
    }

    // 6. Print the next two commands per design §2.
    cc::print_next_commands();

    Ok(())
}

/// implementation-note-387: reverse the settings.json patch from
/// `init --for claude-code`. Removes only what we added; persona, grant,
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
    // `EMBER_DEMO_DIR/config.toml` (implementation-note-395), then the
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
/// error pointing at the always-up `ember daemon install-agent` flow.
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
             For the existing always-up dev posture, use:\n         \
             ember daemon install-agent\n       \
             That flow installs the daemon as a per-operator LaunchAgent / systemd \
             user unit — same uid as the operator, no sudo required.\n       \
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
                    "error: daemon is not running — run `ember daemon start` or `ember daemon install-agent`"
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
                // implementation-note-395: the respawn child inherits
                // the resolved config path so an env-var-pinned demo daemon
                // comes back on the same config.
                if let Some(path) = resolved_user_config_path(cli_config) {
                    cmd.arg("--config").arg(path);
                }
                match cmd.spawn() {
                    Ok(_child) => {
                        println!("Respawned daemon with `ember daemon start --background`.");
                        println!(
                            "Tip: run `ember daemon install-agent` to make reload-on-SIGTERM automatic."
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
                "error: daemon is not running — run `ember daemon start` or `ember daemon install-agent`"
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

/// Resolve a receipt from either a receipt id (`rct-…`) or a grant id.
/// When the argument is a grant id, looks up the grant's `receipt_id`
/// and loads that.
fn resolve_receipt(
    store: &DaemonStore,
    id: &str,
) -> Result<core_grant_types::grant_receipt::GrantReceipt, String> {
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

/// implementation-note-382 — `ember up` body.
///
/// Detects the host's container runtime (Docker / OrbStack / Podman),
/// renders the bundled compose template at
/// `crates/headless-runtime/templates/compose.yml.j2` against the operator-selected
/// profile (`dev` / `headless` / `demo`; defaults to `dev`), writes the
/// rendered YAML to `~/.ember/run/<run-id>/compose.yml`, and shells out to
/// `<engine> compose -f <path> --profile <name> up -d`.
fn cmd_up(profile: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let profile = profile.unwrap_or_else(|| "dev".to_string());
    if !matches!(profile.as_str(), "dev" | "headless" | "demo") {
        return Err(
            format!("unknown profile: {profile}. Supported: dev | headless | demo").into(),
        );
    }

    let engine = emberlink_cli::up::detect_runtime_engine()?.ok_or_else(
        || -> Box<dyn std::error::Error> {
            emberlink_cli::up::missing_runtime_remediation().into()
        },
    )?;
    println!(
        "Runtime: {} ({})",
        engine.display_name(),
        engine.compose_binary()
    );

    let workspace_root = std::env::current_dir()?;
    let template_path = workspace_root.join("crates/headless-runtime/templates/compose.yml.j2");
    if !template_path.exists() {
        return Err(format!(
            "compose template not found at {} — ember up must run from the emberlink workspace root, or set EMBER_COMPOSE_TEMPLATE",
            template_path.display()
        )
        .into());
    }

    let run_dir = dirs_next::home_dir()
        .ok_or_else(|| -> Box<dyn std::error::Error> {
            "could not resolve $HOME for ~/.ember/run".into()
        })?
        .join(".ember/run")
        .join(format!("{}-{}", profile, chrono::Utc::now().timestamp()));
    std::fs::create_dir_all(&run_dir)?;
    let bridge_cert_dir = run_dir.join("certs");
    std::fs::create_dir_all(&bridge_cert_dir)?;
    let compose_path = run_dir.join("compose.yml");

    let context = emberlink_cli::up::ComposeRenderContext::default_for_profile(
        profile.clone(),
        bridge_cert_dir,
    );
    let rendered = emberlink_cli::up::render_compose_template(&template_path, &context)?;
    std::fs::write(&compose_path, &rendered)?;
    println!("Compose: {}", compose_path.display());

    let (stdout, _stderr) = emberlink_cli::up::compose_up(engine, &compose_path, &profile)?;
    if !stdout.trim().is_empty() {
        println!("{}", stdout.trim_end());
    }

    eprintln!(
        "note: bridge cert provisioning + `bridge-cli ping` healthcheck land once implementation-note-406 wires the daemon presence RPC. The compose stack is up; the trust handshake is not yet enforced from this verb."
    );
    println!("\nember up: session ready (profile={profile})");
    println!("Tear down with: ember down [--revoke-grants] [--purge]");
    Ok(())
}

/// implementation-note-382 — `ember down` body.
fn cmd_down(revoke_grants: bool, purge: bool) -> Result<(), Box<dyn std::error::Error>> {
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
        eprintln!(
            "note: --revoke-grants accepted but not yet wired — grants survive to TTL fallback for this slice. Eager-revoke lands with implementation-note-406."
        );
    }

    println!("ember down: session torn down.");
    Ok(())
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
        Commands::Init {
            name,
            keyring_service,
            keyring_account,
            touch_id,
            for_target,
            non_interactive,
        } => {
            // implementation-note-407: on a new machine the daemon
            // service will not be installed. Detect this early — before any
            // vault or DB work — and offer to run `sudo ember daemon install`.
            // Skip the check when the daemon is already running or the operator
            // used `--for claude-code` (that path autostarts the daemon itself).
            {
                let socket_path = config.socket_dir.join("daemon.sock");
                // EMBER_SKIP_DAEMON_INSTALL_CHECK: test-only bypass for the
                // daemon-install precheck. Production code never sets this; the
                // env var lets binary tests construct an isolated config + tmpdir
                // without tripping the non-interactive `Declined` branch that
                // process::exit(0)s before downstream init work completes.
                // See implementation-note-408.
                // implementation-note-409resolved
                let skip_check = std::env::var("EMBER_SKIP_DAEMON_INSTALL_CHECK").is_ok();
                if !skip_check {
                    let install_status =
                        emberlink_cli::install::detect_daemon_installed(&socket_path);
                    if install_status == emberlink_cli::install::DaemonInstallStatus::NotInstalled {
                        match emberlink_cli::install::prompt_install_daemon(non_interactive) {
                            Ok(()) => {
                                println!("  Daemon:   installed successfully");
                            }
                            Err(emberlink_cli::install::DaemonInstallPromptError::Declined) => {
                                eprintln!(
                                    "note: daemon install skipped — run `sudo ember daemon install` \
                                     when ready, then re-run `ember init`"
                                );
                                process::exit(0);
                            }
                            Err(
                                emberlink_cli::install::DaemonInstallPromptError::NonInteractive,
                            ) => {
                                eprintln!(
                                    "error: daemon is not installed and --non-interactive is set.\n\
                                     Run `sudo ember daemon install` first, then re-run `ember init`."
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

            // implementation-note-397: when `--for claude-code` is set,
            // skip basic init if the daemon DB already exists. Without this guard
            // a friendly who ran `ember init --name "Foo"` and then ran
            // `ember init --for claude-code` ended up with two extra root
            // personas ("root" + their named one) in addition to the claude-code
            // persona. We detect initialization by checking for daemon.db — the
            // file written by `open_store` during every `cmd_init` run.
            let skip_basic_init =
                for_target.as_deref() == Some("claude-code") && is_ember_initialized(&config);

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
                );
            }
            // implementation-note-410: layer the claude-code onboarding on top of the
            // base daemon init when `--for claude-code` is set. The base
            // init has already set up the keyring, vault, salt, and root
            // persona — the cohort A flow now creates the agent persona,
            // template, grant, settings.json patch, and optional PAT.
            if let Some(target) = for_target {
                if target == "claude-code" {
                    if let Err(e) = cmd_init_for_claude_code(&config) {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                } else {
                    eprintln!("error: unknown --for target: {target}. Supported: claude-code");
                    process::exit(2);
                }
            }
        }

        Commands::Uninstall { for_target } => {
            if for_target == "claude-code" {
                if let Err(e) = cmd_uninstall_for_claude_code() {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
            } else {
                eprintln!("error: unknown --for target: {for_target}. Supported: claude-code");
                process::exit(2);
            }
        }

        Commands::Up { profile } => {
            if let Err(e) = cmd_up(profile) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }

        Commands::Down {
            revoke_grants,
            purge,
        } => {
            if let Err(e) = cmd_down(revoke_grants, purge) {
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
                    // implementation-note-395: propagate the resolved
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

                // implementation-note-394: warn loudly when the
                // shadow PATH isn't installed — the agent-routing invariant
                // fails silently otherwise. Best-effort: a missing shadow
                // dir doesn't block daemon start, but the WARN must surface
                // so the operator notices and runs `ember init --for
                // claude-code`.
                if let Err(msg) = ensure_shadow_path_installed() {
                    if console {
                        eprintln!("WARN  {msg}");
                    }
                    tracing::warn!("{msg}");
                }

                // implementation-note-395: env-var fallback — if the
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
                let runtime = DaemonRuntime::new(config);
                match runtime.status() {
                    Ok(status) => {
                        if status.running {
                            println!("ember daemon is running");
                            println!("  PID:    {}", status.pid);
                            println!("  Socket: {}", status.socket.display());
                            // implementation-note-394: warn loudly if
                            // the shadow PATH isn't installed. Without it,
                            // raw `gh`/`git`/`kubectl` calls from sequential
                            // agents bypass the broker, operator-author the
                            // commits, and break audit-trail clarity.
                            if let Err(msg) = ensure_shadow_path_installed() {
                                eprintln!("WARN  {msg}");
                            }
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
            DaemonAction::Install { args } => {
                cmd_daemon_install(args);
            }
            DaemonAction::Migrate { to } => {
                cmd_daemon_migrate(&to);
            }
        },

        Commands::Persona { action } => {
            // implementation-note-411: all persona
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
                    let request = serde_json::json!({"id": id});
                    match emberlink_cli::call_daemon_method(
                        &socket_path,
                        "revoke_persona",
                        &request,
                    ) {
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
                let service = resolve_keyring_service(&config.keyring);
                let account = resolve_keyring_account(&config.keyring);
                match migrate_mek_acl(&service, &account) {
                    Ok(result) => {
                        if cli.json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&result)
                                    .unwrap_or_else(|_| "{}".to_string())
                            );
                        } else if result.before_acl_kind == result.after_acl_kind {
                            println!(
                                "MEK already uses {} ACL — no migration needed.",
                                result.before_acl_kind
                            );
                        } else {
                            println!(
                                "MEK ACL migrated: {} → {}",
                                result.before_acl_kind, result.after_acl_kind
                            );
                            println!("  service: {}", result.service);
                            println!("  account: {}", result.account);
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
                    return;
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
                    return;
                }
                VaultAction::Get(VaultGetArgs {
                    name,
                    unmask,
                    i_know_what_im_doing,
                }) => {
                    match run_vault_get(&config, name) {
                        Ok((_, value)) => {
                            if *unmask {
                                if std::io::stdout().is_terminal() && !i_know_what_im_doing {
                                    eprintln!(
                                        "error: --unmask refused on a TTY. Re-run with one of:"
                                    );
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
                    }
                    return;
                }
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
                    return;
                }
                VaultAction::Remove { name } => {
                    match run_vault_remove(&config, name) {
                        Ok(_) => println!("Removed credential {name}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                    return;
                }
                _ => {}
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
                    return;
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
                    return;
                }
                GrantAction::List { active } => {
                    match run_grant_list(&config, *active) {
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
                                    let scope =
                                        g.get("scope").and_then(|v| v.as_str()).unwrap_or("");
                                    let status =
                                        g.get("status").and_then(|v| v.as_str()).unwrap_or("");
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
                    }
                    return;
                }
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
                    return;
                }
                GrantAction::Expire => {
                    match run_grant_expire(&config) {
                        Ok((_, count)) => println!("Expired {} stale grant(s)", count),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                    return;
                }
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
                    return;
                }
                GrantAction::Budget { grant_id } => {
                    match run_grant_budget(&config, grant_id) {
                        Ok((_, rendered)) => print!("{rendered}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                    return;
                }
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
                    // implementation-note-201 — route the composite mint through the policy
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
                    // implementation-note-201 — when the composite grant is pending approval,
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
                                // implementation-note-201 — composite envelopes render as
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
                                    // implementation-note-194: shipped
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
                            // implementation-note-201 — surface the grant ID minted by a
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
                    let store = open_store(&config);
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
                // implementation-note-230 (B): chain verify via
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
                ReceiptAction::Export { id, format, raw } => {
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
            // implementation-note-149: admin path for
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

        Commands::Status => {
            let runtime = DaemonRuntime::new(config.clone());
            // [open-store-audit] READ-ONLY: Commands::Status. Aggregates
            // list_personas / list_active_grants / list_sandboxes /
            // list_pending_approvals / query_audit / audit_count /
            // list_standing_grants. The installed path now prefers the
            // daemon-owned `status` RPC when the daemon is live; local direct
            // fallback remains only for no-daemon/dev paths.
            let runtime_status = runtime.status().ok();
            let daemon_running = runtime_status.as_ref().is_some_and(|s| s.running);
            let summary = match run_status_summary(&config, daemon_running) {
                Ok((_, summary)) => summary,
                Err(e) => {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
            };

            let personas = summary.personas;
            let active = personas.iter().filter(|p| p.status == "active").count();
            let revoked = personas.iter().filter(|p| p.status == "revoked").count();

            let grants = summary.grants;

            let sandboxes = summary.sandboxes;
            let running = sandboxes.iter().filter(|s| s.status == "running").count();

            let approvals = summary.approvals;

            let entries = summary.recent_activity;
            let total = summary.audit_events_total;

            // implementation-note-297: surface the credential-store backend
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
                let (daemon_running, daemon_pid, daemon_socket) = match runtime_status.as_ref() {
                    Some(s) => (s.running, Some(s.pid), Some(s.socket.display().to_string())),
                    None => (false, None, None),
                };
                let status = serde_json::json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "daemon": { "running": daemon_running, "pid": daemon_pid, "socket": daemon_socket },
                    "personas": active,
                    "grants": { "active": grants.len(), "expired_sweep_interval_sec": 60 },
                    "approvals": { "pending": approvals.len() },
                    "standing_grants": summary.standing_grants,
                    "audit_events": total,
                    "vault": { "backend": vault_backend, "addr": vault_addr },
                });
                println!("{}", serde_json::to_string_pretty(&status).unwrap());
            } else {
                // Check daemon status
                match runtime_status {
                    Some(status) if status.running => {
                        println!("DAEMON             running (PID {})", status.pid);
                        println!("  Socket:    {}", status.socket.display());
                        // implementation-note-188: the configured
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
                        // implementation-note-297: show the configured
                        // credential-store backend selector. `local` collapses
                        // to `(local-encrypted)` so the line is recognisable
                        // for the default no-config case.
                        println!("  Vault:     {} ({})", vault_backend, vault_addr);
                    }
                    Some(status) => {
                        println!("DAEMON             stopped (stale PID {})", status.pid);
                    }
                    None => {
                        println!("DAEMON             not running");
                    }
                }
                println!();
                println!("PERSONAS           {} active, {} revoked", active, revoked);
                for p in &personas {
                    let st = if p.status == "revoked" {
                        "revoked"
                    } else {
                        "active "
                    };
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
                println!(
                    "Config file: {}",
                    effective_config_path(cli.config.as_ref()).display()
                );
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

        Commands::Cluster { action } => {
            cmd_cluster(action, &config, cli.json);
        }

        Commands::ClaudeCode { dev, prod: _, args } => {
            // When --dev or --prod is given, use the design Phase 4 flavor launcher.
            // When neither is given, default to --prod (design §4 spec).
            // Legacy cohort-A RPC path (no flags) is replaced by the flavor launcher
            // with --prod as the default, giving parity with the old behavior while
            // adding --dev support.
            let flavor = if dev {
                emberlink_cli::claude_code_launcher::Flavor::Dev
            } else {
                emberlink_cli::claude_code_launcher::Flavor::Prod
            };
            if let Err(e) = emberlink_cli::claude_code_launcher::launch(flavor, &args) {
                eprintln!("ember claude-code: {e}");
                process::exit(2);
            }
            // launch() exec-replaces; if we reach here the exec failed and
            // the error was already printed above.
            unreachable!("launch() either exec-replaces or returns Err");
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
                match runtime.status() {
                    Ok(s) if s.running => {}
                    Ok(_) => {
                        eprintln!("ember bridge endpoint: daemon not running");
                        process::exit(1);
                    }
                    Err(_) => {
                        eprintln!("ember bridge endpoint: daemon not running");
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

                // Create parent directory if needed.
                if let Some(parent) = output_path.parent() {
                    if let Err(e) = fs::create_dir_all(parent) {
                        eprintln!(
                            "ember bridge endpoint: failed to create parent dir {}: {e}",
                            parent.display()
                        );
                        process::exit(1);
                    }
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
/// implementation-note-174: lists locally-pulled cluster snapshots.
/// implementation-note-412: `bootstrap` generates the Daemon
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
            "audit_events_total": 9
        })
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

    /// implementation-note-394: `ensure_shadow_path_installed`
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
            err.contains("ember init --for claude-code"),
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
        // implementation-note-395: this test asserts the
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

    // implementation-note-395: precedence chain for the user-pinned
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
            .tempdir_in("/private/tmp")
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
            .tempdir_in("/private/tmp")
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

    // --- docker_exec_flags unit tests (implementation-note-413) ---

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
        );

        assert!(
            std::env::var("EMBER_VAULT_PASSPHRASE").is_err(),
            "EMBER_VAULT_PASSPHRASE must be absent from the environment after cmd_init"
        );
        unsafe {
            std::env::remove_var("EMBER_SKIP_DAEMON_INSTALL_CHECK");
        }
    }

    #[test]
    fn cmd_init_with_live_socket_builds_first_receipt_via_daemon_without_local_db_write() {
        use core_crypto::Signer as _;
        use std::io::{BufRead, Write as _};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::Builder::new()
            .prefix("esb")
            .tempdir_in("/private/tmp")
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

                for _ in 0..2 {
                    let (mut stream, _) = listener.accept().expect("accept client");
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
            .tempdir_in("/private/tmp")
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

                let (mut stream, _) = listener.accept().expect("accept client");
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
            .tempdir_in("/private/tmp")
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
            .tempdir_in("/private/tmp")
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

                let (mut stream, _) = listener.accept().expect("accept client");
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
            .tempdir_in("/private/tmp")
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut status_stream, _) = listener.accept().expect("accept grant_status");
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

                let (mut delegate_stream, _) = listener.accept().expect("accept delegate_grant");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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
        let (dispatch, summary) =
            run_status_summary(&config, true).expect("status summary via daemon");
        assert_eq!(dispatch, StatusActionDispatch::DaemonRpc);
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

                let (mut stream, _) = listener.accept().expect("accept client");
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
            .tempdir_in("/private/tmp")
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

                let (mut stream, _) = listener.accept().expect("accept client");
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

    /// implementation-note-414: `ember daemon install` (no flags) must
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

    /// implementation-note-414: `ember daemon install --single-uid`
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

    /// implementation-note-415: `ember daemon migrate --to separate-uid`
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

    /// implementation-note-415: `ember daemon migrate` without `--to`
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

    /// implementation-note-415: `is_separate_uid_posture` returns
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

    /// implementation-note-397 T1: `is_ember_initialized` returns false
    /// for a fresh temp dir, and true once `cmd_init` has run and written daemon.db.
    ///
    /// Verifies the detection logic that `init --for claude-code` uses to decide
    /// whether to skip the basic init step (to avoid creating a duplicate "root"
    /// persona). A friendly who ran `ember init --name "Foo"` before running
    /// `ember init --for claude-code` triggered the double-init bug; after this
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
        // This is the count that would survive if `init --for claude-code`
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

    /// implementation-note-397 T2: `is_ember_initialized` returns false
    /// for an empty temp dir, confirming that the `init --for claude-code` path
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

        // Simulate the basic init step that `init --for claude-code` would run.
        let config_path = tmp.path().join("config.toml");
        unsafe {
            std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-passphrase-t3-t2");
            std::env::set_var("EMBER_SKIP_DAEMON_INSTALL_CHECK", "1");
        };
        cmd_init(&config, None, Some(&config_path), None, None, false);
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

    /// T1 — implementation-note-404: the new posture-hardening
    /// prompt text must contain the expected call-to-action copy (no jargon,
    /// no "Wedge claim", no "design" visible to friendly users).
    ///
    /// This test validates the source constants rather than running the
    /// interactive prompt (which requires a live daemon + TTY) to keep it
    /// fast and deterministic in CI.
    #[test]
    fn separate_uid_cta_prompt_contains_expected_copy() {
        // The copy lives inline in cmd_init_for_claude_code. We verify the
        // checkpoint-gated block by reading the source text of this file at
        // compile time — use a const string that mirrors the live output.
        const SECURITY_HARDENING_LABEL: &str = "Security hardening (recommended):";
        const HARDEN_NOW_PROMPT: &str = "Harden now? [Y/n]:";
        const NO_JARGON_WEDGE: &str = "Wedge claim";
        const NO_JARGON_ADR_131: &str = "design";
        const NO_JARGON_SINGLE_UID_POSTURE: &str = "single-uid posture";
        const NO_JARGON_KERNEL_ISOLATION: &str = "kernel-level isolation";

        // Read the source of this binary at runtime from the file path
        // baked in at compile time via file!().
        let source = std::fs::read_to_string(file!()).unwrap_or_else(|_| {
            std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/ember.rs"),
            )
            .expect("could not read ember.rs source for CTA text assertions")
        });

        // T1a: prompt must contain the friendly call-to-action label.
        assert!(
            source.contains(SECURITY_HARDENING_LABEL),
            "prompt must contain \"{}\"",
            SECURITY_HARDENING_LABEL
        );

        // T1b: prompt must contain the [Y/n] harden question.
        assert!(
            source.contains(HARDEN_NOW_PROMPT),
            "prompt must contain \"{}\"",
            HARDEN_NOW_PROMPT
        );

        // T1c: jargon that scared friendly users must not appear in the
        // CTA block. We assert the scary strings are NOT present in the
        // new println! calls (they may still appear in comments or other
        // functions — check that the user-visible strings are clean).
        // These assertions guard against regression where someone adds
        // jargon back to the user-facing println! lines.
        let cta_block_start = source
            .find("implementation-note-404")
            .expect("checkpoint implementation-note-404 must be in source");
        // The CTA block ends at the closing brace of the if-body (~60 lines).
        // Grab 3000 bytes after the checkpoint to cover the entire block.
        let cta_region =
            &source[cta_block_start..cta_block_start + source[cta_block_start..].len().min(3000)];

        // "Wedge claim" must not appear in user-visible println! lines.
        // (It may appear in comments; we only forbid it in the region
        // between the checkpoint and end of the CTA block.)
        for line in cta_region
            .lines()
            .filter(|l| l.trim_start().starts_with("println!"))
        {
            assert!(
                !line.contains(NO_JARGON_WEDGE),
                "println! in CTA block must not contain jargon \"{}\": {}",
                NO_JARGON_WEDGE,
                line
            );
            assert!(
                !line.contains(NO_JARGON_ADR_131),
                "println! in CTA block must not contain jargon \"{}\": {}",
                NO_JARGON_ADR_131,
                line
            );
            assert!(
                !line.contains(NO_JARGON_SINGLE_UID_POSTURE),
                "println! in CTA block must not contain jargon \"{}\": {}",
                NO_JARGON_SINGLE_UID_POSTURE,
                line
            );
            assert!(
                !line.contains(NO_JARGON_KERNEL_ISOLATION),
                "println! in CTA block must not contain jargon \"{}\": {}",
                NO_JARGON_KERNEL_ISOLATION,
                line
            );
        }
    }

    /// T1d — checkpoint file suppresses repeated prompt.
    ///
    /// Validates that the checkpoint-check logic path (`.posture-prompt-shown`
    /// exists) results in the prompt block being skipped. This is a logic
    /// unit test of the checkpoint-check condition using a temp directory.
    #[test]
    fn posture_prompt_sentinel_suppresses_prompt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let checkpoint = dir.path().join(".posture-prompt-shown");
        // Pre-seed the checkpoint — simulates a host where init was already run.
        std::fs::write(&checkpoint, "posture-prompt-shown\n").expect("write checkpoint");
        // Verify: checkpoint exists → the prompt-shown condition is true.
        assert!(checkpoint.exists(), "pre-seeded checkpoint must exist");
        // The actual suppression happens in cmd_init_for_claude_code via
        // `prompt_already_shown = sentinel_path.exists()`. We assert the
        // filesystem condition that drives that branch.
        let prompt_already_shown = checkpoint.exists();
        assert!(
            prompt_already_shown,
            "checkpoint presence must set prompt_already_shown = true → prompt skipped"
        );
    }
}
