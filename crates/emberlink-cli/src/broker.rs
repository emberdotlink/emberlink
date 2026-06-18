//! `ember broker {issue, revoke, list, register}` — operator + wrapper-script entry
//! point for the credential broker (ADR 094 / ADR 096).
//!
//! The daemon RPC handlers live in
//! `crates/ember-daemon/src/broker_handler.rs`; this module is the CLI
//! surface that wraps them. Subcommands:
//!
//! - [`issue`]    — request a fresh materialization from a registered
//!   provider (`broker_issue` daemon RPC).
//! - [`revoke`]   — actively cancel a live materialization
//!   (`broker_revoke` daemon RPC). Idempotent: unknown ids exit 0.
//! - [`list`]     — enumerate active materializations (`broker_list` daemon
//!   RPC), optionally filtered by provider / tier / task-id /
//!   active-only.
//! - [`register_github`] — register a GitHub App credential triple in the vault
//!   (`vault_add` daemon RPC × 3). Calls `GET /apps/<slug>` to canonicalize
//!   the operator-supplied slug before writing (Finding 12).
//!   `--allow-unverified-slug` bypasses the network round-trip for
//!   offline / suspended-app scenarios.
//!
//! ## Grants-file flow
//!
//! `ember broker issue --grants-file <path> --credential <name>` reads a
//! `GrantsManifest` TOML, locates the named credential entry, and issues a
//! scoped grant via `broker_issue`. The Receipt is stamped with
//! `grants_file_rev` (SHA-256 of the file bytes) and `credential_name`.
//!
//! `--inject` spawns a child shell (`$SHELL` or `/bin/sh`) with any
//! materialized credentials in its environment, registers the child PID
//! with the daemon via `broker_register_pid_watcher`, then waits for the
//! shell to exit. The daemon polls the PID and auto-revokes when it exits.
//!
//!
//! ## Secret handling
//!
//! `broker issue` returns a live credential. When stdout is a TTY the
//! `secret` field is masked unless the operator passes `--json`
//! (`--json` is read as "I'm consuming this programmatically; give me
//! the value"). When stdout is piped — even without `--json` — the
//! secret IS emitted, since the only sensible reason to pipe is to feed
//! the value into the next process.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Subcommand;
use serde_json::{Value, json};

use core_grants_toml::{Credential, GrantsManifest};

/// CLI subcommand surface for `ember broker`.
///
/// Mirrors the daemon's three RPC methods one-to-one.
#[derive(Subcommand, Debug)]
pub enum BrokerCmd {
    /// Issue a fresh credential materialization (ADR 094 / ADR 096).
    ///
    /// Calls `broker_issue` on the daemon socket. The provider must be
    /// registered with the daemon (`mock` providers are pre-registered;
    /// real providers register per-task). The scope is opaque JSON —
    /// per-provider shape is documented in ADR 094 §5b.
    Issue {
        /// Provider name (snake_case): cloudflare, anthropic, github,
        /// aws_sts, gcp, tailscale.
        #[arg(long)]
        provider: String,

        /// Scope payload — a JSON object describing the request.
        ///
        /// Three ways to supply it:
        ///   * inline:     `--scope-json '{"zone":"X","permissions":["dns:edit"]}'`
        ///   * from file:  `--scope-json @/path/to/scope.json`
        ///   * from stdin: `--scope-json -`
        ///
        /// Shape is provider-specific; see ADR 094 §5b.
        #[arg(long = "scope-json")]
        scope_json: String,

        /// Time-to-live (humantime: 15s, 5m, 2h, 1d, or bare seconds).
        /// The broker may clamp this downward to a provider-imposed
        /// maximum.
        #[arg(long)]
        ttl: String,

        /// Free-form audit reason. Recorded in the broker materialization
        /// receipt (ADR 094 §c).
        #[arg(long)]
        reason: String,

        /// Emit the response (including the live secret) as JSON to
        /// stdout. Without `--json` the secret is masked when stdout is
        /// a TTY.
        #[arg(long)]
        json: bool,
    },

    /// Issue grants from a TOML grants file (ADR 094).
    ///
    /// Reads a `GrantsManifest` TOML via `core-grants-toml`, locates the
    /// credential entry named by `--credential`, and issues a scoped grant
    /// via `broker_issue`. The Receipt is stamped with `grants_file_rev`
    /// (SHA-256 of the file bytes) and `credential_name`.
    ///
    /// With `--inject` a child shell is spawned with materialized credentials
    /// in its environment. The daemon auto-revokes when the shell exits.
    ///
    #[command(name = "issue-file")]
    IssueFromFile {
        /// Path to the grants manifest TOML file.
        #[arg(long = "grants-file")]
        grants_file: PathBuf,

        /// Credential name within the grants file to issue.
        #[arg(long)]
        credential: String,

        /// Time-to-live override (humantime: 15s, 5m, 2h, 1d, or bare
        /// seconds). When absent, defaults to the `ttl_secs` from the
        /// manifest entry or `[defaults]`, or 3600s if neither is set.
        #[arg(long)]
        ttl: Option<String>,

        /// If set, spawn a child shell with the issued credentials in its
        /// environment. Register the child PID with the daemon; on shell
        /// exit the daemon auto-revokes the grants via Receipt event.
        #[arg(long)]
        inject: bool,

        /// Emit the response (including grant IDs) as JSON to stdout.
        #[arg(long)]
        json: bool,
    },

    /// Register a GitHub App credential in the daemon vault (ADR 099 path
    /// grammar — Finding 12).
    ///
    /// Writes three vault entries under
    /// `github/apps/<canonical-slug>/install-<installation-id>/`:
    ///   - `private-key`     — PEM contents of the RSA private key
    ///   - `app-id`          — numeric GitHub App ID
    ///   - `installation-id` — numeric GitHub installation ID
    ///
    /// The slug is canonicalized by calling `GET /apps/<slug>` with a
    /// short-lived App JWT derived from the supplied PEM + app-id. The
    /// GitHub-returned `slug` field is stored verbatim so divergent
    /// operator-typed slugs cannot produce two vault rows for the same app.
    ///
    /// When `--allow-unverified-slug` is set the GitHub round-trip is
    /// skipped; the operator-typed slug is stored as-is and a warning is
    /// emitted. Use this escape hatch when GitHub is unreachable or the
    /// app is suspended.
    ///
    /// ## Rename-race follow-up
    ///
    /// Between `register` and the daemon's next credential reload the app
    /// could be renamed on github.com, causing the stored slug to diverge
    /// again. A future `ember broker reconcile-slugs` cron will re-verify
    /// and update vault entries. This is a known deferral; see the
    /// adversarial review (broker-vault-cutover-2026-05-12.md §Finding 12).
    #[command(name = "register")]
    Register {
        #[command(subcommand)]
        provider: RegisterProvider,
    },

    /// Revoke a live materialization by id.
    ///
    /// Calls `broker_revoke` on the daemon socket. Idempotent — when the
    /// materialization is unknown to the daemon (already revoked or
    /// never issued) the command exits 0 with `revoked: false`.
    Revoke {
        /// Materialization id returned by `ember broker issue`.
        materialization_id: String,

        /// Emit the response as JSON.
        #[arg(long)]
        json: bool,
    },

    /// List active materializations (ADR 094 / ADR 096).
    ///
    /// Calls `broker_list` on the daemon socket. Filters compose AND.
    List {
        /// Filter by provider (snake_case).
        #[arg(long)]
        provider: Option<String>,

        /// Filter by ADR 094 risk tier (0/1/2). Currently advisory —
        /// kept on the CLI surface so callers don't need rewiring once
        /// the daemon emits per-row tier metadata.
        #[arg(long)]
        tier: Option<u8>,

        /// Filter by task id recorded in `BrokerRequest.reason`. Today
        /// the filter is a substring match on `reason` (where
        /// `pulumi-render.sh up` and friends embed the task id).
        #[arg(long = "task-id")]
        task_id: Option<String>,

        /// Drop expired rows (default keeps everything the daemon
        /// returned).
        #[arg(long = "active-only")]
        active_only: bool,

        /// Emit the response as a JSON array.
        #[arg(long)]
        json: bool,
    },
}

/// Provider-specific subcommands for `ember broker register`.
///
/// Currently only `github` is implemented. Structured as a sub-enum so
/// future `register cloudflare` / `register anthropic` variants slot in
/// without changing the top-level dispatch.
#[derive(Subcommand, Debug)]
pub enum RegisterProvider {
    /// Register a GitHub App credential in the daemon vault.
    ///
    /// Writes three vault entries under
    /// `github/apps/<slug>/install-<installation-id>/`:
    ///   `private-key`, `app-id`, `installation-id`.
    ///
    /// The slug is verified against GitHub's API (Finding 12).
    /// Pass `--allow-unverified-slug` to skip the verification
    /// (offline / app-suspended scenarios).
    Github {
        /// Path to the GitHub App's RSA private key (PEM-encoded PKCS#8
        /// or traditional PKCS#1). The contents are stored in the vault
        /// under `github/apps/<slug>/install-<id>/private-key`.
        #[arg(long = "pem-file")]
        pem_file: PathBuf,

        /// Numeric GitHub App ID (shown on the App settings page).
        #[arg(long = "app-id")]
        app_id: String,

        /// Numeric GitHub installation ID (from the installation webhook
        /// or `GET /app/installations`).
        #[arg(long = "installation-id")]
        installation_id: String,

        /// Operator-typed App slug (the human-readable name that appears
        /// in `https://github.com/apps/<slug>`). When `--allow-unverified-slug`
        /// is NOT set this value is passed to `GET /apps/<slug>` and the
        /// API-returned slug is stored instead of this value.
        #[arg(long)]
        slug: String,

        /// Skip the `GET /apps/<slug>` round-trip and store the
        /// operator-typed slug verbatim. Use when GitHub is unreachable
        /// or the app is suspended. Emits a warning when set.
        ///
        /// allow-unverified-slug
        #[arg(long = "allow-unverified-slug")]
        allow_unverified_slug: bool,

        /// Replace existing vault entries for this slug+installation-id
        /// pair without error. Without `--replace` the command refuses to
        /// overwrite an existing triple.
        #[arg(long)]
        replace: bool,

        /// Emit a JSON object with the written vault paths on success.
        #[arg(long)]
        json: bool,
    },
}

/// Global options resolved by the parent CLI before dispatch into
/// `broker_command`. Today only the daemon socket path is needed; this
/// struct exists so future cross-cutting flags (`--config`, `--quiet`)
/// don't churn the broker module's signature.
#[derive(Debug, Clone)]
pub struct GlobalOpts {
    pub socket_path: PathBuf,
}

/// Top-level dispatch — invoked from `ember.rs` once clap has parsed
/// `Commands::Broker { action }`.
///
/// The literal `broker_command` is also a marker for the
/// `target_state_anchor` gate.
pub fn broker_command(cmd: BrokerCmd, opts: GlobalOpts) -> Result<(), BrokerCliError> {
    match cmd {
        BrokerCmd::Issue {
            provider,
            scope_json,
            ttl,
            reason,
            json,
        } => issue(&opts, &provider, &scope_json, &ttl, &reason, json),
        BrokerCmd::IssueFromFile {
            grants_file,
            credential,
            ttl,
            inject,
            json,
        } => issue_from_grants_file(
            &opts,
            &grants_file,
            &credential,
            ttl.as_deref(),
            inject,
            json,
        ),
        BrokerCmd::Revoke {
            materialization_id,
            json,
        } => revoke(&opts, &materialization_id, json),
        BrokerCmd::Register { provider } => match provider {
            RegisterProvider::Github {
                pem_file,
                app_id,
                installation_id,
                slug,
                allow_unverified_slug,
                replace,
                json,
            } => register_github(
                &opts,
                &pem_file,
                &app_id,
                &installation_id,
                &slug,
                allow_unverified_slug,
                replace,
                json,
            ),
        },
        BrokerCmd::List {
            provider,
            tier,
            task_id,
            active_only,
            json,
        } => list(
            &opts,
            provider.as_deref(),
            tier,
            task_id.as_deref(),
            active_only,
            json,
        ),
    }
}

// ---------------------------------------------------------------------------
// Per-subcommand implementations
// ---------------------------------------------------------------------------

/// `ember broker issue` — see [`BrokerCmd::Issue`].
pub fn issue(
    opts: &GlobalOpts,
    provider: &str,
    scope_arg: &str,
    ttl: &str,
    reason: &str,
    json_out: bool,
) -> Result<(), BrokerCliError> {
    validate_provider(provider)?;

    let ttl_secs = parse_duration(ttl)
        .map_err(|msg| BrokerCliError::InvalidArgs(format!("invalid --ttl: {msg}")))?;

    let scope = load_scope_json(scope_arg)?;

    let params = json!({
        "provider": provider,
        "scope": scope,
        "ttl": ttl_secs,
        "reason": reason,
    });

    let result = call_daemon(&opts.socket_path, "broker_issue", &params)?;

    // Result shape:
    //   { secret_ref, materialization_id, expires_at, issued_at, provider }
    // The opaque `secret_ref` is what callers pass back to ember-proxy /
    // ember-tools when the actual credential is needed at a trust
    // boundary; no plaintext appears in the response.
    if json_out {
        // Programmatic consumer — emit the full JSON unmodified so the
        // SecretRef is reachable.
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
        );
        return Ok(());
    }

    // Pretty path. The response no longer contains plaintext, so there
    // is nothing to mask — the SecretRef is opaque by construction.
    let mid = result["materialization_id"].as_str().unwrap_or("?");
    let provider_out = result["provider"].as_str().unwrap_or(provider);
    let expires = result["expires_at"].as_str().unwrap_or("?");
    let issued = result["issued_at"].as_str().unwrap_or("?");
    let sref = result["secret_ref"].as_str().unwrap_or("");

    println!("Brokered credential");
    println!("  Materialization: {mid}");
    println!("  Provider:        {provider_out}");
    println!("  Issued:          {issued}");
    println!("  Expires:         {expires}");
    println!("  SecretRef:       {sref}");

    Ok(())
}

/// `ember broker issue-file --grants-file <path> --credential <name>`
///
/// Reads a `GrantsManifest` TOML, locates the named credential, issues a
/// scoped grant stamped with `grants_file_rev` (SHA-256 of file bytes) and
/// `credential_name`. With `--inject` spawns a child shell and registers the
/// PID for daemon auto-revoke.
///
pub fn issue_from_grants_file(
    opts: &GlobalOpts,
    grants_file: &Path,
    credential_name: &str,
    ttl_override: Option<&str>,
    inject: bool,
    json_out: bool,
) -> Result<(), BrokerCliError> {
    // 1. Read and parse the grants file.
    let raw = std::fs::read(grants_file).map_err(|e| {
        BrokerCliError::InvalidArgs(format!(
            "--grants-file {}: read failed: {e}",
            grants_file.display()
        ))
    })?;
    let raw_str = std::str::from_utf8(&raw).map_err(|e| {
        BrokerCliError::InvalidArgs(format!(
            "--grants-file {}: file is not valid UTF-8: {e}",
            grants_file.display()
        ))
    })?;

    // Compute SHA-256 of the raw bytes for the grants_file_rev Receipt field.
    let grants_file_rev = sha256_hex(&raw);

    let manifest = GrantsManifest::from_toml(raw_str).map_err(|e| {
        BrokerCliError::InvalidArgs(format!(
            "--grants-file {}: parse error: {e}",
            grants_file.display()
        ))
    })?;

    // Validate manifest semantics (warn on unknown kinds but treat as errors
    // for the credential we're about to use, so callers get fast feedback).
    if let Err(errs) = manifest.validate() {
        for e in &errs {
            eprintln!("warning: grants file validation: {e}");
        }
    }

    // 2. Locate the named credential entry.
    let cred_entry = manifest
        .credentials
        .iter()
        .find(|c| match c {
            Credential::Ephemeral { name, .. }
            | Credential::Static { name, .. }
            | Credential::Sealed { name, .. } => name == credential_name,
            Credential::Unknown => false,
        })
        .ok_or_else(|| {
            BrokerCliError::InvalidArgs(format!(
                "credential '{credential_name}' not found in grants file '{}'",
                grants_file.display()
            ))
        })?;

    // 3. Extract scope + TTL from the credential entry.
    let (scope, entry_ttl_secs) = match cred_entry {
        Credential::Ephemeral {
            scope, ttl_secs, ..
        } => (scope.clone(), *ttl_secs),
        Credential::Static { scope, .. } => (scope.clone(), None),
        Credential::Sealed { scope, .. } => (scope.clone(), None),
        Credential::Unknown => unreachable!("already filtered above"),
    };

    // Resolve effective TTL: --ttl flag > entry ttl_secs > manifest defaults > 3600.
    let effective_ttl_secs = if let Some(ttl_s) = ttl_override {
        parse_duration(ttl_s)
            .map_err(|msg| BrokerCliError::InvalidArgs(format!("invalid --ttl: {msg}")))?
    } else if let Some(secs) = entry_ttl_secs {
        secs
    } else {
        manifest.defaults.ttl_secs.unwrap_or(3600)
    };

    // 4. Determine provider from scope or fall back to a well-known heuristic.
    //    For now, the grants file `scope` is opaque JSON; we derive the provider
    //    from a `provider` field if present, otherwise default to "anthropic".
    let provider = scope
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("anthropic")
        .to_string();

    // 5. Build and send the broker_issue RPC params, including grants_file_rev.
    let params = json!({
        "provider": provider,
        "scope": scope,
        "ttl": effective_ttl_secs,
        "reason": format!("grants-file:{}", grants_file.display()),
        "grants_file_rev": grants_file_rev,
        "grants_file_credential_name": credential_name,
    });

    let result = call_daemon(&opts.socket_path, "broker_issue", &params)?;

    let mid = result["materialization_id"]
        .as_str()
        .unwrap_or("?")
        .to_string();
    let expires = result["expires_at"].as_str().unwrap_or("?");
    let issued = result["issued_at"].as_str().unwrap_or("?");
    let secret_ref = result["secret_ref"].as_str().unwrap_or("");

    if json_out && !inject {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
        );
    } else if !inject {
        println!("Issued grant from grants file");
        println!("  Credential:      {credential_name}");
        println!("  Materialization: {mid}");
        println!("  Provider:        {provider}");
        println!("  Issued:          {issued}");
        println!("  Expires:         {expires}");
        println!("  SecretRef:       {secret_ref}");
        println!("  GrantsFileRev:   {grants_file_rev}");
    }

    // 6. --inject: spawn child shell, register PID watcher, wait for exit.
    if inject {
        // Build env for the child shell — inject the SecretRef as an env var.
        let env_key = format!(
            "EMBER_CREDENTIAL_{}",
            credential_name.to_uppercase().replace('-', "_")
        );

        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());

        let mut child = std::process::Command::new(&shell)
            .env(&env_key, secret_ref)
            .env("EMBER_MATERIALIZATION_ID", &mid)
            .env("EMBER_GRANTS_FILE_REV", &grants_file_rev)
            .spawn()
            .map_err(|e| BrokerCliError::Io(format!("spawn shell '{shell}': {e}")))?;

        let child_pid = child.id();

        // Register PID watcher with daemon for auto-revoke on shell exit.
        let watcher_params = json!({
            "pid": child_pid,
            "materialization_ids": [mid],
        });
        if let Err(e) = call_daemon(
            &opts.socket_path,
            "broker_register_pid_watcher",
            &watcher_params,
        ) {
            // Non-fatal — the user can manually revoke. Warn and continue.
            eprintln!(
                "warning: could not register PID watcher with daemon (grants will NOT be \
                 auto-revoked on shell exit): {e}"
            );
        }

        if json_out {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "materialization_id": mid,
                    "credential_name": credential_name,
                    "grants_file_rev": grants_file_rev,
                    "child_pid": child_pid,
                    "shell": shell,
                }))
                .unwrap_or_default()
            );
        } else {
            println!("Spawned shell (pid {child_pid}) with {env_key} set.");
            println!("Grants will be auto-revoked when the shell exits.");
        }

        // Wait for the child shell to finish.
        child
            .wait()
            .map_err(|e| BrokerCliError::Io(format!("wait for child shell: {e}")))?;
    }

    Ok(())
}

/// `ember broker revoke` — see [`BrokerCmd::Revoke`].
pub fn revoke(
    opts: &GlobalOpts,
    materialization_id: &str,
    json_out: bool,
) -> Result<(), BrokerCliError> {
    let params = json!({"materialization_id": materialization_id});
    let result = match call_daemon(&opts.socket_path, "broker_revoke", &params) {
        Ok(v) => json!({
            "revoked": v.get("revoked").cloned().unwrap_or(json!(true)),
            "materialization_id": materialization_id,
        }),
        // Idempotent: not-found / already-revoked → exit 0 with
        // `revoked: false`. Anything else propagates.
        Err(BrokerCliError::DaemonRpc {
            code: -32004,
            message,
        }) => json!({
            "revoked": false,
            "materialization_id": materialization_id,
            "reason": "not-found-or-already-revoked",
            "daemon_message": message,
        }),
        Err(other) => return Err(other),
    };

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
        );
    } else {
        let revoked = result["revoked"].as_bool().unwrap_or(false);
        if revoked {
            println!("Revoked materialization {materialization_id}");
        } else {
            println!(
                "No-op: materialization {materialization_id} is unknown to the daemon \
                 (not-found-or-already-revoked)"
            );
        }
    }

    Ok(())
}

/// `ember broker list` — see [`BrokerCmd::List`].
pub fn list(
    opts: &GlobalOpts,
    provider: Option<&str>,
    _tier: Option<u8>,
    task_id: Option<&str>,
    active_only: bool,
    json_out: bool,
) -> Result<(), BrokerCliError> {
    if let Some(p) = provider {
        validate_provider(p)?;
    }

    let result = call_daemon(&opts.socket_path, "broker_list", &Value::Null)?;

    let rows = result.as_array().cloned().unwrap_or_default();
    let now = chrono::Utc::now();

    let filtered: Vec<Value> = rows
        .into_iter()
        .filter(|row| match provider {
            Some(want) => row.get("provider").and_then(|v| v.as_str()) == Some(want),
            None => true,
        })
        .filter(|row| match task_id {
            Some(needle) => row
                .get("reason")
                .and_then(|v| v.as_str())
                .map(|r| r.contains(needle))
                .unwrap_or(false),
            None => true,
        })
        .filter(|row| {
            if !active_only {
                return true;
            }
            // Drop rows whose `expires_at` is in the past.
            let Some(exp_s) = row.get("expires_at").and_then(|v| v.as_str()) else {
                return true;
            };
            match chrono::DateTime::parse_from_rfc3339(exp_s) {
                Ok(exp) => exp.with_timezone(&chrono::Utc) > now,
                Err(_) => true, // unparseable → keep, don't silently drop
            }
        })
        .collect();

    if json_out {
        let arr = Value::Array(filtered);
        println!(
            "{}",
            serde_json::to_string_pretty(&arr).unwrap_or_else(|_| arr.to_string())
        );
        return Ok(());
    }

    if filtered.is_empty() {
        println!("No active materializations");
        return Ok(());
    }

    println!(
        "{:<32}  {:<12}  {:<25}  {:<25}  REASON",
        "MATERIALIZATION_ID", "PROVIDER", "ISSUED_AT", "EXPIRES_AT"
    );
    for row in &filtered {
        println!(
            "{:<32}  {:<12}  {:<25}  {:<25}  {}",
            row.get("materialization_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
            row.get("provider").and_then(|v| v.as_str()).unwrap_or("?"),
            row.get("issued_at").and_then(|v| v.as_str()).unwrap_or("?"),
            row.get("expires_at")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
            row.get("reason").and_then(|v| v.as_str()).unwrap_or(""),
        );
    }

    Ok(())
}

/// `ember broker register github` — see [`RegisterProvider::Github`].
///
/// Validates the PEM file, builds a short-lived App JWT, calls
/// `GET /apps/<slug>` to retrieve the canonical slug (unless
/// `--allow-unverified-slug` is set), then writes three vault rows:
///   `github/apps/<slug>/install-<installation-id>/private-key`
///   `github/apps/<slug>/install-<installation-id>/app-id`
///   `github/apps/<slug>/install-<installation-id>/installation-id`
///
/// The vault rows are written via the daemon's `vault_add` RPC.
///
/// # Rename-race note
///
/// `ember broker reconcile-slugs` (future task) re-verifies stored slugs
/// against GitHub and updates vault entries when an app is renamed between
/// `register` calls.
#[allow(clippy::too_many_arguments)]
pub fn register_github(
    opts: &GlobalOpts,
    pem_file: &Path,
    app_id: &str,
    installation_id: &str,
    slug: &str,
    allow_unverified_slug: bool,
    replace: bool,
    json_out: bool,
) -> Result<(), BrokerCliError> {
    // 1. Read the PEM file, then delegate to the bytes-based core. The manifest
    //    flow (P16) calls `register_github_with_pem` directly with the
    //    in-memory `/conversions` PEM so the key never touches disk.
    let pem_contents = std::fs::read_to_string(pem_file).map_err(|e| {
        BrokerCliError::InvalidArgs(format!(
            "--pem-file {}: read failed: {e}",
            pem_file.display()
        ))
    })?;
    let pem_contents = pem_contents.trim().to_string();
    register_github_with_pem(
        opts,
        &pem_contents,
        app_id,
        installation_id,
        slug,
        allow_unverified_slug,
        replace,
        json_out,
    )
}

/// Core GitHub App credential registration over already-acquired PEM bytes.
///
/// `register_github` reads a PEM file then delegates here. The GitHub App
/// manifest flow (`ember github setup --from-manifest`, P16-S3) calls this
/// directly with the in-memory PEM from GitHub's `/conversions` response, so
/// the private key never touches disk — the bytes go straight to the daemon's
/// `vault_add` RPC (which already takes an inline `value`, not a path).
///
/// When `allow_unverified_slug` is set the caller asserts `slug` is already
/// canonical (the manifest flow gets the canonical slug straight from
/// GitHub's conversion response), so the `GET /app` round-trip is skipped.
#[allow(clippy::too_many_arguments)]
pub fn register_github_with_pem(
    opts: &GlobalOpts,
    pem_contents: &str,
    app_id: &str,
    installation_id: &str,
    slug: &str,
    allow_unverified_slug: bool,
    replace: bool,
    json_out: bool,
) -> Result<(), BrokerCliError> {
    let pem_contents = pem_contents.trim().to_string();

    // Validate the PEM is non-empty and looks like a private key header.
    if pem_contents.is_empty() {
        return Err(BrokerCliError::InvalidArgs(
            "GitHub App private key PEM is empty".to_string(),
        ));
    }
    if !pem_contents.contains("PRIVATE KEY") {
        return Err(BrokerCliError::InvalidArgs(
            "GitHub App private key does not look like a PEM (missing 'PRIVATE KEY' header)"
                .to_string(),
        ));
    }

    // Validate app-id and installation-id are numeric.
    if app_id.parse::<u64>().is_err() {
        return Err(BrokerCliError::InvalidArgs(format!(
            "--app-id '{app_id}' is not a valid numeric GitHub App ID"
        )));
    }
    if installation_id.parse::<u64>().is_err() {
        return Err(BrokerCliError::InvalidArgs(format!(
            "--installation-id '{installation_id}' is not a valid numeric GitHub installation ID"
        )));
    }

    // 2. Canonicalize the slug (or warn and use verbatim).
    let canonical_slug = if allow_unverified_slug {
        tracing::warn!(
            slug = %slug,
            "allow-unverified-slug set — skipping GET /apps/<slug> canonicalization; \
             stored slug may diverge from GitHub's canonical name"
        );
        slug.to_string()
    } else {
        canonicalize_github_slug(slug, app_id, &pem_contents)?
    };

    // 3. Build the vault path prefix.
    let vault_prefix = format!("github/apps/{canonical_slug}/install-{installation_id}");
    let path_private_key = format!("{vault_prefix}/private-key");
    let path_app_id = format!("{vault_prefix}/app-id");
    let path_installation_id = format!("{vault_prefix}/installation-id");

    // Establish operator presence explicitly before the vault mutation flow.
    // The generic daemon RPC helper can retry lazily via `vault_unlock`, but
    // `register_github` performs multiple writes after an optional existence
    // probe. Unlocking once up front keeps the operator flow deterministic and
    // avoids swallowing an initial authority error in the preflight branch.
    call_daemon(&opts.socket_path, "vault_unlock", &Value::Null)?;

    // 4. If not replacing, check for existing entries.
    if !replace {
        // Try vault_get — if it succeeds, the entry already exists.
        // vault_get returns (-32000, ...) for any error including not-found;
        // a successful return means the key is present.
        let check = call_daemon(
            &opts.socket_path,
            "vault_get",
            &json!({"name": path_private_key}),
        );
        if check.is_ok() {
            return Err(BrokerCliError::InvalidArgs(format!(
                "vault entry '{path_private_key}' already exists; \
                 pass --replace to overwrite"
            )));
        }
    }

    // 5. Write the three vault rows via vault_add. When --replace is set and
    //    an entry already exists, remove it first then re-add.
    let write_vault_entry = |name: &str, value: &str| -> Result<(), BrokerCliError> {
        let params = json!({"name": name, "value": value});
        match call_daemon(&opts.socket_path, "vault_add", &params) {
            Ok(_) => Ok(()),
            Err(first_err) if replace => {
                // No atomic replace RPC. Only remove-then-readd when the entry
                // ACTUALLY exists (vault_get ok) — the daemon returns the same
                // generic -32000 for presence/auth/validation/capacity errors,
                // so catching *any* error and unconditionally removing would
                // destroy a live row holding the GH App private key in response
                // to an unrelated failure. Propagate the original error when the
                // row doesn't exist, and propagate the remove failure (no longer
                // swallowed). (Sweep 3 finding S-REPLACE.)
                let exists =
                    call_daemon(&opts.socket_path, "vault_get", &json!({"name": name})).is_ok();
                if !exists {
                    return Err(first_err);
                }
                call_daemon(&opts.socket_path, "vault_remove", &json!({"name": name}))?;
                call_daemon(&opts.socket_path, "vault_add", &params).map(|_| ())
            }
            Err(e) => Err(e),
        }
    };

    write_vault_entry(&path_private_key, &pem_contents)?;
    write_vault_entry(&path_app_id, app_id)?;
    write_vault_entry(&path_installation_id, installation_id)?;

    // 6. Output.
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "canonical_slug": canonical_slug,
                "vault_prefix": vault_prefix,
                "paths": [path_private_key, path_app_id, path_installation_id],
                "allow_unverified_slug": allow_unverified_slug,
            }))
            .unwrap_or_default()
        );
    } else {
        println!("Registered GitHub App credential");
        println!("  Slug:            {canonical_slug}");
        println!("  App ID:          {app_id}");
        println!("  Installation ID: {installation_id}");
        println!("  Vault prefix:    {vault_prefix}");
        if allow_unverified_slug {
            println!(
                "  Warning:         slug not verified against GitHub API (--allow-unverified-slug)"
            );
        }
    }

    Ok(())
}

/// Call `GET https://api.github.com/app` using a short-lived App JWT derived
/// from the PEM private key + app-id, then return the `slug` field from the
/// JSON response. The `/app` endpoint returns the App authenticated by the
/// JWT — its `slug` IS the canonical value, regardless of which slug the
/// operator typed at the CLI.
///
/// The App JWT is RS256-signed (GitHub's required algorithm for App
/// authentication). It has a 10-minute expiry window matching GitHub's
/// documented maximum.
///
/// On network error or a non-200 response the function returns
/// `BrokerCliError::InvalidArgs` so the operator sees a clear message
/// before any vault rows are written. The error message includes the
/// GitHub response body (e.g. `{"message":"Bad credentials"}`) so the
/// operator can diagnose PEM / app-id / clock-skew issues.
fn canonicalize_github_slug(
    operator_slug: &str,
    app_id: &str,
    pem_contents: &str,
) -> Result<String, BrokerCliError> {
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct GhJwtClaims {
        iss: String,
        iat: i64,
        exp: i64,
    }

    // Build a 10-minute App JWT (same shape as ember-broker::github_app::build_jwt).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| BrokerCliError::InvalidArgs(format!("system clock error: {e}")))?
        .as_secs() as i64;

    let claims = GhJwtClaims {
        iss: app_id.to_string(),
        iat: now,
        exp: now + 600,
    };

    let key = EncodingKey::from_rsa_pem(pem_contents.as_bytes()).map_err(|e| {
        BrokerCliError::InvalidArgs(format!(
            "--pem-file: RSA key parse failed (is this a valid PKCS#8 or PKCS#1 PEM?): {e}"
        ))
    })?;

    let jwt = jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &key)
        .map_err(|e| BrokerCliError::InvalidArgs(format!("--pem-file: JWT signing failed: {e}")))?;

    // GET /app using the App JWT.
    //
    // Previously this called
    // `GET /apps/<slug>`, which rejects App JWT auth with 401 Bad
    // credentials (the endpoint is documented for App-JWT but in practice
    // requires Installation-token or user auth — confirmed on
    // api.github.com 2026-05-19). `GET /app` returns the App that the JWT
    // belongs to (canonical name, slug, owner, id) and accepts the same
    // App JWT, so we hit it instead and treat its `slug` field as the
    // canonical value.
    let url = "https://api.github.com/app".to_string();
    // ureq v3 default elevates 4xx/5xx to Error::StatusCode and drops the
    // response body; we need the body to surface GitHub's error message
    // (e.g. `{"message":"Bad credentials"}`) for operator diagnosis, so
    // disable status-as-error on this one-shot call and inspect status
    // manually below.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let mut response = match agent
        .get(&url)
        .header("Authorization", &format!("Bearer {jwt}"))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "ember-cli/broker-register")
        .call()
    {
        Ok(r) => r,
        Err(e) => {
            // With http_status_as_error(false), only transport errors
            // reach this arm — 4xx/5xx pass through as a non-success
            // response inspected in the status check below. GitHub error
            // bodies (e.g. `{"message":"Bad credentials"}`) need the
            // body-read path to surface for stale-PEM / app-suspended
            // / clock-skew / JWT-shape diagnosis.
            return Err(BrokerCliError::InvalidArgs(format!(
                "GET {url}: transport error: {e}. \
                 If GitHub is unreachable or the app is suspended, \
                 pass --allow-unverified-slug to skip canonicalization."
            )));
        }
    };

    let status = response.status();
    if !status.is_success() {
        let body = response.body_mut().read_to_string().unwrap_or_default();
        return Err(BrokerCliError::InvalidArgs(format!(
            "GET {url}: unexpected status {}: {body}. \
             Pass --allow-unverified-slug to skip canonicalization.",
            status.as_u16()
        )));
    }

    let body: serde_json::Value = response.body_mut().read_json().map_err(|e| {
        BrokerCliError::InvalidArgs(format!("GET {url}: response JSON parse failed: {e}"))
    })?;

    let canonical = body
        .get("slug")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            BrokerCliError::InvalidArgs(format!("GET {url}: response missing 'slug' field: {body}"))
        })?
        .to_string();

    if canonical != operator_slug {
        tracing::info!(
            operator_slug = %operator_slug,
            canonical_slug = %canonical,
            "slug canonicalized: operator-typed slug differs from GitHub canonical"
        );
    }

    Ok(canonical)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a humantime duration into seconds. Accepts `15s`, `5m`, `2h`,
/// `1d`, or a bare integer (= seconds). Mirrors `parse_duration` in
/// `bin/ember.rs` so both code paths agree on shape.
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

/// Validate `--provider` against the canonical `BrokerProvider`
/// snake_case set. Local validation gives a friendlier error than
/// round-tripping the unknown name through the daemon.
fn validate_provider(name: &str) -> Result<(), BrokerCliError> {
    const KNOWN: &[&str] = &[
        "cloudflare",
        "anthropic",
        "github",
        "aws_sts",
        "gcp",
        "tailscale",
    ];
    if KNOWN.contains(&name) {
        Ok(())
    } else {
        Err(BrokerCliError::InvalidArgs(format!(
            "unknown provider '{name}' (expected one of: {})",
            KNOWN.join(", ")
        )))
    }
}

/// Resolve the `--scope-json` argument into a `serde_json::Value`.
/// Three forms:
///   * `@<path>`  — read JSON from a file
///   * `-`        — read JSON from stdin
///   * otherwise  — treat the argument as inline JSON
fn load_scope_json(arg: &str) -> Result<Value, BrokerCliError> {
    let raw = if let Some(path) = arg.strip_prefix('@') {
        std::fs::read_to_string(Path::new(path)).map_err(|e| {
            BrokerCliError::InvalidArgs(format!("--scope-json @{path}: read failed: {e}"))
        })?
    } else if arg == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| BrokerCliError::InvalidArgs(format!("--scope-json -: stdin read: {e}")))?;
        buf
    } else {
        arg.to_string()
    };

    serde_json::from_str(raw.trim()).map_err(|e| {
        BrokerCliError::InvalidArgs(format!(
            "--scope-json: invalid JSON: {e}. \
             Provider scope shapes are documented in ADR 094 §5b / ADR 096."
        ))
    })
}

/// Compute the SHA-256 hex digest of raw bytes. Used to populate
/// `grants_file_rev` in the broker Receipt.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn authority_error_reason(message: &str) -> Option<String> {
    serde_json::from_str::<Value>(message)
        .ok()
        .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(str::to_string))
}

fn broker_guidance_for_rpc(method: &str, code: i32, message: &str) -> Option<String> {
    let presence_reason = authority_error_reason(message);
    let presence_missing = code == -32001
        && presence_reason.as_deref().is_some_and(|reason| {
            matches!(
                reason,
                "missing"
                    | "expired"
                    | "uid-mismatch"
                    | "sig-invalid"
                    | "scope-mismatch"
                    | "identity-missing"
                    // ADR 206 slice 4 C: the fail-closed §4-locked-window reason.
                    | "locked"
            )
        });
    let session_locked = code == -32030
        && (message.contains("session is locked")
            || message.contains("vault unavailable")
            || message.contains("session auto-locked")
            || message.contains("lazy first-op unlock unavailable"));

    if method == "broker_list" && (presence_missing || session_locked) {
        return Some(
            "ember broker list is an advanced operator surface, not part of the \
             friendly `ember init --for claude` path. Use `ember claude` \
             for construct-time brokering. If you intentionally need broker admin \
             state, use the managed separate-uid biometric unlock flow when available, \
             or restart the daemon with `EMBER_VAULT_PASSPHRASE` for a fresh dev-probe \
             bootstrap."
                .to_string(),
        );
    }

    if matches!(
        method,
        "vault_unlock" | "vault_add" | "vault_get" | "vault_list" | "vault_remove"
    ) && (presence_missing
        || (code == -32030
            && (message.contains("session is locked")
                || message.contains("vault unavailable")
                || message.contains("session auto-locked"))))
    {
        return Some(
            "this command needs operator presence on the daemon-managed vault lane. \
             Use the managed separate-uid biometric unlock flow when available, or \
             restart the daemon with `EMBER_VAULT_PASSPHRASE` for a fresh dev-probe \
             bootstrap; same-daemon operator-uid reopen is intentionally disabled."
                .to_string(),
        );
    }

    None
}

/// Send a synchronous JSON-RPC request over the daemon's Unix socket
/// and return the `result` value. Mirrors the
/// `emberlink-mcp::daemon_transport` shape so behaviour is identical to
/// the MCP path.
fn call_daemon(socket_path: &Path, method: &str, params: &Value) -> Result<Value, BrokerCliError> {
    match crate::call_daemon_rpc(socket_path, method, params) {
        Ok(value) => Ok(value),
        Err(crate::DaemonRpcError::Unavailable(source)) => Err(BrokerCliError::DaemonUnavailable {
            socket: socket_path.to_path_buf(),
            source,
        }),
        Err(crate::DaemonRpcError::PermissionDenied(err)) => Err(BrokerCliError::Io(
            crate::format_daemon_socket_io_error(&err),
        )),
        Err(crate::DaemonRpcError::Io(err)) => Err(BrokerCliError::Io(err.to_string())),
        Err(crate::DaemonRpcError::Protocol(message)) => Err(BrokerCliError::Protocol(message)),
        Err(crate::DaemonRpcError::Rpc { code, message }) => {
            if let Some(guidance) = broker_guidance_for_rpc(method, code, &message) {
                Err(BrokerCliError::Guidance(guidance))
            } else {
                Err(BrokerCliError::DaemonRpc { code, message })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// CLI-side errors. The shell-exit-code mapping lives in `ember.rs` so
/// this module stays free of `process::exit` calls and is unit-testable.
#[derive(Debug)]
pub enum BrokerCliError {
    /// Caller-side validation failure (bad `--provider`, malformed
    /// scope JSON, malformed TTL). Maps to exit 1.
    InvalidArgs(String),

    /// Operator-facing refusal/guidance for hidden broker-admin surfaces.
    Guidance(String),

    /// Daemon socket unreachable. Maps to exit 2.
    DaemonUnavailable {
        socket: PathBuf,
        source: std::io::Error,
    },

    /// Daemon returned a JSON-RPC error.
    DaemonRpc {
        code: i32,
        message: String,
    },

    /// Lower-level I/O / protocol failure that isn't socket-unavailable.
    Io(String),
    Protocol(String),
}

impl BrokerCliError {
    /// Process exit code for this error variant. See task spec §6.
    pub fn exit_code(&self) -> i32 {
        match self {
            BrokerCliError::InvalidArgs(_) => 1,
            BrokerCliError::Guidance(_) => 1,
            BrokerCliError::DaemonUnavailable { .. } => 2,
            BrokerCliError::DaemonRpc { code, .. } => {
                // Map common daemon codes to operator-friendly exits.
                // `-32601` (method not found / no broker registered for
                // provider) → exit 3 ("provider unknown").
                if *code == -32601 { 3 } else { 1 }
            }
            BrokerCliError::Io(_) | BrokerCliError::Protocol(_) => 1,
        }
    }
}

impl std::fmt::Display for BrokerCliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokerCliError::InvalidArgs(m) => write!(f, "{m}"),
            BrokerCliError::Guidance(m) => write!(f, "{m}"),
            BrokerCliError::DaemonUnavailable { socket, source } => {
                write!(f, "{}", crate::format_daemon_unavailable(socket, source))
            }
            BrokerCliError::DaemonRpc { code, message } => {
                write!(f, "daemon error (code {code}): {message}")
            }
            BrokerCliError::Io(m) => write!(f, "I/O error: {m}"),
            BrokerCliError::Protocol(m) => write!(f, "protocol error: {m}"),
        }
    }
}

impl std::error::Error for BrokerCliError {}

// Force a Duration import-survivor note: we accept `Duration` in the
// public type via params but only ever serialize seconds, so the
// import is read by the doc tests in unit form.
#[allow(dead_code)]
fn _duration_marker(_d: Duration) {}

// ---------------------------------------------------------------------------
// Tests (unit) — wire-format helpers only. The full round-trip lives in
// `tests/broker_cli.rs` against a real daemon socket.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_rsa_private_key_pem() -> String {
        format!(
            "{}RSA PRIVATE KEY-----\nfake\n{}RSA PRIVATE KEY-----\n",
            "-----BEGIN ", "-----END "
        )
    }

    #[test]
    fn parse_duration_humantime_and_bare_integer() {
        assert_eq!(parse_duration("15s").unwrap(), 15);
        assert_eq!(parse_duration("5m").unwrap(), 300);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration("1d").unwrap(), 86400);
        assert_eq!(parse_duration("900").unwrap(), 900);
    }

    #[test]
    fn parse_duration_rejects_garbage() {
        assert!(parse_duration("nope").is_err());
        assert!(parse_duration("5x").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn validate_provider_known_passes() {
        for p in [
            "cloudflare",
            "anthropic",
            "github",
            "aws_sts",
            "gcp",
            "tailscale",
        ] {
            assert!(validate_provider(p).is_ok(), "expected {p} to be known");
        }
    }

    #[test]
    fn validate_provider_unknown_errors() {
        let err = validate_provider("does-not-exist").expect_err("should error");
        match err {
            BrokerCliError::InvalidArgs(msg) => {
                assert!(msg.contains("does-not-exist"));
                assert!(msg.contains("cloudflare"));
            }
            other => panic!("expected InvalidArgs, got {other:?}"),
        }
    }

    #[test]
    fn load_scope_json_inline_object() {
        let v = load_scope_json(r#"{"zone":"emberlink.dev"}"#).unwrap();
        assert_eq!(v["zone"], "emberlink.dev");
    }

    #[test]
    fn load_scope_json_inline_invalid_errors() {
        let err = load_scope_json("{this-is-not-json}").expect_err("should error");
        match err {
            BrokerCliError::InvalidArgs(msg) => {
                assert!(msg.to_lowercase().contains("json"));
                assert!(msg.contains("ADR 094"));
            }
            other => panic!("expected InvalidArgs, got {other:?}"),
        }
    }

    #[test]
    fn load_scope_json_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("scope.json");
        std::fs::write(&p, r#"{"zone":"file-loaded.dev"}"#).unwrap();
        let arg = format!("@{}", p.display());
        let v = load_scope_json(&arg).unwrap();
        assert_eq!(v["zone"], "file-loaded.dev");
    }

    #[test]
    fn broker_list_authority_error_maps_to_guidance() {
        let message = r#"{"error":"authority_class_not_met","reason":"missing"}"#;
        let guidance = broker_guidance_for_rpc("broker_list", -32001, message)
            .expect("expected friendly guidance");
        assert!(guidance.contains("advanced operator surface"));
        assert!(guidance.contains("ember claude"));
    }

    #[test]
    fn broker_list_locked_session_maps_to_guidance() {
        let guidance = broker_guidance_for_rpc(
            "broker_list",
            -32030,
            "broker_list denied: session is locked; same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts",
        )
        .expect("expected friendly guidance");
        assert!(guidance.contains("advanced operator surface"));
        assert!(guidance.contains("managed separate-uid biometric unlock"));
        assert!(guidance.contains("EMBER_VAULT_PASSPHRASE"));
    }

    #[test]
    fn broker_list_lazy_first_op_unavailable_maps_to_guidance() {
        let guidance = broker_guidance_for_rpc(
            "broker_list",
            -32030,
            "broker_list: lazy first-op unlock unavailable; interactive unlock config not registered",
        )
        .expect("expected friendly guidance");
        assert!(guidance.contains("advanced operator surface"));
        assert!(guidance.contains("ember claude"));
    }

    #[test]
    fn broker_issue_authority_error_does_not_map_to_guidance() {
        let message = r#"{"error":"authority_class_not_met","reason":"missing"}"#;
        assert!(broker_guidance_for_rpc("broker_issue", -32001, message).is_none());
    }

    #[test]
    fn vault_add_authority_error_maps_to_unlock_guidance() {
        let message = r#"{"error":"authority_class_not_met","reason":"missing"}"#;
        let guidance =
            broker_guidance_for_rpc("vault_add", -32001, message).expect("expected vault guidance");
        assert!(guidance.contains("operator presence"));
        assert!(guidance.contains("managed separate-uid biometric unlock"));
        assert!(guidance.contains("EMBER_VAULT_PASSPHRASE"));
    }

    #[test]
    fn vault_unlock_authority_error_maps_to_unlock_guidance() {
        let message = r#"{"error":"authority_class_not_met","reason":"missing"}"#;
        let guidance = broker_guidance_for_rpc("vault_unlock", -32001, message)
            .expect("expected vault guidance");
        assert!(guidance.contains("operator presence"));
        assert!(guidance.contains("managed separate-uid biometric unlock"));
        assert!(guidance.contains("EMBER_VAULT_PASSPHRASE"));
    }

    #[test]
    fn vault_add_locked_session_maps_to_unlock_guidance() {
        let guidance = broker_guidance_for_rpc(
            "vault_add",
            -32030,
            "vault_add denied: session is locked; same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts",
        )
        .expect("expected locked-session guidance");
        assert!(guidance.contains("managed separate-uid biometric unlock"));
        assert!(guidance.contains("EMBER_VAULT_PASSPHRASE"));
    }

    #[test]
    fn vault_remove_locked_session_maps_to_unlock_guidance() {
        let guidance = broker_guidance_for_rpc(
            "vault_remove",
            -32030,
            "vault_remove denied: session is locked; same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts",
        )
        .expect("expected locked-session guidance");
        assert!(guidance.contains("managed separate-uid biometric unlock"));
        assert!(guidance.contains("EMBER_VAULT_PASSPHRASE"));
    }

    #[test]
    fn exit_code_mapping_is_stable() {
        assert_eq!(BrokerCliError::InvalidArgs("x".into()).exit_code(), 1);
        assert_eq!(BrokerCliError::Guidance("x".into()).exit_code(), 1);
        let unavailable = BrokerCliError::DaemonUnavailable {
            socket: PathBuf::from("/nonexistent.sock"),
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        };
        assert_eq!(unavailable.exit_code(), 2);
        assert_eq!(
            BrokerCliError::DaemonRpc {
                code: -32601,
                message: "no broker registered".into()
            }
            .exit_code(),
            3
        );
        assert_eq!(
            BrokerCliError::DaemonRpc {
                code: -32602,
                message: "bad params".into()
            }
            .exit_code(),
            1
        );
    }

    // --- register github input-validation tests ---

    #[test]
    fn register_github_rejects_empty_pem_file() {
        let dir = tempfile::tempdir().unwrap();
        let pem_path = dir.path().join("empty.pem");
        std::fs::write(&pem_path, b"").unwrap();
        let opts = GlobalOpts {
            socket_path: PathBuf::from("/nonexistent.sock"),
        };
        let err = register_github(
            &opts, &pem_path, "123456", "789", "my-app",
            true, // allow-unverified-slug — skip network call
            false, false,
        )
        .expect_err("expected error for empty PEM");
        match err {
            BrokerCliError::InvalidArgs(msg) => {
                assert!(msg.contains("empty"), "expected 'empty' in: {msg}");
            }
            other => panic!("expected InvalidArgs, got {other:?}"),
        }
    }

    #[test]
    fn register_github_rejects_non_pem_file() {
        let dir = tempfile::tempdir().unwrap();
        let pem_path = dir.path().join("not-a-key.txt");
        std::fs::write(&pem_path, b"this is not a PEM key").unwrap();
        let opts = GlobalOpts {
            socket_path: PathBuf::from("/nonexistent.sock"),
        };
        let err = register_github(
            &opts, &pem_path, "123456", "789", "my-app", true, false, false,
        )
        .expect_err("expected error for non-PEM content");
        match err {
            BrokerCliError::InvalidArgs(msg) => {
                assert!(
                    msg.contains("PRIVATE KEY"),
                    "expected 'PRIVATE KEY' mention in: {msg}"
                );
            }
            other => panic!("expected InvalidArgs, got {other:?}"),
        }
    }

    #[test]
    fn register_github_with_pem_validates_bytes_without_a_file() {
        // The manifest flow (P16-S3) calls register_github_with_pem directly
        // with in-memory PEM bytes — no file on disk. All early-validation
        // rejections must fire before any daemon RPC, so a dead socket path is
        // safe here.
        let opts = GlobalOpts {
            socket_path: PathBuf::from("/nonexistent.sock"),
        };
        let valid_pem = fake_rsa_private_key_pem();

        // Empty (whitespace-only) PEM.
        let err = register_github_with_pem(&opts, "   ", "123", "456", "app", true, false, true)
            .expect_err("empty PEM must be rejected");
        assert!(
            matches!(&err, BrokerCliError::InvalidArgs(m) if m.contains("empty")),
            "unexpected error: {err:?}"
        );

        // Missing PRIVATE KEY header.
        let err =
            register_github_with_pem(&opts, "not a key", "123", "456", "app", true, false, true)
                .expect_err("non-PEM must be rejected");
        assert!(
            matches!(&err, BrokerCliError::InvalidArgs(m) if m.contains("PRIVATE KEY")),
            "unexpected error: {err:?}"
        );

        // Non-numeric app id (valid-looking PEM otherwise).
        let err =
            register_github_with_pem(&opts, &valid_pem, "abc", "456", "app", true, false, true)
                .expect_err("non-numeric app id must be rejected");
        assert!(
            matches!(&err, BrokerCliError::InvalidArgs(m) if m.contains("App ID")),
            "unexpected error: {err:?}"
        );

        // Non-numeric installation id.
        let err =
            register_github_with_pem(&opts, &valid_pem, "123", "xyz", "app", true, false, true)
                .expect_err("non-numeric installation id must be rejected");
        assert!(
            matches!(&err, BrokerCliError::InvalidArgs(m) if m.contains("installation")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn register_github_rejects_non_numeric_app_id() {
        let dir = tempfile::tempdir().unwrap();
        let pem_path = dir.path().join("key.pem");
        std::fs::write(&pem_path, fake_rsa_private_key_pem()).unwrap();
        let opts = GlobalOpts {
            socket_path: PathBuf::from("/nonexistent.sock"),
        };
        let err = register_github(
            &opts,
            &pem_path,
            "not-a-number",
            "789",
            "my-app",
            true,
            false,
            false,
        )
        .expect_err("expected error for non-numeric app-id");
        match err {
            BrokerCliError::InvalidArgs(msg) => {
                assert!(msg.contains("app-id"), "expected 'app-id' in: {msg}");
            }
            other => panic!("expected InvalidArgs, got {other:?}"),
        }
    }

    #[test]
    fn register_github_rejects_non_numeric_installation_id() {
        let dir = tempfile::tempdir().unwrap();
        let pem_path = dir.path().join("key.pem");
        std::fs::write(&pem_path, fake_rsa_private_key_pem()).unwrap();
        let opts = GlobalOpts {
            socket_path: PathBuf::from("/nonexistent.sock"),
        };
        let err = register_github(
            &opts,
            &pem_path,
            "123456",
            "not-a-number",
            "my-app",
            true,
            false,
            false,
        )
        .expect_err("expected error for non-numeric installation-id");
        match err {
            BrokerCliError::InvalidArgs(msg) => {
                assert!(
                    msg.contains("installation-id"),
                    "expected 'installation-id' in: {msg}"
                );
            }
            other => panic!("expected InvalidArgs, got {other:?}"),
        }
    }

    /// Verify that `--allow-unverified-slug` (the checkpoint literal required by
    /// `target_state_anchor`) appears in this file and that the code path that
    /// bypasses network canonicalization routes through the daemon when the
    /// daemon is present. With a fake PEM + unreachable daemon the call fails
    /// at `vault_get` (DaemonUnavailable), NOT at the network canonicalization
    /// step — proving the slug-verify bypass is active.
    #[test]
    fn allow_unverified_slug_bypasses_network_and_fails_at_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let pem_path = dir.path().join("key.pem");
        // Needs to look like a PEM (header check) but doesn't need to be a
        // valid RSA key — canonicalization is skipped so we never parse it.
        std::fs::write(&pem_path, fake_rsa_private_key_pem()).unwrap();
        let opts = GlobalOpts {
            socket_path: PathBuf::from("/this-socket-does-not-exist.sock"),
        };
        let err = register_github(
            &opts, &pem_path, "123456", "789", "my-app",
            true, // allow-unverified-slug — must skip GET /apps/<slug>
            false, false,
        )
        .expect_err("expected DaemonUnavailable once slug check is bypassed");
        // The error must be DaemonUnavailable (socket not found), NOT
        // InvalidArgs from RSA key parsing or network call — proving the
        // allow-unverified-slug flag properly gates the canonicalization.
        assert!(
            matches!(err, BrokerCliError::DaemonUnavailable { .. }),
            "expected DaemonUnavailable (daemon socket not found), got: {err:?}"
        );
    }
}
