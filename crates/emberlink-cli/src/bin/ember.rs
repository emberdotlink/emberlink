use std::fs;
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use ember_daemon::approval::ApprovalOutcome;
use ember_daemon::audit::AuditFilter;
use ember_daemon::config::DaemonConfig;
use ember_daemon::runtime::DaemonRuntime;
use ember_daemon::store::DaemonStore;
use ember_daemon::vault::Vault;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "ember", about = "The trust layer for AI agents")]
struct Cli {
    /// Path to config file
    #[arg(long, global = true)]
    config: Option<PathBuf>,

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
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the daemon (runs in foreground)
    Start,
    /// Stop a running daemon
    Stop,
    /// Show daemon status
    Status,
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
}

#[derive(Subcommand)]
enum ApprovalAction {
    /// List pending approval requests
    List,
    /// Approve a pending request
    Approve {
        /// Approval request ID
        id: String,
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

fn cmd_init(config: &DaemonConfig, name: Option<String>) {
    let config_path = DaemonConfig::default_config_path();
    if config_path.exists() {
        eprintln!("Already initialized ({})", config_path.display());
        process::exit(1);
    }

    if let Err(e) = config.ensure_dirs() {
        eprintln!("error: failed to create directories: {e}");
        process::exit(1);
    }

    let default_config = "\
# Ember daemon configuration

[daemon]
# socket_dir = \"~/.ember/run\"
# data_dir = \"~/.ember/data\"
log_level = \"info\"
";
    if let Err(e) = fs::write(&config_path, default_config) {
        eprintln!("error: failed to write config: {e}");
        process::exit(1);
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

    println!("Initialized ember");
    println!("  Config:   {}", config_path.display());
    println!("  Database: {}", config.data_dir.join("daemon.db").display());
    println!("  Root:     {} ({})", persona.id, persona.name);
    println!();
    println!("Run `ember daemon start` to start the daemon.");
}

fn main() {
    let cli = Cli::parse();
    let config = load_config(cli.config.as_ref());

    match cli.command {
        Commands::Init { name } => cmd_init(&config, name),

        Commands::Daemon { action } => match action {
            DaemonAction::Start => {
                tracing_subscriber::fmt()
                    .with_env_filter(
                        EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| EnvFilter::new(config.log_level.as_filter_str())),
                    )
                    .init();

                let runtime = DaemonRuntime::new(config);
                let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
                if let Err(e) = rt.block_on(runtime.run()) {
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
                        if personas.is_empty() {
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
            // TODO: derive vault key from passphrase or hardware key
            let vault_key = [0x42u8; 32];
            let vault = Vault::new(vault_key);

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
                        if creds.is_empty() {
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
                } => match store.create_grant(&persona, &credential, &scope, ttl) {
                    Ok(info) => {
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
                            if list.is_empty() {
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
            }
        }

        Commands::Sandbox { action } => {
            let store = open_store(&config);
            match action {
                SandboxAction::Create { name, image } => {
                    let sandbox = match store.create_sandbox(&name, &image) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };
                    let container_id = match store.start_container(&sandbox.id) {
                        Ok(cid) => cid,
                        Err(e) => {
                            eprintln!("warning: sandbox created but container failed: {e}");
                            "none".to_string()
                        }
                    };
                    println!("Created sandbox");
                    println!("  ID:        {}", sandbox.id);
                    println!("  Persona:   {}", sandbox.persona_id);
                    println!("  Container: {container_id}");
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
                ApprovalAction::Approve { id } => {
                    match store.resolve_approval(&id, &ApprovalOutcome::Approved) {
                        Ok(()) => println!("Approved {id}"),
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
                            if entries.is_empty() {
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
            }
        }
    }
}
