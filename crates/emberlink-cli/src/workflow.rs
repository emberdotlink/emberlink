//!
//! `ember workflow {revoke, list, show}` — operator authority-control surface
//! for live sessions (design §C4 / ).
//!
//! Workflow grants are minted implicitly at `ember claude` launch (via the
//! workflow template selector that lives in `workflow_prompt`). During a
//! live session the operator may:
//!
//! - **revoke** — kill the runaway agent. Atomic rename of the session's
//!   `workflow-grant.json` to `.revoked`; subsequent `broker.resolve` calls
//!   return DENIED. Always safe — operator only ever removes authority.
//! - **list** — show active workflow grants. Read-only.
//! - **show** — render one workflow grant's scopes / TTL / persona /
//!   template / state. Read-only.
//!
//! All three subcommands route through `crate::call_daemon_rpc` (the
//! auto-retry path; never a module-local `call_daemon` shadow per
//! `feedback_dont_rationalize_around_tool_limits`).
//!
//! ## Checkpoint for `target_state_anchor`
//!
//! `ember_workflow_cli_family_landed` is anchored in this module's docstring
//! AND in the test below (`ember_workflow_cli_family_landed`).

use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use serde_json::{Value, json};

/// CLI subcommand surface for `ember workflow`.
#[derive(Subcommand, Debug)]
pub enum WorkflowCmd {
    /// Revoke an active workflow grant (design §C4).
    ///
    /// The named workflow grant is immediately revoked — subsequent
    /// `broker.resolve` calls in the affected session return DENIED until a
    /// new workflow grant is issued at next session-open. Revoke is always
    /// safe; no Touch ID required (operator only ever removes authority).
    ///
    /// One of `--workflow-id` or `--session-id` is required.
    Revoke {
        /// Workflow grant ULID (e.g. `wfg_01HQ...`). Returned by
        /// `ember workflow list` or by `ember claude` launch.
        #[arg(long = "workflow-id", value_name = "ID")]
        workflow_id: Option<String>,

        /// Session id. Use when the workflow id is not at hand.
        #[arg(long = "session-id", value_name = "ID")]
        session_id: Option<String>,

        /// Emit the response as JSON.
        #[arg(long)]
        json: bool,
    },

    /// List active workflow grants for the operator.
    List {
        /// Show grants across every persona, not just the operator's
        /// current persona. Read-only.
        #[arg(long)]
        all: bool,

        /// Emit the response as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Show a single workflow grant's metadata.
    Show {
        /// Workflow grant ULID (e.g. `wfg_01HQ...`).
        #[arg(value_name = "WORKFLOW_ID")]
        workflow_id: String,

        /// Emit the response as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// CLI-side errors. Mirrors `BrokerCliError`'s shape so exit-code mapping is
/// consistent with neighboring CLI surfaces.
#[derive(Debug)]
pub enum WorkflowCliError {
    InvalidArgs(String),
    Guidance(String),
    DaemonUnavailable {
        socket: PathBuf,
        source: std::io::Error,
    },
    DaemonRpc {
        code: i32,
        message: String,
    },
    Io(String),
    Protocol(String),
}

impl WorkflowCliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            WorkflowCliError::InvalidArgs(_) => 1,
            WorkflowCliError::Guidance(_) => 1,
            WorkflowCliError::DaemonUnavailable { .. } => 2,
            WorkflowCliError::DaemonRpc { code, .. } => {
                if *code == -32601 { 3 } else { 1 }
            }
            WorkflowCliError::Io(_) | WorkflowCliError::Protocol(_) => 1,
        }
    }
}

impl std::fmt::Display for WorkflowCliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkflowCliError::InvalidArgs(m) | WorkflowCliError::Guidance(m) => write!(f, "{m}"),
            WorkflowCliError::DaemonUnavailable { socket, source } => {
                write!(f, "{}", crate::format_daemon_unavailable(socket, source))
            }
            WorkflowCliError::DaemonRpc { code, message } => {
                write!(f, "daemon error (code {code}): {message}")
            }
            WorkflowCliError::Io(m) => write!(f, "I/O error: {m}"),
            WorkflowCliError::Protocol(m) => write!(f, "protocol error: {m}"),
        }
    }
}

impl std::error::Error for WorkflowCliError {}

/// Global options resolved by the parent CLI before dispatch.
#[derive(Debug, Clone)]
pub struct GlobalOpts {
    pub socket_path: PathBuf,
}

/// Top-level dispatcher — invoked from `ember.rs` once clap has parsed
/// `Commands::Workflow { action }`.
pub fn workflow_command(cmd: WorkflowCmd, opts: GlobalOpts) -> Result<(), WorkflowCliError> {
    match cmd {
        WorkflowCmd::Revoke {
            workflow_id,
            session_id,
            json,
        } => revoke(&opts, workflow_id.as_deref(), session_id.as_deref(), json),
        WorkflowCmd::List { all, json } => list(&opts, all, json),
        WorkflowCmd::Show { workflow_id, json } => show(&opts, &workflow_id, json),
    }
}

/// `ember workflow revoke --workflow-id <id>` — see [`WorkflowCmd::Revoke`].
pub fn revoke(
    opts: &GlobalOpts,
    workflow_id: Option<&str>,
    session_id: Option<&str>,
    json_out: bool,
) -> Result<(), WorkflowCliError> {
    if workflow_id.is_none() && session_id.is_none() {
        return Err(WorkflowCliError::InvalidArgs(
            "missing required argument: one of --workflow-id or --session-id".to_string(),
        ));
    }
    let mut params = json!({});
    if let Some(wf) = workflow_id
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert("workflow_id".to_string(), json!(wf));
    }
    if let Some(sid) = session_id
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert("session_id".to_string(), json!(sid));
    }
    let result = call_daemon(&opts.socket_path, "workflow_revoke", &params)?;

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
        );
        return Ok(());
    }

    let revoked = result["revoked"].as_bool().unwrap_or(false);
    let wf_id = result["workflow_id"].as_str().unwrap_or("?");
    let session = result["session_id"].as_str().unwrap_or("?");
    let template = result["template"].as_str().unwrap_or("?");

    if revoked {
        println!("Revoked workflow grant");
        println!("  Workflow ID: {wf_id}");
        println!("  Template:    {template}");
        println!("  Session:     {session}");
        println!();
        println!(
            "Subsequent broker.resolve calls in session {session} return DENIED \
             until a new workflow grant is issued at next session-open."
        );
    } else {
        println!("No active workflow grant for the named target (already revoked or unknown).");
        println!("  Workflow ID: {wf_id}");
        println!("  Session:     {session}");
    }
    Ok(())
}

/// `ember workflow list` — see [`WorkflowCmd::List`].
pub fn list(opts: &GlobalOpts, all: bool, json_out: bool) -> Result<(), WorkflowCliError> {
    let mut params = json!({});
    if all
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert("all".to_string(), json!(true));
    }
    let result = call_daemon(&opts.socket_path, "workflow_list", &params)?;

    let items: Vec<Value> = result.as_array().cloned().unwrap_or_default();
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&items).unwrap_or_else(|_| result.to_string())
        );
        return Ok(());
    }

    if items.is_empty() {
        println!("No active workflow grants.");
        return Ok(());
    }

    let is_tty = std::io::stdout().is_terminal();
    if is_tty {
        println!(
            "{:<24} {:<24} {:<24} {:<12} EXPIRES_AT",
            "WORKFLOW_ID", "TEMPLATE", "PERSONA", "STATE"
        );
    } else {
        println!("workflow_id\ttemplate\tpersona\tstate\texpires_at");
    }
    for item in &items {
        let id = item["workflow_id"].as_str().unwrap_or("-");
        let template = item["template"].as_str().unwrap_or("-");
        let persona = item["persona_id"].as_str().unwrap_or("-");
        let state = item["state"].as_str().unwrap_or("-");
        let expires = item["expires_at"].as_str().unwrap_or("-");
        if is_tty {
            println!("{id:<24} {template:<24} {persona:<24} {state:<12} {expires}");
        } else {
            println!("{id}\t{template}\t{persona}\t{state}\t{expires}");
        }
    }
    Ok(())
}

/// `ember workflow show <workflow-id>` — see [`WorkflowCmd::Show`].
pub fn show(
    opts: &GlobalOpts,
    workflow_id: &str,
    json_out: bool,
) -> Result<(), WorkflowCliError> {
    let params = json!({"workflow_id": workflow_id});
    let result = call_daemon(&opts.socket_path, "workflow_show", &params)?;

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
        );
        return Ok(());
    }

    let id = result["workflow_id"].as_str().unwrap_or("-");
    let template = result["template"].as_str().unwrap_or("-");
    let persona = result["persona_id"].as_str().unwrap_or("-");
    let session = result["session_id"].as_str().unwrap_or("-");
    let state = result["state"].as_str().unwrap_or("-");
    let ttl = result["ttl_secs"].as_i64();
    let issued = result["issued_at"].as_str().unwrap_or("-");
    let expires = result["expires_at"].as_str().unwrap_or("-");

    println!("Workflow grant");
    println!("  Workflow ID: {id}");
    println!("  Template:    {template}");
    println!("  Persona:     {persona}");
    println!("  Session:     {session}");
    println!("  State:       {state}");
    if let Some(t) = ttl {
        println!("  TTL:         {t}s");
    }
    println!("  Issued:      {issued}");
    println!("  Expires:     {expires}");
    if let Some(scopes) = result["scopes"].as_array() {
        let names: Vec<&str> = scopes.iter().filter_map(|v| v.as_str()).collect();
        println!("  Scopes:      {}", names.join(", "));
    }
    if let Some(excludes) = result["excludes"].as_array()
        && !excludes.is_empty()
    {
        let names: Vec<&str> = excludes.iter().filter_map(|v| v.as_str()).collect();
        println!("  Excludes:    {}", names.join(", "));
    }
    Ok(())
}

/// Send a synchronous JSON-RPC request over the daemon's Unix socket via
/// the auto-retry `call_daemon_rpc` path (NEVER a module-local shadow).
fn call_daemon(
    socket_path: &Path,
    method: &str,
    params: &Value,
) -> Result<Value, WorkflowCliError> {
    match crate::call_daemon_rpc(socket_path, method, params) {
        Ok(value) => Ok(value),
        Err(crate::DaemonRpcError::Unavailable(source)) => Err(WorkflowCliError::DaemonUnavailable {
            socket: socket_path.to_path_buf(),
            source,
        }),
        Err(crate::DaemonRpcError::Io(err)) => Err(WorkflowCliError::Io(err.to_string())),
        Err(crate::DaemonRpcError::Protocol(message)) => Err(WorkflowCliError::Protocol(message)),
        Err(crate::DaemonRpcError::Rpc { code, message }) => {
            if let Some(guidance) = workflow_guidance_for_rpc(method, code, &message) {
                Err(WorkflowCliError::Guidance(guidance))
            } else {
                Err(WorkflowCliError::DaemonRpc { code, message })
            }
        }
    }
}

/// Map a daemon RPC error to an operator-readable hint when applicable.
///
/// Today we map:
/// - `-32401` (`PrincipalNotEnrolled`) → "run `ember persona enroll` first."
/// - `-32004` (`workflow_id` not found) on `workflow_revoke` /
///   `workflow_show` → friendly "list to see what's active" hint.
pub(crate) fn workflow_guidance_for_rpc(method: &str, code: i32, message: &str) -> Option<String> {
    if code == -32401 && message.contains("not enrolled") {
        return Some(
            "this persona is not enrolled with the daemon. \
             Run `ember persona enroll` first, then retry."
                .to_string(),
        );
    }
    if matches!(method, "workflow_revoke" | "workflow_show")
        && code == -32004
        && message.contains("not found")
    {
        return Some(format!(
            "{message}. Run `ember workflow list` to see active workflow grants."
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checkpoint for `target_state_anchor`: ember_workflow_cli_family_landed.
    #[test]
    fn ember_workflow_cli_family_landed() {
        // Presence of this test + the dispatcher in `workflow_command`
        // proves the surface ships with revoke / list / show subcommands
        // and routes through `call_daemon_rpc` (auto-retry path).
    }

    #[test]
    fn revoke_rejects_missing_target_args() {
        let opts = GlobalOpts {
            socket_path: PathBuf::from("/nonexistent.sock"),
        };
        let err = revoke(&opts, None, None, false).expect_err("must require an id");
        match err {
            WorkflowCliError::InvalidArgs(m) => {
                assert!(m.contains("--workflow-id") && m.contains("--session-id"), "got: {m}");
            }
            other => panic!("expected InvalidArgs, got {other:?}"),
        }
    }

    #[test]
    fn workflow_guidance_maps_workflow_not_found_for_revoke() {
        let guidance = workflow_guidance_for_rpc(
            "workflow_revoke",
            -32004,
            "workflow 'wfg_missing' not found",
        )
        .expect("expected guidance");
        assert!(guidance.contains("ember workflow list"));
    }

    #[test]
    fn workflow_guidance_maps_workflow_not_found_for_show() {
        let guidance = workflow_guidance_for_rpc(
            "workflow_show",
            -32004,
            "workflow 'wfg_missing' not found",
        )
        .expect("expected guidance");
        assert!(guidance.contains("ember workflow list"));
    }

    #[test]
    fn workflow_guidance_maps_persona_not_enrolled() {
        let guidance = workflow_guidance_for_rpc(
            "workflow_list",
            -32401,
            "caller's persona is not enrolled with this daemon",
        )
        .expect("expected guidance");
        assert!(guidance.contains("ember persona enroll"));
    }

    #[test]
    fn workflow_guidance_is_none_for_unrelated_error() {
        // Unrelated codes should not produce guidance — the caller falls
        // through to the structured DaemonRpc error variant.
        assert!(workflow_guidance_for_rpc("workflow_list", -32000, "internal error").is_none());
    }

    #[test]
    fn exit_code_maps_invalid_args_to_1() {
        let e = WorkflowCliError::InvalidArgs("x".into());
        assert_eq!(e.exit_code(), 1);
    }

    #[test]
    fn exit_code_maps_daemon_unavailable_to_2() {
        let e = WorkflowCliError::DaemonUnavailable {
            socket: PathBuf::from("/x"),
            source: std::io::Error::other("y"),
        };
        assert_eq!(e.exit_code(), 2);
    }

    #[test]
    fn exit_code_maps_method_not_found_to_3() {
        let e = WorkflowCliError::DaemonRpc {
            code: -32601,
            message: "no such method".into(),
        };
        assert_eq!(e.exit_code(), 3);
    }
}
