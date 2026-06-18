//! `ember bind {register, list, remove, move}` — admin verb for managing
//! daemon-controlled credential bindings (META-ARCH-DAEMON-CONTROLLED-CONFIG
//! Phase 3 / META-ARCH-DCC-7-EMBER-BIND-ADMIN-VERB).
//!
//! A binding ties `(persona, working_tree, remote_name)` to a remote URL the
//! broker is authorized to inject credentials for. This verb is the EXPLICIT
//! admin path — operators pre-register bindings or recover from rename/repo-
//! move scenarios without going through the TOFU biometric flow. Per the
//! SESSION plan, the admin path does NOT require biometric: the caller has
//! already authenticated to the daemon via the kernel-attested PeerCred
//! principal. Biometric will gate the TOFU flow shipped in DCC-3, not this
//! verb.
//!
//! Daemon RPC surface (canonical names; underscore aliases also accepted):
//!   * `broker.bindings.register`
//!   * `broker.bindings.list`
//!   * `broker.bindings.remove`
//!   * `broker.bindings.move`
//!
//! Marker for `target_state_anchor` (META-ARCH-DCC-7): `fn cmd_bind` lives in
//! this file as the top-level dispatch entry.

use std::path::{Path, PathBuf};

use clap::Subcommand;
use serde_json::{Value, json};

use crate::broker::BrokerCliError;

/// CLI subcommand surface for `ember bind`.
///
/// Each verb mirrors a single daemon RPC method one-to-one.
#[derive(Subcommand, Debug)]
pub enum BindCmd {
    /// Register (or re-register) a credential binding.
    ///
    /// Idempotent — re-registering the same `(persona, working-tree,
    /// remote)` triple with a new URL is an in-place update on the daemon
    /// side (`INSERT OR REPLACE`). Use this to pre-register bindings
    /// during admin work without going through the biometric TOFU flow.
    Register {
        /// Canonical absolute path of the working-tree root.
        #[arg(long = "working-tree")]
        working_tree: PathBuf,

        /// Remote name (typically `origin`).
        #[arg(long)]
        remote: String,

        /// Full remote URL the broker is authorized to inject credentials
        /// for (e.g. `git@github.com:foo/bar.git`).
        #[arg(long)]
        url: String,

        /// Persona UUID — defaults to `$EMBER_PERSONA` when set.
        #[arg(long)]
        persona: Option<String>,

        /// Emit the response as JSON.
        #[arg(long)]
        json: bool,
    },

    /// List bindings owned by the caller persona, optionally filtered by
    /// working tree.
    List {
        /// Filter by working-tree path.
        #[arg(long = "working-tree")]
        working_tree: Option<PathBuf>,

        /// Persona UUID — defaults to `$EMBER_PERSONA` when set.
        #[arg(long)]
        persona: Option<String>,

        /// Emit the response as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },

    /// Remove a binding by `(working-tree, remote)`. Idempotent — when no
    /// matching row exists the command reports `removed: false` and
    /// exits 0.
    Remove {
        /// Canonical absolute path of the working-tree root.
        #[arg(long = "working-tree")]
        working_tree: PathBuf,

        /// Remote name.
        #[arg(long)]
        remote: String,

        /// Persona UUID — defaults to `$EMBER_PERSONA` when set.
        #[arg(long)]
        persona: Option<String>,

        /// Emit the response as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Re-root every binding owned by the caller persona from `--old-path`
    /// to `--new-path`. Used to recover from rename/repo-move scenarios
    /// without re-issuing every binding manually.
    Move {
        /// Previous canonical working-tree path.
        #[arg(long = "old-path")]
        old_path: PathBuf,

        /// New canonical working-tree path.
        #[arg(long = "new-path")]
        new_path: PathBuf,

        /// Persona UUID — defaults to `$EMBER_PERSONA` when set.
        #[arg(long)]
        persona: Option<String>,

        /// Emit the response as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Global options resolved by the parent CLI before dispatch into
/// `cmd_bind`. Today only the daemon socket path is needed; mirroring
/// `broker::GlobalOpts` so the two admin surfaces share shape.
#[derive(Debug, Clone)]
pub struct GlobalOpts {
    pub socket_path: PathBuf,
}

/// Top-level dispatch — invoked from `ember.rs` once clap has parsed
/// `Commands::Bind { action }`.
///
/// The literal `fn cmd_bind` is the load-bearing marker for the
/// META-ARCH-DCC-7 `target_state_anchor` gate.
pub fn cmd_bind(cmd: BindCmd, opts: GlobalOpts) -> Result<(), BrokerCliError> {
    match cmd {
        BindCmd::Register {
            working_tree,
            remote,
            url,
            persona,
            json,
        } => cmd_bind_register(
            &opts,
            &working_tree,
            &remote,
            &url,
            persona.as_deref(),
            json,
        ),
        BindCmd::List {
            working_tree,
            persona,
            json,
        } => cmd_bind_list(&opts, working_tree.as_deref(), persona.as_deref(), json),
        BindCmd::Remove {
            working_tree,
            remote,
            persona,
            json,
        } => cmd_bind_remove(&opts, &working_tree, &remote, persona.as_deref(), json),
        BindCmd::Move {
            old_path,
            new_path,
            persona,
            json,
        } => cmd_bind_move(&opts, &old_path, &new_path, persona.as_deref(), json),
    }
}

// ---------------------------------------------------------------------------
// Per-subcommand implementations
// ---------------------------------------------------------------------------

fn cmd_bind_register(
    opts: &GlobalOpts,
    working_tree: &Path,
    remote: &str,
    url: &str,
    persona: Option<&str>,
    json_out: bool,
) -> Result<(), BrokerCliError> {
    let caller = resolve_persona(persona)?;
    let working_tree_id = working_tree.to_string_lossy().to_string();
    let params = json!({
        "caller_persona": caller,
        "working_tree_id": working_tree_id,
        "remote_name": remote,
        "remote_url": url,
    });
    let result = call_daemon(&opts.socket_path, "broker.bindings.register", &params)?;

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
        );
    } else {
        println!("Registered binding");
        println!("  Persona:      {caller}");
        println!("  Working tree: {working_tree_id}");
        println!("  Remote:       {remote}");
        println!("  URL:          {url}");
    }
    Ok(())
}

fn cmd_bind_list(
    opts: &GlobalOpts,
    working_tree: Option<&Path>,
    persona: Option<&str>,
    json_out: bool,
) -> Result<(), BrokerCliError> {
    let caller = resolve_persona(persona)?;
    let mut params = json!({"caller_persona": caller});
    if let Some(tree) = working_tree {
        params["working_tree_id"] = json!(tree.to_string_lossy().to_string());
    }
    let result = call_daemon(&opts.socket_path, "broker.bindings.list", &params)?;
    let rows = result
        .get("bindings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if json_out {
        let arr = Value::Array(rows);
        println!(
            "{}",
            serde_json::to_string_pretty(&arr).unwrap_or_else(|_| arr.to_string())
        );
        return Ok(());
    }

    if rows.is_empty() {
        println!("No bindings for persona {caller}");
        return Ok(());
    }

    println!("{:<60}  {:<10}  REMOTE_URL", "WORKING_TREE", "REMOTE",);
    for row in &rows {
        println!(
            "{:<60}  {:<10}  {}",
            row.get("working_tree_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
            row.get("remote_name")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
            row.get("remote_url")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
        );
    }
    Ok(())
}

fn cmd_bind_remove(
    opts: &GlobalOpts,
    working_tree: &Path,
    remote: &str,
    persona: Option<&str>,
    json_out: bool,
) -> Result<(), BrokerCliError> {
    let caller = resolve_persona(persona)?;
    let working_tree_id = working_tree.to_string_lossy().to_string();
    let params = json!({
        "caller_persona": caller,
        "working_tree_id": working_tree_id,
        "remote_name": remote,
    });
    let result = call_daemon(&opts.socket_path, "broker.bindings.remove", &params)?;
    let removed = result["removed"].as_bool().unwrap_or(false);

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
        );
    } else if removed {
        println!("Removed binding {working_tree_id} :: {remote}");
    } else {
        println!("No-op: no binding for ({caller}, {working_tree_id}, {remote})");
    }
    Ok(())
}

fn cmd_bind_move(
    opts: &GlobalOpts,
    old_path: &Path,
    new_path: &Path,
    persona: Option<&str>,
    json_out: bool,
) -> Result<(), BrokerCliError> {
    let caller = resolve_persona(persona)?;
    let old = old_path.to_string_lossy().to_string();
    let new = new_path.to_string_lossy().to_string();
    let params = json!({
        "caller_persona": caller,
        "old_path": old,
        "new_path": new,
    });
    let result = call_daemon(&opts.socket_path, "broker.bindings.move", &params)?;
    let moved = result["moved"].as_u64().unwrap_or(0);

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
        );
    } else {
        println!("Moved {moved} binding(s) from {old} to {new}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the caller persona — explicit `--persona` wins, otherwise fall
/// back to `$EMBER_PERSONA`. Both branches reject a nil/empty value so the
/// daemon-side `extract_caller_persona` gate never has to handle the empty
/// string.
fn resolve_persona(explicit: Option<&str>) -> Result<String, BrokerCliError> {
    if let Some(p) = explicit {
        if p.is_empty() {
            return Err(BrokerCliError::InvalidArgs(
                "--persona must not be empty".to_string(),
            ));
        }
        return Ok(p.to_string());
    }
    match std::env::var("EMBER_PERSONA") {
        Ok(p) if !p.is_empty() => Ok(p),
        _ => Err(BrokerCliError::InvalidArgs(
            "no persona supplied: pass --persona <uuid> or set $EMBER_PERSONA".to_string(),
        )),
    }
}

/// Send a synchronous JSON-RPC request over the daemon's Unix socket and
/// return the `result` value. Mirrors `broker.rs::call_daemon` shape — we
/// keep a copy here rather than re-exporting so the admin surface stays
/// independent of the broker module's internal refactors.
fn call_daemon(socket_path: &Path, method: &str, params: &Value) -> Result<Value, BrokerCliError> {
    use std::io::{BufRead, BufReader, Write};

    let stream = std::os::unix::net::UnixStream::connect(socket_path).map_err(|e| {
        BrokerCliError::DaemonUnavailable {
            socket: socket_path.to_path_buf(),
            source: e,
        }
    })?;
    let mut writer = stream
        .try_clone()
        .map_err(|e| BrokerCliError::Io(format!("clone socket: {e}")))?;
    let mut reader = BufReader::new(stream);

    let request = json!({
        "id": "1",
        "method": method,
        "params": params,
    });
    let mut line = serde_json::to_string(&request).expect("serialize request");
    line.push('\n');

    writer
        .write_all(line.as_bytes())
        .map_err(|e| BrokerCliError::Io(format!("write request: {e}")))?;

    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| BrokerCliError::Io(format!("read response: {e}")))?;

    let response: Value = serde_json::from_str(response_line.trim())
        .map_err(|e| BrokerCliError::Protocol(format!("invalid JSON-RPC response: {e}")))?;

    if let Some(err) = response.get("error").filter(|v| !v.is_null()) {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000) as i32;
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        return Err(BrokerCliError::DaemonRpc { code, message });
    }

    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

// ---------------------------------------------------------------------------
// Tests — caller-side validation only. Full round-trip lives in
// daemon-side integration tests in `crates/ember-daemon/src/broker/handler.rs`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_persona_explicit_wins() {
        let p = resolve_persona(Some("00000000-0000-0000-0000-000000000001"))
            .expect("explicit must resolve");
        assert_eq!(p, "00000000-0000-0000-0000-000000000001");
    }

    #[test]
    fn resolve_persona_rejects_empty_explicit() {
        let err = resolve_persona(Some("")).expect_err("empty must error");
        match err {
            BrokerCliError::InvalidArgs(msg) => assert!(msg.contains("must not be empty")),
            other => panic!("expected InvalidArgs, got {other:?}"),
        }
    }

    #[test]
    fn resolve_persona_rejects_when_no_source_present() {
        // Serialize against other EMBER_PERSONA-touching tests in this
        // crate (notably `launcher::claude_code::tests::persona_uses_env_var_when_set`).
        // The cargo parallel runner used to race set/remove and produce
        // test-order-dependent failures.
        let _g = crate::EMBER_PERSONA_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Save + clear EMBER_PERSONA for the duration of the test.
        let prior = std::env::var("EMBER_PERSONA").ok();
        // SAFETY: holds EMBER_PERSONA_TEST_LOCK for the duration of the
        // env mutation; restored before return.
        unsafe {
            std::env::remove_var("EMBER_PERSONA");
        }
        let err = resolve_persona(None).expect_err("missing must error");
        match err {
            BrokerCliError::InvalidArgs(msg) => assert!(msg.contains("no persona supplied")),
            other => panic!("expected InvalidArgs, got {other:?}"),
        }
        if let Some(v) = prior {
            unsafe {
                std::env::set_var("EMBER_PERSONA", v);
            }
        }
    }
}
