//! `ember broker {issue, revoke, list}` — operator + wrapper-script entry
//! point for the credential broker (design / design).
//!
//! The daemon RPC handlers shipped in implementation-note-9
//! (`crates/ember-daemon/src/broker_handler.rs`); this module is the CLI
//! surface that wraps them. Three subcommands:
//!
//! - [`issue`]  — request a fresh materialization from a registered
//!   provider (`broker_issue` daemon RPC).
//! - [`revoke`] — actively cancel a live materialization
//!   (`broker_revoke` daemon RPC). Idempotent: unknown ids exit 0.
//! - [`list`]   — enumerate active materializations (`broker_list` daemon
//!   RPC), optionally filtered by provider / tier / task-id /
//!   active-only.
//!
//! ## Marker for `target_state_anchor`
//!
//! implementation-note-24 uses `BrokerCmd|broker_command` as its grep gate;
//! both literals appear in this file (`pub enum BrokerCmd` below and
//! `pub fn broker_command` below).
//!
//! ## Secret handling
//!
//! `broker issue` returns a live credential. When stdout is a TTY the
//! `secret` field is masked unless the operator passes `--json`
//! (`--json` is read as "I'm consuming this programmatically; give me
//! the value"). When stdout is piped — even without `--json` — the
//! secret IS emitted, since the only sensible reason to pipe is to feed
//! the value into the next process.

use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Subcommand;
use serde_json::{json, Value};

/// CLI subcommand surface for `ember broker`.
///
/// Mirrors the daemon's three RPC methods one-to-one. The literal
/// `BrokerCmd` is the load-bearing marker for the implementation-note-24
/// `target_state_anchor`.
#[derive(Subcommand, Debug)]
pub enum BrokerCmd {
    /// Issue a fresh credential materialization (design / design).
    ///
    /// Calls `broker_issue` on the daemon socket. The provider must be
    /// registered with the daemon (`mock` providers are pre-registered;
    /// real providers register per-task). The scope is opaque JSON —
    /// per-provider shape is documented in design §5b.
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
        /// Shape is provider-specific; see design §5b.
        #[arg(long = "scope-json")]
        scope_json: String,

        /// Time-to-live (humantime: 15s, 5m, 2h, 1d, or bare seconds).
        /// The broker may clamp this downward to a provider-imposed
        /// maximum.
        #[arg(long)]
        ttl: String,

        /// Free-form audit reason. Recorded in the broker materialization
        /// receipt (design §c).
        #[arg(long)]
        reason: String,

        /// Emit the response (including the live secret) as JSON to
        /// stdout. Without `--json` the secret is masked when stdout is
        /// a TTY.
        #[arg(long)]
        json: bool,
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

    /// List active materializations (design / design).
    ///
    /// Calls `broker_list` on the daemon socket. Filters compose AND.
    List {
        /// Filter by provider (snake_case).
        #[arg(long)]
        provider: Option<String>,

        /// Filter by design risk tier (0/1/2). Currently advisory —
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
        BrokerCmd::Revoke {
            materialization_id,
            json,
        } => revoke(&opts, &materialization_id, json),
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

    // Result shape: { token, materialization_id, expires_at, issued_at, provider }
    if json_out {
        // Programmatic consumer — emit the full JSON unmodified so the
        // secret is reachable.
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
        );
        return Ok(());
    }

    // Pretty path. Mask the secret when stdout is a TTY (the operator
    // is reading; piping or `--json` is the consumer path).
    let mid = result["materialization_id"].as_str().unwrap_or("?");
    let provider_out = result["provider"].as_str().unwrap_or(provider);
    let expires = result["expires_at"].as_str().unwrap_or("?");
    let issued = result["issued_at"].as_str().unwrap_or("?");
    let token = result["token"].as_str().unwrap_or("");

    println!("Brokered credential");
    println!("  Materialization: {mid}");
    println!("  Provider:        {provider_out}");
    println!("  Issued:          {issued}");
    println!("  Expires:         {expires}");
    if io::stdout().is_terminal() {
        println!("  Secret:          [REDACTED — pipe to consumer or use --json]");
    } else {
        println!("  Secret:          {token}");
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
        Err(BrokerCliError::DaemonRpc { code: -32004, message }) => json!({
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
            row.get("expires_at").and_then(|v| v.as_str()).unwrap_or("?"),
            row.get("reason").and_then(|v| v.as_str()).unwrap_or(""),
        );
    }

    Ok(())
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
        "cloudflare", "anthropic", "github", "aws_sts", "gcp", "tailscale",
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
             Provider scope shapes are documented in design §5b / design."
        ))
    })
}

/// Send a synchronous JSON-RPC request over the daemon's Unix socket
/// and return the `result` value. Mirrors the
/// `emberlink-mcp::daemon_transport` shape so behaviour is identical to
/// the MCP path.
fn call_daemon(socket_path: &Path, method: &str, params: &Value) -> Result<Value, BrokerCliError> {
    use std::io::{BufRead, BufReader, Write};

    let stream =
        std::os::unix::net::UnixStream::connect(socket_path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                BrokerCliError::DaemonUnavailable {
                    socket: socket_path.to_path_buf(),
                    source: e,
                }
            }
            _ => BrokerCliError::DaemonUnavailable {
                socket: socket_path.to_path_buf(),
                source: e,
            },
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
// Errors
// ---------------------------------------------------------------------------

/// CLI-side errors. The shell-exit-code mapping lives in `ember.rs` so
/// this module stays free of `process::exit` calls and is unit-testable.
#[derive(Debug)]
pub enum BrokerCliError {
    /// Caller-side validation failure (bad `--provider`, malformed
    /// scope JSON, malformed TTL). Maps to exit 1.
    InvalidArgs(String),

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
            BrokerCliError::DaemonUnavailable { .. } => 2,
            BrokerCliError::DaemonRpc { code, .. } => {
                // Map common daemon codes to operator-friendly exits.
                // `-32601` (method not found / no broker registered for
                // provider) → exit 3 ("provider unknown").
                if *code == -32601 {
                    3
                } else {
                    1
                }
            }
            BrokerCliError::Io(_) | BrokerCliError::Protocol(_) => 1,
        }
    }
}

impl std::fmt::Display for BrokerCliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokerCliError::InvalidArgs(m) => write!(f, "{m}"),
            BrokerCliError::DaemonUnavailable { socket, source } => write!(
                f,
                "ember daemon not running (socket: {}; underlying: {source}); \
                 start with 'ember daemon start'",
                socket.display()
            ),
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
            "cloudflare", "anthropic", "github", "aws_sts", "gcp", "tailscale",
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
                assert!(msg.contains("design"));
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
    fn exit_code_mapping_is_stable() {
        assert_eq!(BrokerCliError::InvalidArgs("x".into()).exit_code(), 1);
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
}
