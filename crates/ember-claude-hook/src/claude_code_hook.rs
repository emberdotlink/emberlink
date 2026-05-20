//! Claude Code PreToolUse hook entry.
//!
//! Invoked as `ember-proxy --claude-code-hook` (also accepts the bare
//! subcommand form `ember-proxy hook` for the documented 3-line
//! `~/.claude/settings.json` snippet). Reads a JSON request from stdin,
//! validates against the active grant policy (or permits in dev mode),
//! emits a Receipt, exits 0 (allow) or 1 (deny).
//!
//! Claude Code settings.json invocation:
//! ```json
//! {
//!   "hooks": {
//!     "PreToolUse": [
//!       { "matcher": "*", "hooks": [
//!         { "type": "command", "command": "ember-proxy hook" }
//!       ]}
//!     ]
//!   }
//! }
//! ```
//!
//! Wire shape (implementation-note-74, 2026-04-27):
//! Claude Code's PreToolUse hook contract is documented in the Claude Code
//! docs as a JSON object on stdin with at least `tool_name` (string) and
//! `tool_input` / `params` (opaque object). Field names are best-effort
//! against the public docs; we accept either `params` or `tool_input` via
//! `#[serde(alias)]` so a future field-rename in Claude Code does not
//! silently drop validation.
//!
//! Exit semantics:
//!  * `0` -> allow the tool call (Claude Code proceeds).
//!  * `1` -> deny (Claude Code surfaces the JSON `reason` to the agent).
//!
//! Dev fallback: when `EMBER_PROXY_DEV_PERMIT=1` is set in the environment,
//! the hook permits every call regardless of grant state. This is the
//! intended path for first-run install before `emberd` is reachable.
//! Production callers MUST leave the variable unset; in that mode the hook
//! still permits today (full grant validation lands in
//! `implementation-note-75`) but logs a structured WARN line so the
//! operator can see the gating gap.

use anyhow::Result;
use core_config::EmberConfig;
use core_policy::{ScopeDecision, ScopeTemplate};
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use crate::evaluator;

/// Inbound request shape from Claude Code's PreToolUse hook.
///
/// Field names track the Claude Code hook contract; `params` aliases
/// `tool_input` so renames in either direction stay parseable.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PreToolUseRequest {
    pub tool_name: String,
    #[serde(default, alias = "tool_input")]
    pub params: serde_json::Value,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub transcript_path: Option<String>,
}

/// Outbound response written to stdout.
///
/// Claude Code does not require a structured response on allow paths
/// (any zero exit is fine); we emit one anyway so dashboards / log
/// scrapers downstream get a consistent JSON line per tool call.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct HookResponse {
    pub allow: bool,
    pub reason: String,
}

/// Lazily-parsed default Claude Code scope template. Parse cost is paid
/// once per process; the regex compilation in `ScopeTemplate::compile` is
/// not cheap so we don't want it on every hook invocation.
///
/// Currently only consumed by [`evaluate_inproc`] (test-only since the
/// implementation-note-76 daemon wiring landed). Retained for implementation-note-77 — the
/// daemon will fold the template into its own evaluator path and the
/// proxy will keep this seam for offline / fallback decisions.
#[allow(dead_code)]
fn default_template() -> &'static ScopeTemplate {
    static TEMPLATE: OnceLock<ScopeTemplate> = OnceLock::new();
    TEMPLATE.get_or_init(|| {
        ScopeTemplate::default_claude_code()
            .expect("embedded claude-code-default-v1 template must parse")
    })
}

/// implementation-note-76: route a hook evaluation through the daemon socket so the
/// daemon owns grant lookup + audit-event emission.
///
/// 1. `EMBER_PROXY_DEV_PERMIT=1` short-circuits to permit (first-run install).
/// 2. Otherwise open `~/.ember/run/daemon.sock`, send `evaluate_tool_call`
///    JSON-RPC, return [`HookResponse`] from the daemon decision.
/// 3. Daemon-unreachable ⇒ deny with the canned "implementation-note-13 will add
///    fail-open" reason (this branch is the only path that bails today;
///    implementation-note-13 wires the controlled fail-open + panic-catch surface).
///
/// The dev-permit short-circuit at step 1 is intentionally unconditional —
/// without an emberd reachable on the local socket the install path
/// would otherwise refuse every tool call before the operator has had a
/// chance to mint their first grant.
fn evaluate(req: &PreToolUseRequest, dev_permit: bool) -> HookResponse {
    if dev_permit {
        return HookResponse {
            allow: true,
            reason: "ember-proxy: EMBER_PROXY_DEV_PERMIT=1 (dev permit)".to_string(),
        };
    }

    evaluate_via_daemon(req, &default_socket_path())
}

/// Resolve the per-user emberd Unix socket path.
///
/// `EMBER_SOCKET_PATH` overrides everything (used by `qember.sh` and the
/// integration tests). Otherwise default to `~/.ember/run/daemon.sock`,
/// matching `crates/ember-daemon/src/config.rs::DaemonConfig::default()`.
/// Falls back to `/tmp/.ember/run/daemon.sock` when `$HOME` is unset
/// (no panic — the daemon-unreachable path will surface a clean error).
fn default_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("EMBER_SOCKET_PATH") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join(".ember").join("run").join("daemon.sock")
}

/// Resolve the persona name the proxy should send to the daemon.
///
/// The Cohort A convention (design §3) is `claude-code-{hostname}`.
/// We read `$HOSTNAME` first; on systems where the shell does not
/// export it (most non-interactive contexts) we fall back to a fixed
/// `claude-code-local` so the lookup is at least deterministic. The
/// daemon's persona-by-name lookup is exact-match — operators that
/// run multiple hosts should mint a persona with the matching
/// `claude-code-<host>` name on each one.
fn default_persona_name() -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "local".to_string());
    format!("claude-code-{host}")
}

/// Wire-shape of the `evaluate_tool_call` JSON-RPC request. Mirrors the
/// daemon-side params block in `handler.rs` (`"evaluate_tool_call"`
/// arm) — keeping the type literal here avoids a cross-crate dep and
/// keeps the proxy build closed under its current Cargo deps.
#[derive(Debug, Serialize)]
struct EvaluateToolCallParams<'a> {
    persona: &'a str,
    tool_name: &'a str,
    params: &'a serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_id: Option<&'a str>,
}

/// Wire-shape of the daemon response. Field set must match
/// `crate::grant::ToolCallDecision` in `ember-daemon`. Decoupled type
/// so we don't drag the daemon crate into the proxy build.
///
/// implementation-note-42: `await_approval_request_id` is surfaced when the daemon's
/// evaluator routes a call into the approval queue. When present (and
/// `permit == false`), the hook calls back into the daemon via
/// `await_approval` to block until the operator resolves the request.
#[derive(Debug, Deserialize)]
struct ToolCallDecisionWire {
    permit: bool,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    grant_id: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // surfaced for implementation-note-35 receipt-termination work
    emitted_event_id: Option<String>,
    #[serde(default)]
    await_approval_request_id: Option<String>,
}

/// implementation-note-42 — wire-shape mirror of `core_grant_types::approval::ApprovalDecision`.
///
/// Decoupled local type so the proxy build does not drag in `core-types`.
/// Tag/case must match the daemon-side serialization (`#[serde(tag =
/// "kind", rename_all = "snake_case")]` over `Approved | Denied { reason
/// } | TimedOut`).
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ApprovalDecisionWire {
    Approved,
    Denied { reason: String },
    TimedOut,
}

/// Wire-shape of the daemon's `await_approval` response envelope. The
/// resolved decision is wrapped in a `decision` object so future
/// response-level fields (latency, resolver hint) can be added without a
/// wire-format bump.
#[derive(Debug, Deserialize)]
struct AwaitApprovalResponseWire {
    decision: ApprovalDecisionWire,
}

/// Default block-and-poll deadline for the proxy's `await_approval` call.
///
/// Five minutes covers the realistic upper-bound for a human to walk to
/// their dashboard and resolve a tap. Configurable via EmberConfig is
/// follow-up work — surfacing it here avoids hard-coding the literal in
/// multiple call sites.
const AWAIT_APPROVAL_TIMEOUT_SECS: u64 = 300;

/// Append a JSON audit-gap record to `~/.ember/sessions/<session_id>/audit-gaps.jsonl`.
///
/// Best-effort — logs via `tracing::warn!` on failure, never propagates.
/// One record per daemon-unreachable event per the implementation-note-13 spec.
fn append_audit_gap(session_id: &str, reason: &str) {
    let Ok(home) = std::env::var("HOME") else {
        eprintln!("ember-proxy: audit-gap: $HOME not set, skipping gap record");
        return;
    };
    let path = std::path::Path::new(&home)
        .join(".ember")
        .join("sessions")
        .join(session_id)
        .join("audit-gaps.jsonl");
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        eprintln!(
            "ember-proxy: audit-gap: create_dir_all {}: {e}",
            parent.display()
        );
        return;
    }
    let entry = serde_json::json!({
        "from": "ember-proxy",
        "to": "daemon",
        "reason": reason,
    });
    let result = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| writeln!(f, "{entry}"));
    if let Err(e) = result {
        eprintln!("ember-proxy: audit-gap: write {}: {e}", path.display());
    }
}

/// Open the daemon socket, send `evaluate_tool_call`, return a
/// [`HookResponse`].
///
/// implementation-note-13: when the daemon is unreachable, consults
/// `EmberConfig::load_or_default().explicit_fail_open`. If true (default),
/// returns `{allow: true}` with a structured reason and records an audit-gap.
/// If false, returns `{allow: false}` (original fail-closed behaviour).
fn evaluate_via_daemon(req: &PreToolUseRequest, socket_path: &Path) -> HookResponse {
    let persona = default_persona_name();
    let grant_id_owned = std::env::var("EMBER_GRANT_ID").ok();
    let params = EvaluateToolCallParams {
        persona: &persona,
        tool_name: &req.tool_name,
        params: &req.params,
        session_id: req.session_id.as_deref(),
        grant_id: grant_id_owned.as_deref(),
    };

    let decision = match call_daemon_evaluate(socket_path, &params) {
        Ok(d) => d,
        Err(e) => {
            let cfg = EmberConfig::load_or_default();
            let fail_open = cfg.explicit_fail_open;
            let session_id = req.session_id.clone().unwrap_or_else(|| {
                std::env::var("EMBER_SESSION_ID").unwrap_or_else(|_| "unknown".to_string())
            });
            let reason = format!(
                "ember-proxy: daemon unreachable; {} (explicit_fail_open={}; A-9) — {e}",
                if fail_open { "permitting" } else { "denying" },
                fail_open,
            );
            append_audit_gap(&session_id, &reason);
            return HookResponse {
                allow: fail_open,
                reason,
            };
        }
    };

    if decision.permit {
        return HookResponse {
            allow: true,
            reason: format!(
                "ember-proxy: permit (daemon, grant_id={})",
                decision.grant_id.as_deref().unwrap_or("<none>")
            ),
        };
    }

    // implementation-note-42: when the daemon routed the call into the approval queue
    // (signaled by `await_approval_request_id`), block-and-poll the daemon
    // for the operator's resolution instead of denying outright. On
    // unreachable / decode error we fall back to the original deny reason
    // so a wedged dashboard does not silently permit traffic.
    if let Some(request_id) = decision.await_approval_request_id.as_deref() {
        match call_daemon_await_approval(socket_path, request_id, AWAIT_APPROVAL_TIMEOUT_SECS) {
            Ok(ApprovalDecisionWire::Approved) => {
                return HookResponse {
                    allow: true,
                    reason: format!(
                        "ember-proxy: permit (daemon approval, request_id={request_id})"
                    ),
                };
            }
            Ok(ApprovalDecisionWire::Denied { reason }) => {
                return HookResponse {
                    allow: false,
                    reason: format!(
                        "ember-proxy: deny (daemon approval denied, request_id={request_id}): {reason}"
                    ),
                };
            }
            Ok(ApprovalDecisionWire::TimedOut) => {
                return HookResponse {
                    allow: false,
                    reason: format!(
                        "ember-proxy: deny (daemon approval timed out after {AWAIT_APPROVAL_TIMEOUT_SECS}s, request_id={request_id})"
                    ),
                };
            }
            Err(e) => {
                return HookResponse {
                    allow: false,
                    reason: format!(
                        "ember-proxy: deny (daemon await_approval failed for request_id={request_id}): {e}"
                    ),
                };
            }
        }
    }

    HookResponse {
        allow: false,
        reason: format!(
            "ember-proxy: deny — {}",
            decision.reason.as_deref().unwrap_or("no reason supplied")
        ),
    }
}

/// Internal RPC helper. Connects, writes one request line, reads one
/// response line, decodes the result.
///
/// Bounded read timeout so a wedged daemon doesn't stall the hook
/// indefinitely (Claude Code surfaces a hung hook to the user as a
/// frozen tool call). The 5s budget is comfortably above the daemon's
/// in-process eval cost (sub-millisecond) but well under the user-
/// perceptible-latency threshold.
fn call_daemon_evaluate(
    socket_path: &Path,
    params: &EvaluateToolCallParams<'_>,
) -> Result<ToolCallDecisionWire, String> {
    const RPC_TIMEOUT: Duration = Duration::from_secs(5);

    let stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("connect {}: {e}", socket_path.display()))?;
    stream
        .set_read_timeout(Some(RPC_TIMEOUT))
        .map_err(|e| format!("set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(RPC_TIMEOUT))
        .map_err(|e| format!("set write timeout: {e}"))?;
    let mut writer = stream
        .try_clone()
        .map_err(|e| format!("clone socket: {e}"))?;
    let mut reader = BufReader::new(stream);

    let req_body = serde_json::json!({
        "id": "ember-proxy-claude-code-hook",
        "method": "evaluate_tool_call",
        "params": params,
    });
    let mut line =
        serde_json::to_string(&req_body).map_err(|e| format!("serialize request: {e}"))?;
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .map_err(|e| format!("write request: {e}"))?;

    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| format!("read response: {e}"))?;
    if response_line.is_empty() {
        return Err("daemon closed socket before responding".to_string());
    }

    let env: serde_json::Value =
        serde_json::from_str(response_line.trim()).map_err(|e| format!("parse response: {e}"))?;
    if let Some(err) = env.get("error").filter(|v| !v.is_null()) {
        let code = err.get("code").and_then(|v| v.as_i64()).unwrap_or(-32000);
        let msg = err
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown daemon error");
        return Err(format!("daemon error {code}: {msg}"));
    }
    let result = env
        .get("result")
        .ok_or_else(|| "response missing 'result' field".to_string())?
        .clone();
    serde_json::from_value::<ToolCallDecisionWire>(result)
        .map_err(|e| format!("decode ToolCallDecision: {e}"))
}

/// implementation-note-42 — block-and-poll RPC helper for the approval round-trip.
///
/// Mirrors [`call_daemon_evaluate`] but invokes `await_approval` against
/// an existing `request_id` minted by an earlier `evaluate_tool_call`
/// dispatch. The read timeout is set to `timeout_secs + 5s` so we always
/// outlast the daemon's poll deadline (the daemon returns `TimedOut`
/// rather than dropping the connection on its own deadline). Connect /
/// write timeouts use the standard 5s budget — same as
/// `call_daemon_evaluate`.
fn call_daemon_await_approval(
    socket_path: &Path,
    request_id: &str,
    timeout_secs: u64,
) -> Result<ApprovalDecisionWire, String> {
    const RPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

    let stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("connect {}: {e}", socket_path.display()))?;
    // Read budget = daemon's poll deadline + 5s slack so we don't time out
    // before the daemon's own TimedOut response can land.
    let read_budget = Duration::from_secs(timeout_secs.saturating_add(5));
    stream
        .set_read_timeout(Some(read_budget))
        .map_err(|e| format!("set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(RPC_CONNECT_TIMEOUT))
        .map_err(|e| format!("set write timeout: {e}"))?;
    let mut writer = stream
        .try_clone()
        .map_err(|e| format!("clone socket: {e}"))?;
    let mut reader = BufReader::new(stream);

    let req_body = serde_json::json!({
        "id": "ember-proxy-claude-code-hook-await",
        "method": "await_approval",
        "params": {
            "request_id": request_id,
            "timeout_secs": timeout_secs,
        },
    });
    let mut line =
        serde_json::to_string(&req_body).map_err(|e| format!("serialize request: {e}"))?;
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .map_err(|e| format!("write request: {e}"))?;

    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| format!("read response: {e}"))?;
    if response_line.is_empty() {
        return Err("daemon closed socket before responding".to_string());
    }

    let env: serde_json::Value =
        serde_json::from_str(response_line.trim()).map_err(|e| format!("parse response: {e}"))?;
    if let Some(err) = env.get("error").filter(|v| !v.is_null()) {
        let code = err.get("code").and_then(|v| v.as_i64()).unwrap_or(-32000);
        let msg = err
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown daemon error");
        return Err(format!("daemon error {code}: {msg}"));
    }
    let result = env
        .get("result")
        .ok_or_else(|| "response missing 'result' field".to_string())?
        .clone();
    let resp = serde_json::from_value::<AwaitApprovalResponseWire>(result)
        .map_err(|e| format!("decode AwaitApprovalResponse: {e}"))?;
    Ok(resp.decision)
}

/// In-process scope evaluator. Unchanged from the pre-implementation-note-76 hook
/// path; retained here so unit tests can exercise the embedded
/// `claude-code-default-v1` template's deny / approval / permit rules
/// without standing up a daemon. Production traffic flows through
/// `evaluate_via_daemon` instead — this lives on as the implementation-note-77
/// real-evaluator scaffold.
#[allow(dead_code)]
fn evaluate_inproc(req: &PreToolUseRequest) -> HookResponse {
    let project_root = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("/"));
    let decision = evaluator::evaluate_tool_call(
        default_template(),
        &project_root,
        &req.tool_name,
        &req.params,
    );

    match decision {
        ScopeDecision::Permit => HookResponse {
            allow: true,
            reason: "ember-proxy: permit (claude-code-default-v1)".to_string(),
        },
        ScopeDecision::Deny { reason, rule } => HookResponse {
            allow: false,
            reason: format!("ember-proxy: deny ({rule}): {reason}"),
        },
        ScopeDecision::RequireApproval { reason, rule } => HookResponse {
            allow: false,
            reason: format!(
                "ember-proxy: approval-required ({rule}): {reason} — block-and-poll await-approval lands in implementation-note-42"
            ),
        },
    }
}

/// Entry point invoked by `main.rs` when `--claude-code-hook` /
/// `hook` is on the CLI.
pub fn run() -> Result<()> {
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf)?;

    // Empty stdin -> emit a structured failure response and exit 1 so
    // Claude Code surfaces a clear reason rather than a parse panic.
    let trimmed = buf.trim();
    if trimmed.is_empty() {
        let resp = HookResponse {
            allow: false,
            reason: "ember-proxy: empty stdin (expected Claude Code PreToolUse JSON)".to_string(),
        };
        println!("{}", serde_json::to_string(&resp)?);
        std::process::exit(1);
    }

    let req: PreToolUseRequest = match serde_json::from_str(trimmed) {
        Ok(r) => r,
        Err(e) => {
            let resp = HookResponse {
                allow: false,
                reason: format!("ember-proxy: invalid PreToolUse JSON: {e}"),
            };
            println!("{}", serde_json::to_string(&resp)?);
            std::process::exit(1);
        }
    };

    let dev_permit = std::env::var("EMBER_PROXY_DEV_PERMIT").is_ok();
    let resp = evaluate(&req, dev_permit);

    // TODO: emit a `tool_call_attempt` Receipt
    // (signed event into the local emberd event log) for every request
    // we evaluate. The Receipt is the demoable artifact even on the
    // permit path.

    println!("{}", serde_json::to_string(&resp)?);
    if !resp.allow {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_tool_use_request_round_trip() {
        let req = PreToolUseRequest {
            tool_name: "Bash".to_string(),
            params: serde_json::json!({"command": "ls -la"}),
            session_id: Some("sess-123".to_string()),
            transcript_path: None,
        };
        let wire = serde_json::to_string(&req).expect("serialize");
        let back: PreToolUseRequest = serde_json::from_str(&wire).expect("deserialize");
        assert_eq!(back.tool_name, "Bash");
        assert_eq!(back.params, serde_json::json!({"command": "ls -la"}));
        assert_eq!(back.session_id.as_deref(), Some("sess-123"));
    }

    #[test]
    fn pre_tool_use_request_accepts_tool_input_alias() {
        // Claude Code's actual wire field is `tool_input`; verify the
        // serde alias so we don't silently lose params.
        let wire = r#"{"tool_name":"Bash","tool_input":{"command":"echo hi"}}"#;
        let req: PreToolUseRequest = serde_json::from_str(wire).expect("parse alias");
        assert_eq!(req.tool_name, "Bash");
        assert_eq!(req.params, serde_json::json!({"command": "echo hi"}));
    }

    #[test]
    fn pre_tool_use_request_minimal_payload() {
        let wire = r#"{"tool_name":"Read"}"#;
        let req: PreToolUseRequest = serde_json::from_str(wire).expect("parse minimal");
        assert_eq!(req.tool_name, "Read");
        assert!(req.params.is_null());
        assert!(req.session_id.is_none());
    }

    #[test]
    fn evaluate_dev_permit_allows() {
        let req = PreToolUseRequest {
            tool_name: "Bash".to_string(),
            params: serde_json::Value::Null,
            session_id: None,
            transcript_path: None,
        };
        let resp = evaluate(&req, true);
        assert!(resp.allow);
        assert!(resp.reason.contains("dev permit"));
    }

    // Scope-rule tests below exercise the in-process evaluator
    // directly — production traffic now goes through
    // `evaluate_via_daemon`, but the embedded scope template is the
    // single source of truth that implementation-note-77 will fold back into the
    // daemon. Pinning the rule semantics here keeps the rule table
    // honest as A-3 lands.

    #[test]
    fn evaluate_bash_cargo_permits() {
        let req = PreToolUseRequest {
            tool_name: "Bash".to_string(),
            params: serde_json::json!({"command": "cargo build"}),
            session_id: None,
            transcript_path: None,
        };
        let resp = evaluate_inproc(&req);
        assert!(resp.allow, "cargo build should permit, got: {resp:?}");
        assert!(resp.reason.contains("claude-code-default-v1"));
    }

    #[test]
    fn evaluate_destructive_bash_denies() {
        let req = PreToolUseRequest {
            tool_name: "Bash".to_string(),
            params: serde_json::json!({"command": "rm -rf /"}),
            session_id: None,
            transcript_path: None,
        };
        let resp = evaluate_inproc(&req);
        assert!(!resp.allow, "rm -rf must deny");
        assert!(
            resp.reason.contains("deny.destructive"),
            "reason should attribute deny rule, got: {}",
            resp.reason
        );
    }

    #[test]
    fn evaluate_git_push_requires_approval() {
        let req = PreToolUseRequest {
            tool_name: "Bash".to_string(),
            params: serde_json::json!({"command": "git push origin main"}),
            session_id: None,
            transcript_path: None,
        };
        let resp = evaluate_inproc(&req);
        // Until implementation-note-42 await-approval lands, RequireApproval ⇒ deny.
        assert!(!resp.allow);
        assert!(resp.reason.contains("approval.git_push"));
        assert!(resp.reason.contains("implementation-note-42"));
    }

    #[test]
    fn evaluate_unknown_tool_requires_approval() {
        let req = PreToolUseRequest {
            tool_name: "mcp__random_thing".to_string(),
            params: serde_json::json!({}),
            session_id: None,
            transcript_path: None,
        };
        let resp = evaluate_inproc(&req);
        assert!(!resp.allow);
        assert!(resp.reason.contains("approval.novel_tool"));
    }

    /// implementation-note-13: when the daemon socket is unreachable and
    /// `explicit_fail_open=true` (the default), the hook permits with a
    /// structured reason. The old fail-closed branch is replaced by a
    /// configurable fail-open + panic-catch surface.
    #[test]
    fn evaluate_via_daemon_unreachable_permits_when_fail_open() {
        let req = PreToolUseRequest {
            tool_name: "Bash".to_string(),
            params: serde_json::json!({"command": "ls"}),
            session_id: None,
            transcript_path: None,
        };
        // Path that demonstrably does not exist on a CI worker.
        let bogus = std::path::PathBuf::from(
            "/tmp/ember-proxy-cohort-a-9-nonexistent-socket-do-not-create.sock",
        );
        // Default config has explicit_fail_open=true, so unreachable daemon
        // should permit.
        let resp = evaluate_via_daemon(&req, &bogus);
        assert!(
            resp.allow,
            "daemon-unreachable with fail_open=true must permit: {resp:?}"
        );
        assert!(
            resp.reason.contains("daemon unreachable"),
            "reason should explain why, got: {}",
            resp.reason
        );
        assert!(
            resp.reason.contains("A-9"),
            "reason should reference A-9, got: {}",
            resp.reason
        );
        assert!(
            resp.reason.contains("permitting"),
            "reason should say permitting, got: {}",
            resp.reason
        );
    }

    /// implementation-note-76: `default_socket_path()` must honor `EMBER_SOCKET_PATH`
    /// (used by `qember.sh` and the integration tests) and fall back
    /// to `~/.ember/run/daemon.sock` otherwise. This locks the
    /// resolution order so a future refactor cannot silently re-route
    /// the hook to the wrong socket.
    #[test]
    fn default_socket_path_honors_env_override() {
        // Snapshot any pre-existing value so we don't pollute the
        // shared process env across tests in this binary. The set/
        // remove dance is safe here — the test crate is single-threaded
        // by default, and `cargo test` does not parallelize within
        // the same crate's test binary at the function-call level
        // unless --test-threads > 1, in which case the harness's
        // ordering guarantees still hold for env access through this
        // single key (no other test reads `EMBER_SOCKET_PATH`).
        let prior = std::env::var("EMBER_SOCKET_PATH").ok();
        // SAFETY: tests run with no untrusted concurrent env writers.
        unsafe {
            std::env::set_var("EMBER_SOCKET_PATH", "/tmp/ember-proxy-test-override.sock");
        }
        let p = default_socket_path();
        assert_eq!(
            p,
            std::path::PathBuf::from("/tmp/ember-proxy-test-override.sock")
        );
        // Restore.
        unsafe {
            match prior {
                Some(v) => std::env::set_var("EMBER_SOCKET_PATH", v),
                None => std::env::remove_var("EMBER_SOCKET_PATH"),
            }
        }
    }

    /// implementation-note-42: when the daemon is unreachable, the await_approval
    /// helper surfaces a structured error that the caller maps to deny.
    /// We exercise the connect-failure path here; mid-poll resolution
    /// requires a real daemon and is covered by the T2 integration test
    /// (TODO implementation-note-78).
    #[test]
    fn call_daemon_await_approval_unreachable_returns_err() {
        let bogus = std::path::PathBuf::from(
            "/tmp/ember-proxy-cohort-a-4-nonexistent-socket-do-not-create.sock",
        );
        let res = call_daemon_await_approval(&bogus, "approval-bogus", 1);
        assert!(
            res.is_err(),
            "unreachable daemon must return Err, got: {res:?}"
        );
        let err = res.unwrap_err();
        assert!(
            err.contains("connect"),
            "err should mention connect, got: {err}"
        );
    }

    /// implementation-note-42: ApprovalDecisionWire round-trips against the daemon's
    /// JSON tag/case convention. Locks the wire shape so a daemon-side
    /// rename of `core_types::ApprovalDecision` cannot silently break the
    /// proxy's decode without the test catching it.
    #[test]
    fn approval_decision_wire_round_trip() {
        let cases = [
            (r#"{"kind":"approved"}"#, ApprovalDecisionWire::Approved),
            (
                r#"{"kind":"denied","reason":"nope"}"#,
                ApprovalDecisionWire::Denied {
                    reason: "nope".to_string(),
                },
            ),
            (r#"{"kind":"timed_out"}"#, ApprovalDecisionWire::TimedOut),
        ];
        for (wire, expected) in cases {
            let parsed: ApprovalDecisionWire =
                serde_json::from_str(wire).unwrap_or_else(|e| panic!("parse {wire}: {e}"));
            assert_eq!(parsed, expected, "wire: {wire}");
        }
    }

    /// implementation-note-42: the `await_approval_request_id` field on
    /// `ToolCallDecisionWire` is optional + backward-compatible — old
    /// daemons that don't surface it must still decode cleanly into a
    /// permit/deny decision.
    #[test]
    fn tool_call_decision_wire_accepts_missing_await_request_id() {
        let wire = r#"{"permit":true,"reason":null,"grant_id":"g-1","emitted_event_id":"42"}"#;
        let parsed: ToolCallDecisionWire = serde_json::from_str(wire).expect("decode legacy shape");
        assert!(parsed.permit);
        assert!(parsed.await_approval_request_id.is_none());
    }

    #[test]
    fn tool_call_decision_wire_decodes_await_request_id() {
        let wire = r#"{"permit":false,"reason":"approval required","await_approval_request_id":"approval-abc"}"#;
        let parsed: ToolCallDecisionWire = serde_json::from_str(wire).expect("decode A-4 shape");
        assert!(!parsed.permit);
        assert_eq!(
            parsed.await_approval_request_id.as_deref(),
            Some("approval-abc")
        );
    }

    #[test]
    fn hook_response_round_trip() {
        let resp = HookResponse {
            allow: false,
            reason: "denied: scope mismatch".to_string(),
        };
        let wire = serde_json::to_string(&resp).expect("serialize");
        let back: HookResponse = serde_json::from_str(&wire).expect("deserialize");
        assert_eq!(back, resp);
    }
}
