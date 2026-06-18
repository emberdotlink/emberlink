//! Shared daemon session RPC helpers for harness launchers.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use crate::launcher::core::{
    AuthorityFallbackMode, AuthorityPosture, SessionRegistration, StandingGrantMode,
};
use crate::launcher::presence;

const PROD_EMBER_DAEMON_PATH: &str = "/usr/local/bin/emberd";
const MANAGED_DAEMON_DRIFT_THRESHOLD: Duration = Duration::from_secs(300);

/// Map a launcher label to its binary-pin manifest caller key, which also
/// selects the daemon's per-session lane: `claude-code` → Door-1 peercred UDS
/// (PR-C); `codex-network-proxy` → loopback-TCP responses-API-proxy (codex
/// HOST lane); `cursor-agent` → loopback HTTPS egress proxy (audit/egress only,
/// no model-auth brokering). `None` → no per-session lane (transitional TCP).
fn attestation_caller_for_label(launcher_label: &str) -> Option<&'static str> {
    if launcher_label.contains("codex") {
        Some("codex-network-proxy")
    } else if launcher_label.contains("cursor") {
        Some("cursor-agent")
    } else if launcher_label.contains("claude") {
        Some("claude-code")
    } else if launcher_label.contains("gemini") {
        // ADR 215 §2 — the gemini Code Assist lane: the daemon stands up the
        // per-session loopback Code Assist proxy and returns `gemini_proxy_url`.
        Some("gemini-code-assist-network-proxy")
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RepoBuildManagedDaemonDrift {
    launcher_path: PathBuf,
    daemon_path: PathBuf,
}

fn sudo_daemon_install_command(launcher_path: &Path) -> String {
    format!("sudo {} daemon install", shell_quote(launcher_path))
}

fn launcher_command(launcher_path: &Path, command_line: &str) -> String {
    match command_line.strip_prefix("ember ") {
        Some(rest) => format!("{} {}", shell_quote(launcher_path), rest),
        None => command_line.to_string(),
    }
}

fn shell_quote(path: &Path) -> String {
    let rendered = path.display().to_string();
    let safe = rendered
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.' | '=' | ':'));
    if safe {
        rendered
    } else {
        format!("'{}'", rendered.replace('\'', "'\\''"))
    }
}

/// Call the daemon `register_session` RPC and return the session bundle.
pub fn register_session_rpc(
    persona: &str,
    socket_path: &Path,
    authority_strict: bool,
    launcher_label: &str,
    rerun_hint: &str,
) -> io::Result<SessionRegistration> {
    register_session_rpc_with_options(
        persona,
        socket_path,
        None,
        None,
        authority_strict,
        None,
        false,
        launcher_label,
        rerun_hint,
    )
}

/// Call the daemon `register_session` RPC with an optional delegation template.
pub fn register_session_rpc_with_workflow(
    persona: &str,
    socket_path: &Path,
    delegation_template: Option<&str>,
    authority_strict: bool,
    attach_runtime_persona_id: Option<&str>,
    launcher_label: &str,
    rerun_hint: &str,
) -> io::Result<SessionRegistration> {
    register_session_rpc_with_workflow_and_workspace_ref(
        persona,
        socket_path,
        delegation_template,
        authority_strict,
        attach_runtime_persona_id,
        None,
        launcher_label,
        rerun_hint,
    )
}

/// Call the daemon `register_session` RPC with launcher workspace coordinates.
// RPC/plumbing signature — structurally many params; refactor would touch callers in other files.
#[allow(clippy::too_many_arguments)]
pub fn register_session_rpc_with_workflow_and_workspace_ref(
    persona: &str,
    socket_path: &Path,
    delegation_template: Option<&str>,
    authority_strict: bool,
    attach_runtime_persona_id: Option<&str>,
    workspace_ref: Option<&str>,
    launcher_label: &str,
    rerun_hint: &str,
) -> io::Result<SessionRegistration> {
    register_session_rpc_with_options(
        persona,
        socket_path,
        delegation_template,
        workspace_ref,
        authority_strict,
        attach_runtime_persona_id,
        false,
        launcher_label,
        rerun_hint,
    )
}

/// Call the daemon `register_session` RPC and request an isolated bridge bundle.
pub fn register_session_rpc_with_isolated_bridge(
    persona: &str,
    socket_path: &Path,
    delegation_template: Option<&str>,
    authority_strict: bool,
    attach_runtime_persona_id: Option<&str>,
    launcher_label: &str,
    rerun_hint: &str,
) -> io::Result<SessionRegistration> {
    register_session_rpc_with_options(
        persona,
        socket_path,
        delegation_template,
        None,
        authority_strict,
        attach_runtime_persona_id,
        true,
        launcher_label,
        rerun_hint,
    )
}

// RPC/plumbing signature — structurally many params; refactor would touch sibling callers in this file.
#[allow(clippy::too_many_arguments)]
fn register_session_rpc_with_options(
    persona: &str,
    socket_path: &Path,
    delegation_template: Option<&str>,
    workspace_ref: Option<&str>,
    authority_strict: bool,
    attach_runtime_persona_id: Option<&str>,
    want_bridge_client_bundle: bool,
    launcher_label: &str,
    rerun_hint: &str,
) -> io::Result<SessionRegistration> {
    let launcher_pid = std::process::id();
    let mut params = json!({
        "persona": persona,
        "launcher_pid": launcher_pid,
        "authority_strict": authority_strict,
    });
    // P22-S2 (ADR 197) — tell the daemon which harness this is so it stands up
    // the right per-session lane: `claude-code` → Door-1 peercred UDS (PR-C);
    // `codex-network-proxy` → loopback-TCP responses-API-proxy (codex HOST
    // lane), whose URL is returned in the response. Also the binary-pin
    // manifest caller key.
    if let Some(attestation_caller) = attestation_caller_for_label(launcher_label)
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert("attestation_caller".to_string(), json!(attestation_caller));
    }
    if let Some(template) = delegation_template
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert("delegation_template".to_string(), json!(template));
    }
    if let Some(runtime_persona_id) = attach_runtime_persona_id
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert(
            "attach_runtime_persona_id".to_string(),
            json!(runtime_persona_id),
        );
    }
    if let Some(workspace_ref) = workspace_ref.filter(|value| !value.trim().is_empty())
        && let Some(obj) = params.as_object_mut()
    {
        let worktree_path = std::env::current_dir()?;
        obj.insert("workspace_ref".to_string(), json!(workspace_ref));
        obj.insert(
            "worktree_path".to_string(),
            json!(worktree_path.to_string_lossy().into_owned()),
        );
    }
    if want_bridge_client_bundle && let Some(obj) = params.as_object_mut() {
        obj.insert("bridge_client_bundle".to_string(), json!(true));
    }
    if let Some(runtime_persona_id) = attach_runtime_persona_id {
        let summary = call_daemon(
            socket_path,
            "describe_runtime_attach_target",
            &json!({ "runtime_persona_id": runtime_persona_id }),
            launcher_label,
            rerun_hint,
        )?;
        eprintln!(
            "{}",
            render_runtime_attach_summary(launcher_label, runtime_persona_id, &summary)
        );
    }
    let result = call_daemon(
        socket_path,
        "register_session",
        &params,
        launcher_label,
        rerun_hint,
    )?;
    let registration = parse_register_session_result(
        &result,
        socket_path,
        launcher_label,
        AuthorityPosture::from_components(authority_strict, delegation_template),
    )?;
    eprintln!(
        "{}",
        render_current_lane_authority_summary(launcher_label, &registration, &result)
    );
    // P10 — strict lanes deny out-of-scope actions instead of prompting, so the
    // operator needs the coverage answer before the agent starts and fails
    // closed mid-work. Best-effort: a daemon error degrades to a pointer and
    // never blocks launch. Jit lanes prompt on demand, so the rollup is skipped
    // there to keep the launch output tight.
    if matches!(
        registration.authority_posture.fallback,
        AuthorityFallbackMode::Strict
    ) {
        eprintln!(
            "{}",
            crate::preflight::strict_lane_coverage_line(
                socket_path,
                launcher_label,
                result["durable_persona_id"].as_str(),
                matches!(
                    registration.authority_posture.delegation,
                    StandingGrantMode::Delegated
                ),
                delegation_template,
            )
        );
    }
    Ok(registration)
}

fn render_runtime_attach_summary(
    launcher_label: &str,
    requested_runtime_persona_id: &str,
    summary: &Value,
) -> String {
    let runtime = summary["runtime_persona_id"]
        .as_str()
        .unwrap_or(requested_runtime_persona_id);
    let durable = summary["durable_persona_id"]
        .as_str()
        .unwrap_or("<unknown>");
    let binding = summary["caller_binding_id"].as_str().unwrap_or("<unknown>");
    let attachments = summary["attachment_count"].as_u64().unwrap_or(0);
    let fallback = summary["authority_posture"]["fallback"]
        .as_str()
        .unwrap_or("unknown");
    let delegation = summary["delegation"]["state"].as_str().unwrap_or("unknown");
    let delegation_detail = match delegation {
        "active" | "expired" => {
            let template = summary["delegation"]["template"].as_str().unwrap_or("-");
            let expires_at = summary["delegation"]["expires_at"].as_str().unwrap_or("-");
            format!("{delegation} ({template}, expires {expires_at})")
        }
        other => other.to_string(),
    };
    let next = if delegation == "expired" {
        "Approve once for one exact-plan prompt, or renew delegation with `--fork --delegated <template>`."
    } else {
        "operator presence will confirm this attach."
    };
    format!(
        "{launcher_label}: attach target summary\n  Runtime Persona: {runtime}\n  Durable Persona: {durable}\n  Caller Binding: {binding}\n  Attachments: {attachments}\n  Authority: fallback={fallback}, delegation={delegation_detail}\n  Next: {next}"
    )
}

fn render_current_lane_authority_summary(
    launcher_label: &str,
    registration: &SessionRegistration,
    result: &Value,
) -> String {
    let runtime = result["runtime_persona_id"]
        .as_str()
        .or(registration.persona_id.as_deref())
        .unwrap_or("<unknown>");
    let durable = result["durable_persona_id"].as_str().unwrap_or("<unknown>");
    let attachment = registration
        .attachment_id
        .as_deref()
        .or_else(|| result["attachment_id"].as_str())
        .unwrap_or("<legacy>");
    let delegation_state = result["delegation"]["state"]
        .as_str()
        .unwrap_or_else(|| registration.authority_posture.delegation.as_str());
    let delegation = render_lane_delegation(result, delegation_state);
    let fallback = match registration.authority_posture.fallback {
        AuthorityFallbackMode::Jit => "out-of-scope actions prompt for Approve once",
        AuthorityFallbackMode::Strict => "out-of-scope actions deny instead of prompting",
    };
    // BKR-4c (ADR 205 §6): `ember delegation revoke` was folded into
    // `ember grant`. Revoke is by grant id (`ember grant list` enumerates the
    // lane's standing grant); there is no session-id revoke form.
    let revoke = "revoke with `ember grant revoke <id>` (see `ember grant list`)".to_string();
    let switch = match (
        registration.authority_posture.fallback,
        registration.authority_posture.delegation,
    ) {
        (AuthorityFallbackMode::Jit, StandingGrantMode::Ambient) => {
            "switch with `--strict` or `--delegated <template>`".to_string()
        }
        (AuthorityFallbackMode::Jit, StandingGrantMode::Delegated) => {
            format!("switch with `--strict`; {revoke}")
        }
        (AuthorityFallbackMode::Strict, StandingGrantMode::Ambient) => {
            "switch by omitting `--strict` or adding `--delegated <template>`".to_string()
        }
        (AuthorityFallbackMode::Strict, StandingGrantMode::Delegated) => {
            format!("switch by omitting `--strict`; {revoke}")
        }
    };

    format!(
        "{launcher_label}: authority summary\n  Acting: runtime {runtime} (durable {durable})\n  Lane: attachment {attachment}; posture={}\n  Delegation: {delegation}\n  Fallback: {fallback}\n  Controls: lock with `ember vault lock`; {switch}",
        registration.authority_posture.describe(),
    )
}

fn render_lane_delegation(result: &Value, state: &str) -> String {
    match state {
        "active" | "expired" => {
            let template = result["delegation"]["template"].as_str().unwrap_or("-");
            let expires_at = result["delegation"]["expires_at"].as_str().unwrap_or("-");
            format!("{state} template `{template}` until {expires_at}")
        }
        "ambient" => "none attached".to_string(),
        other => other.to_string(),
    }
}

/// Call the daemon `close_session` RPC.
///
/// Errors are logged to stderr but do not affect the launcher's exit code.
pub fn close_session_rpc(
    session_id: &str,
    socket_path: &Path,
    launcher_label: &str,
    rerun_hint: &str,
) {
    let params = json!({ "session_id": session_id });
    if let Err(e) = call_daemon(
        socket_path,
        "close_session",
        &params,
        launcher_label,
        rerun_hint,
    ) {
        eprintln!("{launcher_label}: close_session failed: {e}");
    }
}

/// P22-S2 Door-1 leaf-pin (ADR 197 §2). After the launcher spawns the harness
/// child, report that child's pid to the daemon so the per-session UDS accept
/// gate pins against this exact process (`evaluate_primary_gate` leaf-pin arm).
///
/// Best-effort + non-fatal: a failed report leaves the gate **fail-closed** —
/// the harness's API calls over the UDS are rejected until a leaf is pinned,
/// which is the safe direction — so we log loudly rather than abort the launch.
/// Only called on the per-session UDS lane (`anthropic_unix_socket.is_some()`);
/// the transitional TCP lane has no per-session socket to pin.
pub fn report_session_leaf_rpc(
    session_id: &str,
    leaf_pid: u32,
    leaf_report_nonce: &str,
    socket_path: &Path,
    launcher_label: &str,
) {
    let params = json!({
        "session_id": session_id,
        "leaf_pid": leaf_pid,
        "nonce": leaf_report_nonce,
    });
    if let Err(e) = call_daemon(
        socket_path,
        "report_session_leaf",
        &params,
        launcher_label,
        "",
    ) {
        eprintln!(
            "{launcher_label}: report_session_leaf failed — the per-session UDS gate will \
             fail-closed (reject the harness) until a leaf pid is pinned: {e}"
        );
    }
}

/// Run `f` and always attempt `close_session` afterward, even when `f`
/// returns an error after a successful `register_session`.
pub fn with_session_close<T, F>(
    session_id: &str,
    socket_path: &Path,
    launcher_label: &str,
    rerun_hint: &str,
    f: F,
) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T>,
{
    let result = f();
    close_session_rpc(session_id, socket_path, launcher_label, rerun_hint);
    result
}

pub(crate) fn parse_register_session_result(
    result: &Value,
    socket_path: &Path,
    launcher_label: &str,
    compat_posture: AuthorityPosture,
) -> io::Result<SessionRegistration> {
    if let (Some(tab_url), Some(prompt_id)) = (
        result["presence_required"]["tab_url"].as_str(),
        result["presence_required"]["prompt_id"].as_str(),
    ) {
        return Err(presence::session_open_presence_unavailable(
            socket_path,
            prompt_id,
            tab_url,
        ));
    }

    let session_id = result["session_id"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "daemon: missing session_id"))?
        .to_string();
    let grant_id = result["grant_id"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "daemon: missing grant_id"))?
        .to_string();
    let proxy_url = match result["proxy_url"].as_str() {
        Some(url) => url.to_string(),
        None => {
            eprintln!(
                "{launcher_label}: WARNING — daemon did not return proxy_url in register_session response; \
                 falling back to http://127.0.0.1:8484 which is likely not bound."
            );
            "http://127.0.0.1:8484".to_string()
        }
    };
    let persona_id = result["persona_id"].as_str().map(|s| s.to_string());
    let anthropic_base_url = result["anthropic_base_url"].as_str().map(|s| s.to_string());
    let anthropic_custom_headers = result["anthropic_custom_headers"]
        .as_str()
        .map(|s| s.to_string());
    let git_proxy_url = result["git_proxy_url"].as_str().map(|s| s.to_string());
    let cursor_egress_proxy_url = result["cursor_egress_proxy_url"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let codex_responses_proxy_url = result["codex_responses_proxy_url"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    // ADR 215 §2 — per-session loopback Code Assist proxy base URL (gemini lane).
    let gemini_proxy_url = result["gemini_proxy_url"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let ssh_auth_sock = result["ssh_auth_sock"].as_str().map(|s| s.to_string());
    let delegation_id = result["delegation_id"].as_str().map(|s| s.to_string());
    let delegation_template = result["delegation_template"]
        .as_str()
        .map(|s| s.to_string());
    let authority_posture = parse_authority_posture(result, compat_posture)?;
    let attachment_id = result["attachment_id"].as_str().map(|s| s.to_string());
    let attachment_endpoint_token = result["attachment_endpoint_token"]
        .as_str()
        .map(|s| s.to_string());
    // P22-S2 (ADR 197 §2): per-session UDS path for the Claude lane.
    let anthropic_unix_socket = result["anthropic_unix_socket"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    // P22-S2 Door-1 leaf-pin (FINDING-1): launcher-only nonce echoed back on
    // `report_session_leaf`.
    let leaf_report_nonce = result["leaf_report_nonce"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let bridge_client_bundle = result["bridge_client_bundle"]
        .as_object()
        .map(
            |bundle| -> io::Result<crate::launcher::core::BridgeClientBundle> {
                Ok(crate::launcher::core::BridgeClientBundle {
                    port: bundle
                        .get("port")
                        .and_then(|value| value.as_u64())
                        .and_then(|value| u16::try_from(value).ok())
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "daemon: bridge_client_bundle missing usable port",
                            )
                        })?,
                    client_cert_pem: bundle
                        .get("client_cert_pem")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "daemon: bridge_client_bundle missing client_cert_pem",
                            )
                        })?
                        .to_string(),
                    client_key_pem: bundle
                        .get("client_key_pem")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "daemon: bridge_client_bundle missing client_key_pem",
                            )
                        })?
                        .to_string(),
                    ca_cert_pem: bundle
                        .get("ca_cert_pem")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "daemon: bridge_client_bundle missing ca_cert_pem",
                            )
                        })?
                        .to_string(),
                })
            },
        )
        .transpose()?;

    Ok(SessionRegistration {
        session_id,
        grant_id,
        proxy_url,
        persona_id,
        anthropic_base_url,
        anthropic_custom_headers,
        git_proxy_url,
        cursor_egress_proxy_url,
        codex_responses_proxy_url,
        gemini_proxy_url,
        ssh_auth_sock,
        delegation_id,
        delegation_template,
        authority_posture,
        bridge_client_bundle,
        attachment_id,
        attachment_endpoint_token,
        anthropic_unix_socket,
        leaf_report_nonce,
    })
}

fn parse_authority_posture(
    result: &Value,
    compat_posture: AuthorityPosture,
) -> io::Result<AuthorityPosture> {
    let fallback_raw = result["authority_posture"]["fallback"].as_str();
    let delegation_raw = result["authority_posture"]["delegation"].as_str();
    match (fallback_raw, delegation_raw) {
        (None, None) => Ok(compat_posture),
        (Some(fallback), Some(delegation)) => {
            let fallback = AuthorityFallbackMode::parse(fallback).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("daemon: invalid authority_posture.fallback={fallback:?}"),
                )
            })?;
            let delegation = StandingGrantMode::parse(delegation).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("daemon: invalid authority_posture.delegation={delegation:?}"),
                )
            })?;
            Ok(AuthorityPosture {
                fallback,
                delegation,
            })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "daemon: authority_posture must include both fallback and delegation",
        )),
    }
}

pub(crate) fn call_daemon(
    socket_path: &Path,
    method: &str,
    params: &Value,
    launcher_label: &str,
    rerun_hint: &str,
) -> io::Result<Value> {
    match crate::call_daemon_rpc(socket_path, method, params) {
        Ok(result) => Ok(result),
        Err(crate::DaemonRpcError::Unavailable(e)) => Err(io::Error::new(
            e.kind(),
            format!(
                "{launcher_label}: daemon not running (socket: {}): {e}; \
                 run `ember status` or repair/install with `sudo ember daemon install`",
                socket_path.display()
            ),
        )),
        Err(crate::DaemonRpcError::PermissionDenied(e)) => Err(io::Error::new(
            e.kind(),
            crate::format_daemon_socket_io_error(&e),
        )),
        Err(crate::DaemonRpcError::Io(e)) => Err(io::Error::new(
            e.kind(),
            crate::format_daemon_socket_io_error(&e),
        )),
        Err(crate::DaemonRpcError::Protocol(e)) => {
            Err(io::Error::new(io::ErrorKind::InvalidData, e))
        }
        Err(crate::DaemonRpcError::Rpc { code, message }) => {
            if let Some(guidance) =
                launcher_guidance_for_rpc(socket_path, method, code, &message, rerun_hint)
            {
                return Err(io::Error::other(guidance));
            }
            Err(io::Error::other(format!("daemon error: {message}")))
        }
    }
}

pub(crate) fn launcher_guidance_for_rpc(
    socket_path: &Path,
    method: &str,
    code: i32,
    message: &str,
    rerun_hint: &str,
) -> Option<String> {
    let drift = detect_repo_build_managed_daemon_drift();
    launcher_guidance_for_rpc_with_drift(
        socket_path,
        method,
        code,
        message,
        rerun_hint,
        drift.as_ref(),
    )
}

fn launcher_guidance_for_rpc_with_drift(
    socket_path: &Path,
    method: &str,
    code: i32,
    message: &str,
    rerun_hint: &str,
    repo_build_drift: Option<&RepoBuildManagedDaemonDrift>,
) -> Option<String> {
    let is_locked = code == -32030
        && (message.contains("session is locked")
            || message.contains("live vault is locked")
            || message.contains("vault unavailable")
            || message.contains("session auto-locked"));
    let authority_error_reason = authority_error_reason(message);
    let register_session_authority_blocked = method == "register_session"
        && code == -32001
        && authority_error_reason.as_deref().is_some_and(|reason| {
            matches!(
                reason,
                "locked"
                    | "missing"
                    | "expired"
                    | "uid-mismatch"
                    | "sig-invalid"
                    | "scope-mismatch"
                    | "identity-missing"
            )
        });
    let is_no_active_grant = code == -32004
        && (message.contains("no active grant for persona")
            || message.contains("no active runtime-delegable grant for persona")
            || (message.contains("no active ")
                && message.contains(" runtime-delegable grant for persona")));
    let is_quarantined =
        message.contains("daemon quarantined") && message.contains("write-class method");

    if method == "register_session" && (is_locked || register_session_authority_blocked) {
        if let Some(drift) = repo_build_drift {
            let install_cmd = sudo_daemon_install_command(&drift.launcher_path);
            let rerun_cmd = launcher_command(&drift.launcher_path, rerun_hint);
            return Some(format!(
                "this session needs operator presence on the daemon-managed vault lane. \
                 The repo-built launcher at {} is newer than the managed daemon at {} on this host, \
                 so the live service may still be missing newer launch-time presence behavior. \
                 Refresh the managed daemon with `{install_cmd}`, then re-run `{rerun_cmd}` from \
                 an interactive signed host launcher.",
                drift.launcher_path.display(),
                drift.daemon_path.display(),
            ));
        }
        if authority_error_reason.as_deref() == Some("missing") {
            return Some(format!(
                "this session needs a session-runtime presence credential. The host launcher \
                 normally mints and caches that credential during `register_session` after \
                 the ADR 206 §4 Touch ID window opens; reaching this error means that handshake \
                 did not complete. Run `ember status` and `ember doctor`, then re-run \
                 `{rerun_hint}` from an interactive signed host launcher."
            ));
        }
        return Some(format!(
            "this session needs authority custody unlocked (ADR 206 §4 presence-as-decryption). \
             The host launcher normally performs this Touch ID unlock implicitly; reaching this \
             error means the tap could not be completed here (non-interactive shell, unsigned \
             launcher, no Secure Enclave, declined prompt, or stale daemon). Re-run \
             `{rerun_hint}` from an interactive signed host launcher. If you need to repair the \
             custody window directly, run `ember vault se-unlock` once and retry."
        ));
    }

    if method == "register_session" && is_quarantined {
        return Some(format!(
            "this session is blocked because the daemon quarantined write-class methods after an audit-chain integrity failure. Run `ember doctor` to diagnose the repair path, then repair the daemon before re-running `{rerun_hint}`."
        ));
    }

    if method == "register_session" && is_no_active_grant {
        return Some(render_no_active_grant_guidance(
            message,
            rerun_hint,
            daemon_vault_appears_locked(socket_path),
        ));
    }

    None
}

fn authority_error_reason(message: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(message)
        .ok()
        .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(str::to_string))
}

fn daemon_vault_appears_locked(socket_path: &Path) -> bool {
    let Ok(status) = crate::call_daemon_rpc(socket_path, "status", &json!({})) else {
        return false;
    };
    let Some(session) = status.get("vault").and_then(|v| v.get("session")) else {
        return false;
    };
    let unlocked = session
        .get("unlocked")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let live_vault_attached = session
        .get("live_vault_attached")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let posture = session
        .get("posture")
        .and_then(Value::as_str)
        .unwrap_or_default();
    !unlocked
        || !live_vault_attached
        || matches!(
            posture,
            "hard-locked" | "soft-locked" | "interactive-locked"
        )
}

fn render_no_active_grant_guidance(message: &str, rerun_hint: &str, vault_locked: bool) -> String {
    let init_hint = no_active_grant_init_hint(message, rerun_hint);
    if vault_locked {
        return format!(
            "the daemon vault is locked, so launcher grants cannot be read or refreshed yet. Run `ember vault unlock`, then re-run `{rerun_hint}`. If the grant is still missing after unlock, run `{init_hint}`."
        );
    }
    format!(
        "no active brokered runtime grant is attached to this persona. This is expected after recovery, reinstall, grant expiry, or launcher-exit revocation. Run `{init_hint}` to mint or refresh it, then re-run `{rerun_hint}`."
    )
}

fn no_active_grant_init_hint(message: &str, rerun_hint: &str) -> &'static str {
    let rerun_args = || rerun_hint.split_whitespace();
    if message.contains("cursor-default") || rerun_args().any(|arg| arg == "cursor") {
        "ember init --for cursor"
    } else if message.contains("codex-default") || rerun_args().any(|arg| arg == "codex") {
        "ember init --for codex"
    } else {
        "ember init --for claude"
    }
}

fn detect_repo_build_managed_daemon_drift() -> Option<RepoBuildManagedDaemonDrift> {
    let launcher_path = std::env::current_exe().ok()?;
    detect_repo_build_managed_daemon_drift_at(
        &launcher_path,
        Path::new(PROD_EMBER_DAEMON_PATH),
        MANAGED_DAEMON_DRIFT_THRESHOLD,
    )
}

fn detect_repo_build_managed_daemon_drift_at(
    launcher_path: &Path,
    daemon_path: &Path,
    drift_threshold: Duration,
) -> Option<RepoBuildManagedDaemonDrift> {
    if launcher_path.file_name().is_none_or(|name| name != "ember")
        || !launcher_path
            .components()
            .any(|component| component.as_os_str() == "target")
    {
        return None;
    }
    let launcher_mtime = fs::metadata(launcher_path).ok()?.modified().ok()?;
    let daemon_mtime = fs::metadata(daemon_path).ok()?.modified().ok()?;
    let drift = launcher_mtime.duration_since(daemon_mtime).ok()?;
    (drift > drift_threshold).then(|| RepoBuildManagedDaemonDrift {
        launcher_path: launcher_path.to_path_buf(),
        daemon_path: daemon_path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc;
    use std::time::Duration;

    use serde_json::json;

    use crate::launcher::core::{
        AuthorityFallbackMode, AuthorityPosture, SessionRegistration, StandingGrantMode,
    };

    use super::{
        RepoBuildManagedDaemonDrift, attestation_caller_for_label, launcher_guidance_for_rpc,
        launcher_guidance_for_rpc_with_drift, parse_register_session_result,
        register_session_rpc_with_workflow_and_workspace_ref,
        render_current_lane_authority_summary, render_no_active_grant_guidance,
        render_runtime_attach_summary,
    };

    #[test]
    fn label_maps_to_attestation_caller_per_harness() {
        assert_eq!(
            attestation_caller_for_label("ember codex"),
            Some("codex-network-proxy")
        );
        // PR-C: claude → claude-code (selects the Door-1 peercred UDS lane).
        assert_eq!(
            attestation_caller_for_label("ember claude"),
            Some("claude-code")
        );
        assert_eq!(
            attestation_caller_for_label("ember cursor"),
            Some("cursor-agent")
        );
        // Non-harness labels → no per-session lane (transitional TCP).
        assert_eq!(attestation_caller_for_label("ember up"), None);
    }

    #[test]
    fn parse_extracts_codex_responses_proxy_url() {
        let result = json!({
            "session_id": "sess_codex",
            "grant_id": "grant_codex",
            "proxy_url": "http://127.0.0.1:9000",
            "codex_responses_proxy_url": "http://127.0.0.1:54321/v1",
        });
        let reg = parse_register_session_result(
            &result,
            Path::new("/tmp/ignored.sock"),
            "ember codex",
            AuthorityPosture::from_components(false, None),
        )
        .expect("parse");
        assert_eq!(
            reg.codex_responses_proxy_url.as_deref(),
            Some("http://127.0.0.1:54321/v1")
        );
    }

    #[test]
    fn parse_extracts_gemini_proxy_url() {
        // ADR 215 §2 — the gemini Code Assist lane returns a BARE base URL (no
        // `/v1`); the launcher forwards it as `CODE_ASSIST_ENDPOINT`.
        let result = json!({
            "session_id": "sess_gemini",
            "grant_id": "grant_gemini",
            "proxy_url": "http://127.0.0.1:9000",
            "gemini_proxy_url": "http://127.0.0.1:54322",
        });
        let reg = parse_register_session_result(
            &result,
            Path::new("/tmp/ignored.sock"),
            "ember gemini",
            AuthorityPosture::from_components(false, None),
        )
        .expect("parse");
        assert_eq!(reg.gemini_proxy_url.as_deref(), Some("http://127.0.0.1:54322"));
        // The codex field stays distinct and absent on a gemini registration.
        assert!(reg.codex_responses_proxy_url.is_none());
    }

    #[test]
    fn parse_extracts_cursor_egress_proxy_url() {
        let result = json!({
            "session_id": "sess_cursor",
            "grant_id": "grant_cursor",
            "proxy_url": "http://127.0.0.1:9000",
            "cursor_egress_proxy_url": "http://127.0.0.1:61234",
        });
        let reg = parse_register_session_result(
            &result,
            Path::new("/tmp/ignored.sock"),
            "ember cursor",
            AuthorityPosture::from_components(false, None),
        )
        .expect("parse");
        assert_eq!(
            reg.cursor_egress_proxy_url.as_deref(),
            Some("http://127.0.0.1:61234")
        );
    }

    #[test]
    fn parse_codex_url_absent_is_none() {
        let result = json!({
            "session_id": "sess_x",
            "grant_id": "grant_x",
            "proxy_url": "http://127.0.0.1:9000",
        });
        let reg = parse_register_session_result(
            &result,
            Path::new("/tmp/ignored.sock"),
            "ember claude",
            AuthorityPosture::from_components(false, None),
        )
        .expect("parse");
        assert!(reg.codex_responses_proxy_url.is_none());
        assert!(reg.cursor_egress_proxy_url.is_none());
        assert!(reg.gemini_proxy_url.is_none());
    }

    struct CwdGuard {
        previous: PathBuf,
    }

    impl CwdGuard {
        fn change_to(path: &Path) -> Self {
            let previous = std::env::current_dir().unwrap_or_else(|_| {
                let fallback = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
                std::env::set_current_dir(&fallback).expect("restore test cwd fallback");
                fallback
            });
            std::env::set_current_dir(path).expect("set current dir");
            Self { previous }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.previous);
        }
    }

    fn wait_for_socket(socket_path: &Path) {
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !socket_path.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            socket_path.exists(),
            "mock daemon socket never appeared at {}",
            socket_path.display()
        );
    }

    fn spawn_register_session_capture_daemon(
        socket_path: PathBuf,
        tx: mpsc::Sender<serde_json::Value>,
    ) {
        std::thread::spawn(move || {
            let listener = UnixListener::bind(&socket_path).expect("bind mock socket");
            let (stream, _) = listener.accept().expect("accept register_session");
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
            let mut writer = stream;
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read register_session request");
            let req: serde_json::Value =
                serde_json::from_str(line.trim()).expect("register_session json");
            tx.send(req.clone()).expect("send captured request");
            let resp = json!({
                "id": req["id"],
                "result": {
                    "session_id": "sess_workspace_binding",
                    "grant_id": "grant_workspace_binding",
                    "proxy_url": "http://127.0.0.1:18484",
                    "persona_id": "persona_workspace_binding",
                    "attachment_id": "att_workspace_binding",
                    "attachment_endpoint_token": "ep_workspace_binding",
                }
            });
            let mut resp_str = serde_json::to_string(&resp).expect("response json");
            resp_str.push('\n');
            writer
                .write_all(resp_str.as_bytes())
                .expect("write register_session response");
        });
    }

    #[test]
    fn launcher_guidance_maps_no_active_grant_for_claude_register_session() {
        let guidance = launcher_guidance_for_rpc(
            Path::new("/tmp/daemon.sock"),
            "register_session",
            -32004,
            "no active grant for persona 'claude-code-default'",
            "ember claude --host",
        )
        .expect("expected guidance");
        assert!(guidance.contains("expected after recovery"));
        assert!(guidance.contains("ember init --for claude"));
        assert!(guidance.contains("ember claude --host"));
    }

    #[test]
    fn launcher_guidance_maps_no_active_grant_for_codex_register_session() {
        let guidance = launcher_guidance_for_rpc(
            Path::new("/tmp/daemon.sock"),
            "register_session",
            -32004,
            "no active grant for persona 'codex-default'",
            "ember codex --isolated",
        )
        .expect("expected guidance");
        assert!(guidance.contains("expected after recovery"));
        assert!(guidance.contains("ember init --for codex"));
        assert!(guidance.contains("ember codex --isolated"));
    }

    #[test]
    fn launcher_guidance_maps_no_active_grant_for_cursor_register_session() {
        let guidance = launcher_guidance_for_rpc(
            Path::new("/tmp/daemon.sock"),
            "register_session",
            -32004,
            "no active grant for persona 'cursor-default'",
            "ember cursor --host",
        )
        .expect("expected guidance");
        assert!(guidance.contains("expected after recovery"));
        assert!(guidance.contains("ember init --for cursor"));
        assert!(guidance.contains("ember cursor --host"));
        assert!(!guidance.contains("ember init --for claude"));
    }

    #[test]
    fn launcher_guidance_maps_openai_runtime_delegable_grant_for_codex_register_session() {
        let guidance = launcher_guidance_for_rpc(
            Path::new("daemon.sock"),
            "register_session",
            -32004,
            "no active OpenAI runtime-delegable grant for persona 'codex-default'; this launcher session requires brokered model auth via openai/plan/chatgpt-oauth/<account>/<subject> and cannot fall back to legacy codex-default-v1 authority. Rerun `ember init --for codex` after storing the missing vault credential",
            "ember codex --host",
        )
        .expect("expected guidance");
        assert!(guidance.contains("expected after recovery"));
        assert!(guidance.contains("ember init --for codex"));
        assert!(guidance.contains("ember codex --host"));
        assert!(!guidance.starts_with("daemon error:"));
    }

    #[test]
    fn launcher_guidance_maps_anthropic_runtime_delegable_grant_for_claude_register_session() {
        let guidance = launcher_guidance_for_rpc(
            Path::new("daemon.sock"),
            "register_session",
            -32004,
            "no active Anthropic runtime-delegable grant for persona 'claude-code-default'; this launcher session requires brokered model auth via anthropic/plan/claude-oauth/* or anthropic/api/key/* and cannot fall back to legacy claude-code-default-v1 authority. Rerun `ember init --for claude` after storing the missing vault credential",
            "ember claude --host",
        )
        .expect("expected guidance");
        assert!(guidance.contains("expected after recovery"));
        assert!(guidance.contains("ember init --for claude"));
        assert!(guidance.contains("ember claude --host"));
        assert!(!guidance.starts_with("daemon error:"));
    }

    #[test]
    fn launcher_guidance_names_implicit_se_unlock_for_locked_register_session() {
        let guidance = launcher_guidance_for_rpc(
            Path::new("/tmp/daemon.sock"),
            "register_session",
            -32030,
            "register_session denied: session is locked; same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts",
            "ember claude --host",
        )
        .expect("expected guidance");
        assert!(guidance.contains("normally performs this Touch ID unlock implicitly"));
        assert!(guidance.contains("ember vault se-unlock"));
        assert!(!guidance.contains("ember vault unlock"));
        assert!(guidance.contains("ember claude --host"));
    }

    #[test]
    fn launcher_guidance_maps_live_vault_locked_register_session() {
        let guidance = launcher_guidance_for_rpc(
            Path::new("/tmp/daemon.sock"),
            "register_session",
            -32030,
            "register_session: live vault is locked; same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts",
            "ember claude --host",
        )
        .expect("expected guidance");
        assert!(guidance.contains("ADR 206 §4"));
        assert!(guidance.contains("interactive signed host launcher"));
        assert!(!guidance.contains("ember vault unlock"));
        assert!(guidance.contains("ember claude --host"));
    }

    #[test]
    fn launcher_guidance_maps_missing_runtime_presence_for_register_session() {
        let guidance = launcher_guidance_for_rpc(
            Path::new("/tmp/daemon.sock"),
            "register_session",
            -32001,
            r#"{"error":"authority_class_not_met","reason":"missing"}"#,
            "ember claude --host",
        )
        .expect("expected guidance");
        assert!(guidance.contains("session-runtime presence credential"));
        assert!(guidance.contains("register_session"));
        assert!(guidance.contains("ember status"));
        assert!(!guidance.contains("ember vault unlock"));
    }

    #[test]
    fn launcher_guidance_names_repo_build_vs_managed_daemon_drift() {
        let drift = RepoBuildManagedDaemonDrift {
            launcher_path: PathBuf::from("target/debug/ember"),
            daemon_path: PathBuf::from("/usr/local/bin/emberd"),
        };
        let guidance = launcher_guidance_for_rpc_with_drift(
            Path::new("/tmp/daemon.sock"),
            "register_session",
            -32030,
            "register_session: live vault is locked; same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts",
            "ember codex --host",
            Some(&drift),
        )
        .expect("expected guidance");
        assert!(guidance.contains("repo-built launcher"));
        assert!(guidance.contains("/usr/local/bin/emberd"));
        assert!(guidance.contains("sudo target/debug/ember daemon install"));
        assert!(guidance.contains("target/debug/ember codex --host"));
        assert!(!guidance.contains("vault unlock"));
    }

    #[test]
    fn render_no_active_grant_guidance_prefers_unlock_when_vault_is_locked() {
        let guidance = render_no_active_grant_guidance(
            "no active grant for persona 'codex-default'",
            "ember codex --host",
            true,
        );
        assert!(guidance.contains("ember vault unlock"));
        assert!(guidance.contains("ember codex --host"));
        assert!(guidance.contains("ember init --for codex"));
    }

    #[test]
    fn attach_summary_names_expired_delegation_recovery_choices() {
        let summary = json!({
            "runtime_persona_id": "runtime-1",
            "durable_persona_id": "persona-1",
            "caller_binding_id": "binding-1",
            "attachment_count": 2,
            "authority_posture": {
                "fallback": "jit",
                "delegation": "delegated",
            },
            "delegation": {
                "state": "expired",
                "template": "release-proof",
                "expires_at": "2026-05-27T00:00:00Z",
            },
        });

        let rendered = render_runtime_attach_summary("ember codex", "runtime-1", &summary);

        assert!(rendered.contains("delegation=expired"));
        assert!(rendered.contains("Approve once"));
        assert!(rendered.contains("renew delegation"));
        assert!(rendered.contains("--fork --delegated <template>"));
    }

    #[test]
    fn current_lane_summary_renders_posture_delegation_and_controls() {
        let registration = SessionRegistration {
            session_id: "sess-one".to_string(),
            grant_id: "grant-one".to_string(),
            proxy_url: "http://127.0.0.1:8484".to_string(),
            persona_id: Some("runtime-one".to_string()),
            anthropic_base_url: None,
            anthropic_custom_headers: None,
            git_proxy_url: None,
            cursor_egress_proxy_url: None,
            codex_responses_proxy_url: None,
            gemini_proxy_url: None,
            ssh_auth_sock: None,
            delegation_id: Some("del-one".to_string()),
            delegation_template: Some("release-proof".to_string()),
            authority_posture: AuthorityPosture {
                fallback: AuthorityFallbackMode::Strict,
                delegation: StandingGrantMode::Delegated,
            },
            bridge_client_bundle: None,
            attachment_id: Some("att-one".to_string()),
            attachment_endpoint_token: Some("ep-one".to_string()),
            anthropic_unix_socket: None,
            leaf_report_nonce: None,
        };
        let raw = json!({
            "runtime_persona_id": "runtime-one",
            "durable_persona_id": "durable-one",
            "attachment_id": "att-one",
            "delegation": {
                "state": "active",
                "template": "release-proof",
                "expires_at": "2026-05-27T05:00:00Z",
            },
        });

        let rendered = render_current_lane_authority_summary("ember codex", &registration, &raw);

        assert!(rendered.contains("runtime runtime-one"));
        assert!(rendered.contains("durable durable-one"));
        assert!(rendered.contains("posture=strict+delegated"));
        assert!(rendered.contains("active template `release-proof`"));
        assert!(rendered.contains("out-of-scope actions deny"));
        assert!(rendered.contains("ember grant revoke <id>"));
        assert!(!rendered.contains("ember delegation revoke"));
        assert!(rendered.contains("ember vault lock"));
    }

    #[test]
    fn register_session_rpc_sends_workspace_binding_from_current_worktree() {
        let _guard = crate::PROCESS_ENV_CWD_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        let worktree = tmp.path().join("repo/.ember/worktrees/oscar");
        std::fs::create_dir_all(&worktree).expect("create worktree");
        std::fs::write(
            worktree.join(".git"),
            "gitdir: ../../../.git/worktrees/oscar\n",
        )
        .expect("write gitfile");
        let socket_path = tmp.path().join("daemon.sock");
        let (tx, rx) = mpsc::channel();
        spawn_register_session_capture_daemon(socket_path.clone(), tx);
        wait_for_socket(&socket_path);
        let _cwd = CwdGuard::change_to(&worktree);

        let registration = register_session_rpc_with_workflow_and_workspace_ref(
            "claude-code-test",
            &socket_path,
            Some("read-only"),
            false,
            None,
            Some("managed_worktree:rt-oscar"),
            "ember claude",
            "ember claude --host --worktree oscar",
        )
        .expect("register_session");

        assert_eq!(registration.session_id, "sess_workspace_binding");
        let req = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("captured register_session request");
        assert_eq!(req["method"], "register_session");
        assert_eq!(req["params"]["persona"], "claude-code-test");
        assert_eq!(req["params"]["delegation_template"], "read-only");
        assert_eq!(req["params"]["workspace_ref"], "managed_worktree:rt-oscar");
        assert_eq!(
            PathBuf::from(
                req["params"]["worktree_path"]
                    .as_str()
                    .expect("worktree_path")
            ),
            std::env::current_dir().expect("current worktree")
        );
    }
}
