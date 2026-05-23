//! Shared daemon session RPC helpers for harness launchers.

use std::io;
use std::path::Path;

use serde_json::{Value, json};

use crate::launcher::core::SessionRegistration;
use crate::launcher::presence;

/// Call the daemon `register_session` RPC and return the session bundle.
pub fn register_session_rpc(
    persona: &str,
    socket_path: &Path,
    launcher_label: &str,
    rerun_hint: &str,
) -> io::Result<SessionRegistration> {
    register_session_rpc_with_workflow(persona, socket_path, None, launcher_label, rerun_hint)
}

/// Call the daemon `register_session` RPC with an optional workflow template.
pub fn register_session_rpc_with_workflow(
    persona: &str,
    socket_path: &Path,
    workflow_template: Option<&str>,
    launcher_label: &str,
    rerun_hint: &str,
) -> io::Result<SessionRegistration> {
    let launcher_pid = std::process::id();
    let mut params = json!({
        "persona": persona,
        "launcher_pid": launcher_pid,
    });
    if let Some(template) = workflow_template
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert("workflow_template".to_string(), json!(template));
    }
    let result = call_daemon(
        socket_path,
        "register_session",
        &params,
        launcher_label,
        rerun_hint,
    )?;
    parse_register_session_result(&result, socket_path, launcher_label)
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
    let presence_token_json = result
        .get("presence_token")
        .map(|token| {
            serde_json::to_string(token).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("daemon: invalid presence_token payload: {e}"),
                )
            })
        })
        .transpose()?;
    let anthropic_base_url = result["anthropic_base_url"].as_str().map(|s| s.to_string());
    let anthropic_custom_headers = result["anthropic_custom_headers"]
        .as_str()
        .map(|s| s.to_string());
    let git_proxy_url = result["git_proxy_url"].as_str().map(|s| s.to_string());
    let ssh_auth_sock = result["ssh_auth_sock"].as_str().map(|s| s.to_string());
    let workflow_id = result["workflow_id"].as_str().map(|s| s.to_string());
    let workflow_template = result["workflow_template"].as_str().map(|s| s.to_string());

    Ok(SessionRegistration {
        session_id,
        grant_id,
        proxy_url,
        presence_token_json,
        anthropic_base_url,
        anthropic_custom_headers,
        git_proxy_url,
        ssh_auth_sock,
        workflow_id,
        workflow_template,
    })
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
        Err(crate::DaemonRpcError::Io(e)) => Err(io::Error::new(
            e.kind(),
            crate::format_daemon_socket_io_error(&e),
        )),
        Err(crate::DaemonRpcError::Protocol(e)) => {
            Err(io::Error::new(io::ErrorKind::InvalidData, e))
        }
        Err(crate::DaemonRpcError::Rpc { code, message }) => {
            if let Some(guidance) = launcher_guidance_for_rpc(method, code, &message, rerun_hint) {
                return Err(io::Error::other(guidance));
            }
            Err(io::Error::other(format!("daemon error: {message}")))
        }
    }
}

pub(crate) fn launcher_guidance_for_rpc(
    method: &str,
    code: i32,
    message: &str,
    rerun_hint: &str,
) -> Option<String> {
    let is_locked = code == -32030
        && (message.contains("session is locked")
            || message.contains("vault unavailable")
            || message.contains("session auto-locked"));
    let is_no_active_grant = code == -32004 && message.contains("no active grant for persona");
    let is_quarantined =
        message.contains("daemon quarantined") && message.contains("write-class method");

    if method == "register_session"
        && (is_locked || (code == -32001 && message.contains("authority_class_not_met")))
    {
        return Some(format!(
            "this session needs operator presence on the daemon-managed vault lane. \
             Use the managed separate-uid biometric unlock flow when available. If you are on a \
             dev probe lane, restart the daemon with `EMBER_VAULT_PASSPHRASE`; same-daemon \
             operator-uid reopen is intentionally disabled. Then re-run `{rerun_hint}`."
        ));
    }

    if method == "register_session" && is_quarantined {
        return Some(format!(
            "this session is blocked because the daemon quarantined write-class methods after an audit-chain integrity failure. Run `ember audit verify` to inspect the chain, then repair the daemon before re-running `{rerun_hint}`."
        ));
    }

    if method == "register_session" && is_no_active_grant {
        let init_hint = if rerun_hint.contains("codex") {
            "ember init --for codex"
        } else {
            "ember init --for claude"
        };
        return Some(format!(
            "no active grant is attached to this persona. Run `{init_hint}` to mint or refresh a launcher grant, approve or unlock if prompted, then re-run `{rerun_hint}`."
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::launcher_guidance_for_rpc;

    #[test]
    fn launcher_guidance_maps_no_active_grant_for_claude_register_session() {
        let guidance = launcher_guidance_for_rpc(
            "register_session",
            -32004,
            "no active grant for persona 'claude-code-default'",
            "ember claude --host",
        )
        .expect("expected guidance");
        assert!(guidance.contains("ember init --for claude"));
        assert!(guidance.contains("ember claude --host"));
    }

    #[test]
    fn launcher_guidance_maps_no_active_grant_for_codex_register_session() {
        let guidance = launcher_guidance_for_rpc(
            "register_session",
            -32004,
            "no active grant for persona 'codex-default'",
            "ember codex --isolated",
        )
        .expect("expected guidance");
        assert!(guidance.contains("ember init --for codex"));
        assert!(guidance.contains("ember codex --isolated"));
    }
}
