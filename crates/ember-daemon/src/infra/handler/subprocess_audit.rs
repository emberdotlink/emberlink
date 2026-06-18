use serde_json::{Value, json};

use crate::infra::rpc_error::RpcError;
use crate::infra::store::DaemonStore;

/// META-AP-EMBER-INIT-CLAUDE-CODE-GRADIENT-WARNING (Tier 1) — subprocess
/// observability without a session. A Construct shim that finds
/// `EMBER_SESSION_ID` unset (or its classifier returning `None`) still
/// passthrough-execs the wrapped binary, but emits this best-effort RPC
/// first so the tamper-evident audit chain records that the invocation
/// happened. The shim does not block waiting for the reply.
///
/// Wire shape (validated below):
///
/// ```text
/// params: {
///     "vendor":       "git" | "gh" | "kubectl" | ... (whitelist),
///     "verb":         "<classified action key or raw subcommand>",
///     "outcome":      "ambient_credential_used" | "passthrough_no_classify",
///     "argv_summary": "<first ≤3 argv tokens, ≤256 chars>"
/// }
/// result: { "logged": true, "id": <audit_log row id> }
/// ```
///
/// Authority class is `ConnectOnly` — peer-cred + ember-clients group
/// membership is sufficient. The validation gates below prevent abuse:
///
/// 1. **Vendor whitelist** — the `vendor` MUST appear in
///    `ember_construct::VENDORS`. The action string is built from this
///    field, so a forged vendor would plant rows under attacker-controlled
///    `subprocess.<vendor>.invoke_no_session` action keys.
/// 2. **Action-prefix lock** — the daemon, NOT the caller, builds the
///    action string. The wire shape never accepts a free-text `action`
///    field, so a caller cannot impersonate broker / vault / grant
///    actions.
/// 3. **Length caps** — verb ≤128 chars, argv_summary ≤256 chars. Both
///    are inserted into the chain-canonical body and feed downstream
///    queries; unbounded strings would let one caller bloat the DB.
/// 4. **Outcome enum** — only the two values listed above; anything else
///    is `-32602`.
///
/// Quarantine: the dispatch-layer gate refuses this method while quarantined
/// because it's NOT in `is_read_class_method`. The `append_audit_event_with_chain`
/// call also re-checks quarantine as defense-in-depth.
///
/// `peer_cred_principal`, when present, contributes `uid` + `pid` to the
/// `details` JSON. Internal callers (`None`) record `agent_id = NULL` —
/// matches the convention used by other non-persona-bound audit rows
/// (`broker.materialization`, etc.).
///
/// # target_state_anchor
///
/// `subprocess_audit_log_routes_through_chain`
pub fn handle_subprocess_audit_log(
    store: &DaemonStore,
    params: &Value,
    peer_cred_principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
) -> Result<Value, (i32, String)> {
    const MAX_VERB_LEN: usize = 128;
    const MAX_ARGV_SUMMARY_LEN: usize = 256;
    const ALLOWED_OUTCOMES: &[&str] = &[
        "denied_no_session",
        "ambient_credential_used",
        "passthrough_no_classify",
    ];

    let vendor = params
        .get("vendor")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RpcError::InvalidParams("subprocess_audit_log: missing `vendor`".to_string())
        })?;
    if !ember_construct::VENDORS.iter().any(|v| v.name == vendor) {
        return Err(RpcError::InvalidParams(format!(
            "subprocess_audit_log: vendor `{vendor}` not in whitelist"
        ))
        .into());
    }

    let verb = params.get("verb").and_then(|v| v.as_str()).ok_or_else(|| {
        RpcError::InvalidParams("subprocess_audit_log: missing `verb`".to_string())
    })?;
    if verb.is_empty() || verb.len() > MAX_VERB_LEN {
        return Err(RpcError::InvalidParams(format!(
            "subprocess_audit_log: `verb` length {} out of range (1..={MAX_VERB_LEN})",
            verb.len()
        ))
        .into());
    }
    if !verb.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
        return Err(RpcError::InvalidParams(
            "subprocess_audit_log: `verb` must be printable ASCII".to_string(),
        )
        .into());
    }

    let outcome = params
        .get("outcome")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RpcError::InvalidParams("subprocess_audit_log: missing `outcome`".to_string())
        })?;
    if !ALLOWED_OUTCOMES.contains(&outcome) {
        return Err(RpcError::InvalidParams(format!(
            "subprocess_audit_log: `outcome` must be one of {ALLOWED_OUTCOMES:?}, got `{outcome}`"
        ))
        .into());
    }

    let argv_summary = params
        .get("argv_summary")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if argv_summary.len() > MAX_ARGV_SUMMARY_LEN {
        return Err(RpcError::InvalidParams(format!(
            "subprocess_audit_log: `argv_summary` length {} exceeds {MAX_ARGV_SUMMARY_LEN}",
            argv_summary.len()
        ))
        .into());
    }

    let action = format!("subprocess.{vendor}.invoke_no_session");

    let mut details_map = serde_json::Map::new();
    details_map.insert("verb".to_string(), Value::String(verb.to_string()));
    details_map.insert(
        "argv_summary".to_string(),
        Value::String(argv_summary.to_string()),
    );
    if let Some(p) = peer_cred_principal {
        details_map.insert("peer_uid".to_string(), Value::from(p.uid));
        details_map.insert("peer_pid".to_string(), Value::from(p.pid));
    }
    let details = serde_json::to_string(&Value::Object(details_map))
        .map_err(|e| RpcError::Internal(format!("subprocess_audit_log: encode details: {e}")))?;

    let id = crate::infra::audit::append_audit_event_with_chain(
        store,
        None,
        &action,
        None,
        outcome,
        Some(&details),
    )
    .map_err(|e| RpcError::Internal(format!("subprocess_audit_log: chain append: {e}")))?;

    Ok(json!({
        "logged": true,
        "id": id,
    }))
}
