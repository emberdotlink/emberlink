use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hyper::HeaderMap;
use serde_json::Value;

const REBIND_HOLD_TIMEOUT: Duration = Duration::from_millis(500);
const REBIND_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttachmentAuthority {
    pub session_id: String,
    pub attachment_id: String,
    pub runtime_persona_id: String,
    pub durable_persona_id: String,
    pub caller_binding_id: String,
    pub grant_id: String,
    pub state: String,
    pub workspace_ref: Option<String>,
    pub worktree_path: Option<PathBuf>,
    /// ADR 190 §4 base posture for this session: `true` => strict (a lapsed
    /// authority denies until re-delegated), `false` => jit (re-approvable).
    /// Carried so the LLM lane can render a posture-aware recovery signal
    /// instead of a flat 403 when a grant goes non-active mid-session.
    pub authority_strict: bool,
}

// P22-S2 — the production `handle_request` (the only non-test daemon caller)
// moved into `proxy-forward-runtime`, which carries its own pure copy of this
// header parser. This daemon copy is still exercised by the in-tree
// `proxy::tests` harness (`handle_request_boxed`), so keep it but silence the
// dead-code warning in non-test builds.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn attachment_endpoint_from_headers(headers: &HeaderMap) -> Option<(&str, &str)> {
    let attachment_id = headers
        .get("x-ember-attachment-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())?;
    let endpoint_token = headers
        .get("x-ember-endpoint-token")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())?;
    Some((attachment_id, endpoint_token))
}

pub(crate) fn attachment_endpoint_from_params(params: &Value) -> Option<(&str, &str)> {
    let attachment_id = params
        .get("attachment_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())?;
    let endpoint_token = params
        .get("attachment_endpoint_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())?;
    Some((attachment_id, endpoint_token))
}

pub(crate) async fn resolve_attachment_authority(
    sessions_dir: &Path,
    attachment_id: &str,
    endpoint_token: &str,
) -> Result<AttachmentAuthority, (i32, String)> {
    let store = core_state::SessionStore::new(sessions_dir.to_path_buf());
    let started = Instant::now();
    loop {
        let (meta, endpoint) = store
            .resolve_attachment_endpoint(attachment_id, endpoint_token)
            .map_err(|e| (-32000, format!("resolve attachment endpoint: {e}")))?
            .ok_or_else(|| {
                (
                    -32004,
                    "attachment endpoint not found or token mismatch".to_string(),
                )
            })?;

        if endpoint.is_active() {
            let workspace_binding = store
                .read_workspace_binding(&meta.session_id)
                .map_err(|e| (-32000, format!("read session workspace binding: {e}")))?;
            let durable_persona_id = meta.durable_persona.clone().ok_or_else(|| {
                (
                    -32000,
                    "attachment endpoint resolved legacy session without durable persona"
                        .to_string(),
                )
            })?;
            let caller_binding_id = meta.caller_binding_id.clone().ok_or_else(|| {
                (
                    -32000,
                    "attachment endpoint resolved legacy session without caller binding"
                        .to_string(),
                )
            })?;
            return Ok(AttachmentAuthority {
                session_id: meta.session_id,
                attachment_id: endpoint.attachment_id,
                runtime_persona_id: meta.persona,
                durable_persona_id,
                caller_binding_id,
                grant_id: meta.grant_id,
                state: endpoint.state,
                workspace_ref: workspace_binding
                    .as_ref()
                    .map(|binding| binding.workspace_ref.clone()),
                worktree_path: workspace_binding.map(|binding| binding.worktree_path),
                authority_strict: meta.authority_strict,
            });
        }

        if endpoint.is_rebinding() && started.elapsed() < REBIND_HOLD_TIMEOUT {
            tokio::time::sleep(REBIND_POLL_INTERVAL).await;
            continue;
        }

        if endpoint.is_rebinding() {
            return Err((
                -32029,
                "attachment is rebinding; retry this authority-using operation".to_string(),
            ));
        }

        return Err((
            -32030,
            format!(
                "attachment is not active for authority use: state={}",
                endpoint.state
            ),
        ));
    }
}

pub(crate) fn overlay_broker_attachment_authority(
    params: &Value,
    authority: &AttachmentAuthority,
) -> Result<Value, (i32, String)> {
    let mut overlaid = params.clone();
    let Some(obj) = overlaid.as_object_mut() else {
        return Err((-32602, "broker params must be a JSON object".to_string()));
    };

    insert_or_match(obj, "session_id", &authority.session_id)?;
    insert_or_match(obj, "persona_id", &authority.runtime_persona_id)?;
    insert_or_match(obj, "caller_persona", &authority.runtime_persona_id)?;
    insert_or_match(
        obj,
        "caller_ref",
        &format!("persona:{}", authority.runtime_persona_id),
    )?;
    insert_or_match(
        obj,
        "authority_ref",
        &format!("grant:{}", authority.grant_id),
    )?;

    if let Some(contract) = obj
        .get_mut("execution_contract")
        .and_then(serde_json::Value::as_object_mut)
    {
        if let Some(workspace_ref) = authority.workspace_ref.as_deref() {
            insert_or_match(contract, "workspace_ref", workspace_ref)?;
        }
        insert_or_match(
            contract,
            "caller_ref",
            &format!("persona:{}", authority.runtime_persona_id),
        )?;
        insert_or_match(
            contract,
            "authority_ref",
            &format!("grant:{}", authority.grant_id),
        )?;
    }

    Ok(overlaid)
}

fn insert_or_match(
    obj: &mut serde_json::Map<String, Value>,
    key: &str,
    value: &str,
) -> Result<(), (i32, String)> {
    match obj
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        Some(existing) if existing == value => Ok(()),
        Some(existing) => Err((
            -32003,
            format!("attachment authority mismatch for {key}: request={existing} resolved={value}"),
        )),
        None => {
            obj.insert(key.to_string(), Value::String(value.to_string()));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use core_state::sessions::{AttachmentEndpoint, SessionMeta, SessionStore};

    fn make_runtime_session(id: &str) -> SessionMeta {
        SessionMeta {
            session_id: id.to_string(),
            persona: "persona-runtime".to_string(),
            grant_id: "grant-runtime".to_string(),
            started_at: Utc::now(),
            launcher_pid: std::process::id(),
            authority_strict: false,
            delegation_id: None,
            delegation_template: None,
            durable_persona: Some("persona-durable".to_string()),
            caller_binding_id: Some("binding-live".to_string()),
        }
    }

    #[tokio::test]
    async fn resolves_active_attachment_authority() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sessions = SessionStore::new(dir.path().to_path_buf());
        let meta = make_runtime_session("sess-a");
        sessions.create(&meta).expect("create session");
        sessions
            .write_attachment_endpoint(
                &meta.session_id,
                &AttachmentEndpoint::active("att-a".to_string(), "token-a".to_string()),
            )
            .expect("write endpoint");

        let resolved = resolve_attachment_authority(dir.path(), "att-a", "token-a")
            .await
            .expect("resolve attachment");
        assert_eq!(resolved.session_id, "sess-a");
        assert_eq!(resolved.runtime_persona_id, "persona-runtime");
        assert_eq!(resolved.caller_binding_id, "binding-live");
        assert_eq!(resolved.grant_id, "grant-runtime");
        // jit session (authority_strict=false) propagates to the authority.
        assert!(!resolved.authority_strict);
    }

    // ADR 190 §4 / ADR 197 §2: the session base posture must flow into the
    // resolved authority so the LLM lane can render a posture-aware recovery
    // signal on a lapsed grant. A strict session must surface as strict.
    #[tokio::test]
    async fn resolves_strict_session_posture() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sessions = SessionStore::new(dir.path().to_path_buf());
        let mut meta = make_runtime_session("sess-strict");
        meta.authority_strict = true;
        sessions.create(&meta).expect("create session");
        sessions
            .write_attachment_endpoint(
                &meta.session_id,
                &AttachmentEndpoint::active("att-s".to_string(), "token-s".to_string()),
            )
            .expect("write endpoint");

        let resolved = resolve_attachment_authority(dir.path(), "att-s", "token-s")
            .await
            .expect("resolve attachment");
        assert!(resolved.authority_strict);
    }

    #[tokio::test]
    async fn rebinding_attachment_times_out_retryably() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sessions = SessionStore::new(dir.path().to_path_buf());
        let meta = make_runtime_session("sess-a");
        sessions.create(&meta).expect("create session");
        sessions
            .write_attachment_endpoint(
                &meta.session_id,
                &AttachmentEndpoint::active("att-a".to_string(), "token-a".to_string()),
            )
            .expect("write endpoint");
        sessions
            .set_attachment_state(&meta.session_id, "rebinding")
            .expect("set state");

        let started = Instant::now();
        let (code, msg) = resolve_attachment_authority(dir.path(), "att-a", "token-a")
            .await
            .expect_err("rebinding should time out");
        assert_eq!(code, -32029);
        assert!(msg.contains("retry"));
        assert!(started.elapsed() >= REBIND_HOLD_TIMEOUT);
    }

    #[test]
    fn overlay_broker_attachment_authority_inserts_live_binding_fields() {
        let authority = AttachmentAuthority {
            session_id: "sess-live".to_string(),
            attachment_id: "att-live".to_string(),
            runtime_persona_id: "persona-live".to_string(),
            durable_persona_id: "persona-durable".to_string(),
            caller_binding_id: "binding-live".to_string(),
            grant_id: "grant-live".to_string(),
            state: "active".to_string(),
            workspace_ref: Some("managed_worktree:rt-live".to_string()),
            worktree_path: Some(PathBuf::from("/tmp/emberlink-live-worktree")),
            authority_strict: false,
        };
        let params = serde_json::json!({
            "attachment_id": "att-live",
            "attachment_endpoint_token": "ep-live",
            "execution_contract": {}
        });

        let overlaid =
            overlay_broker_attachment_authority(&params, &authority).expect("overlay authority");

        assert_eq!(overlaid["session_id"], "sess-live");
        assert_eq!(overlaid["persona_id"], "persona-live");
        assert_eq!(overlaid["caller_persona"], "persona-live");
        assert_eq!(overlaid["caller_ref"], "persona:persona-live");
        assert_eq!(overlaid["authority_ref"], "grant:grant-live");
        assert_eq!(
            overlaid["execution_contract"]["caller_ref"],
            "persona:persona-live"
        );
        assert_eq!(
            overlaid["execution_contract"]["authority_ref"],
            "grant:grant-live"
        );
        assert_eq!(
            overlaid["execution_contract"]["workspace_ref"],
            "managed_worktree:rt-live"
        );
    }

    #[test]
    fn overlay_broker_attachment_authority_rejects_request_mismatch() {
        let authority = AttachmentAuthority {
            session_id: "sess-live".to_string(),
            attachment_id: "att-live".to_string(),
            runtime_persona_id: "persona-live".to_string(),
            durable_persona_id: "persona-durable".to_string(),
            caller_binding_id: "binding-live".to_string(),
            grant_id: "grant-live".to_string(),
            state: "active".to_string(),
            workspace_ref: None,
            worktree_path: None,
            authority_strict: false,
        };
        let params = serde_json::json!({
            "attachment_id": "att-live",
            "attachment_endpoint_token": "ep-live",
            "persona_id": "persona-other"
        });

        let (code, message) = overlay_broker_attachment_authority(&params, &authority)
            .expect_err("mismatched request must be refused");

        assert_eq!(code, -32003);
        assert!(message.contains("persona_id"));
    }
}
