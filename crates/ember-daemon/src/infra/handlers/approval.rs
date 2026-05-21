//! Approval RPC helpers for the socket-facing `list_pending_approvals` and
//! `resolve_approval` methods.

use serde_json::Value;

use crate::infra::{
    handler::{DispatchSource, RequestContext, check_user_presence_gate},
    store::DaemonStore,
};
use crate::trust::presence::HighRiskOp;

pub(crate) fn handle_list_pending(
    store: &DaemonStore,
    ctx: &RequestContext,
) -> Result<Value, (i32, String)> {
    let persona_scope = crate::infra::handlers::principal::team0_connect_only_persona_scope(
        ctx,
        "list_pending_approvals",
    )?;
    let requests = store
        .list_pending_approvals()
        .map_err(|e| (-32000, e.to_string()))?;
    let list: Vec<Value> = requests
        .iter()
        .filter(|request| match persona_scope.as_deref() {
            Some(persona_id) => request.persona_id == persona_id,
            None => true,
        })
        .map(|request| serde_json::to_value(request).unwrap_or(Value::Null))
        .collect();
    Ok(Value::Array(list))
}

pub(crate) async fn handle_resolve(
    store: &DaemonStore,
    ctx: &RequestContext,
    source: DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let id = params["id"]
        .as_str()
        .ok_or((-32602, "missing 'id'".to_string()))?;
    let decision = params["decision"]
        .as_str()
        .ok_or((-32602, "missing 'decision'".to_string()))?;

    if !source.is_internal() {
        let pending = store.get_approval(id).map_err(|e| match e {
            crate::infra::store::StoreError::NotFound => {
                (-32004, format!("approval {id} not found"))
            }
            other => (-32000, other.to_string()),
        })?;
        let caller_principal =
            crate::infra::handlers::support::resolve_caller_principal(ctx, params).await?;
        if caller_principal == pending.persona_id {
            tracing::warn!(
                caller_persona_id = %caller_principal,
                approval_id = %id,
                "rejecting resolve_approval: caller is the submitter (self-approval forbidden)"
            );
            return Err((
                -32003,
                "resolve_approval: caller cannot approve own request \
                 (two-party invariant; the dashboard path is the \
                 operator-attested route for self-submitted approvals)"
                    .to_string(),
            ));
        }
        let override_qh = params["override_quiet_hours"].as_bool().unwrap_or(false);
        check_user_presence_gate(HighRiskOp::ApprovalResolve, override_qh)?;
    }

    let outcome = match decision {
        "approve" => crate::trust::approval::ApprovalOutcome::Approved,
        "deny" => crate::trust::approval::ApprovalOutcome::Denied {
            reason: params["reason"]
                .as_str()
                .ok_or((-32602, "missing 'reason'".to_string()))?
                .to_string(),
        },
        "narrow" => crate::trust::approval::ApprovalOutcome::Narrowed {
            new_scope: params["scope"]
                .as_str()
                .ok_or((-32602, "missing 'scope'".to_string()))?
                .to_string(),
        },
        "always" => crate::trust::approval::ApprovalOutcome::Always {
            scope: params["scope"].as_str().map(str::to_owned),
            expires_at: params["expires_at"].as_str().map(str::to_owned),
        },
        other => {
            return Err((
                -32602,
                format!("invalid 'decision': expected approve|deny|narrow|always, got {other}"),
            ));
        }
    };
    store.resolve_approval(id, &outcome).map_err(|e| match e {
        crate::infra::store::StoreError::NotFound => (-32004, format!("approval {id} not found")),
        other => (-32000, other.to_string()),
    })?;
    let resolved = store.get_approval(id).map_err(|e| match e {
        crate::infra::store::StoreError::NotFound => {
            (-32004, format!("approval {id} not found after resolve"))
        }
        other => (-32000, other.to_string()),
    })?;
    serde_json::to_value(&resolved)
        .map_err(|e| (-32000, format!("serialize resolved approval: {e}")))
}
