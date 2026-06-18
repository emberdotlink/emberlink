//! Trusted-principal and ConnectOnly persona-scoping helpers.
//! CLASSIFICATION: PUBLIC

use serde_json::Value;

use crate::infra::handler::{
    HandlerError, RequestContext, current_dispatch_deployment_tier, peercred_principal,
};

pub(crate) fn trusted_request_persona(
    ctx: &RequestContext,
) -> Result<Option<String>, HandlerError> {
    if let Some(principal) = &ctx.principal {
        return Ok(Some(principal.clone()));
    }
    if let Some(peer) = &ctx.peer {
        match peercred_principal(peer) {
            Ok(principal) => return Ok(Some(principal)),
            Err(HandlerError::PrincipalNotEnrolled) => {}
            Err(other) => return Err(other),
        }
    }
    if let Some(mtls) = ctx.mtls_principal() {
        return Ok(Some(mtls.persona_id.clone()));
    }
    Ok(None)
}

pub(crate) fn team0_connect_only_persona_scope(
    ctx: &RequestContext,
    method: &str,
) -> Result<Option<String>, (i32, String)> {
    let tier = current_dispatch_deployment_tier();
    if !tier.requires_multi_uid_authz() {
        return Ok(None);
    }

    trusted_request_persona(ctx)
        .map_err(|e| e.to_jsonrpc())?
        .ok_or((
            -32004,
            format!(
                "{method}: deployment tier {} requires a trusted enrolled principal for \
             ConnectOnly read scoping",
                tier.as_str()
            ),
        ))
        .map(Some)
}

pub(crate) fn persona_scoped_param_for_connect_only(
    ctx: &RequestContext,
    params: &Value,
    method: &str,
    field: &str,
    required_in_dev0: bool,
) -> Result<Option<String>, (i32, String)> {
    let scoped_principal = team0_connect_only_persona_scope(ctx, method)?;
    let claimed = params.get(field).and_then(|v| v.as_str());

    match scoped_principal {
        Some(principal) => {
            if let Some(claimed) = claimed
                && claimed != principal
            {
                tracing::warn!(
                    method = %method,
                    field = %field,
                    claimed_persona_id = %claimed,
                    trusted_persona_id = %principal,
                    tier = current_dispatch_deployment_tier().as_str(),
                    "connect-only persona-scoped read refused: claimed persona does not match trusted principal"
                );
                return Err((
                    -32004,
                    format!("{method}: claimed {field} does not match trusted principal"),
                ));
            }
            Ok(Some(principal))
        }
        None => {
            if required_in_dev0 {
                claimed
                    .map(|value| Some(value.to_string()))
                    .ok_or((-32602, format!("missing '{field}'")))
            } else {
                Ok(claimed.map(|value| value.to_string()))
            }
        }
    }
}

pub(crate) fn ensure_connect_only_owner_matches_trusted_principal(
    ctx: &RequestContext,
    method: &str,
    owner_persona_id: &str,
) -> Result<(), (i32, String)> {
    let Some(trusted_persona) = team0_connect_only_persona_scope(ctx, method)? else {
        return Ok(());
    };

    if owner_persona_id != trusted_persona {
        tracing::warn!(
            method = %method,
            owner_persona_id = %owner_persona_id,
            trusted_persona_id = %trusted_persona,
            tier = current_dispatch_deployment_tier().as_str(),
            "connect-only persona-scoped lookup refused: owner does not match trusted principal"
        );
        return Err((
            -32004,
            format!("{method}: requested object does not belong to trusted principal"),
        ));
    }

    Ok(())
}
