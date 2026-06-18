use serde_json::{Value, json};
use tokio::sync::broadcast;

use core_approval::{ApprovalLifecycle, SubmitMetadata};
use core_events::receipt::{
    AuthorityGrantIssuedBody, AuthorityPresenceProof, RECEIPT_KIND_AUTHORITY_GRANT_ISSUED,
    RECEIPT_KIND_COMPOSITE_GRANT, StatementProjection, TerminationAuthority, TerminationReason,
};

use crate::infra::claim_journal::summarize_grant_scope_best_effort;
use crate::infra::events::GrantEvent;
use crate::infra::receipt::{
    current_identity,
    issue::{
        TerminationMeta, issue_atomic_receipt, issue_cohort_a_receipt,
        issue_session_receipt_from_closed_scope,
    },
};
use crate::infra::rpc_error::RpcError;
use crate::infra::store::DaemonStore;
use crate::trust::approval::{DaemonApprovalStoreRef, GrantShapeFields};
use crate::trust::policy::{ApprovalRequirement, PolicyEngine};
use crate::trust::presence::HighRiskOp;

use super::{
    DispatchSource, HandlerError, RequestContext, VerifiedPresenceProof, check_user_presence_gate,
    notify_require_approval,
};

fn current_grant_scope_projection(
    store: &DaemonStore,
    grant_id: &str,
) -> Result<Vec<StatementProjection>, RpcError> {
    let access_grant = store
        .get_access_grant(grant_id)
        .map_err(|e| RpcError::Internal(format!("load issued grant chain for receipt: {e}")))?;
    let tail = access_grant
        .blocks
        .last()
        .ok_or_else(|| RpcError::Internal("issued grant chain is empty".to_string()))?;
    Ok(tail
        .block
        .statements
        .iter()
        .map(StatementProjection::from)
        .collect())
}

fn issue_authority_grant_issued_receipt(
    store: &DaemonStore,
    method: &str,
    grant: &crate::trust::grant::GrantInfo,
    params: &Value,
    proof: Option<&VerifiedPresenceProof>,
) -> Result<Option<String>, RpcError> {
    let Some(proof) = proof else {
        return Ok(None);
    };

    let data_dir = store.data_dir().ok_or_else(|| {
        RpcError::Internal(
            "authority grant-issued receipt: daemon store has no data_dir".to_string(),
        )
    })?;
    let identity_store =
        crate::infra::identity_substrate::open_identity_store(data_dir).map_err(|e| {
            RpcError::Internal(format!(
                "authority grant-issued receipt: open identity store: {e}"
            ))
        })?;
    let state = identity_store.materialized();
    let operator_root_id = crate::infra::operator_identity::operator_root_id(state)
        .ok_or_else(|| {
            RpcError::Internal(
                "authority grant-issued receipt: no unambiguous active operator root".to_string(),
            )
        })?
        .to_string();
    let operator_persona_id = crate::infra::operator_identity::operator_persona_id(state)
        .ok_or_else(|| {
            RpcError::Internal(
                "authority grant-issued receipt: no unambiguous active operator persona"
                    .to_string(),
            )
        })?
        .to_string();
    let identity = current_identity().ok_or_else(|| {
        RpcError::Internal(
            "authority grant-issued receipt: daemon identity not initialized".to_string(),
        )
    })?;
    let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);
    let mut request_params = params.clone();
    if let Value::Object(map) = &mut request_params {
        map.remove("_presence_proof");
        map.remove("scope_kek");
        map.remove("_presence_token");
    }
    let body = AuthorityGrantIssuedBody {
        grant_id: grant.id.clone(),
        grantee_principal_id: grant.persona_id.clone(),
        credential_name: grant.credential_name.clone(),
        request_params,
        issued_at: grant.created_at.clone(),
        expires_at: grant.expires_at.clone(),
        granted_scope: current_grant_scope_projection(store, &grant.id)?,
        operator_root_id,
        operator_persona_id,
        signing_device_id: proof.presence_authenticator_id.clone(),
        presence_proof: AuthorityPresenceProof {
            method: method.to_string(),
            op_id: proof.op_id.clone(),
            nonce: proof.nonce.clone(),
            daemon_fingerprint: proof.daemon_fingerprint.clone(),
            params_digest: proof.params_digest.clone(),
            signature: proof.signature.clone(),
        },
    };
    let envelope = issue_atomic_receipt(
        RECEIPT_KIND_AUTHORITY_GRANT_ISSUED,
        &body,
        TerminationAuthority::UserSession,
        &identity.pubkey_hex(),
        &signer,
    )
    .map_err(|e| {
        RpcError::Internal(format!(
            "authority grant-issued receipt: issue envelope: {e}"
        ))
    })?;
    store
        .store_atomic_receipt_v2(&envelope, &grant.id, &grant.persona_id, "issued")
        .map_err(|e| {
            RpcError::Internal(format!(
                "authority grant-issued receipt: persist envelope: {e}"
            ))
        })?;
    Ok(Some(envelope.receipt_id))
}

pub(crate) async fn handle_create(
    store: &DaemonStore,
    policy: &PolicyEngine,
    source: &DispatchSource,
    params: &Value,
    verified_presence_proof: Option<&VerifiedPresenceProof>,
) -> Result<Value, (i32, String)> {
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'persona_id'".to_string()))?;
    let credential_name = params["credential_name"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'credential_name'".to_string()))?;
    let scope = params["scope"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'scope'".to_string()))?;
    let ttl_secs = params["ttl_secs"].as_u64();
    let max_uses_per_hour = params["max_uses_per_hour"].as_u64();
    let allowed_hours_start = params["allowed_hours_start"].as_u64().map(|v| v as u32);
    let allowed_hours_end = params["allowed_hours_end"].as_u64().map(|v| v as u32);
    // ADR 207 SEAM-8B follow-up — `allowed_targets_storage_and_parse_one_encoding`.
    // Per-entry validation refuses entries flagged by the SEAM-8B
    // adversarial review (empty, bare `*`, `*.<empty>`). Storage is JSON
    // array; every reader routes through `parse_allowed_targets`.
    let allowed_targets = match params["allowed_targets"].as_array() {
        Some(arr) => {
            let entries: Vec<String> = arr
                .iter()
                .map(|v| {
                    v.as_str().ok_or_else(|| {
                        RpcError::InvalidParams(
                            "invalid_allowed_targets_entry: each entry must be a string"
                                .to_string(),
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|s| s.to_string())
                .collect();
            for entry in &entries {
                core_proxy_forward::validate_allowed_target_entry(entry).map_err(|reason| {
                    RpcError::InvalidParams(format!("invalid_allowed_targets_entry: {reason}"))
                })?;
            }
            Some(serde_json::to_string(&entries).unwrap_or_default())
        }
        None => None,
    };
    let max_delegation_depth = params["max_delegation_depth"].as_u64().map(|v| v as u32);
    let budget: Option<core_grant_types::Budget> = if params["budget"].is_object() {
        Some(
            serde_json::from_value(params["budget"].clone())
                .map_err(|e| RpcError::InvalidParams(format!("invalid 'budget': {e}")))?,
        )
    } else {
        None
    };
    let max_children_per_day = params["max_children_per_day"].as_u64();
    let auto_delegate_scope_template = params["auto_delegate_scope_template"]
        .as_str()
        .map(str::to_owned);
    let grant_shape = GrantShapeFields {
        max_delegation_depth,
        max_uses_per_hour,
        allowed_hours_start,
        allowed_hours_end,
        allowed_targets: allowed_targets.clone(),
        budget: budget.clone(),
        max_children_per_day,
        auto_delegate_scope_template: auto_delegate_scope_template.clone(),
    };

    if grant_shape.max_children_per_day.is_some() && grant_shape.max_delegation_depth.is_none() {
        return Err(RpcError::InvalidParams(
            "standing create_grant requires 'max_delegation_depth'".to_string(),
        )
        .into());
    }
    if grant_shape.auto_delegate_scope_template.is_some()
        && grant_shape.max_children_per_day.is_none()
    {
        return Err(RpcError::InvalidParams(
            "'auto_delegate_scope_template' requires 'max_children_per_day'".to_string(),
        )
        .into());
    }

    // Evaluate policy unless force=true (human/admin bypass).
    //
    // C39-HANDLER-C2 fix: `force` is ONLY honored for in-process
    // admin/test callers (`DispatchSource::Internal`). Socket
    // callers that supply `force: true` are rejected loudly so an
    // attacker can never silently bypass the policy gate.
    let force_requested = params["force"].as_bool().unwrap_or(false);
    if force_requested && !source.is_internal() {
        return Err(RpcError::InvalidParams(
            "the 'force' parameter is not permitted on the socket API".to_string(),
        )
        .into());
    }
    let force = force_requested && source.is_internal();

    // Per-op user-presence gate. Applied BEFORE policy evaluation
    // so a locked session is rejected with a
    // re-auth message instead of being silently routed into the
    // approval queue. Internal callers + force-allowed callers
    // bypass (test harness, admin CLI, recovery flow). Quiet
    // hours apply (grant create is NOT emergency-eligible).
    if !source.is_internal() && !force {
        let override_qh = params["override_quiet_hours"].as_bool().unwrap_or(false);
        check_user_presence_gate(HighRiskOp::GrantCreate, override_qh)?;
    }

    if !force {
        let action = "credential.access";
        let eval = policy.evaluate(action);

        match eval.requirement {
            ApprovalRequirement::Denied => {
                return Err(RpcError::PolicyDenied(format!(
                    "policy denied: {}",
                    eval.matched_rule.unwrap_or_default()
                ))
                .into());
            }
            ApprovalRequirement::Required => {
                let risk_str = format!("{:?}", eval.risk).to_lowercase();
                // PHASE-C-1-MIGRATED: trait crossing per ADR 113 §3
                let adapter = DaemonApprovalStoreRef::new(store);
                let metadata = SubmitMetadata {
                    action: "create_grant".to_string(),
                    ttl_secs,
                    risk_level: risk_str.clone(),
                    tool_name: None,
                    target_host: None,
                    target_url: None,
                    agent_framework: None,
                    max_delegation_depth: grant_shape.max_delegation_depth,
                    max_uses_per_hour: grant_shape.max_uses_per_hour,
                    allowed_hours_start: grant_shape.allowed_hours_start,
                    allowed_hours_end: grant_shape.allowed_hours_end,
                    allowed_targets: grant_shape.allowed_targets.clone(),
                    budget: grant_shape.budget.clone(),
                    max_children_per_day: grant_shape.max_children_per_day,
                    auto_delegate_scope_template: grant_shape.auto_delegate_scope_template.clone(),
                };
                let scope_obj = core_grant_types::approval::RequestedScope {
                    capability: scope.to_string(),
                    resource_id: None,
                    constraints: vec![],
                };
                let request_id = adapter
                    .submit_request(persona_id, credential_name, scope_obj, metadata)
                    .await
                    .map_err(|e| RpcError::Internal(e.to_string()))?;
                let req = store
                    .get_approval(&request_id.0)
                    .map_err(|e| RpcError::Internal(e.to_string()))?;
                notify_require_approval(store, &req);
                return Ok(json!({
                    "status": "pending_approval",
                    "approval_id": request_id.0,
                    "message": "Grant creation requires approval. Use list_pending_approvals to check status."
                }));
            }
            ApprovalRequirement::Auto => {
                // Fall through to create grant
            }
        }
    }

    let grant = store
        .create_grant_with_budget(persona_id, credential_name, scope, ttl_secs, budget.clone())
        .map_err(|e| RpcError::Internal(e.to_string()))?;

    store
        .apply_grant_shape_to_grant(&grant.id, &grant_shape)
        .map_err(|e| RpcError::Internal(e.to_string()))?;

    let _ = store.log_event(
        Some(persona_id),
        "grant.issued",
        Some(credential_name),
        "allowed",
        Some(
            &serde_json::json!({
                "grant_id": grant.id,
                "scope": scope,
                "ttl_secs": ttl_secs,
                "allowed_targets": params["allowed_targets"],
            })
            .to_string(),
        ),
    );
    let authority_receipt_id = issue_authority_grant_issued_receipt(
        store,
        "create_grant",
        &grant,
        params,
        verified_presence_proof,
    )?;

    Ok(json!({
        "id": grant.id,
        "expires_at": grant.expires_at,
        "authority_receipt_id": authority_receipt_id,
        "budget": budget,
        "standing": max_children_per_day.map(|limit| {
            json!({
                "max_children_per_day": limit,
                "auto_delegate_scope_template": auto_delegate_scope_template,
            })
        }),
        "conditions": {
            "max_uses_per_hour": max_uses_per_hour,
            "allowed_hours": if allowed_hours_start.is_some() {
                Some(format!("{}:00-{}:00 UTC", allowed_hours_start.unwrap_or(0), allowed_hours_end.unwrap_or(0)))
            } else { None },
            "allowed_targets": params["allowed_targets"].as_array(),
            "max_delegation_depth": max_delegation_depth,
            "max_children_per_day": max_children_per_day,
        }
    }))
}

pub(super) fn handle_create_composite(
    store: &DaemonStore,
    source: &DispatchSource,
    params: &Value,
    verified_presence_proof: Option<&VerifiedPresenceProof>,
) -> Result<Value, (i32, String)> {
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'persona_id'".to_string()))?;
    let credential_name = params["credential_name"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'credential_name'".to_string()))?;
    let scope = params["scope"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'scope'".to_string()))?;
    let ttl_secs = params["ttl_secs"].as_u64();
    let max_delegation_depth = params["max_delegation_depth"].as_u64().map(|v| v as u32);
    let stmt_values = params["statements"]
        .as_array()
        .ok_or_else(|| RpcError::InvalidParams("missing 'statements' array".to_string()))?;
    if stmt_values.is_empty() {
        return Err(RpcError::InvalidParams("statements must not be empty".to_string()).into());
    }

    if !source.is_internal() {
        let override_qh = params["override_quiet_hours"].as_bool().unwrap_or(false);
        check_user_presence_gate(HighRiskOp::GrantCreate, override_qh)?;
    }

    let statements: Vec<core_grant_types::StatementProposal> = stmt_values
        .iter()
        .map(|v| {
            serde_json::from_value(v.clone())
                .map_err(|e| RpcError::InvalidParams(format!("invalid statement proposal: {e}")))
        })
        .collect::<Result<_, _>>()?;
    let grant_shape = GrantShapeFields {
        max_delegation_depth,
        max_uses_per_hour: None,
        allowed_hours_start: None,
        allowed_hours_end: None,
        allowed_targets: None,
        budget: None,
        max_children_per_day: None,
        auto_delegate_scope_template: None,
    };

    let grant = store
        .create_grant_with_budget_suppress_minted_event(
            persona_id,
            credential_name,
            scope,
            ttl_secs,
            None,
        )
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    let materialized_statements = statements
        .into_iter()
        .enumerate()
        .map(|(idx, stmt)| core_grant_types::Statement {
            sid: format!("s{idx}"),
            resource_type: stmt.resource_type,
            actions: stmt.actions,
            resource: stmt.resource,
            budget: stmt.budget,
            usage: core_grant_types::Usage::default(),
            conditions: stmt.conditions,
            can_delegate: None,
        })
        .collect::<Vec<_>>();
    let issued_at = chrono::Utc::now().timestamp().max(0) as u64;
    let expires_at = ttl_secs.map(|secs| issued_at.saturating_add(secs));
    let parent_bound = crate::trust::grant::access_grant_from_statements_for_persona(
        store,
        &grant.id,
        persona_id,
        credential_name,
        crate::trust::attenuation::compute_statements_union_bound(&materialized_statements),
        issued_at,
        expires_at,
    )
    .map_err(|e| RpcError::Internal(e.to_string()))?;
    let access_grant = crate::trust::grant::access_grant_from_statements_for_persona(
        store,
        &grant.id,
        persona_id,
        credential_name,
        materialized_statements,
        issued_at,
        expires_at,
    )
    .map_err(|e| RpcError::Internal(e.to_string()))?;
    let statement_count = access_grant.statements().count();
    store
        .overwrite_grant_blocks_with_parent_bound(&grant.id, &access_grant, &parent_bound)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    store
        .apply_grant_shape_to_grant(&grant.id, &grant_shape)
        .map_err(|e| RpcError::Internal(e.to_string()))?;

    let _ = store.log_event(
        Some(persona_id),
        "grant.minted",
        Some(credential_name),
        "minted",
        Some(
            &serde_json::json!({
                "grant_id": grant.id,
                "statement_count": statement_count,
                "ttl_secs": ttl_secs,
                "max_delegation_depth": max_delegation_depth,
                "creation_mode": "composite",
            })
            .to_string(),
        ),
    );

    let _ = store.log_event(
        Some(persona_id),
        "grant.issued",
        Some(credential_name),
        "allowed",
        Some(
            &serde_json::json!({
                "grant_id": grant.id,
                "scope": scope,
                "ttl_secs": ttl_secs,
                "statement_count": statement_count,
                "max_delegation_depth": max_delegation_depth,
                "shape": "composite",
            })
            .to_string(),
        ),
    );
    let authority_receipt_id = issue_authority_grant_issued_receipt(
        store,
        "create_composite_grant",
        &grant,
        params,
        verified_presence_proof,
    )?;

    Ok(json!({
        "id": grant.id,
        "expires_at": grant.expires_at,
        "max_delegation_depth": max_delegation_depth,
        "statement_count": statement_count,
        "authority_receipt_id": authority_receipt_id,
    }))
}

pub(crate) async fn handle_delegate(
    store: &DaemonStore,
    ctx: &RequestContext,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let parent_grant_id = params["parent_grant_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'parent_grant_id'".to_string()))?;
    let child_persona_id = params["child_persona_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'child_persona_id'".to_string()))?;
    let scope = params["scope"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'scope'".to_string()))?;
    let ttl_secs = params["ttl_secs"].as_u64();
    // Optional child budget — when present, `delegate_grant_full`
    // enforces offline attenuation (child ≤ parent − usage on every
    // axis). When absent we fall back to the no-budget shape so
    // callers that don't set budgets keep working.
    let child_budget: Option<core_grant_types::Budget> = if params["budget"].is_object() {
        Some(
            serde_json::from_value(params["budget"].clone())
                .map_err(|e| RpcError::InvalidParams(format!("invalid 'budget': {e}")))?,
        )
    } else {
        None
    };
    // GRANT-SM-PHASE-C-3A: load via DaemonGrantStore to obtain
    // core_grants::Grant at the state-machine boundary. Ownership
    // checks below use `parent_grant.issuer.0` (persona_id) directly.
    // TODO: delegate_grant log_event credential_name
    // — not present in core_grants::Grant; requires a lookup helper.
    let parent_grant = store
        .grant_store()
        .load_grant(parent_grant_id)
        .map_err(|e| RpcError::Internal(e.to_string()))?;

    // C39-HANDLER-C3-FULL — full principal binding via shared helper.
    //
    // `resolve_caller_principal` resolves the caller's persona id
    // from (in order): pre-resolved ctx.principal, kernel peercred
    // PID registry, mTLS bridge lane, params["caller_persona_id"]
    // legacy fallback. Internal source bypasses — mirrors C39-HANDLER-C2.
    if !source.is_internal() {
        let principal =
            crate::infra::handlers::support::resolve_caller_principal(ctx, params).await?;
        // Mismatch check: if params["caller_persona_id"] was supplied and
        // differs from the kernel-derived principal, reject loudly
        // (C39-HANDLER-C3-FULL — attacker cannot impersonate by forging params).
        if let Some(asserted) = params["caller_persona_id"].as_str()
            && asserted != principal
        {
            tracing::warn!(
                asserted_persona_id = %asserted,
                kernel_persona_id = %principal,
                parent_grant_id = %parent_grant_id,
                "rejecting delegate_grant: params.caller_persona_id \
                 does not match kernel-derived principal"
            );
            return Err(HandlerError::PrincipalMismatch.to_jsonrpc());
        }
        // GRANT-SM-PHASE-C-3A: compare against issuer.0 (core_grants::PrincipalId).
        if principal != parent_grant.issuer.0 {
            tracing::warn!(
                caller_persona_id = %principal,
                parent_grant_id = %parent_grant_id,
                parent_owner_persona_id = %parent_grant.issuer.0,
                "rejecting delegate_grant: caller does not own parent grant"
            );
            return Err(RpcError::GrantOwnershipMismatch(
                "delegate_grant: caller does not own parent grant".to_string(),
            )
            .into());
        }
    }

    let grant = store
        .delegate_grant_full(
            parent_grant_id,
            child_persona_id,
            scope,
            ttl_secs,
            child_budget,
        )
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    // TODO: delegate_grant credential_name not in core_grants::Grant;
    // audit logs emit None here until a lookup helper is added. The parent_grant_id
    // in the JSON body lets operators reconstruct the credential from the grant record.
    let _ = store.log_event(
        Some(child_persona_id),
        "grant.delegated",
        None,
        "allowed",
        Some(
            &serde_json::json!({
                "parent_grant_id": parent_grant_id,
                "child_grant_id": grant.id,
                "child_persona_id": child_persona_id,
                "scope": scope,
            })
            .to_string(),
        ),
    );
    Ok(json!({
        "id": grant.id,
        "scope": grant.scope,
        "parent": parent_grant_id,
        "expires_at": grant.expires_at,
        "budget": grant.budget,
    }))
}

pub(crate) fn handle_revoke(
    store: &DaemonStore,
    ctx: &RequestContext,
    events_tx: Option<&broadcast::Sender<GrantEvent>>,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let id = params["id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'id'".to_string()))?;
    // GRANT-SM-PHASE-C-3A: load via DaemonGrantStore for issuer.
    // credential_name lives on GrantInfo (the SQL row projection),
    // not on core_grants::Grant — fetch both so the audit row carries
    // the credential identity.
    let core_grant = store.grant_store().load_grant(id).ok();
    let grant_info = store.get_grant(id).ok();
    let grant_persona = core_grant.as_ref().map(|g| g.issuer.0.clone());
    let grant_credential = grant_info.as_ref().map(|g| g.credential_name.clone());
    store
        .revoke_grant(id)
        .map_err(|e| RpcError::Internal(e.to_string()))?;

    // v2_receipt_coverage_audit_v030_2026_05_09: extend Receipt to TTL/revoke per M3 follow-up
    // Emit a signed v2 cohort-A Receipt with ExplicitRevoke for H1
    // coverage. Grant may have no live session; use a synthetic
    // session_id derived from the grant_id so the Receipt envelope is
    // well-formed (spec option (a)).
    let synthetic_session_id = format!("grant:{id}");
    let grant_claim_summary =
        summarize_grant_scope_best_effort(store, id, "dispatch_method_with_context::revoke_grant");
    if let Some(identity) = current_identity() {
        let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);
        let termination = Some(TerminationMeta {
            reason: TerminationReason::ExplicitRevoke,
            last_heartbeat_at: None,
            pid_alive_at_check: None,
        });
        let envelope_result = if let Some(summary) = grant_claim_summary.as_ref() {
            issue_session_receipt_from_closed_scope(
                RECEIPT_KIND_COMPOSITE_GRANT,
                &synthetic_session_id,
                summary,
                None,
                TerminationAuthority::DaemonPersona,
                &identity.pubkey_hex(),
                termination,
                &signer,
            )
        } else {
            issue_cohort_a_receipt(
                &synthetic_session_id,
                Vec::new(),
                None,
                TerminationAuthority::DaemonPersona,
                &identity.pubkey_hex(),
                termination,
                &signer,
            )
        };
        match envelope_result {
            Ok(envelope) => {
                // Persist the Receipt sidecar if a sessions_dir is
                // available. Best-effort: a write failure does not
                // abort the revocation itself.
                if let Some(sessions_dir) = &ctx.sessions_dir {
                    let receipt_dir = sessions_dir.join(&synthetic_session_id);
                    let _ = std::fs::create_dir_all(&receipt_dir);
                    let receipt_path = receipt_dir.join("receipt.json");
                    if let Ok(bytes) = serde_json::to_vec_pretty(&envelope)
                        && let Err(e) = std::fs::write(&receipt_path, &bytes)
                    {
                        tracing::warn!(
                            grant_id = %id,
                            path = %receipt_path.display(),
                            error = %e,
                            "revoke_grant: failed to persist v2 Receipt sidecar"
                        );
                    }
                }
                tracing::info!(
                    grant_id = %id,
                    receipt_id = %envelope.receipt_id,
                    "revoke_grant: signed v2 cohort-A Receipt emitted (ExplicitRevoke)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    grant_id = %id,
                    error = %e,
                    "revoke_grant: failed to issue v2 cohort-A Receipt — revocation still committed"
                );
            }
        }
    } else {
        tracing::warn!(
            grant_id = %id,
            "revoke_grant: daemon identity not initialised — skipping v2 Receipt emission"
        );
    }

    // Push revocation notification (best-effort, queued for polling)
    if let Some(persona_id) = &grant_persona {
        let _ = store.push_notification(persona_id, "grant.revoked", &json!({"grant_id": id}));
    }
    // Log the revocation event.
    let _ = store.log_event(
        core_grant.as_ref().map(|g| g.issuer.0.as_str()),
        "grant.revoked",
        grant_credential.as_deref(),
        "allowed",
        Some(&serde_json::json!({"grant_id": id}).to_string()),
    );
    // Broadcast GRANT_REVOKED over the unix socket so connected agents
    // can zeroize cached credentials without waiting on polling.
    if let (Some(tx), Some(persona_id)) = (events_tx, grant_persona) {
        let event = GrantEvent::Revoked {
            grant_id: id.to_string(),
            persona_id: persona_id.clone(),
        };
        // send() returns Err only when there are no active subscribers,
        // which is expected at startup; ignore the result.
        let _ = tx.send(event);
        tracing::info!(grant_id = %id, "broadcasting grant revocation to connected agents");
    }
    Ok(json!({"revoked": true}))
}

pub(crate) fn handle_revoke_statement(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // DEMO-MAY3-COMPOSITE-PER-STMT-REVOKE — revoke a single Statement
    // within a composite grant. The grant remains active; only requests
    // resolving to the named sid are denied at the proxy + use_credential
    // boundaries.
    let grant_id = params["grant_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'grant_id'".to_string()))?;
    let sid = params["statement_sid"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'statement_sid'".to_string()))?;
    store
        .revoke_grant_statement(grant_id, sid)
        .map_err(|e| match e {
            crate::infra::store::StoreError::NotFound => {
                RpcError::NotFound(format!("grant {grant_id} not found"))
            }
            other => RpcError::Internal(other.to_string()),
        })?;
    Ok(json!({
        "status": "revoked",
        "grant_id": grant_id,
        "statement_sid": sid,
    }))
}

pub(crate) fn handle_evaluate(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona_id = crate::infra::handlers::principal::persona_scoped_param_for_connect_only(
        ctx,
        params,
        "evaluate_grant",
        "persona_id",
        true,
    )?
    .ok_or_else(|| RpcError::InvalidParams("missing 'persona_id'".to_string()))?;
    let credential_name = params["credential_name"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'credential_name'".to_string()))?;
    let grant = store
        .evaluate_grant(&persona_id, credential_name)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    Ok(json!({"id": grant.id, "scope": grant.scope, "expires_at": grant.expires_at}))
}

// grant_extend_rpc_landed: dotted `grant.extend` RPC for the ADR 131
// open_store migration. Extend mints a delta (additive tokens / cents /
// ttl_secs) against an existing grant; scope is structurally absent
// from the parameter set, so the non-escalation invariant is satisfied
// by construction. Authority gates mirror `handle_create`: socket
// callers cannot pass `force`, the per-op user-presence gate fires
// under `HighRiskOp::GrantCreate` (extend is in the same risk class —
// it expands the existing grant's authority surface), and the policy
// engine evaluates `credential.access`. `extend_grant` remains as the
// legacy spelling for older CLI callers.
pub(crate) fn handle_extend(
    store: &DaemonStore,
    policy: &PolicyEngine,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let grant_id = params["grant_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'grant_id'".to_string()))?;
    let add_tokens = params["add_tokens"].as_u64();
    let add_cents = params["add_cents"].as_u64();
    let add_ttl_secs = params["add_ttl_secs"].as_u64();

    // Authority gates — mirror `handle_create` (above). C39-HANDLER-C2:
    // `force` is honored only for in-process Internal callers; socket
    // callers passing `force: true` are rejected loudly so an attacker
    // can never silently bypass the policy/presence gates via extend.
    let force_requested = params["force"].as_bool().unwrap_or(false);
    if force_requested && !source.is_internal() {
        return Err(RpcError::InvalidParams(
            "the 'force' parameter is not permitted on the socket API".to_string(),
        )
        .into());
    }
    let force = force_requested && source.is_internal();

    // Per-op user-presence gate. Applied BEFORE policy evaluation, same
    // posture as `handle_create`. Extend is NOT emergency-eligible
    // (extending budget/TTL during quiet hours requires explicit
    // operator presence + `override_quiet_hours: true`).
    if !source.is_internal() && !force {
        let override_qh = params["override_quiet_hours"].as_bool().unwrap_or(false);
        check_user_presence_gate(HighRiskOp::GrantCreate, override_qh)?;
    }

    if !force {
        let action = "credential.access";
        let eval = policy.evaluate(action);
        match eval.requirement {
            ApprovalRequirement::Denied => {
                return Err(RpcError::PolicyDenied(format!(
                    "policy denied: {}",
                    eval.matched_rule.unwrap_or_default()
                ))
                .into());
            }
            ApprovalRequirement::Required => {
                // Conservative posture: extend does not queue approvals
                // (the approval-queue schema is `credential_name` +
                // `scope`-shaped, which extend lacks). A grant whose
                // policy requires approval to extend must be re-issued
                // through `create_grant`. This is intentionally narrower
                // than `handle_create`'s queue-on-Required behavior so
                // an extend can never silently park as a pending
                // approval that the operator forgets about.
                return Err(RpcError::PolicyDenied(
                    "policy requires approval for credential.access; \
                     extend does not queue approvals — re-issue via create_grant"
                        .to_string(),
                )
                .into());
            }
            ApprovalRequirement::Auto => {
                // Fall through to extend.
            }
        }
    }

    let updated = store
        .extend_grant(grant_id, add_tokens, add_cents, add_ttl_secs)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    Ok(json!({
        "grant_id": updated.id,
        "expires_at": updated.expires_at,
        "budget": updated.budget,
    }))
}

pub(crate) fn handle_expire_stale(store: &DaemonStore) -> Result<Value, (i32, String)> {
    // grant_expire_stale_rpc_landed: daemon-owned expiry sweep for the
    // ADR 131 open_store migration; `expire_grants` remains a compatibility
    // spelling for older CLI callers.
    let count = store
        .expire_stale_grants()
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    Ok(json!({"expired_count": count}))
}
