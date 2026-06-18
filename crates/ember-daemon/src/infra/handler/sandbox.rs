use super::*;
use crate::infra::rpc_error::RpcError;

fn close_session_by_id(
    store: &DaemonStore,
    ctx: &RequestContext,
    session_id: &str,
) -> Result<(), (i32, String)> {
    let internal_ctx = RequestContext {
        sessions_dir: ctx.sessions_dir.clone(),
        ..RequestContext::internal("sandbox-close-session")
    };
    crate::infra::handlers::session::handle_close_session(
        store,
        &internal_ctx,
        &json!({ "session_id": session_id }),
    )
    .map(|_| ())
}

/// ADR 207 §I2 — close the internal `register_session` bound to a sandbox (if
/// any) so its vault-lock pin + host-mode enrollment + attachment are released
/// when the container is stopped or deleted. The binding is cleared ONLY when
/// the session is confirmed gone (success or a benign `-32004` already-closed);
/// on any other close failure the binding is RETAINED so a later stop/delete
/// retries instead of orphaning the pin with no handle.
fn close_session_best_effort(store: &DaemonStore, ctx: &RequestContext, sandbox_id: &str) {
    let session_id = match store.sandbox_session_id(sandbox_id) {
        Ok(Some(session_id)) => session_id,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(error = %e, sandbox_id = %sandbox_id, "failed to read sandbox session id for close");
            return;
        }
    };
    let gone = match close_session_by_id(store, ctx, &session_id) {
        Ok(()) => true,
        // -32004 == session not found / already closed: benign on a repeated
        // stop->delete, and the pin is already released.
        Err((code, _)) if code == RpcError::NotFound(String::new()).code() => true,
        Err((code, msg)) => {
            tracing::warn!(code, error = %msg, sandbox_id = %sandbox_id, session_id = %session_id, "sandbox session close failed; retaining binding for retry");
            false
        }
    };
    if gone && let Err(e) = store.clear_sandbox_session_id(sandbox_id) {
        tracing::warn!(error = %e, sandbox_id = %sandbox_id, "failed to clear sandbox session id after close");
    }
}

/// ADR 207 daemon-sandbox launch contract — assemble a sandbox container's
/// runtime env + control-plane mount. Shared by `sandbox_create` and
/// `sandbox_run` (one launch contract, ADR 207 seam 6).
///
/// Returns the container `-e` env (caller `extra_env` + the minted LLM gateway
/// lane vars) and, when a per-spawn ADR 154 bridge bundle was minted, the
/// `(cert_dir, port)` for `start_container`'s mTLS control-plane mount.
///
/// Mints the proxy-injected LLM gateway lane (ADR 207 §I1/§I2) + the bridge
/// bundle off the sandbox's OWNER persona (the fresh per-sandbox persona holds
/// no grant — same as the isolated/`up` lane, which registers under the operator
/// persona). The session is bound to the sandbox BEFORE `start_container` so a
/// start failure still leaves a closable session id on the row.
///
/// Trust note (dev0): `owner_persona_id` is caller-supplied, but the
/// OperatorPresence + `SO_PEERCRED` gate restricts the caller to the single
/// device-owner, who owns ALL personas — so naming one of their own personas is
/// not a confused-deputy, and this is strictly narrower than the pre-ADR-207
/// behavior (which injected the daemon's ambient raw key). A multi-human (team0)
/// daemon would need to bind owner->caller authority; tracked as a follow-up.
///
/// Fully FAIL-SOFT: with no owner, no gateway grant, no `sessions_dir`, a locked
/// vault, an unconfigured bridge, or a cert-write failure, the container still
/// starts — just without that capability, NEVER with a raw credential and NEVER
/// with the dead daemon UDS mounted in (ADR 154).
// env vars + optional (cert_dir, port) tuple — refactoring to a named struct is out of scope for the lint-clear
#[allow(clippy::type_complexity)]
fn prepare_runtime_env(
    store: &DaemonStore,
    ctx: &RequestContext,
    sandbox: &crate::infra::sandbox::SandboxInfo,
    extra_env: &[(String, String)],
    data_dir: &std::path::Path,
) -> (Vec<(String, String)>, Option<(std::path::PathBuf, u16)>) {
    let mut env = extra_env.to_vec();

    let Some(owner_persona) = sandbox.owner_persona_id.as_deref() else {
        tracing::debug!(
            sandbox_id = %sandbox.id,
            "sandbox has no owner persona; skipping brokered LLM lane mint"
        );
        return (env, None);
    };

    let lane = match crate::infra::handlers::session::mint_sandbox_gateway_env(
        store,
        ctx,
        owner_persona,
        std::process::id(),
    ) {
        Ok(Some(lane)) => lane,
        Ok(None) => {
            tracing::debug!(
                sandbox_id = %sandbox.id,
                "owner persona has no anthropic gateway grant; container starts without brokered LLM lane"
            );
            return (env, None);
        }
        Err((code, msg)) => {
            tracing::warn!(
                code,
                error = %msg,
                sandbox_id = %sandbox.id,
                "sandbox gateway minting failed; container starts without brokered LLM lane"
            );
            return (env, None);
        }
    };

    // Bind the session to the sandbox so stop/delete can close it (releasing the
    // vault-lock pin). If the bind fails (e.g. a concurrent delete left no row),
    // the session could never be closed by stop/delete — so close it now and
    // start without the lane rather than strand the pin.
    if let Err(e) = store.set_sandbox_session_id(&sandbox.id, &lane.session_id) {
        tracing::warn!(
            error = %e,
            sandbox_id = %sandbox.id,
            session_id = %lane.session_id,
            "failed to bind sandbox session id; closing minted session, container starts without brokered LLM lane"
        );
        if let Err((code, msg)) = close_session_by_id(store, ctx, &lane.session_id) {
            tracing::warn!(code, error = %msg, session_id = %lane.session_id, "failed to close unbound sandbox session");
        }
        return (env, None);
    }

    env.extend(lane.env);

    // ADR 207 seam 6 / ADR 154 — materialize the per-spawn mTLS bridge bundle so
    // the container has an emberd control plane. Fail-soft: a cert-write failure
    // drops the control plane but keeps the (already-bound) LLM lane.
    let bridge_cert = match lane.bridge {
        Some(bundle) => match crate::infra::sandbox::materialize_sandbox_bridge_certs(
            data_dir,
            &sandbox.id,
            &bundle.client_cert_pem,
            &bundle.client_key_pem,
            &bundle.ca_cert_pem,
        ) {
            Ok(cert_dir) => Some((cert_dir, bundle.port)),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    sandbox_id = %sandbox.id,
                    "failed to materialize sandbox bridge certs; container starts without control-plane bridge"
                );
                None
            }
        },
        None => None,
    };

    (env, bridge_cert)
}

pub(super) fn handle_create(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // ADR 216 S4 — sandbox spawn requires bridge CA (mTLS cert minting).
    // Fail closed until both double-envelope purposes are unlocked.
    if store.bridge_ca().is_none() {
        return Err(RpcError::BridgeCaUnavailable(
            "sandbox spawn requires bridge CA; vault not yet unlocked (ADR 216)".to_string(),
        )
        .into());
    }
    let opts: crate::infra::sandbox::SandboxCreateOpts = serde_json::from_value(params.clone())
        .map_err(|e| RpcError::InvalidParams(format!("invalid sandbox_create params: {e}")))?;
    let data_dir = runtime_data_dir_from_context(ctx)?;
    let sandbox = store
        .create_sandbox_with_opts(&opts, Some(&data_dir))
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    // ADR 207 §I1/§I2 + seam 6 — mint the proxy-injected LLM gateway lane
    // (no raw key) and the per-spawn mTLS bridge control plane, bind the
    // session, materialize bridge certs. Fully fail-soft; see
    // `prepare_runtime_env`.
    let (sandbox_env, bridge_cert) =
        prepare_runtime_env(store, ctx, &sandbox, &opts.extra_env, &data_dir);
    let bridge_mount =
        bridge_cert.as_ref().map(
            |(cert_dir, port)| crate::infra::sandbox::SandboxBridgeMount {
                cert_dir: cert_dir.as_path(),
                port: *port,
            },
        );
    let (container_id, start_error) = match store.start_container(
        &sandbox.id,
        opts.network.as_deref(),
        &sandbox_env,
        bridge_mount,
    ) {
        Ok(cid) => (Some(cid), None),
        Err(e) => (None, Some(e.to_string())),
    };
    // ADR 207 §I2 — a start failure after a successful mint would
    // otherwise strand the minted session (pin/enrollment/attachment)
    // until manual delete. Release it now; for a running container the
    // session is closed later by sandbox_stop.
    if start_error.is_some() {
        close_session_best_effort(store, ctx, &sandbox.id);
    }
    serde_json::to_value(crate::infra::sandbox::SandboxCreateResult {
        sandbox,
        container_id,
        start_error,
    })
    .map_err(|e| RpcError::Internal(format!("serialize SandboxCreateResult: {e}")).into())
}

pub(super) fn handle_list(store: &DaemonStore) -> Result<Value, (i32, String)> {
    let sandboxes = store
        .list_sandboxes()
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    serde_json::to_value(sandboxes)
        .map_err(|e| RpcError::Internal(format!("serialize SandboxInfo list: {e}")).into())
}

pub(super) fn handle_stop(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let id_or_name = params["id_or_name"]
        .as_str()
        .or_else(|| params["id"].as_str())
        .ok_or_else(|| RpcError::InvalidParams("missing 'id_or_name' parameter".to_string()))?;
    let resolved_id = store
        .resolve_sandbox_id(id_or_name)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    // ADR 207 seam 6 — pass data_dir (non-fatal) so the per-sandbox state
    // dir, including the 0600 bridge client key, is removed on stop.
    let data_dir = runtime_data_dir_from_context(ctx).ok();
    store
        .stop_sandbox(&resolved_id, data_dir.as_deref())
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    // ADR 207 §I2 — release the sandbox's internal LLM-lane session
    // (vault-lock pin + host-mode enrollment + attachment) now that the
    // container is stopped.
    close_session_best_effort(store, ctx, &resolved_id);
    Ok(json!({
        "resolved_id": resolved_id,
        "stopped": true,
    }))
}

pub(super) fn handle_delete(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let id_or_name = params["id_or_name"]
        .as_str()
        .or_else(|| params["id"].as_str())
        .ok_or_else(|| RpcError::InvalidParams("missing 'id_or_name' parameter".to_string()))?;
    // ADR 207 seam 6 — non-fatal: resolve data_dir to remove the whole
    // per-sandbox state dir (workspace + the 0600 bridge client key), but
    // don't let a missing sessions_dir block the row/container reap (the
    // `None` branch still cleans the recorded workspace path).
    let data_dir = runtime_data_dir_from_context(ctx).ok();
    let result = match store.resolve_sandbox_id(id_or_name) {
        Ok(resolved_id) => {
            // ADR 207 §I2 — close the internal LLM-lane session before the
            // row (which holds the session id) is removed.
            close_session_best_effort(store, ctx, &resolved_id);
            store
                .delete_sandbox(&resolved_id, data_dir.as_deref())
                .map_err(|e| RpcError::Internal(e.to_string()))?;
            crate::infra::sandbox::SandboxDeleteResult {
                resolved_id: Some(resolved_id),
                already_absent: false,
            }
        }
        Err(crate::infra::store::StoreError::NotFound) => {
            crate::infra::sandbox::SandboxDeleteResult {
                resolved_id: None,
                already_absent: true,
            }
        }
        Err(e) => return Err(RpcError::Internal(e.to_string()).into()),
    };
    serde_json::to_value(result)
        .map_err(|e| RpcError::Internal(format!("serialize SandboxDeleteResult: {e}")).into())
}

pub(super) async fn handle_exec(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let id_or_name = params["id_or_name"]
        .as_str()
        .or_else(|| params["id"].as_str())
        .ok_or_else(|| RpcError::InvalidParams("missing 'id_or_name' parameter".to_string()))?;
    let command = params["command"]
        .as_array()
        .ok_or_else(|| RpcError::InvalidParams("missing 'command' parameter".to_string()))?;
    let resolved_id = store
        .resolve_sandbox_id(id_or_name)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    let caller_persona =
        crate::infra::handlers::support::resolve_caller_principal(ctx, params).await?;
    let refs: Vec<&str> = command
        .iter()
        .map(|item| {
            item.as_str().ok_or_else(|| {
                RpcError::InvalidParams("'command' must be an array of strings".to_string())
            })
        })
        .collect::<Result<_, _>>()?;
    let output = store
        .exec_sandbox(&resolved_id, &refs, &caller_persona)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    Ok(json!({
        "resolved_id": resolved_id,
        "output": output,
    }))
}

pub(super) fn handle_run(
    store: &DaemonStore,
    policy: &PolicyEngine,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // ADR 216 S4 — sandbox spawn requires bridge CA (mTLS cert minting).
    // Fail closed until both double-envelope purposes are unlocked.
    if store.bridge_ca().is_none() {
        return Err(RpcError::BridgeCaUnavailable(
            "sandbox spawn requires bridge CA; vault not yet unlocked (ADR 216)".to_string(),
        )
        .into());
    }
    let opts: crate::infra::sandbox::SandboxCreateOpts =
        serde_json::from_value(params["sandbox"].clone()).map_err(|e| {
            RpcError::InvalidParams(format!("invalid sandbox_run sandbox params: {e}"))
        })?;
    let ttl_secs = params["ttl_secs"].as_u64();
    let credential_resource = params["credential_resource"].as_str();
    let statements: Vec<core_grant_types::StatementProposal> =
        match params.get("statements").and_then(|v| v.as_array()) {
            Some(values) => values
                .iter()
                .map(|value| {
                    serde_json::from_value(value.clone()).map_err(|e| {
                        RpcError::InvalidParams(format!("invalid sandbox_run statement: {e}"))
                    })
                })
                .collect::<Result<_, _>>()?,
            None => Vec::new(),
        };

    let data_dir = runtime_data_dir_from_context(ctx)?;
    let sandbox = store
        .create_sandbox_with_opts(&opts, Some(&data_dir))
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    // ADR 207 §I1/§I2 + seam 6 — mint the proxy-injected LLM gateway lane
    // (no raw key) and the per-spawn mTLS bridge control plane, bind the
    // session, materialize bridge certs. Fully fail-soft; see
    // `prepare_runtime_env`.
    let (sandbox_env, bridge_cert) =
        prepare_runtime_env(store, ctx, &sandbox, &opts.extra_env, &data_dir);
    let bridge_mount =
        bridge_cert.as_ref().map(
            |(cert_dir, port)| crate::infra::sandbox::SandboxBridgeMount {
                cert_dir: cert_dir.as_path(),
                port: *port,
            },
        );
    let (container_id, start_error) = match store.start_container(
        &sandbox.id,
        opts.network.as_deref(),
        &sandbox_env,
        bridge_mount,
    ) {
        Ok(cid) => (Some(cid), None),
        Err(e) => (None, Some(e.to_string())),
    };
    // ADR 207 §I2 — a start failure after a successful mint would
    // otherwise strand the minted session (pin/enrollment/attachment)
    // until manual delete. Release it now; for a running container the
    // session is closed later by sandbox_stop.
    if start_error.is_some() {
        close_session_best_effort(store, ctx, &sandbox.id);
    }

    let grant = if statements.is_empty() {
        crate::infra::sandbox::SandboxRunGrantDisposition::NotRequested
    } else {
        let policy_action = "credential.access".to_string();
        let eval = policy.evaluate(&policy_action);
        let risk_str = format!("{:?}", eval.risk).to_lowercase();
        let proposal = core_grant_types::GrantProposal {
            persona_id: sandbox.persona_id.clone(),
            statements,
            expires_at: ttl_secs,
            label: None,
            skill_ref: None,
            note: None,
        };

        match eval.requirement {
            ApprovalRequirement::Denied => {
                let credential_res = credential_resource.unwrap_or("");
                return Err(RpcError::PolicyDenied(format!(
                    "policy denied composite grant mint for {credential_res} (rule: {})",
                    eval.matched_rule.as_deref().unwrap_or("(default)")
                ))
                .into());
            }
            ApprovalRequirement::Required => {
                match store.propose_grant_typed(&proposal, &policy_action, &risk_str) {
                    Ok(req) => {
                        notify_require_approval(store, &req);
                        crate::infra::sandbox::SandboxRunGrantDisposition::PendingApproval {
                            approval_id: req.id,
                        }
                    }
                    Err(e) => crate::infra::sandbox::SandboxRunGrantDisposition::Failed {
                        message: format!("submitting approval failed: {e}"),
                    },
                }
            }
            ApprovalRequirement::Auto => {
                match store.propose_grant_typed(&proposal, &policy_action, &risk_str) {
                    Ok(req) => match store.auto_resolve(&req.id) {
                        Ok(()) => {
                            let grant_id = store
                                .get_approval(&req.id)
                                .ok()
                                .and_then(|r| r.result_grant_id);
                            crate::infra::sandbox::SandboxRunGrantDisposition::Minted { grant_id }
                        }
                        Err(e) => crate::infra::sandbox::SandboxRunGrantDisposition::Failed {
                            message: format!("auto-resolve failed: {e}"),
                        },
                    },
                    Err(e) => crate::infra::sandbox::SandboxRunGrantDisposition::Failed {
                        message: format!("submitting approval failed: {e}"),
                    },
                }
            }
        }
    };

    serde_json::to_value(crate::infra::sandbox::SandboxRunResult {
        sandbox,
        container_id,
        start_error,
        grant,
    })
    .map_err(|e| RpcError::Internal(format!("serialize SandboxRunResult: {e}")).into())
}
