use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SandboxActionDispatch {
    DaemonRpc,
    LocalFallback,
}
pub(super) fn run_sandbox_create(
    config: &DaemonConfig,
    opts: &SandboxCreateOpts,
) -> Result<(SandboxActionDispatch, SandboxCreateResult), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let params = serde_json::to_value(opts)
            .map_err(|e| core_types::ValidationError::new(format!("sandbox_create params: {e}")))?;
        let result = emberlink_cli::call_daemon_method(&socket_path, "sandbox_create", &params)?;
        let created: SandboxCreateResult = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon sandbox_create: {e}")))?;
        Ok((SandboxActionDispatch::DaemonRpc, created))
    } else {
        let store = open_store(config);
        let sandbox = store
            .create_sandbox_with_opts(opts, Some(&config.data_dir))
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        // Local fallback (no daemon socket): no register_session, so no LLM lane
        // and no mTLS bridge control plane are minted — `bridge: None`. The
        // daemon-RPC path above (`sandbox_create`) is where the ADR 207 seam 6
        // bridge control plane is wired.
        let (container_id, start_error) = match store.start_container(
            &sandbox.id,
            opts.network.as_deref(),
            &opts.extra_env,
            None,
        ) {
            Ok(cid) => (Some(cid), None),
            Err(e) => (None, Some(e.to_string())),
        };
        Ok((
            SandboxActionDispatch::LocalFallback,
            SandboxCreateResult {
                sandbox,
                container_id,
                start_error,
            },
        ))
    }
}

pub(super) fn run_sandbox_list(
    config: &DaemonConfig,
) -> Result<(SandboxActionDispatch, Vec<SandboxInfo>), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "sandbox_list",
            &serde_json::Value::Null,
        )?;
        let sandboxes: Vec<SandboxInfo> = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon sandbox_list: {e}")))?;
        Ok((SandboxActionDispatch::DaemonRpc, sandboxes))
    } else {
        let store = open_store(config);
        let sandboxes = store
            .list_sandboxes()
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((SandboxActionDispatch::LocalFallback, sandboxes))
    }
}

pub(super) fn run_sandbox_stop(
    config: &DaemonConfig,
    id_or_name: &str,
) -> Result<(SandboxActionDispatch, String), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "sandbox_stop",
            &serde_json::json!({ "id_or_name": id_or_name }),
        )?;
        let resolved_id = result
            .get("resolved_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                core_types::ValidationError::new("daemon sandbox_stop: missing resolved_id")
            })?;
        Ok((SandboxActionDispatch::DaemonRpc, resolved_id.to_string()))
    } else {
        let store = open_store(config);
        let resolved_id = store
            .resolve_sandbox_id(id_or_name)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        store
            .stop_sandbox(&resolved_id, Some(&config.data_dir))
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((SandboxActionDispatch::LocalFallback, resolved_id))
    }
}

/// Anchor: sandbox_open_store_migration_resolved
///
/// ADR-131 EXCEPTION (META-AP-EMBER-CLI-OPEN-STORE-MIGRATE-SANDBOX, Path B):
/// Sandbox surface stays on direct `open_store` for the LocalFallback
/// branch only. Rationale —
///
/// (a) Primary path (daemon socket present) already routes through
///     `daemon_rpc::call("sandbox_delete", ...)` under the
///     separate-uid posture. ADR 131's intent is satisfied for the
///     load-bearing happy path.
/// (b) LocalFallback fires only when `socket_path.exists()` is false
///     — daemon unavailable, offline recovery, or pre-install. In
///     that scenario the CLI is the only viable actor and the
///     daemon-side RPC cannot be reached by definition. Forcing the
///     CLI to call a nonexistent RPC there would degrade the
///     recovery surface, not improve it.
/// (c) Per the parent META-AP-EMBER-CLI-OPEN-STORE-COMPLETE digest,
///     a Path-A migration (file `META-AP-DAEMON-SANDBOX-RPC-EXPOSE`
///     + thread sandbox actions through it) is the principled
///     long-term fix; it is intentionally out of scope here.
pub(super) fn run_sandbox_delete(
    config: &DaemonConfig,
    id_or_name: &str,
) -> Result<(SandboxActionDispatch, SandboxDeleteResult), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "sandbox_delete",
            &serde_json::json!({ "id_or_name": id_or_name }),
        )?;
        let deleted: SandboxDeleteResult = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon sandbox_delete: {e}")))?;
        Ok((SandboxActionDispatch::DaemonRpc, deleted))
    } else {
        // ADR-131 EXCEPTION: LocalFallback only (daemon socket absent).
        // See doc-comment on `run_sandbox_delete` for the carve-out
        // rationale and the META-AP-DAEMON-SANDBOX-RPC-EXPOSE pointer
        // that captures the long-term migration path.
        let deleted = run_sandbox_delete_local(&open_store(config), id_or_name)?;
        Ok((SandboxActionDispatch::LocalFallback, deleted))
    }
}

pub(super) fn run_sandbox_exec(
    config: &DaemonConfig,
    id_or_name: &str,
    caller_persona_id: Option<String>,
    command: &[String],
) -> Result<(SandboxActionDispatch, String), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let mut params = serde_json::json!({
            "id_or_name": id_or_name,
            "command": command,
        });
        if let Some(caller) = caller_persona_id.clone() {
            params["caller_persona_id"] = serde_json::json!(caller);
        }
        let result = emberlink_cli::call_daemon_method(&socket_path, "sandbox_exec", &params)?;
        let output = result
            .get("output")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                core_types::ValidationError::new("daemon sandbox_exec: missing output")
            })?;
        Ok((SandboxActionDispatch::DaemonRpc, output.to_string()))
    } else {
        let store = open_store(config);
        let resolved_id = store
            .resolve_sandbox_id(id_or_name)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        let caller_persona = caller_persona_id.unwrap_or_default();
        let refs: Vec<&str> = command.iter().map(String::as_str).collect();
        let output = store
            .exec_sandbox(&resolved_id, &refs, &caller_persona)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((SandboxActionDispatch::LocalFallback, output))
    }
}

pub(super) fn run_sandbox_run(
    config: &DaemonConfig,
    opts: &SandboxCreateOpts,
    statements: &[StatementProposal],
    ttl_secs: Option<u64>,
    credential_resource: Option<&str>,
) -> Result<(SandboxActionDispatch, SandboxRunResult), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "sandbox_run",
            &serde_json::json!({
                "sandbox": opts,
                "statements": statements,
                "ttl_secs": ttl_secs,
                "credential_resource": credential_resource,
            }),
        )?;
        let prepared: SandboxRunResult = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon sandbox_run: {e}")))?;
        Ok((SandboxActionDispatch::DaemonRpc, prepared))
    } else {
        let store = open_store(config);
        let sandbox = store
            .create_sandbox_with_opts(opts, Some(&config.data_dir))
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        // Local fallback (no daemon socket): no register_session ⇒ no LLM lane
        // and no mTLS bridge control plane (`bridge: None`). Network arg stays
        // `None` (default bridge) to preserve the prior local-fallback behavior.
        let (container_id, start_error) =
            match store.start_container(&sandbox.id, None, &opts.extra_env, None) {
                Ok(cid) => (Some(cid), None),
                Err(e) => (None, Some(e.to_string())),
            };

        let grant = if statements.is_empty() {
            SandboxRunGrantDisposition::NotRequested
        } else {
            let policy_engine = if config.policy_file.exists() {
                ember_daemon::trust::policy::PolicyEngine::from_file(&config.policy_file)
                    .unwrap_or_default()
            } else {
                ember_daemon::trust::policy::PolicyEngine::default()
            };
            let policy_action = "credential.access".to_string();
            let eval = policy_engine.evaluate(&policy_action);
            let risk_str = format!("{:?}", eval.risk).to_lowercase();
            let grant_proposal = GrantProposal {
                persona_id: sandbox.persona_id.clone(),
                statements: statements.to_vec(),
                expires_at: ttl_secs,
                label: None,
                skill_ref: None,
                note: None,
            };

            match eval.requirement {
                ember_daemon::trust::policy::ApprovalRequirement::Denied => {
                    let credential_res = credential_resource.unwrap_or("");
                    return Err(core_types::ValidationError::new(format!(
                        "policy denied composite grant mint for {credential_res} (rule: {})",
                        eval.matched_rule.as_deref().unwrap_or("(default)")
                    )));
                }
                ember_daemon::trust::policy::ApprovalRequirement::Required => {
                    match store.propose_grant_typed(&grant_proposal, &policy_action, &risk_str) {
                        Ok(req) => SandboxRunGrantDisposition::PendingApproval {
                            approval_id: req.id,
                        },
                        Err(e) => SandboxRunGrantDisposition::Failed {
                            message: format!("submitting approval failed: {e}"),
                        },
                    }
                }
                ember_daemon::trust::policy::ApprovalRequirement::Auto => {
                    match store.propose_grant_typed(&grant_proposal, &policy_action, &risk_str) {
                        Ok(req) => match store.auto_resolve(&req.id) {
                            Ok(()) => {
                                let grant_id = store
                                    .get_approval(&req.id)
                                    .ok()
                                    .and_then(|r| r.result_grant_id);
                                SandboxRunGrantDisposition::Minted { grant_id }
                            }
                            Err(e) => SandboxRunGrantDisposition::Failed {
                                message: format!("auto-resolve failed: {e}"),
                            },
                        },
                        Err(e) => SandboxRunGrantDisposition::Failed {
                            message: format!("submitting approval failed: {e}"),
                        },
                    }
                }
            }
        };

        Ok((
            SandboxActionDispatch::LocalFallback,
            SandboxRunResult {
                sandbox,
                container_id,
                start_error,
                grant,
            },
        ))
    }
}
/// Return the `docker exec` flags appropriate for the caller's TTY state.
///
/// When stdin is a TTY both `-i` (keep stdin open) and `-t` (allocate a
/// pseudo-TTY) are useful for interactive sessions.  When stdin is **not** a
/// TTY (CI, pipes, headless agents) passing `-t` causes Docker to fail with
/// "the input device is not a TTY".  In that case only `-i` is emitted.
pub(super) fn docker_exec_flags(is_tty: bool) -> Vec<&'static str> {
    if is_tty { vec!["-i", "-t"] } else { vec!["-i"] }
}
/// Local fallback for `ember sandbox delete <id|name>`.
///
/// Resolves the argument to a sandbox UUID, then asks the store to delete the
/// row + container + auto-created persona (when unreferenced). Idempotent: a
/// missing sandbox returns `already_absent = true` so callers can preserve the
/// friendly "already deleted" UX without hard-exiting.
pub(super) fn run_sandbox_delete_local(
    store: &DaemonStore,
    id_or_name: &str,
) -> Result<SandboxDeleteResult, core_types::ValidationError> {
    match store.resolve_sandbox_id(id_or_name) {
        Ok(resolved_id) => {
            // Local fallback: no bridge certs were minted here, so `None` cleans
            // the recorded workspace path (the daemon RPC path passes `data_dir`).
            store
                .delete_sandbox(&resolved_id, None)
                .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
            Ok(SandboxDeleteResult {
                resolved_id: Some(resolved_id),
                already_absent: false,
            })
        }
        Err(ember_daemon::infra::store::StoreError::NotFound) => Ok(SandboxDeleteResult {
            resolved_id: None,
            already_absent: true,
        }),
        Err(e) => Err(core_types::ValidationError::new(e.to_string())),
    }
}
