//! Broker exec admission.
//!
//! This Module is the ADR 183/184 narrow waist for `broker_exec`: collapse the
//! raw RPC request plus any resolve-time spawn handle into one canonical
//! authority-side [`ExecutionContract`], then select the runner-local dispatch
//! facts from that contract. It intentionally does not mint credentials or spawn
//! processes.

use core_event_types::{ActionRef, ExecutionContract};

use crate::broker::runners::{
    RunnerDispatchResolution, dispatch_runner_for_exec_with_workspace_path,
};
use crate::infra::attachment::AttachmentAuthority;

use super::exec_policy::{BrokerExecRequest, inherit_execution_contract_from_resolve};
use super::registry::PendingSpawnHandle;

#[derive(Debug)]
pub(super) struct BrokerExecAdmission {
    pub(super) execution_contract: ExecutionContract,
    pub(super) contract_id: String,
    pub(super) action_ref: ActionRef,
    pub(super) workspace_ref: Option<String>,
    pub(super) subject_ref: Option<String>,
    pub(super) coordination_ref: Option<String>,
    pub(super) caller_ref: Option<String>,
    pub(super) authority_ref: Option<String>,
    pub(super) runner_resolution: RunnerDispatchResolution,
}

pub(super) fn admit_broker_exec_contract(
    req: &BrokerExecRequest,
    pending_spawn_handle: Option<&PendingSpawnHandle>,
    attachment_authority: Option<&AttachmentAuthority>,
) -> Result<BrokerExecAdmission, (i32, String)> {
    let request_contract = req
        .execution_contract
        .clone()
        .ok_or((-32602, "broker_exec missing_execution_contract".to_string()))?;
    let mut execution_contract = if let Some(handle) = pending_spawn_handle {
        inherit_execution_contract_from_resolve(request_contract, &handle.execution_contract)?
    } else {
        request_contract
    };

    let contract_id = execution_contract
        .contract_id
        .clone()
        .unwrap_or_else(|| format!("contract-{}", uuid::Uuid::new_v4()));
    if execution_contract.contract_id.is_none() {
        execution_contract.contract_id = Some(contract_id.clone());
    }

    execution_contract
        .validate()
        .map_err(|e| (-32602, format!("invalid execution_contract: {e}")))?;

    let action_ref = execution_contract.action_ref.clone();
    let workspace_ref = execution_contract.workspace_ref.clone();
    let subject_ref = execution_contract.subject_ref.clone();
    let coordination_ref = execution_contract.coordination_ref.clone();
    let caller_ref = execution_contract.caller_ref.clone();
    let authority_ref = execution_contract.authority_ref.clone();

    let compatibility_cwd = if workspace_ref.is_some() {
        if let Some(cwd) = req.cwd.as_deref().filter(|value| !value.is_empty()) {
            tracing::warn!(
                cwd = %cwd,
                "broker_exec: deprecated cwd compatibility fallback ignored because nested execution_contract.workspace_ref is present"
            );
        }
        None
    } else {
        req.cwd.clone().filter(|value| !value.is_empty())
    };

    let workspace_path_hint = attachment_authority.and_then(|authority| {
        let workspace_ref = workspace_ref.as_deref()?;
        let authority_ref = authority.workspace_ref.as_deref()?;
        (workspace_ref == authority_ref)
            .then_some(authority.worktree_path.as_deref())
            .flatten()
    });

    let runner_resolution = dispatch_runner_for_exec_with_workspace_path(
        &execution_contract,
        compatibility_cwd.as_deref(),
        workspace_path_hint,
    )
    .map_err(|e| e.into_rpc_error())?;

    Ok(BrokerExecAdmission {
        execution_contract,
        contract_id,
        action_ref,
        workspace_ref,
        subject_ref,
        coordination_ref,
        caller_ref,
        authority_ref,
        runner_resolution,
    })
}
