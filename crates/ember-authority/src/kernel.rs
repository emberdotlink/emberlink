use std::sync::Arc;

use crate::{
    action_admission::ActionAdmission,
    action_definition::ActionDefinitionRegistry,
    audit::{DurableStore, now_unix, sha256},
    device::DeviceCustody,
    model::{ActionRequest, ActionResponse, OperationStatus, Refusal, SessionState},
    network_enforcement::NetworkEnforcement,
    operation::{OperationSettlement, ReplayDisposition},
    runner::{JournalHealth, RunnerRegistry},
    runtime_presence::{AuthenticatedProcess, ExecutionBindingAuthority},
};

pub struct AuthorityKernel {
    store: Arc<DurableStore>,
}

impl AuthorityKernel {
    pub fn new(store: Arc<DurableStore>) -> Self {
        Self { store }
    }

    pub fn submit(
        &self,
        session_id: &str,
        authenticated_process: AuthenticatedProcess,
        request: ActionRequest,
    ) -> Result<ActionResponse, Refusal> {
        let journal = StoreJournalHealth {
            store: self.store.clone(),
        };
        self.submit_with_journal_at(
            session_id,
            authenticated_process,
            request,
            now_unix(),
            &journal,
        )
    }

    pub fn submit_with_journal_at(
        &self,
        session_id: &str,
        authenticated_process: AuthenticatedProcess,
        request: ActionRequest,
        now: u64,
        journal: &dyn JournalHealth,
    ) -> Result<ActionResponse, Refusal> {
        if request.schema != crate::model::ACTION_REQUEST_SCHEMA {
            return Err(Refusal::new("invalid_request"));
        }
        let submission_id = request.submission_id.as_str();
        let parsed_submission_id =
            uuid::Uuid::parse_str(submission_id).map_err(|_| Refusal::new("invalid_request"))?;
        if submission_id.len() != 36
            || parsed_submission_id.hyphenated().to_string() != submission_id
        {
            return Err(Refusal::new("invalid_request"));
        }
        request.input.validate()?;
        let expected_definition_digest = request.required_definition_digest()?;
        let input_bytes =
            serde_jcs::to_vec(&request.input).map_err(|_| Refusal::new("invalid_input"))?;
        let typed_input_digest = sha256(&input_bytes);

        let snapshot = self.store.snapshot()?;
        let session = snapshot
            .sessions
            .get(session_id)
            .cloned()
            .ok_or_else(|| Refusal::new("missing_session"))?;
        if session.state != SessionState::Active {
            return Err(Refusal::new("session_binding_mismatch"));
        }
        ExecutionBindingAuthority::revalidate(&session, authenticated_process)?;

        match OperationSettlement::replay_lookup(
            &self.store,
            session_id,
            &session.execution_binding_digest,
            &request.submission_id,
            &request,
        )? {
            ReplayDisposition::New => {}
            ReplayDisposition::Running => return Err(Refusal::new("replay_in_progress")),
            ReplayDisposition::Completed(operation, receipt) => {
                let facts = operation
                    .facts
                    .ok_or_else(|| Refusal::new("replayed_failure"))?;
                return Ok(ActionResponse {
                    action_ref: operation.action_ref,
                    definition_digest: operation.definition_digest,
                    facts,
                    operation_id: operation.operation_id,
                    receipt_id: receipt.row.receipt_id,
                    status: "success".into(),
                    classification: snapshot.classification.clone(),
                    initialization_evidence: snapshot.initialization.evidence.clone(),
                });
            }
        }

        let registry = ActionDefinitionRegistry::restore(&snapshot.registry_bytes)?;
        let definition = registry.resolve(&request.action_ref, expected_definition_digest, now)?;
        let decision = ActionAdmission::admit(
            &session,
            &definition,
            &request.input,
            now,
            &snapshot.qualification_coverage,
        )?;
        let custody = DeviceCustody::restore(&snapshot.devices)?;
        let permit = NetworkEnforcement::issue_action_permit(
            &snapshot.authority_fingerprint,
            snapshot.authority_epoch,
            &snapshot.installation_id,
            snapshot.initialization.evidence.release_manifest_digest(),
            &session,
            &request,
            &definition,
            &decision,
            &typed_input_digest,
            &custody,
            now,
        )?;
        let runner = RunnerRegistry::resolve(
            &permit,
            &snapshot.authority_fingerprint,
            snapshot.authority_epoch,
            &snapshot.installation_id,
            snapshot.initialization.evidence.release_manifest_digest(),
            &session,
            &request,
            &definition,
            &decision,
            &typed_input_digest,
            &custody,
            &snapshot.route,
            now,
        )?;
        let operation = OperationSettlement::begin(
            &self.store,
            &permit,
            &request,
            &definition,
            &decision,
            &typed_input_digest,
            authenticated_process,
            now,
        )?;

        let post_begin = self.store.snapshot()?;
        let post_begin_registry = ActionDefinitionRegistry::restore(&post_begin.registry_bytes)?;
        match runner.run(
            &permit,
            &request.input,
            journal,
            &post_begin_registry,
            post_begin.authority_epoch,
            now,
        ) {
            Ok(facts) => {
                // Success liveness is revalidated while the settlement owner
                // holds the state transaction. A lost binding is atomically
                // terminalized as effect-unknown rather than committed success.
                let (operation, receipt) = OperationSettlement::settle(
                    &self.store,
                    &operation.operation_id,
                    OperationStatus::Success,
                    Some(facts.clone()),
                    None,
                    Some(authenticated_process),
                    now_unix().max(now),
                )?;
                if operation.status != OperationStatus::Success {
                    return Err(Refusal::new("session_binding_mismatch"));
                }
                Ok(ActionResponse {
                    action_ref: operation.action_ref,
                    definition_digest: operation.definition_digest,
                    facts,
                    operation_id: operation.operation_id,
                    receipt_id: receipt.row.receipt_id,
                    status: "success".into(),
                    classification: snapshot.classification.clone(),
                    initialization_evidence: snapshot.initialization.evidence.clone(),
                })
            }
            Err(_) => {
                OperationSettlement::settle(
                    &self.store,
                    &operation.operation_id,
                    OperationStatus::ExecutionFailure,
                    None,
                    Some("runner_failed"),
                    None,
                    now_unix().max(now),
                )?;
                Err(Refusal::new("runner_failed"))
            }
        }
    }
}

struct StoreJournalHealth {
    store: Arc<DurableStore>,
}

impl JournalHealth for StoreJournalHealth {
    fn health(&self) -> Result<&'static str, Refusal> {
        crate::audit::EvidenceJournal::health(&self.store.snapshot()?)
    }
}
