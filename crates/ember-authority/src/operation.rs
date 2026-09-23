use crate::{
    action_admission::{ActionAdmission, AdmissionDecision},
    action_definition::{ActionDefinitionRegistry, ResolvedDefinition},
    audit::{DurableStore, EvidenceJournal, now_unix, sha256},
    canonical::LenEncoder,
    device::DeviceCustody,
    model::{
        ActionPermit, ActionRequest, AuthorizationSnapshot, DiagnosticFacts, OperationRecord,
        OperationStatus, Refusal, StoredReceipt, SubmissionBinding,
    },
    network_enforcement::NetworkEnforcement,
    runtime_presence::{AuthenticatedProcess, ExecutionBindingAuthority},
};

pub enum ReplayDisposition {
    New,
    Completed(OperationRecord, StoredReceipt),
    Running,
}

pub struct OperationSettlement;

impl OperationSettlement {
    pub fn replay_lookup(
        store: &DurableStore,
        session_id: &str,
        execution_binding_digest: &str,
        submission_id: &str,
        request: &ActionRequest,
    ) -> Result<ReplayDisposition, Refusal> {
        let state = store.snapshot()?;
        let session = state
            .sessions
            .get(session_id)
            .ok_or_else(|| Refusal::new("session_binding_mismatch"))?;
        let key = submission_binding_key(
            &state.authority_fingerprint,
            &session.persona_id,
            session_id,
            execution_binding_digest,
            submission_id,
        )?;
        let Some(binding) = state.submissions.get(&key) else {
            return Ok(ReplayDisposition::New);
        };
        let canonical_request_digest =
            sha256(&serde_jcs::to_vec(request).map_err(|_| Refusal::new("invalid_request"))?);
        if binding.canonical_request_digest != canonical_request_digest {
            return Err(Refusal::new("replay_conflict"));
        }
        let operation = state
            .operations
            .get(&binding.operation_id)
            .cloned()
            .ok_or_else(|| Refusal::new("state_unavailable"))?;
        if operation.status == OperationStatus::Running {
            return Ok(ReplayDisposition::Running);
        }
        let receipt_id = operation
            .receipt_id
            .as_ref()
            .ok_or_else(|| Refusal::new("state_unavailable"))?;
        let receipt = state
            .receipts
            .get(receipt_id)
            .cloned()
            .ok_or_else(|| Refusal::new("state_unavailable"))?;
        Ok(ReplayDisposition::Completed(operation, receipt))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        store: &DurableStore,
        permit: &ActionPermit,
        request: &ActionRequest,
        definition: &ResolvedDefinition,
        decision: &AdmissionDecision,
        typed_input_digest: &str,
        observed_process: AuthenticatedProcess,
        now: u64,
    ) -> Result<OperationRecord, Refusal> {
        store.transaction(|state| {
            let session = state
                .sessions
                .get(&permit.session_id)
                .cloned()
                .ok_or_else(|| Refusal::new("session_binding_mismatch"))?;
            ExecutionBindingAuthority::revalidate(&session, observed_process)?;
            let registry = ActionDefinitionRegistry::restore(&state.registry_bytes)?;
            let resolved =
                registry.resolve(&request.action_ref, &request.definition_digest, now)?;
            if resolved.digest != definition.digest || resolved.definition != definition.definition
            {
                return Err(Refusal::new("definition_digest_mismatch"));
            }
            let repeated_decision = ActionAdmission::admit(
                &session,
                &resolved,
                &request.input,
                now,
                &state.qualification_coverage,
            )?;
            if repeated_decision.need != decision.need
                || repeated_decision.grant != decision.grant
                || repeated_decision.grant_use_ceiling != decision.grant_use_ceiling
                || repeated_decision.consequence_class != decision.consequence_class
                || repeated_decision.assurance_profile_id != decision.assurance_profile_id
                || repeated_decision.assurance_profile_digest != decision.assurance_profile_digest
                || repeated_decision.qualification_coverage != decision.qualification_coverage
            {
                return Err(Refusal::new("authorization_invalid"));
            }
            let custody = DeviceCustody::restore(&state.devices)?;
            NetworkEnforcement::verify_action_permit(
                permit,
                &state.authority_fingerprint,
                state.authority_epoch,
                &state.installation_id,
                &state.release_manifest_digest,
                &session,
                request,
                &resolved,
                &repeated_decision,
                typed_input_digest,
                &custody,
                now,
            )?;
            if state.used_permit_nonces.contains_key(&permit.nonce) {
                return Err(Refusal::new("authorization_replayed"));
            }
            let submission_binding_key = submission_binding_key(
                &state.authority_fingerprint,
                &session.persona_id,
                &session.session_id,
                &session.execution_binding_digest,
                &request.submission_id,
            )?;
            let canonical_request_digest =
                sha256(&serde_jcs::to_vec(request).map_err(|_| Refusal::new("invalid_request"))?);
            if let Some(existing) = state.submissions.get(&submission_binding_key) {
                if existing.canonical_request_digest == canonical_request_digest {
                    return Err(Refusal::new("replay_in_progress"));
                }
                return Err(Refusal::new("replay_conflict"));
            }
            let operation_id = permit
                .operation_id
                .clone()
                .ok_or_else(|| Refusal::new("authorization_invalid"))?;
            let operation_key = operation_key(
                &state.authority_fingerprint,
                &session.persona_id,
                &session.session_id,
                &session.execution_binding_digest,
                &request.definition_digest,
                &request.submission_id,
            )?;
            let operation = OperationRecord {
                operation_id: operation_id.clone(),
                operation_key,
                submission_binding_key: submission_binding_key.clone(),
                submission_id: request.submission_id.clone(),
                session_id: session.session_id.clone(),
                execution_binding_digest: session.execution_binding_digest.clone(),
                action_ref: request.action_ref.clone(),
                definition_digest: request.definition_digest.clone(),
                typed_input_digest: typed_input_digest.into(),
                authorization: AuthorizationSnapshot {
                    permit: permit.clone(),
                    persona_id: session.persona_id.clone(),
                    delegation_id: session.grant.delegation_id.clone(),
                    grant_id: session.grant.grant_id.clone(),
                    need: decision.need.clone(),
                    grant_use: decision.grant.clone(),
                    registry_sequence: state.registry_sequence,
                    definition_resolved_at: now,
                    qualification_coverage: decision.qualification_coverage.clone(),
                    canonical_request_digest: canonical_request_digest.clone(),
                },
                started_at: now,
                completed_at: None,
                status: OperationStatus::Running,
                facts: None,
                receipt_id: None,
                failure_code: None,
                cleanup_state: "complete".into(),
            };
            let grant = state
                .sessions
                .get_mut(&session.session_id)
                .ok_or_else(|| Refusal::new("session_binding_mismatch"))?;
            if grant.grant.remaining_uses == 0 {
                return Err(Refusal::new("uncovered_need"));
            }
            grant.grant.remaining_uses -= 1;
            state
                .used_permit_nonces
                .insert(permit.nonce.clone(), operation_id.clone());
            state.submissions.insert(
                submission_binding_key,
                SubmissionBinding {
                    canonical_request_digest,
                    operation_id: operation_id.clone(),
                },
            );
            state.operations.insert(operation_id, operation.clone());
            Ok(operation)
        })
    }

    pub fn settle(
        store: &DurableStore,
        operation_id: &str,
        status: OperationStatus,
        facts: Option<DiagnosticFacts>,
        failure_code: Option<&str>,
        completed_at: u64,
    ) -> Result<(OperationRecord, StoredReceipt), Refusal> {
        store.transaction(|state| {
            let current = state
                .operations
                .get(operation_id)
                .cloned()
                .ok_or_else(|| Refusal::new("operation_not_found"))?;
            if current.status != OperationStatus::Running {
                let identical = current.status == status
                    && current.facts == facts
                    && current.failure_code.as_deref() == failure_code;
                if !identical {
                    return Err(Refusal::new("duplicate_settlement_conflict"));
                }
                let receipt = current
                    .receipt_id
                    .as_ref()
                    .and_then(|id| state.receipts.get(id))
                    .cloned()
                    .ok_or_else(|| Refusal::new("state_unavailable"))?;
                return Ok((current, receipt));
            }
            if status == OperationStatus::Running {
                return Err(Refusal::new("settlement_invalid"));
            }
            if status == OperationStatus::Success {
                let session = state
                    .sessions
                    .get(&current.session_id)
                    .ok_or_else(|| Refusal::new("session_binding_mismatch"))?;
                if session.execution_binding_digest != current.execution_binding_digest {
                    return Err(Refusal::new("session_binding_mismatch"));
                }
            }
            let custody = DeviceCustody::restore(&state.devices)?;
            let receipt_signer = custody.receipt_signer()?;
            let receipt = EvidenceJournal::append_terminal(
                state,
                &current,
                facts.as_ref(),
                status.clone(),
                failure_code,
                &receipt_signer,
                completed_at,
            )?;
            let operation = state
                .operations
                .get_mut(operation_id)
                .ok_or_else(|| Refusal::new("operation_not_found"))?;
            operation.status = status;
            operation.facts = facts;
            operation.failure_code = failure_code.map(str::to_owned);
            operation.completed_at = Some(completed_at);
            operation.receipt_id = Some(receipt.row.receipt_id.clone());
            Ok((operation.clone(), receipt))
        })
    }

    pub fn recover_running(store: &DurableStore) -> Result<(), Refusal> {
        let running = store
            .snapshot()?
            .operations
            .values()
            .filter(|operation| operation.status == OperationStatus::Running)
            .map(|operation| operation.operation_id.clone())
            .collect::<Vec<_>>();
        for operation_id in running {
            Self::settle(
                store,
                &operation_id,
                OperationStatus::EffectUnknown,
                None,
                Some("effect_unknown"),
                now_unix(),
            )?;
        }
        Ok(())
    }
}

pub fn submission_binding_key(
    authority_fingerprint: &str,
    persona_id: &str,
    session_id: &str,
    execution_binding_digest: &str,
    submission_id: &str,
) -> Result<String, Refusal> {
    let mut e = LenEncoder::new("ember/action-submission-binding-key/v1")?;
    e.digest(authority_fingerprint)?
        .string(persona_id)?
        .string(session_id)?
        .digest(execution_binding_digest)?
        .string(submission_id)?;
    Ok(sha256(&e.finish()))
}

fn operation_key(
    authority_fingerprint: &str,
    persona_id: &str,
    session_id: &str,
    execution_binding_digest: &str,
    definition_digest: &str,
    submission_id: &str,
) -> Result<String, Refusal> {
    let mut e = LenEncoder::new("ember/action-operation-key/v1")?;
    e.digest(authority_fingerprint)?
        .string(persona_id)?
        .string(session_id)?
        .digest(execution_binding_digest)?
        .digest(definition_digest)?
        .string(submission_id)?;
    Ok(sha256(&e.finish()))
}
