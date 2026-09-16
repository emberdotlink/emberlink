use std::{
    collections::BTreeSet,
    io::Read,
    sync::Arc,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use thiserror::Error;

use crate::{
    artifact::{ArtifactError, ArtifactStore, ImportedArtifact},
    audit::{
        EvidenceJournal, EvidenceLinks, JournalError, JournalTransaction, PrimaryEvidence,
        encode_audit_fact,
    },
    model::{
        ActionBoundary, ActionFacts, ActionRequest, AuditCommitment, AuditFact, DelegationId,
        EventKind, EvidenceId, GrantId, JournalSequence, MaterializationId,
        OPERATION_RESULT_SCHEMA, OperationEvidenceRef, OperationId, OperationOutcome,
        OperationResult, PersonaId, ProcessBindingId, ProviderEvidence, RequestDigest,
        RunnerEvidence, SessionId, SubmissionBinding, SubmissionId, SubmissionResolution,
        TerminalStatus,
    },
    pack::{PackError, PackRegistry},
    principal::{
        AuthorityDecision, AuthorityError, ExecutableDigest, GrantSelection, PersonaAuthority,
        PresenceVerifier, ProcessOrigin, ProcessRegistrationChallenge, ReconnectProof,
        SessionContext, SessionIdentity,
    },
    provider::{MintedCredential, ProviderError, ProviderRegistry, RecoveryReport},
    recovery::{RecoveryError, RecoveryJournal},
    runner::{RunnerFailureKind, RunnerRegistry, RunnerValidation},
    sha256_hex,
};

struct OperationTiming {
    started_at_unix: i64,
    accepted_at: Option<Instant>,
    forced_elapsed: Option<Duration>,
}

impl OperationTiming {
    fn accepted(started_at_unix: i64, forced_elapsed: Option<Duration>) -> Self {
        Self {
            started_at_unix,
            accepted_at: Some(Instant::now()),
            forced_elapsed,
        }
    }

    fn fixed(now_unix: i64) -> Self {
        Self {
            started_at_unix: now_unix,
            accepted_at: None,
            forced_elapsed: None,
        }
    }

    fn completed_at_unix(&self) -> i64 {
        let elapsed = self
            .forced_elapsed
            .or_else(|| self.accepted_at.map(|accepted_at| accepted_at.elapsed()))
            .unwrap_or_default();
        self.started_at_unix
            .saturating_add(i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
    }
}

#[derive(Clone)]
struct ResultAttribution {
    submission_id: Option<SubmissionId>,
    request_digest: Option<RequestDigest>,
    persona_id: PersonaId,
    session_id: SessionId,
    process_binding_id: ProcessBindingId,
    grant_id: Option<GrantId>,
    delegation_path: Vec<DelegationId>,
}

impl From<SessionIdentity> for ResultAttribution {
    fn from(identity: SessionIdentity) -> Self {
        Self {
            submission_id: None,
            request_digest: None,
            persona_id: identity.persona_id,
            session_id: identity.session_id,
            process_binding_id: identity.process_binding_id,
            grant_id: None,
            delegation_path: Vec::new(),
        }
    }
}

fn operation_result_key(operation_id: &OperationId) -> String {
    format!("operation-result/{}", operation_id.as_str())
}

fn operation_binding_key(operation_id: &OperationId) -> String {
    format!("operation-binding/{}", operation_id.as_str())
}

fn submission_binding_key(submission_id: SubmissionId) -> String {
    format!(
        "submission-binding/{}",
        hex::encode(submission_id.as_bytes())
    )
}

fn authority_gap_binding_key(submission_id: SubmissionId) -> String {
    format!(
        "authority-gap-binding/{}",
        hex::encode(submission_id.as_bytes())
    )
}

fn transaction_id(operation_id: &OperationId, first_sequence: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"ember.authority-journal.transaction/v1\0");
    digest.update(operation_id.as_str().as_bytes());
    digest.update(first_sequence.to_be_bytes());
    digest.finalize().into()
}

fn evidence_id(operation_id: &OperationId, sequence: u64, event: EventKind) -> EvidenceId {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"ember.audit-fact.evidence-id/v1\0");
    digest.update(operation_id.as_str().as_bytes());
    digest.update(sequence.to_be_bytes());
    digest.update([event as u8]);
    EvidenceId::from_bytes(digest.finalize().into())
}

impl From<AuthorityDecision> for ResultAttribution {
    fn from(decision: AuthorityDecision) -> Self {
        Self {
            submission_id: None,
            request_digest: None,
            persona_id: decision.persona_id,
            session_id: decision.session_id,
            process_binding_id: decision.process_binding_id,
            grant_id: Some(decision.grant_id),
            delegation_path: decision.delegation_path,
        }
    }
}

#[derive(Clone)]
struct PendingEvidence {
    event: EventKind,
    links: EvidenceLinks,
}

/// Generic authority chokepoint. Callers submit only a signed-pack action and
/// typed input; every authority and execution coordinate is held behind this
/// module's interface.
pub struct AuthorityKernel {
    authority: PersonaAuthority,
    packs: PackRegistry,
    providers: ProviderRegistry,
    artifacts: ArtifactStore,
    journal: Arc<EvidenceJournal>,
    pending_evidence: Vec<PendingEvidence>,
    recovery: RecoveryJournal,
    runners: RunnerRegistry,
    startup_recovered: bool,
}

impl AuthorityKernel {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority: PersonaAuthority,
        packs: PackRegistry,
        providers: ProviderRegistry,
        artifacts: ArtifactStore,
        journal: Arc<EvidenceJournal>,
        recovery: RecoveryJournal,
        runners: RunnerRegistry,
    ) -> Self {
        Self {
            authority,
            packs,
            providers,
            artifacts,
            journal,
            pending_evidence: Vec::new(),
            recovery,
            runners,
            startup_recovered: false,
        }
    }

    fn verified_snapshot(&self) -> Result<crate::audit::VerifiedSnapshot, SubmitError> {
        self.journal
            .verified_snapshot()
            .map_err(SubmitError::Journal)
    }

    fn load_result(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<OperationResult>, SubmitError> {
        self.verified_snapshot()?
            .state(&operation_result_key(operation_id))
            .map(serde_json::from_slice)
            .transpose()
            .map_err(SubmitError::MalformedStoredResult)
    }

    fn binding_for_operation(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<SubmissionBinding>, SubmitError> {
        self.verified_snapshot()?
            .state(&operation_binding_key(operation_id))
            .map(serde_json::from_slice)
            .transpose()
            .map_err(SubmitError::MalformedStoredBinding)
    }

    fn resolve_submission(
        &self,
        submission_id: SubmissionId,
        request_digest: RequestDigest,
    ) -> Result<SubmissionResolution, SubmitError> {
        let snapshot = self.verified_snapshot()?;
        let Some(bytes) = snapshot.state(&submission_binding_key(submission_id)) else {
            return Ok(SubmissionResolution::Admit);
        };
        let binding: SubmissionBinding =
            serde_json::from_slice(bytes).map_err(SubmitError::MalformedStoredBinding)?;
        Ok(if binding.request_digest() == request_digest {
            SubmissionResolution::Existing(binding.operation_id().clone())
        } else {
            SubmissionResolution::Conflict {
                existing_operation_id: binding.operation_id().clone(),
            }
        })
    }

    fn resolve_authority_gap(
        &self,
        submission_id: SubmissionId,
        request_digest: RequestDigest,
    ) -> Result<SubmissionResolution, SubmitError> {
        let snapshot = self.verified_snapshot()?;
        let Some(bytes) = snapshot.state(&authority_gap_binding_key(submission_id)) else {
            return Ok(SubmissionResolution::Admit);
        };
        let binding: SubmissionBinding =
            serde_json::from_slice(bytes).map_err(SubmitError::MalformedStoredBinding)?;
        Ok(if binding.request_digest() == request_digest {
            SubmissionResolution::Existing(binding.operation_id().clone())
        } else {
            SubmissionResolution::Conflict {
                existing_operation_id: binding.operation_id().clone(),
            }
        })
    }

    fn bind_submission(
        &mut self,
        binding: &SubmissionBinding,
    ) -> Result<SubmissionResolution, SubmitError> {
        match self.resolve_submission(binding.submission_id(), binding.request_digest())? {
            SubmissionResolution::Admit => {}
            resolution => return Ok(resolution),
        }
        let operation = binding.operation_id().clone();
        self.journal.commit_with_sequence(|sequence| {
            let fact = AuditFact::new(
                evidence_id(&operation, sequence, EventKind::OperationAdmitted),
                JournalSequence::new(sequence).ok_or(JournalError::SequenceOverflow)?,
                EventKind::OperationAdmitted,
                Some(OperationEvidenceRef::operation(operation.clone())),
            )
            .map_err(|error| JournalError::InvalidPreparedEvidence(error.to_string()))?;
            let mut transaction = JournalTransaction::new(transaction_id(&operation, sequence));
            transaction.push_evidence(
                PrimaryEvidence::audit_fact(
                    &fact,
                    EvidenceLinks {
                        operation_id: Some(operation.clone()),
                        ..EvidenceLinks::default()
                    },
                )?,
                None,
            );
            let canonical = serde_jcs::to_vec(binding).map_err(JournalError::Canonicalize)?;
            transaction.put_state(
                submission_binding_key(binding.submission_id()),
                canonical.clone(),
            );
            transaction.put_state(operation_binding_key(&operation), canonical);
            transaction.delete_state(authority_gap_binding_key(binding.submission_id()));
            Ok(transaction)
        })?;
        Ok(SubmissionResolution::Admit)
    }

    fn append_evidence(
        &mut self,
        operation_id: &OperationId,
        _at_unix: i64,
        kind: &'static str,
        data: Value,
    ) -> Result<(), JournalError> {
        let event = match kind {
            "operation.accepted" | "grant.admitted" => EventKind::OperationAdmitted,
            "action.resolved" => EventKind::ActionResolved,
            "artifact.verified" => EventKind::ArtifactVerified,
            "provider.materialized" => EventKind::CredentialMaterialized,
            "runner.exit" => EventKind::RunnerExecutionOutcome,
            "provider.settlement" => EventKind::ProviderSettlement,
            "provider.recovery" => EventKind::StartupRecoverySettlement,
            "operation.terminal" => EventKind::OperationTerminal,
            _ => return Err(JournalError::InvalidEventKind),
        };
        let materialization_id = data
            .get("materialization_id")
            .and_then(Value::as_str)
            .map(|value| MaterializationId(value.to_owned()));
        self.pending_evidence.push(PendingEvidence {
            event,
            links: EvidenceLinks {
                operation_id: Some(operation_id.clone()),
                materialization_id,
                ..EvidenceLinks::default()
            },
        });
        Ok(())
    }

    /// Resolves or safely quarantines every unresolved mint record before
    /// enabling launch or use.
    pub fn recover_startup(&mut self, now_unix: i64) -> Result<RecoveryReport, SubmitError> {
        self.startup_recovered = false;
        self.journal
            .recover_startup()
            .map_err(SubmitError::Journal)?;
        let recovery_timing = OperationTiming::fixed(now_unix);
        let mut result_proven_revocations = BTreeSet::new();
        for entry in self.recovery.unresolved()? {
            if let Some(result) = self.load_result(&entry.context().operation_id)?
                && result.upstream_revoked
                && result.outcome.materialization_id() == Some(entry.materialization_id())
            {
                result_proven_revocations.insert(entry.materialization_id().clone());
            }
        }

        let outcomes = self
            .providers
            .recover(&self.recovery, &result_proven_revocations)?;
        let quarantined = outcomes
            .iter()
            .filter(|outcome| outcome.quarantined)
            .count();
        let attempted = outcomes.len();
        for outcome in outcomes {
            self.append_evidence(
                &outcome.context.operation_id,
                now_unix,
                "provider.recovery",
                json!({
                    "materialization_id": outcome.materialization_id,
                    "provider": outcome.context.provider,
                    "upstream_revoked": outcome.upstream_revoked,
                    "settlement_ready": outcome.settlement_ready,
                    "message": outcome.message,
                }),
            )?;

            if self.load_result(&outcome.context.operation_id)?.is_some() {
                if outcome.settlement_ready {
                    self.recovery.settle(&outcome.materialization_id)?;
                }
                continue;
            }

            let status = if outcome.upstream_revoked {
                TerminalStatus::ExecutionFailure
            } else {
                TerminalStatus::CompletedButUnsettled
            };
            let provider_materialization = outcome
                .context
                .provider
                .map(|provider| (provider, outcome.materialization_id.clone()));
            let binding = self
                .binding_for_operation(&outcome.context.operation_id)?
                .ok_or_else(|| SubmitError::MissingSubmissionBinding {
                    operation_id: outcome.context.operation_id.clone(),
                })?;
            let attribution = ResultAttribution {
                submission_id: Some(binding.submission_id()),
                request_digest: Some(binding.request_digest()),
                persona_id: outcome.context.persona_id.clone(),
                session_id: outcome.context.session_id.clone(),
                process_binding_id: outcome.context.process_binding_id.clone(),
                grant_id: Some(outcome.context.grant_id.clone()),
                delegation_path: outcome.context.delegation_path.clone(),
            };
            self.terminal(
                outcome.context.operation_id,
                &attribution,
                &recovery_timing,
                status,
                Some(outcome.context.action),
                Some(outcome.context.approved_input),
                Some(outcome.context.need),
                provider_materialization,
                None,
                outcome.upstream_revoked,
                outcome.message,
            )?;
            if outcome.settlement_ready && !outcome.upstream_revoked {
                self.recovery.settle(&outcome.materialization_id)?;
            }
        }
        let unresolved = self.recovery.unresolved()?.len();
        let report = RecoveryReport {
            settled: attempted.saturating_sub(unresolved),
            quarantined,
            unresolved,
        };
        // Any remaining entry is either tied to no installed generation or has
        // caused that exact generation to be quarantined during this pass.
        self.startup_recovered = true;
        Ok(report)
    }

    /// Creates a Session and one-time challenge for its trusted launch report.
    pub fn create_session(
        &mut self,
        persona: &PersonaId,
        reviewed_executable: ExecutableDigest,
    ) -> Result<(SessionId, ProcessRegistrationChallenge), SubmitError> {
        self.require_ready()?;
        self.authority
            .sessions()
            .create(persona, reviewed_executable)
            .map_err(SubmitError::Authority)
    }

    /// Registers the exact process spawned for a Session.
    ///
    /// The challenge is consumed by every attempt, including a failed report.
    pub fn bind_session_origin(
        &mut self,
        session: &SessionId,
        challenge: &ProcessRegistrationChallenge,
        observed_origin: ProcessOrigin,
    ) -> Result<ProcessBindingId, SubmitError> {
        self.require_ready()?;
        self.authority
            .sessions()
            .bind_origin(session, challenge, observed_origin)
            .map_err(SubmitError::Authority)
    }

    /// Attaches selected immutable Grant ceilings under one presence check.
    pub fn attach_selected_grants(
        &mut self,
        presence: &mut impl PresenceVerifier,
        session: &SessionId,
        grants: Vec<(DelegationId, GrantSelection)>,
        now_unix: i64,
        requested_ttl: Duration,
    ) -> Result<Vec<DelegationId>, SubmitError> {
        self.require_ready()?;
        self.authority
            .management()
            .attach_selected_grants(presence, session, grants, now_unix, requested_ttl)
            .map_err(SubmitError::Authority)
    }

    /// Revokes one Grant without requiring presence or serving readiness.
    pub(crate) fn revoke_grant(&mut self, grant: &GrantId) -> Result<(), SubmitError> {
        self.authority
            .management()
            .revoke_grant(grant)
            .map_err(SubmitError::Authority)
    }

    /// Revokes one Delegation without requiring presence or serving readiness.
    pub(crate) fn revoke_delegation(
        &mut self,
        delegation: &DelegationId,
    ) -> Result<(), SubmitError> {
        self.authority
            .management()
            .revoke_delegation(delegation)
            .map_err(SubmitError::Authority)
    }

    /// Terminates the exact origin and all authority held by its Session.
    pub fn end_session_origin(&mut self, binding: &ProcessBindingId) -> Result<(), SubmitError> {
        self.authority
            .sessions()
            .end_origin(binding)
            .map(|_| ())
            .map_err(SubmitError::Authority)
    }
    /// Terminates a Session whether or not an origin was bound.
    pub(crate) fn end_session(&mut self, session: &SessionId) -> Result<(), SubmitError> {
        self.authority
            .sessions()
            .end_session(session)
            .map_err(SubmitError::Authority)
    }

    pub fn connect_session(
        &mut self,
        session: &SessionId,
        binding: &ProcessBindingId,
        observed_origin: &ProcessOrigin,
        reconnect_proof: Option<&ReconnectProof>,
    ) -> Result<(SessionContext, Option<ReconnectProof>), SubmitError> {
        self.require_ready()?;
        self.authority
            .sessions()
            .connect(session, binding, observed_origin, reconnect_proof)
            .map_err(SubmitError::Authority)
    }
    /// Imports caller bytes through the kernel-owned content-addressed store.
    /// The returned ownership handle exposes only its artifact reference and
    /// can remove only the exact verified entry imported for this request.
    pub fn import_artifact(&self, reader: impl Read) -> Result<ImportedArtifact, SubmitError> {
        self.require_ready()?;
        self.artifacts
            .import_scoped(reader)
            .map_err(SubmitError::Artifact)
    }

    /// Removes a request-scoped artifact after synchronous execution ends.
    pub fn cleanup_artifact(&self, artifact: &ImportedArtifact) -> Result<(), ArtifactError> {
        self.artifacts.remove_scoped(artifact)
    }

    /// Executes one typed request for a live Session. Authority is resolved
    /// exclusively from the pack-derived Need and the bound process.
    pub fn submit(
        &mut self,
        context: &SessionContext,
        wire: &[u8],
        now_unix: i64,
    ) -> Result<OperationResult, SubmitError> {
        self.submit_inner(context, wire, now_unix, None)
    }
    fn replay_bound_submission(
        &self,
        operation_id: OperationId,
    ) -> Result<OperationResult, SubmitError> {
        self.load_result(&operation_id)?
            .ok_or(SubmitError::BoundSubmissionMissingResult { operation_id })
    }

    fn submit_inner(
        &mut self,
        context: &SessionContext,
        wire: &[u8],
        now_unix: i64,
        forced_elapsed: Option<Duration>,
    ) -> Result<OperationResult, SubmitError> {
        self.require_ready()?;
        let mut attribution = ResultAttribution::from(
            self.authority
                .execution()
                .identity(context)
                .map_err(SubmitError::Authority)?,
        );
        let value: Value = serde_json::from_slice(wire).map_err(SubmitError::MalformedTransport)?;
        if !value.is_object() {
            return Err(SubmitError::TransportNotObject);
        }
        let request: ActionRequest =
            serde_json::from_value(value).map_err(SubmitError::MalformedTransport)?;
        let submission_id = request
            .submission_id
            .ok_or(SubmitError::MissingSubmissionId)?;
        let canonical_request =
            serde_jcs::to_vec(&request).map_err(SubmitError::MalformedTransport)?;
        let request_digest = RequestDigest::of(&canonical_request);
        match self.resolve_submission(submission_id, request_digest)? {
            SubmissionResolution::Admit => {}
            SubmissionResolution::Existing(operation_id) => {
                return self.replay_bound_submission(operation_id);
            }
            SubmissionResolution::Conflict {
                existing_operation_id,
            } => {
                return Err(SubmitError::SubmissionConflict {
                    existing_operation_id,
                });
            }
        }
        match self.resolve_authority_gap(submission_id, request_digest)? {
            SubmissionResolution::Admit => {}
            SubmissionResolution::Existing(operation_id) => {
                let still_missing = self.packs.resolve(&request).is_ok_and(|resolved| {
                    self.authority
                        .execution()
                        .admit(
                            context,
                            &request.pack,
                            &request.action,
                            &resolved.need,
                            now_unix,
                        )
                        .is_err()
                });
                if still_missing {
                    return self.replay_bound_submission(operation_id);
                }
            }
            SubmissionResolution::Conflict {
                existing_operation_id,
            } => {
                return Err(SubmitError::SubmissionConflict {
                    existing_operation_id,
                });
            }
        }

        let operation = OperationId::new();
        let timing = OperationTiming::accepted(now_unix, forced_elapsed);
        let binding = SubmissionBinding::new(submission_id, request_digest, operation.clone());
        match self.bind_submission(&binding)? {
            SubmissionResolution::Admit => {}
            SubmissionResolution::Existing(operation_id) => {
                return self.replay_bound_submission(operation_id);
            }
            SubmissionResolution::Conflict {
                existing_operation_id,
            } => {
                return Err(SubmitError::SubmissionConflict {
                    existing_operation_id,
                });
            }
        }
        attribution.submission_id = Some(submission_id);
        attribution.request_digest = Some(request_digest);

        let resolved = match self.packs.resolve(&request) {
            Ok(resolved) => resolved,
            Err(error) => {
                return self.refuse_pack(operation, &attribution, &timing, &request, error);
            }
        };
        if let Err(error) = self.append_evidence(
            &operation,
            now_unix,
            "action.resolved",
            json!({
                "pack": resolved.pack.pack.reference(),
                "pack_digest_sha256": resolved.pack.digest_sha256,
                "action": resolved.key,
                "runner_adapter": resolved.runner_adapter,
                "mint_adapter": resolved.mint_adapter,
                "need": resolved.need,
            }),
        ) {
            return self.terminal(
                operation,
                &attribution,
                &timing,
                TerminalStatus::ExecutionFailure,
                Some(resolved.key),
                Some(resolved.input.clone()),
                Some(resolved.need),
                None,
                None,
                false,
                format!("audit failed after action resolution: {error}"),
            );
        }

        let artifact_ref = match self.runners.validate(
            &resolved.runner_adapter,
            RunnerValidation {
                action: &resolved.key,
                input: &resolved.input,
                need: &resolved.need,
                artifact_required: resolved.artifact_required,
                lane: &resolved.lane,
                mint_adapter: &resolved.mint_adapter,
            },
        ) {
            Ok(reference) => reference,
            Err(error) => {
                return self.terminal(
                    operation,
                    &attribution,
                    &timing,
                    TerminalStatus::Refusal,
                    Some(resolved.key),
                    Some(resolved.input.clone()),
                    Some(resolved.need),
                    None,
                    None,
                    false,
                    format!("runner validation refused: {error}"),
                );
            }
        };

        let authority_decision = match self.authority.execution().admit(
            context,
            &request.pack,
            &request.action,
            &resolved.need,
            now_unix,
        ) {
            Ok(decision) => decision,
            Err(error) => {
                return self.terminal(
                    operation,
                    &attribution,
                    &timing,
                    TerminalStatus::Refusal,
                    Some(resolved.key),
                    Some(resolved.input.clone()),
                    Some(resolved.need),
                    None,
                    None,
                    false,
                    format!("authority gap: {error}"),
                );
            }
        };
        let submission_id = attribution.submission_id;
        let request_digest = attribution.request_digest;
        attribution = authority_decision.clone().into();
        attribution.submission_id = submission_id;
        attribution.request_digest = request_digest;
        if let Err(error) = self.append_evidence(
            &operation,
            now_unix,
            "grant.admitted",
            json!({
                "persona_id": attribution.persona_id,
                "session_id": attribution.session_id,
                "process_binding_id": attribution.process_binding_id,
                "grant_id": attribution.grant_id,
                "delegation_path": attribution.delegation_path,
                "need": resolved.need,
            }),
        ) {
            return self.terminal(
                operation,
                &attribution,
                &timing,
                TerminalStatus::ExecutionFailure,
                Some(resolved.key),
                Some(resolved.input.clone()),
                Some(resolved.need),
                None,
                None,
                false,
                format!("audit failed after grant admission: {error}"),
            );
        }

        let artifact = match artifact_ref.as_ref() {
            Some(reference) => match self.artifacts.open_verified(reference) {
                Ok(artifact) => Some(artifact),
                Err(error) => {
                    return self.terminal(
                        operation,
                        &attribution,
                        &timing,
                        TerminalStatus::Refusal,
                        Some(resolved.key),
                        Some(resolved.input.clone()),
                        Some(resolved.need),
                        None,
                        None,
                        false,
                        format!("artifact refused: {error}"),
                    );
                }
            },
            None => None,
        };
        if let (Some(reference), Some(artifact)) = (artifact_ref.as_ref(), artifact.as_ref())
            && let Err(error) = self.append_evidence(
                &operation,
                now_unix,
                "artifact.verified",
                json!({
                    "artifact": reference,
                    "digest_sha256": reference.digest_hex(),
                    "bytes": artifact.len(),
                }),
            )
        {
            return self.terminal(
                operation,
                &attribution,
                &timing,
                TerminalStatus::ExecutionFailure,
                Some(resolved.key),
                Some(resolved.input.clone()),
                Some(resolved.need),
                None,
                None,
                false,
                format!("audit failed after artifact verification: {error}"),
            );
        }

        let credential = match self.providers.mint(
            &operation,
            &authority_decision,
            &resolved.key,
            &resolved.input,
            &resolved.need,
            now_unix,
            &self.recovery,
        ) {
            Ok(credential) => credential,
            Err(error) => {
                let status = match &error {
                    ProviderError::NoEligibleInstance
                    | ProviderError::AmbiguousInstances
                    | ProviderError::EchoRefused => TerminalStatus::Refusal,
                    ProviderError::DuplicateInstance
                    | ProviderError::Adapter(_)
                    | ProviderError::CompensatingRevokeFailed(_)
                    | ProviderError::Recovery(_)
                    | ProviderError::JournalAndCompensatingRevokeFailed { .. }
                    | ProviderError::UnknownInstanceGeneration
                    | ProviderError::RevokeFailed(_) => TerminalStatus::ExecutionFailure,
                };
                return self.terminal(
                    operation,
                    &attribution,
                    &timing,
                    status,
                    Some(resolved.key),
                    Some(resolved.input.clone()),
                    Some(resolved.need),
                    None,
                    None,
                    false,
                    format!("provider materialization failed: {error}"),
                );
            }
        };
        let provider_evidence = credential.evidence().clone();
        let materialization_id = credential.materialization_id().clone();
        if let Err(audit_error) = self.append_evidence(
            &operation,
            now_unix,
            "provider.materialized",
            json!({
                "materialization_id": materialization_id,
                "provider": provider_evidence,
            }),
        ) {
            let (status, upstream_revoked, settlement_message) =
                self.revoke_after_audit_failure(credential);
            return self.terminal(
                operation,
                &attribution,
                &timing,
                status,
                Some(resolved.key),
                Some(resolved.input.clone()),
                Some(resolved.need),
                Some((provider_evidence, materialization_id)),
                None,
                upstream_revoked,
                format!(
                    "audit failed before credential delivery: {audit_error}{settlement_message}"
                ),
            );
        }

        let run = self.runners.run(
            &resolved.runner_adapter,
            &resolved.key,
            &resolved.input,
            artifact,
            &credential,
        );
        let (runner_evidence, facts, run_succeeded, failure_status, run_message, audit_data) =
            match run {
                Ok(output) => (
                    Some(output.evidence),
                    output.facts,
                    output.succeeded,
                    TerminalStatus::ExecutionFailure,
                    output.message,
                    output.audit_data,
                ),
                Err(error) => {
                    let status = match error.kind() {
                        RunnerFailureKind::Refusal => TerminalStatus::Refusal,
                        RunnerFailureKind::ExecutionFailure => TerminalStatus::ExecutionFailure,
                    };
                    let message = format!("runner failed: {error}");
                    (
                        None,
                        None,
                        false,
                        status,
                        message.clone(),
                        json!({"error": message}),
                    )
                }
            };
        if let Err(audit_error) =
            self.append_evidence(&operation, now_unix, "runner.exit", audit_data)
        {
            let (status, upstream_revoked, settlement_message) =
                self.revoke_after_audit_failure(credential);
            return self.terminal(
                operation,
                &attribution,
                &timing,
                status,
                Some(resolved.key),
                Some(resolved.input.clone()),
                Some(resolved.need),
                Some((provider_evidence, materialization_id)),
                runner_evidence,
                upstream_revoked,
                format!("{run_message}; runner audit failed: {audit_error}{settlement_message}"),
            );
        }

        let settlement = self.providers.revoke_credential(credential);
        let (mut status, mut upstream_revoked, mut message) = match settlement {
            Ok(()) if run_succeeded => (TerminalStatus::Success, true, run_message),
            Ok(()) => (failure_status, true, run_message),
            Err(error) => (
                TerminalStatus::CompletedButUnsettled,
                false,
                format!("{run_message}; settlement failed: {error}"),
            ),
        };
        if let Err(error) = self.append_evidence(
            &operation,
            now_unix,
            "provider.settlement",
            json!({
                "materialization_id": &materialization_id,
                "upstream_revoked": upstream_revoked,
                "settled": status != TerminalStatus::CompletedButUnsettled,
            }),
        ) {
            message.push_str(&format!("; settlement audit failed: {error}"));
            status = TerminalStatus::CompletedButUnsettled;
            upstream_revoked = false;
        }

        // This is the sole post-run point where the verified artifact FD has
        // been consumed and dropped. ArtifactStore cleanup can safely attach
        // after this terminal result without racing sealed Git's FD use.
        self.terminal_with_facts(
            operation,
            &attribution,
            &timing,
            status,
            Some(resolved.key),
            Some(resolved.input),
            Some(resolved.need),
            Some((provider_evidence, materialization_id)),
            runner_evidence,
            facts,
            upstream_revoked,
            message,
        )
    }

    pub fn artifact_ingress(&self) -> &ArtifactStore {
        &self.artifacts
    }

    fn require_ready(&self) -> Result<(), SubmitError> {
        if !self.startup_recovered {
            return Err(SubmitError::StartupRecoveryRequired);
        }
        if !self.journal.health()?.permits_new_authority_decision() {
            return Err(SubmitError::JournalDegraded);
        }
        Ok(())
    }

    fn revoke_after_audit_failure(
        &mut self,
        credential: MintedCredential,
    ) -> (TerminalStatus, bool, String) {
        match self.providers.revoke_credential(credential) {
            Ok(()) => (TerminalStatus::ExecutionFailure, true, String::new()),
            Err(error) => (
                TerminalStatus::CompletedButUnsettled,
                false,
                format!("; settlement failed: {error}"),
            ),
        }
    }

    fn refuse_pack(
        &mut self,
        operation: OperationId,
        attribution: &ResultAttribution,
        timing: &OperationTiming,
        request: &ActionRequest,
        error: PackError,
    ) -> Result<OperationResult, SubmitError> {
        self.terminal(
            operation,
            attribution,
            timing,
            TerminalStatus::Refusal,
            Some(request.action.clone()),
            None,
            None,
            None,
            None,
            false,
            format!("pack action refused: {error}"),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn terminal(
        &mut self,
        operation: OperationId,
        attribution: &ResultAttribution,
        timing: &OperationTiming,
        status: TerminalStatus,
        action: Option<String>,
        approved_input: Option<Value>,
        need: Option<crate::model::Need>,
        provider_materialization: Option<(ProviderEvidence, MaterializationId)>,
        runner: Option<RunnerEvidence>,
        upstream_revoked: bool,
        message: String,
    ) -> Result<OperationResult, SubmitError> {
        self.terminal_with_facts(
            operation,
            attribution,
            timing,
            status,
            action,
            approved_input,
            need,
            provider_materialization,
            runner,
            None,
            upstream_revoked,
            message,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn terminal_with_facts(
        &mut self,
        operation: OperationId,
        attribution: &ResultAttribution,
        timing: &OperationTiming,
        status: TerminalStatus,
        action: Option<String>,
        approved_input: Option<Value>,
        need: Option<crate::model::Need>,
        provider_materialization: Option<(ProviderEvidence, MaterializationId)>,
        runner: Option<RunnerEvidence>,
        facts: Option<ActionFacts>,
        upstream_revoked: bool,
        message: String,
    ) -> Result<OperationResult, SubmitError> {
        let completed_at_unix = timing.completed_at_unix();
        self.append_evidence(
            &operation,
            completed_at_unix,
            "operation.terminal",
            json!({"status": status, "message": &message}),
        )?;
        let boundary = match status {
            TerminalStatus::Refusal => ActionBoundary::CancelledBeforeEffect,
            TerminalStatus::Success => ActionBoundary::EffectCompleted { succeeded: true },
            TerminalStatus::ExecutionFailure
                if runner
                    .as_ref()
                    .and_then(|value| value.process.as_ref())
                    .is_some() =>
            {
                ActionBoundary::EffectCompleted { succeeded: false }
            }
            TerminalStatus::ExecutionFailure if provider_materialization.is_none() => {
                ActionBoundary::CancelledBeforeEffect
            }
            TerminalStatus::ExecutionFailure | TerminalStatus::CompletedButUnsettled => {
                ActionBoundary::EffectUnknown
            }
        };
        let recovery_to_finalize = provider_materialization
            .as_ref()
            .filter(|_| upstream_revoked)
            .map(|(_, materialization)| materialization.clone());
        let (provider, materialization_id) = provider_materialization
            .map(|(provider, materialization)| (Some(provider), Some(materialization)))
            .unwrap_or((None, None));
        let submission_id =
            attribution
                .submission_id
                .ok_or_else(|| SubmitError::MissingSubmissionBinding {
                    operation_id: operation.clone(),
                })?;
        let request_digest =
            attribution
                .request_digest
                .ok_or_else(|| SubmitError::MissingSubmissionBinding {
                    operation_id: operation.clone(),
                })?;

        for pending in &mut self.pending_evidence {
            pending.links.session_id = Some(attribution.session_id.clone());
            pending.links.grant_id = attribution.grant_id.clone();
        }
        let pending_evidence = self.pending_evidence.clone();
        let authority_gap =
            status == TerminalStatus::Refusal && message.starts_with("authority gap: ");
        let mut committed_result = None;
        let mut expected_last_sequence = 0;
        let receipt = self.journal.commit_with_sequence(|first_sequence| {
            let mut transaction =
                JournalTransaction::new(transaction_id(&operation, first_sequence));
            let mut fact_hashes = Vec::with_capacity(pending_evidence.len());
            for (offset, pending) in pending_evidence.into_iter().enumerate() {
                let sequence = first_sequence
                    .checked_add(u64::try_from(offset).map_err(|_| JournalError::SequenceOverflow)?)
                    .ok_or(JournalError::SequenceOverflow)?;
                let fact = AuditFact::new(
                    evidence_id(&operation, sequence, pending.event),
                    JournalSequence::new(sequence).ok_or(JournalError::SequenceOverflow)?,
                    pending.event,
                    Some(match pending.links.materialization_id.clone() {
                        Some(materialization_id) => OperationEvidenceRef::materialization(
                            operation.clone(),
                            materialization_id,
                        ),
                        None => OperationEvidenceRef::operation(operation.clone()),
                    }),
                )
                .map_err(|error| JournalError::InvalidPreparedEvidence(error.to_string()))?;
                let canonical = encode_audit_fact(&fact);
                fact_hashes.push(sha256_hex(&canonical));
                transaction.push_evidence(PrimaryEvidence::audit_fact(&fact, pending.links)?, None);
            }
            let last_sequence = first_sequence
                .checked_add(
                    u64::try_from(fact_hashes.len())
                        .map_err(|_| JournalError::SequenceOverflow)?
                        .checked_sub(1)
                        .ok_or(JournalError::SequenceOverflow)?,
                )
                .ok_or(JournalError::SequenceOverflow)?;
            let audit = AuditCommitment {
                first_hash: fact_hashes
                    .first()
                    .cloned()
                    .ok_or(JournalError::SequenceOverflow)?,
                last_hash: fact_hashes
                    .last()
                    .cloned()
                    .ok_or(JournalError::SequenceOverflow)?,
                fact_count: u64::try_from(fact_hashes.len())
                    .map_err(|_| JournalError::SequenceOverflow)?,
            };
            let outcome = OperationOutcome::new(
                operation.clone(),
                submission_id,
                request_digest,
                JournalSequence::new(last_sequence).ok_or(JournalError::SequenceOverflow)?,
                materialization_id,
                boundary,
            );
            let result = OperationResult {
                schema: OPERATION_RESULT_SCHEMA.to_owned(),
                outcome,
                persona_id: attribution.persona_id.clone(),
                session_id: attribution.session_id.clone(),
                process_binding_id: attribution.process_binding_id.clone(),
                grant_id: attribution.grant_id.clone(),
                delegation_path: attribution.delegation_path.clone(),
                status,
                action,
                approved_input,
                resource: need.as_ref().map(|value| value.repository.clone()),
                need,
                provider,
                runner,
                facts,
                upstream_revoked,
                audit,
                started_at_unix: timing.started_at_unix,
                completed_at_unix,
                message,
            };
            transaction.put_state(
                operation_result_key(&operation),
                serde_jcs::to_vec(&result).map_err(JournalError::Canonicalize)?,
            );
            if authority_gap {
                let gap_binding =
                    SubmissionBinding::new(submission_id, request_digest, operation.clone());
                transaction.delete_state(submission_binding_key(submission_id));
                transaction.put_state(
                    authority_gap_binding_key(submission_id),
                    serde_jcs::to_vec(&gap_binding).map_err(JournalError::Canonicalize)?,
                );
            }
            expected_last_sequence = last_sequence;
            committed_result = Some(result);
            Ok(transaction)
        })?;
        if receipt.last_sequence() != expected_last_sequence {
            return Err(SubmitError::InvalidJournalSequence);
        }
        self.pending_evidence.clear();
        let result = committed_result.ok_or(SubmitError::InvalidJournalSequence)?;
        if let Some(materialization) = recovery_to_finalize
            && let Err(error) = self.recovery.settle(&materialization)
        {
            self.startup_recovered = false;
            return Err(error.into());
        }
        Ok(result)
    }
}

#[derive(Debug, Error)]
pub enum SubmitError {
    #[error("startup materialization recovery must settle before serving")]
    StartupRecoveryRequired,
    #[error("malformed transport: {0}")]
    MalformedTransport(serde_json::Error),
    #[error("transport must be a JSON object")]
    TransportNotObject,
    #[error("action request is missing its submission identity")]
    MissingSubmissionId,
    #[error(
        "submission identity is already bound to a different request by operation {existing_operation_id}"
    )]
    SubmissionConflict { existing_operation_id: OperationId },
    #[error("operation {operation_id} is missing its durable submission binding")]
    MissingSubmissionBinding { operation_id: OperationId },
    #[error(
        "submission is durably bound to operation {operation_id}, but no terminal result exists; replay refused"
    )]
    BoundSubmissionMissingResult { operation_id: OperationId },
    #[error("terminal journal sequence is invalid")]
    InvalidJournalSequence,
    #[error("session authority refused: {0}")]
    Authority(AuthorityError),
    #[error("provider recovery failed: {0}")]
    Provider(#[from] ProviderError),
    #[error("evidence journal failed: {0}")]
    Journal(#[from] JournalError),
    #[error("stored operation result is invalid: {0}")]
    MalformedStoredResult(serde_json::Error),
    #[error("stored submission binding is invalid: {0}")]
    MalformedStoredBinding(serde_json::Error),
    #[error("audit fact is invalid: {0}")]
    InvalidAuditFact(crate::model::AuditFactError),
    #[error("evidence journal is degraded; new authority decisions are blocked")]
    JournalDegraded,
    #[error("artifact ingress failed: {0}")]
    Artifact(#[from] ArtifactError),
    #[error("materialization recovery persistence failed: {0}")]
    Recovery(#[from] RecoveryError),
}
#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        str::FromStr,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use ed25519_dalek::SigningKey;
    use parking_lot::Mutex;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use super::*;
    use crate::{
        audit::test_evidence_context,
        git::{GitRunner, ReviewedExecutable},
        model::{
            ACTION_REQUEST_SCHEMA, GitRef, PackRef, PermissionLevel, ProviderGeneration,
            ProviderInstanceId, RepositoryResource,
        },
        pack::{
            DeliveryLane, GITHUB_PACK_ADDRESS, GITHUB_PACK_VERSION, GITHUB_PUBLISH_REF_ACTION,
            PackTrustStore, SignedProviderPack, TrustedPublisher, github_pack_v2,
        },
        principal::{GrantInstallation, PresenceOperation, PresenceVerifier},
        provider::{
            AdapterError, AdapterMint, CredentialEcho, MintRequest, ProviderAdapter,
            ProviderInstance,
        },
        recovery::RecoveryContext,
    };

    const NOW: i64 = 10_000;
    const TOKEN: &str = "installation-token-never-owned-by-the-caller";

    fn test_fixture_peer_fingerprint(_path: &std::path::Path) -> std::io::Result<[u8; 32]> {
        Ok([0_u8; 32])
    }

    struct Present;

    impl PresenceVerifier for Present {
        fn verify_presence(&mut self, _operation: &PresenceOperation) -> bool {
            true
        }
    }

    struct FakeProvider {
        id: ProviderInstanceId,
        generation: ProviderGeneration,
        mint_count: Mutex<usize>,
        revoked: Mutex<Vec<String>>,
        fail_revoke: AtomicBool,
        lock_recovery_on_revoke: Mutex<Option<std::path::PathBuf>>,
        lock_evidence_on_mint: Mutex<Option<std::path::PathBuf>>,
    }

    impl ProviderAdapter for FakeProvider {
        fn mint(&self, request: &MintRequest<'_>) -> Result<AdapterMint, AdapterError> {
            *self.mint_count.lock() += 1;
            if let Some(directory) = self.lock_evidence_on_mint.lock().take() {
                fs::set_permissions(directory, fs::Permissions::from_mode(0o500)).unwrap();
            }
            Ok(AdapterMint::new(
                TOKEN.to_owned(),
                CredentialEcho {
                    provider_instance: self.id.clone(),
                    generation: self.generation.clone(),
                    provider: request.provider.to_owned(),
                    app_slug: request.app_slug.to_owned(),
                    app_id: request.app_id,
                    installation_id: request.installation_id,
                    repositories: vec![request.repository.clone()],
                    permissions: request.permissions.clone(),
                    expires_at_unix: request.now_unix + 600,
                },
            ))
        }

        fn revoke(&self, token: &str) -> Result<(), AdapterError> {
            if self.fail_revoke.load(Ordering::SeqCst) {
                return Err(AdapterError::new("injected revoke failure"));
            }
            self.revoked.lock().push(token.to_owned());
            if let Some(directory) = self.lock_recovery_on_revoke.lock().take() {
                fs::set_permissions(directory, fs::Permissions::from_mode(0o500)).unwrap();
            }
            Ok(())
        }
    }

    struct Fixture {
        _root: TempDir,
        kernel: AuthorityKernel,
        persona: PersonaId,
        session: SessionId,
        grant: GrantId,
        delegation: DelegationId,
        binding: ProcessBindingId,
        origin: ProcessOrigin,
        _executable: ExecutableDigest,
        request: Value,
        provider: Arc<FakeProvider>,
        orphan_operation: Option<OperationId>,
        recovery_directory: std::path::PathBuf,
    }

    impl Fixture {
        fn new(recover_startup: bool, orphaned_token: bool, fail_revoke: bool) -> Self {
            Self::new_at(recover_startup, orphaned_token, fail_revoke, NOW)
        }

        fn new_at(
            recover_startup: bool,
            orphaned_token: bool,
            fail_revoke: bool,
            now_unix: i64,
        ) -> Self {
            Self::with_runner_binding_at(
                recover_startup,
                orphaned_token,
                fail_revoke,
                DeliveryLane::SealedExec,
                "github.app-installation/v1",
                now_unix,
            )
        }

        fn with_runner_binding(
            recover_startup: bool,
            orphaned_token: bool,
            fail_revoke: bool,
            lane: DeliveryLane,
            mint_adapter: &str,
        ) -> Self {
            Self::with_runner_binding_at(
                recover_startup,
                orphaned_token,
                fail_revoke,
                lane,
                mint_adapter,
                NOW,
            )
        }

        fn with_runner_binding_at(
            recover_startup: bool,
            orphaned_token: bool,
            fail_revoke: bool,
            lane: DeliveryLane,
            mint_adapter: &str,
            now_unix: i64,
        ) -> Self {
            let root = tempfile::Builder::new()
                .prefix("kernel-")
                .tempdir_in(std::env::current_dir().unwrap())
                .unwrap();
            let repository = RepositoryResource::from_str("github:acme/planning").unwrap();
            let destination_ref = GitRef::from_str("refs/heads/ws/test/planner-1").unwrap();
            let permissions = BTreeMap::from([
                ("contents".to_owned(), PermissionLevel::Write),
                ("metadata".to_owned(), PermissionLevel::Read),
            ]);

            let artifact_store = ArtifactStore::new(root.path().join("artifacts"), 1024).unwrap();
            let artifact = artifact_store.import("bundle bytes".as_bytes()).unwrap();

            let pack_signing_key = SigningKey::from_bytes(&[7_u8; 32]);
            let mut pack = github_pack_v2("did:key:test");
            let publish = pack.actions.get_mut(GITHUB_PUBLISH_REF_ACTION).unwrap();
            publish.lane = lane;
            publish.mint_adapter = mint_adapter.to_owned();
            let signed_pack =
                SignedProviderPack::sign(pack, "founder-pack-root", &pack_signing_key).unwrap();
            let mut trust = PackTrustStore::default();
            trust.insert(
                "founder-pack-root",
                TrustedPublisher {
                    publisher: "did:key:test".to_owned(),
                    verifying_key: pack_signing_key.verifying_key(),
                    not_before_unix: now_unix - 100,
                    not_after_unix: now_unix + 100,
                    revoked: false,
                },
            );
            let mut packs = PackRegistry::default();
            packs
                .install(trust.verify(signed_pack, now_unix).unwrap())
                .unwrap();

            let executable = ExecutableDigest::from_sha256([9_u8; 32]);
            let root_metadata = fs::metadata(root.path()).unwrap();
            let origin =
                ProcessOrigin::new(42, 1, root_metadata.uid(), root_metadata.gid(), executable)
                    .unwrap();
            let mut authority = PersonaAuthority::new();
            let mut presence = Present;
            let persona = authority
                .management()
                .install_persona(&mut presence)
                .unwrap();
            let grant = authority
                .management()
                .install_grant(
                    &mut presence,
                    GrantInstallation::new(
                        persona.clone(),
                        PackRef {
                            address: GITHUB_PACK_ADDRESS.to_owned(),
                            version: GITHUB_PACK_VERSION,
                        },
                        GITHUB_PUBLISH_REF_ACTION,
                        "github",
                        repository.clone(),
                        Some("refs/heads/ws/".to_owned()),
                        permissions.clone(),
                        now_unix - 1,
                        i64::MAX,
                    )
                    .unwrap(),
                )
                .unwrap();
            let (session, challenge) = authority.sessions().create(&persona, executable).unwrap();
            let binding = authority
                .sessions()
                .bind_origin(&session, &challenge, origin)
                .unwrap();
            let delegation = authority
                .management()
                .attach_selected_grants(
                    &mut presence,
                    &session,
                    vec![(DelegationId::new(), GrantSelection::whole(grant.clone()))],
                    now_unix,
                    Duration::from_secs(4 * 60 * 60),
                )
                .unwrap()
                .remove(0);

            let provider_id = ProviderInstanceId::new();
            let generation = ProviderGeneration::new();
            let provider = Arc::new(FakeProvider {
                id: provider_id.clone(),
                generation: generation.clone(),
                mint_count: Mutex::new(0),
                revoked: Mutex::new(Vec::new()),
                fail_revoke: AtomicBool::new(fail_revoke),
                lock_evidence_on_mint: Mutex::new(None),
                lock_recovery_on_revoke: Mutex::new(None),
            });
            let mut providers = ProviderRegistry::default();
            providers
                .register(ProviderInstance::with_identity(
                    provider_id.clone(),
                    generation.clone(),
                    "github",
                    "planning-app",
                    1,
                    2,
                    [repository.clone()],
                    permissions.clone(),
                    provider.clone(),
                ))
                .unwrap();

            let script = root.path().join("reviewed-git");
            let script_bytes = b"#!/bin/sh\nexit 0\n";
            fs::write(&script, script_bytes).unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
            let script_digest: [u8; 32] = Sha256::digest(script_bytes).into();
            let reviewed = ReviewedExecutable::new(script, script_digest).unwrap();
            let git = GitRunner::new(reviewed.clone(), reviewed)
                .with_credential_peer_fingerprint_for_test(test_fixture_peer_fingerprint);
            let mut runners = RunnerRegistry::default();
            runners.register(Arc::new(git)).unwrap();

            let (journal, _, _) = test_evidence_context(root.path().join("audit")).unwrap();
            let recovery_directory = root.path().join("recovery");
            let recovery =
                RecoveryJournal::open_test_fixture(&recovery_directory, [6_u8; 32]).unwrap();
            let orphan_operation = orphaned_token.then(OperationId::new);
            let mut orphan_binding = None;
            if let Some(operation_id) = &orphan_operation {
                let request_digest = RequestDigest::of(operation_id.as_str().as_bytes());
                orphan_binding = Some(SubmissionBinding::new(
                    SubmissionId::from_bytes([2_u8; 32]),
                    request_digest,
                    operation_id.clone(),
                ));
                let context = RecoveryContext {
                    operation_id: operation_id.clone(),
                    persona_id: persona.clone(),
                    session_id: session.clone(),
                    process_binding_id: binding.clone(),
                    grant_id: grant.clone(),
                    delegation_path: vec![delegation.clone()],
                    action: GITHUB_PUBLISH_REF_ACTION.to_owned(),
                    approved_input: json!({
                        "repository": repository,
                        "artifact": artifact,
                        "expected_old_oid": "1".repeat(40),
                        "new_oid": "2".repeat(40),
                        "destination_ref": destination_ref,
                    }),
                    need: crate::model::Need {
                        provider: "github".to_owned(),
                        repository: repository.clone(),
                        destination_ref: Some(destination_ref.clone()),
                        permissions: permissions.clone(),
                    },
                    provider: Some(ProviderEvidence {
                        provider_instance: provider_id.clone(),
                        generation: generation.clone(),
                        app_slug: "planning-app".to_owned(),
                        app_id: 1,
                        installation_id: 2,
                        repositories: vec![repository.full_name().to_owned()],
                        permissions: permissions.clone(),
                        expires_at_unix: now_unix + 60,
                    }),
                };
                let materialization = recovery
                    .begin_mint(&context, &provider_id, &generation)
                    .unwrap();
                recovery
                    .record_token(
                        &materialization,
                        context.provider.clone().unwrap(),
                        "orphaned-token",
                    )
                    .unwrap();
            }

            let mut kernel = AuthorityKernel::new(
                authority,
                packs,
                providers,
                artifact_store,
                journal,
                recovery,
                runners,
            );
            if let Some(binding) = orphan_binding {
                kernel.bind_submission(&binding).unwrap();
            }
            if recover_startup {
                kernel.recover_startup(now_unix).unwrap();
            }

            let request = json!({
                "schema": ACTION_REQUEST_SCHEMA,
                "pack": {"address": GITHUB_PACK_ADDRESS, "version": GITHUB_PACK_VERSION},
                "action": GITHUB_PUBLISH_REF_ACTION,
                "input": {
                    "repository": repository,
                    "artifact": artifact,
                    "expected_old_oid": "1".repeat(40),
                    "new_oid": "2".repeat(40),
                    "destination_ref": destination_ref,
                },
            "submission_id": vec![1_u8; 32],
            });

            Self {
                _root: root,
                kernel,
                persona,
                session,
                grant,
                delegation,
                binding,
                origin,
                _executable: executable,
                request,
                provider,
                orphan_operation,
                recovery_directory,
            }
        }

        fn connect(&mut self) -> SessionContext {
            let (context, proof) = self
                .kernel
                .connect_session(&self.session, &self.binding, &self.origin, None)
                .unwrap();
            assert!(proof.is_some());
            context
        }

        fn submit(&mut self, context: &SessionContext, request: &Value) -> OperationResult {
            self.kernel
                .submit(context, &serde_json::to_vec(request).unwrap(), NOW)
                .unwrap()
        }

        fn submit_with_elapsed(
            &mut self,
            context: &SessionContext,
            request: &Value,
            elapsed: Duration,
        ) -> OperationResult {
            self.kernel
                .submit_inner(
                    context,
                    &serde_json::to_vec(request).unwrap(),
                    NOW,
                    Some(elapsed),
                )
                .unwrap()
        }
    }

    #[test]
    fn replay_of_bound_submission_without_terminal_result_fails_closed() {
        let mut fixture = Fixture::new(true, false, false);
        let context = fixture.connect();
        let request = fixture.request.clone();
        let action_request: ActionRequest = serde_json::from_value(request.clone()).unwrap();
        let request_digest = RequestDigest::of(&serde_jcs::to_vec(&action_request).unwrap());
        let operation_id = OperationId::new();
        assert_eq!(
            fixture
                .kernel
                .bind_submission(&SubmissionBinding::new(
                    SubmissionId::from_bytes([1_u8; 32]),
                    request_digest,
                    operation_id.clone(),
                ))
                .unwrap(),
            SubmissionResolution::Admit
        );

        let error = fixture
            .kernel
            .submit(&context, &serde_json::to_vec(&request).unwrap(), NOW)
            .unwrap_err();

        assert!(matches!(
            error,
            SubmitError::BoundSubmissionMissingResult {
                operation_id: ref actual,
            } if actual == &operation_id
        ));
        assert_eq!(*fixture.provider.mint_count.lock(), 0);
    }

    #[test]
    fn admitted_publication_persists_immutable_result_and_revokes() {
        let mut fixture = Fixture::new(true, false, false);
        let context = fixture.connect();
        let request = fixture.request.clone();
        let result = fixture.submit(&context, &request);

        assert_eq!(result.status, TerminalStatus::Success, "{}", result.message);
        assert_eq!(result.action.as_deref(), Some(GITHUB_PUBLISH_REF_ACTION));
        assert_eq!(result.approved_input.as_ref(), Some(&request["input"]));
        assert!(result.provider.is_some());
        let runner = result.runner.as_ref().unwrap();
        assert_eq!(runner.process.as_ref().unwrap().exit_code, Some(0));
        assert!(
            runner
                .executable_digest_sha256
                .as_ref()
                .is_some_and(|value| !value.is_empty())
        );
        assert!(
            runner
                .credential_helper_digest_sha256
                .as_ref()
                .is_some_and(|value| !value.is_empty())
        );
        assert!(result.upstream_revoked);
        assert_eq!(*fixture.provider.mint_count.lock(), 1);
        assert_eq!(fixture.provider.revoked.lock().as_slice(), [TOKEN]);
        let reopened =
            RecoveryJournal::open_test_fixture(&fixture.recovery_directory, [6_u8; 32]).unwrap();
        assert!(reopened.unresolved().unwrap().is_empty());
    }

    #[test]
    fn signed_runner_lane_and_mint_mismatches_refuse_before_mint() {
        let cases = [
            (DeliveryLane::Proxy, "github.app-installation/v1", "lane"),
            (
                DeliveryLane::SealedExec,
                "github.app-installation/v2",
                "mint adapter",
            ),
        ];

        for (lane, mint_adapter, case) in cases {
            let mut fixture = Fixture::with_runner_binding(true, false, false, lane, mint_adapter);
            let context = fixture.connect();
            let request = fixture.request.clone();
            let receipt = fixture.submit(&context, &request);

            assert_eq!(receipt.status, TerminalStatus::Refusal, "{case}");
            assert!(receipt.provider.is_none(), "{case}");
            assert_eq!(*fixture.provider.mint_count.lock(), 0, "{case}");
            assert!(
                receipt.message.contains("runner validation refused"),
                "{case}: {}",
                receipt.message
            );
        }
    }

    #[test]
    fn result_timestamps_use_monotonic_elapsed_whole_seconds() {
        let mut fixture = Fixture::new(true, false, false);
        let context = fixture.connect();
        let request = fixture.request.clone();
        let receipt = fixture.submit_with_elapsed(&context, &request, Duration::from_millis(3_999));

        assert_eq!(receipt.started_at_unix, NOW);
        assert_eq!(receipt.completed_at_unix, NOW + 3);
        let snapshot = fixture.kernel.journal.verified_snapshot().unwrap();
        assert_eq!(
            snapshot
                .records()
                .iter()
                .filter(|record| {
                    record.links().operation_id.as_ref() == Some(receipt.outcome.operation_id())
                        && record.event_code() == EventKind::OperationTerminal as u8
                })
                .count(),
            1
        );
    }

    #[test]
    fn caller_supplied_execution_and_authority_coordinates_are_refused_before_mint() {
        let mut fixture = Fixture::new(true, false, false);
        let context = fixture.connect();
        let forbidden = [
            "binary",
            "cwd",
            "socket",
            "uid",
            "gid",
            "provider_instance",
            "scope",
            "permissions",
            "environment",
            "raw_artifact_path",
        ];

        for (index, field) in forbidden.into_iter().enumerate() {
            let mut request = fixture.request.clone();
            request["submission_id"] =
                serde_json::to_value(SubmissionId::from_bytes([(index + 2) as u8; 32])).unwrap();
            request["input"]
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), json!("attacker-controlled"));
            let receipt = fixture.submit(&context, &request);
            assert_eq!(receipt.status, TerminalStatus::Refusal, "{field}");
            assert!(receipt.provider.is_none(), "{field}");
        }
        assert_eq!(*fixture.provider.mint_count.lock(), 0);
        assert!(fixture.provider.revoked.lock().is_empty());
    }

    #[test]
    fn startup_recovery_is_a_serving_gate_and_revokes_orphans() {
        let mut fixture = Fixture::new(false, true, false);
        let planned_delegation = DelegationId::new();
        assert!(matches!(
            fixture.kernel.attach_selected_grants(
                &mut Present,
                &fixture.session,
                vec![(
                    planned_delegation.clone(),
                    GrantSelection::whole(fixture.grant.clone()),
                )],
                NOW,
                Duration::from_secs(60),
            ),
            Err(SubmitError::StartupRecoveryRequired)
        ));
        assert!(matches!(
            fixture.kernel.connect_session(
                &fixture.session,
                &fixture.binding,
                &fixture.origin,
                None,
            ),
            Err(SubmitError::StartupRecoveryRequired)
        ));

        let report = fixture.kernel.recover_startup(NOW).unwrap();
        assert_eq!(report.settled, 1);
        assert_eq!(
            fixture
                .kernel
                .attach_selected_grants(
                    &mut Present,
                    &fixture.session,
                    vec![(
                        planned_delegation.clone(),
                        GrantSelection::whole(fixture.grant.clone()),
                    )],
                    NOW,
                    Duration::from_secs(60),
                )
                .unwrap(),
            vec![planned_delegation]
        );
        let operation_id = fixture.orphan_operation.as_ref().unwrap();
        let receipt = fixture.kernel.load_result(operation_id).unwrap().unwrap();
        assert_eq!(receipt.status, TerminalStatus::ExecutionFailure);
        assert_eq!(receipt.action.as_deref(), Some(GITHUB_PUBLISH_REF_ACTION));
        assert_eq!(
            receipt.approved_input.as_ref(),
            Some(&fixture.request["input"])
        );
        assert!(receipt.provider.is_some());
        assert!(receipt.upstream_revoked);
        assert_eq!(report.unresolved, 0);
        assert_eq!(
            fixture.provider.revoked.lock().as_slice(),
            ["orphaned-token"]
        );
        let _context = fixture.connect();
    }

    #[test]
    fn startup_revoke_failure_quarantines_generation_without_wedging_daemon() {
        let mut fixture = Fixture::new(false, true, true);
        let report = fixture.kernel.recover_startup(NOW).unwrap();
        assert_eq!(report.quarantined, 1);
        assert_eq!(report.unresolved, 1);
        assert!(
            fixture
                .kernel
                .providers
                .is_quarantined(&fixture.provider.id)
        );
        let _context = fixture.connect();
        let reopened =
            RecoveryJournal::open_test_fixture(&fixture.recovery_directory, [6_u8; 32]).unwrap();
        assert_eq!(reopened.unresolved().unwrap().len(), 1);
    }
    #[test]
    fn completed_but_unsettled_result_is_not_replaced_after_recovery() {
        let mut fixture = Fixture::new(true, false, true);
        let context = fixture.connect();
        let request = fixture.request.clone();
        let receipt = fixture.submit(&context, &request);
        assert_eq!(receipt.status, TerminalStatus::CompletedButUnsettled);
        assert!(!receipt.upstream_revoked);
        let operation_id = receipt.outcome.operation_id().clone();
        let reopened =
            RecoveryJournal::open_test_fixture(&fixture.recovery_directory, [6_u8; 32]).unwrap();
        assert_eq!(reopened.unresolved().unwrap().len(), 1);

        fixture.provider.fail_revoke.store(false, Ordering::SeqCst);
        let report = fixture.kernel.recover_startup(NOW + 1).unwrap();
        assert_eq!(report.settled, 1);
        assert_eq!(report.unresolved, 0);
        let retained = fixture.kernel.load_result(&operation_id).unwrap().unwrap();
        assert_eq!(retained, receipt);
        let reopened =
            RecoveryJournal::open_test_fixture(&fixture.recovery_directory, [6_u8; 32]).unwrap();
        assert!(reopened.unresolved().unwrap().is_empty());
    }

    fn seed_intent(
        fixture: &mut Fixture,
        provider_instance: &ProviderInstanceId,
        generation: &ProviderGeneration,
    ) -> OperationId {
        let operation_id = OperationId::new();
        let request_digest = RequestDigest::of(operation_id.as_str().as_bytes());
        fixture
            .kernel
            .bind_submission(&SubmissionBinding::new(
                SubmissionId::from_bytes([3_u8; 32]),
                request_digest,
                operation_id.clone(),
            ))
            .unwrap();
        let repository = RepositoryResource::from_str("github:acme/widgets").unwrap();
        let context = RecoveryContext {
            operation_id: operation_id.clone(),
            persona_id: fixture.persona.clone(),
            session_id: fixture.session.clone(),
            process_binding_id: fixture.binding.clone(),
            grant_id: fixture.grant.clone(),
            delegation_path: vec![fixture.delegation.clone()],
            action: GITHUB_PUBLISH_REF_ACTION.to_owned(),
            approved_input: fixture.request["input"].clone(),
            need: crate::model::Need {
                provider: "github".to_owned(),
                repository,
                destination_ref: Some(GitRef::from_str("refs/heads/ws/test/planner-1").unwrap()),
                permissions: BTreeMap::from([
                    ("contents".to_owned(), PermissionLevel::Write),
                    ("metadata".to_owned(), PermissionLevel::Read),
                ]),
            },
            provider: None,
        };
        fixture
            .kernel
            .recovery
            .begin_mint(&context, provider_instance, generation)
            .unwrap();
        operation_id
    }

    #[test]
    fn intent_only_restart_requarantines_generation_and_allows_startup() {
        let mut fixture = Fixture::new(false, false, false);
        let provider_id = fixture.provider.id.clone();
        let generation = fixture.provider.generation.clone();
        seed_intent(&mut fixture, &provider_id, &generation);

        for boot in 0..2 {
            let report = fixture.kernel.recover_startup(NOW + boot).unwrap();
            assert_eq!(report.quarantined, 1);
            assert_eq!(report.unresolved, 1);
            assert!(
                fixture
                    .kernel
                    .providers
                    .is_quarantined(&fixture.provider.id)
            );
        }
        let _context = fixture.connect();
        assert_eq!(*fixture.provider.mint_count.lock(), 0);
    }

    #[test]
    fn unavailable_instance_intent_does_not_wedge_daemon_startup() {
        let mut fixture = Fixture::new(false, false, false);
        seed_intent(
            &mut fixture,
            &ProviderInstanceId::new(),
            &ProviderGeneration::new(),
        );

        let report = fixture.kernel.recover_startup(NOW).unwrap();
        assert_eq!(report.quarantined, 0);
        assert_eq!(report.unresolved, 1);
        let _context = fixture.connect();
    }

    #[test]
    fn generation_rotation_preserves_ambiguous_intent_and_quarantines_provider() {
        let mut fixture = Fixture::new(false, false, false);
        let provider_id = fixture.provider.id.clone();
        seed_intent(&mut fixture, &provider_id, &ProviderGeneration::new());

        let report = fixture.kernel.recover_startup(NOW).unwrap();
        assert_eq!(report.settled, 0);
        assert_eq!(report.quarantined, 1);
        assert_eq!(report.unresolved, 1);
        assert!(
            fixture
                .kernel
                .providers
                .is_quarantined(&fixture.provider.id)
        );
        let _context = fixture.connect();
    }

    #[test]
    fn settlement_io_failure_is_returned_and_retried_after_result_commit() {
        let mut fixture = Fixture::new(true, false, true);
        let context = fixture.connect();
        let request = fixture.request.clone();
        let receipt = fixture.submit(&context, &request);
        fixture.provider.fail_revoke.store(false, Ordering::SeqCst);
        fs::set_permissions(
            &fixture.recovery_directory,
            fs::Permissions::from_mode(0o500),
        )
        .unwrap();

        let recovery = fixture.kernel.recover_startup(NOW + 1);
        assert!(matches!(recovery, Err(SubmitError::Recovery(_))));
        fs::set_permissions(
            &fixture.recovery_directory,
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert_eq!(
            fixture
                .kernel
                .load_result(receipt.outcome.operation_id())
                .unwrap()
                .unwrap(),
            receipt
        );
        assert_eq!(
            RecoveryJournal::open_test_fixture(&fixture.recovery_directory, [6_u8; 32])
                .unwrap()
                .unresolved()
                .unwrap()
                .len(),
            1
        );

        let report = fixture.kernel.recover_startup(NOW + 2).unwrap();
        assert_eq!(report.settled, 1);
        assert_eq!(report.unresolved, 0);
    }

    #[test]
    fn terminal_evidence_failure_closes_the_mint_gate_until_recovery() {
        let mut fixture = Fixture::new(true, false, false);
        let context = fixture.connect();
        let request = fixture.request.clone();
        let journal_directory = fixture._root.path().join("audit").join("evidence");
        *fixture.provider.lock_evidence_on_mint.lock() = Some(journal_directory.clone());

        let result = fixture
            .kernel
            .submit(&context, &serde_json::to_vec(&request).unwrap(), NOW);
        assert!(matches!(result, Err(SubmitError::Journal(_))));
        fs::set_permissions(&journal_directory, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(
            fixture
                .kernel
                .submit(&context, &serde_json::to_vec(&request).unwrap(), NOW + 1,),
            Err(SubmitError::JournalDegraded)
        ));
        let report = fixture.kernel.recover_startup(NOW + 2).unwrap();
        assert_eq!(report.unresolved, 0);
    }

    #[test]
    fn result_present_restart_settles_without_revoke_loop() {
        let mut fixture = Fixture::new(true, false, false);
        let context = fixture.connect();
        *fixture.provider.lock_recovery_on_revoke.lock() = Some(fixture.recovery_directory.clone());
        let result = fixture.kernel.submit(
            &context,
            &serde_json::to_vec(&fixture.request).unwrap(),
            NOW,
        );
        assert!(matches!(result, Err(SubmitError::Recovery(_))));
        fs::set_permissions(
            &fixture.recovery_directory,
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        let reopened =
            RecoveryJournal::open_test_fixture(&fixture.recovery_directory, [6_u8; 32]).unwrap();
        let entries = reopened.unresolved().unwrap();
        assert_eq!(entries.len(), 1);
        let operation_id = entries[0].context().operation_id.clone();
        let receipt = fixture.kernel.load_result(&operation_id).unwrap().unwrap();
        assert!(receipt.upstream_revoked);
        assert_eq!(fixture.provider.revoked.lock().as_slice(), [TOKEN]);

        let report = fixture.kernel.recover_startup(NOW + 1).unwrap();
        assert_eq!(report.settled, 1);
        assert_eq!(report.unresolved, 0);
        assert_eq!(fixture.provider.revoked.lock().as_slice(), [TOKEN]);
    }

    #[test]
    fn authority_gap_is_coalesced_and_identical_submission_retries_after_authorization() {
        let mut fixture = Fixture::new(true, false, false);
        let context = fixture.connect();
        let request = fixture.request.clone();
        let mut present = Present;
        fixture
            .kernel
            .revoke_delegation(&fixture.delegation)
            .unwrap();

        let refused = fixture.submit(&context, &request);
        assert_eq!(refused.status, TerminalStatus::Refusal);
        assert!(refused.message.starts_with("authority gap: "));
        assert!(refused.message.len() <= 256);
        assert_eq!(*fixture.provider.mint_count.lock(), 0);

        let repeated = fixture.submit(&context, &request);
        assert_eq!(
            repeated.outcome.operation_id(),
            refused.outcome.operation_id()
        );
        assert_eq!(repeated.audit.fact_count, refused.audit.fact_count);
        assert_eq!(*fixture.provider.mint_count.lock(), 0);

        let mut conflicting = request.clone();
        conflicting["input"]["new_oid"] = json!("3".repeat(40));
        assert!(matches!(
            fixture
                .kernel
                .submit(&context, &serde_json::to_vec(&conflicting).unwrap(), NOW,),
            Err(SubmitError::SubmissionConflict { .. })
        ));

        let authorized = fixture
            .kernel
            .attach_selected_grants(
                &mut present,
                &fixture.session,
                vec![(
                    DelegationId::new(),
                    GrantSelection::whole(fixture.grant.clone()),
                )],
                NOW,
                Duration::from_secs(60),
            )
            .unwrap();
        assert_eq!(authorized.len(), 1);

        let admitted = fixture.submit(&context, &request);
        assert_eq!(admitted.status, TerminalStatus::Success);
        assert_ne!(
            admitted.outcome.operation_id(),
            refused.outcome.operation_id()
        );
        assert_eq!(*fixture.provider.mint_count.lock(), 1);
    }
}
