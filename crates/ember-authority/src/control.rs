use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    audit::{DurableStore, EvidenceJournal, atomic_write_new, now_unix, sha256},
    device::{DeviceCustody, DeviceState},
    diagnostic_bootstrap::{DevelopmentInitializationProof, DevelopmentInitializationRequest},
    initialization::{
        CallerEligibilityRecord, HarnessProfileAuthorization, InitializationRequest,
        QualificationGrantRecord, ReleaseVerificationAnchor, RootContinuityRecord,
        RouteAuthorization, TrustedProjectAuthorization, encode_continuity,
    },
    model::{
        GrantUse, InitializationEvidence, InitializationRecord, PersistentAuthorityState,
        ProductClassification, QualificationCoverage, Refusal, SessionRecord, SessionState,
    },
    operation::OperationSettlement,
    receipt::ReceiptProjection,
};

const MAX_ACTIVE_SESSIONS: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializationReceipt {
    pub authority_fingerprint: String,
    pub authority_epoch: u64,
    pub generation: u64,
    pub receipt_id: String,
    pub root_intent_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityStatus {
    pub schema: String,
    pub state: String,
    pub authority_fingerprint: String,
    pub authority_epoch: u64,
    pub generation: u64,
    pub checkpoint_digest: String,
    pub maintenance_window_expiry: u64,
    pub journal_health: String,
    pub active_sessions: u64,
    pub initialization: InitializationRecord,
    pub classification: ProductClassification,
}

#[derive(Clone, Debug)]
pub struct SessionLaunch {
    pub session_id: String,
    pub persona_id: String,
    pub execution_binding_id: String,
    pub endpoint: String,
}

#[derive(Clone)]
pub struct AuthorityControl {
    store: Arc<DurableStore>,
}

struct InitializationPlan {
    authority_fingerprint: String,
    classification: ProductClassification,
    daemon_executable_digest: String,
    daemon_executable_identity: Option<String>,
    registry_bytes: String,
    operator_uid: u32,
    root_intent_digest: String,
    evidence: InitializationEvidence,
    continuity_digest: String,
    development_initialization: Option<DevelopmentInitializationProof>,
    qualification_grant: QualificationGrantRecord,
    caller_eligibility: CallerEligibilityRecord,
    harness_profile_authorization: HarnessProfileAuthorization,
    trusted_project: TrustedProjectAuthorization,
    route: RouteAuthorization,
    devices: DeviceState,
    prior_continuity: RootContinuityRecord,
}

impl AuthorityControl {
    pub fn initialize_release(
        root: &Path,
        request: InitializationRequest,
        anchor: &ReleaseVerificationAnchor,
    ) -> Result<(Self, InitializationReceipt), Refusal> {
        Self::initialize_release_at(root, request, anchor, now_unix())
    }

    pub fn initialize_release_at(
        root: &Path,
        request: InitializationRequest,
        anchor: &ReleaseVerificationAnchor,
        now: u64,
    ) -> Result<(Self, InitializationReceipt), Refusal> {
        let continuity_path = continuity_path(root)?;
        if root.exists() || continuity_path.exists() {
            return Err(Refusal::new("already_initialized"));
        }
        let validated = request.validate(anchor, now)?;
        let plan = InitializationPlan {
            authority_fingerprint: validated.authority_fingerprint,
            classification: ProductClassification::release_qualified(),
            daemon_executable_digest: validated.daemon_executable_digest,
            daemon_executable_identity: Some(validated.daemon_executable_identity),
            registry_bytes: validated.registry_bytes,
            operator_uid: validated.operator_uid,
            root_intent_digest: validated.root_intent_digest,
            evidence: InitializationEvidence::Release {
                release_manifest_digest: validated.release_manifest_digest,
                release_qualification_digest: validated.release_qualification_digest,
            },
            continuity_digest: validated.continuity_digest,
            development_initialization: None,
            qualification_grant: validated.qualification_grant,
            caller_eligibility: validated.caller_eligibility,
            harness_profile_authorization: validated.harness_profile_authorization,
            trusted_project: validated.trusted_project,
            route: validated.route,
            devices: request.devices,
            prior_continuity: request.prior_continuity,
        };
        Self::initialize_plan(root, continuity_path, plan, now)
    }

    pub fn initialize(
        root: &Path,
        request: DevelopmentInitializationRequest,
    ) -> Result<(Self, InitializationReceipt), Refusal> {
        Self::initialize_at(root, request, now_unix())
    }

    pub fn initialize_at(
        root: &Path,
        request: DevelopmentInitializationRequest,
        now: u64,
    ) -> Result<(Self, InitializationReceipt), Refusal> {
        let continuity_path = continuity_path(root)?;
        crate::diagnostic_bootstrap::validate_new_state_root(root)?;
        let validated = request.validate(now)?;
        let development_initialization = request.proof();
        let plan = InitializationPlan {
            authority_fingerprint: validated.authority_fingerprint,
            classification: validated.classification,
            daemon_executable_digest: validated.daemon_executable_digest,
            daemon_executable_identity: Some(validated.daemon_executable_identity),
            registry_bytes: validated.registry_bytes,
            operator_uid: validated.operator_uid,
            root_intent_digest: validated.root_intent_digest,
            evidence: validated.evidence,
            continuity_digest: validated.continuity_digest,
            development_initialization: Some(development_initialization),
            qualification_grant: validated.qualification_grant,
            caller_eligibility: validated.caller_eligibility,
            harness_profile_authorization: validated.harness_profile_authorization,
            trusted_project: validated.trusted_project,
            route: validated.route,
            devices: request.devices,
            prior_continuity: request.prior_continuity,
        };
        Self::initialize_plan(root, continuity_path, plan, now)
    }

    fn initialize_plan(
        root: &Path,
        continuity_path: PathBuf,
        plan: InitializationPlan,
        now: u64,
    ) -> Result<(Self, InitializationReceipt), Refusal> {
        let custody = DeviceCustody::restore(&plan.devices)?;
        let state = PersistentAuthorityState {
            schema: "ember.authority-state/v1".into(),
            generation: 0,
            authority_fingerprint: plan.authority_fingerprint.clone(),
            authority_epoch: 1,
            installation_id: uuid::Uuid::new_v4().to_string(),
            classification: plan.classification,
            daemon_executable_digest: plan.daemon_executable_digest,
            daemon_executable_identity: plan.daemon_executable_identity,
            operator_uid: plan.operator_uid,
            initialized_at: now,
            registry_bytes: plan.registry_bytes,
            registry_sequence: 1,
            qualification_coverage: QualificationCoverage::diagnostic(),
            initialization: InitializationRecord {
                operation_id: format!("initialization:{}", uuid::Uuid::new_v4()),
                root_intent_digest: plan.root_intent_digest.clone(),
                evidence: plan.evidence,
                continuity_digest: plan.continuity_digest,
                initialized_at: now,
                receipt_id: None,
            },
            development_initialization: plan.development_initialization,
            qualification_grant: plan.qualification_grant,
            caller_eligibility: plan.caller_eligibility,
            harness_profile_authorization: plan.harness_profile_authorization,
            trusted_project: plan.trusted_project,
            route: plan.route,
            devices: plan.devices,
            sessions: BTreeMap::new(),
            submissions: BTreeMap::new(),
            operations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            used_permit_nonces: BTreeMap::new(),
            sequence: 0,
            checkpoint_digest: format!("sha256:{}", "0".repeat(64)),
        };
        Self::commit_initialization(
            root,
            continuity_path,
            state,
            &custody,
            plan.authority_fingerprint,
            plan.root_intent_digest,
            plan.prior_continuity,
        )
    }

    fn commit_initialization(
        root: &Path,
        continuity_path: PathBuf,
        mut state: PersistentAuthorityState,
        custody: &DeviceCustody,
        authority_fingerprint: String,
        root_intent_digest: String,
        prior_continuity: RootContinuityRecord,
    ) -> Result<(Self, InitializationReceipt), Refusal> {
        let stored_receipt =
            EvidenceJournal::append_initialization(&mut state, &custody.receipt_signer()?)?;
        let prior_digest = sha256(&encode_continuity(&prior_continuity)?);
        let store = DurableStore::initialize(root, state)?;
        let current_continuity = RootContinuityRecord {
            schema: "ember.root-continuity-record/v1".into(),
            generation: 1,
            authority_fingerprint: authority_fingerprint.clone(),
            prior_record_digest: prior_digest,
            protected_tip_digest: store.protected_tip_digest()?,
            slot_id: prior_continuity.slot_id,
        };
        let continuity_bytes = serde_jcs::to_vec(&current_continuity)
            .map_err(|_| Refusal::new("continuity_unavailable"))?;
        atomic_write_new(&continuity_path, &continuity_bytes)
            .map_err(|_| Refusal::new("continuity_unavailable"))?;
        store.finalize_initial_continuity()?;
        Ok((
            Self {
                store: Arc::new(store),
            },
            InitializationReceipt {
                authority_fingerprint,
                authority_epoch: 1,
                generation: 1,
                receipt_id: stored_receipt.row.receipt_id,
                root_intent_digest,
            },
        ))
    }

    pub fn restore(root: &Path) -> Result<Self, Refusal> {
        let store = Arc::new(DurableStore::restore(root)?);
        let state = store.snapshot()?;
        Self::verify_state_root_for_initialization(root, &state)?;
        verify_initialization_state(&state)?;
        verify_continuity(root, &store, &state)?;
        verify_stored_receipts(&store)?;
        OperationSettlement::recover_running(&store)?;
        Ok(Self { store })
    }

    pub fn restore_read_only(root: &Path) -> Result<Self, Refusal> {
        let store = Arc::new(DurableStore::restore(root)?);
        let state = store.snapshot()?;
        Self::verify_state_root_for_initialization(root, &state)?;
        verify_initialization_state(&state)?;
        verify_continuity(root, &store, &state)?;
        verify_stored_receipts(&store)?;
        Ok(Self { store })
    }

    pub fn read_status(state: &PersistentAuthorityState) -> Result<AuthorityStatus, Refusal> {
        Ok(AuthorityStatus {
            schema: "ember.authority-status/v1".into(),
            state: "ready".into(),
            authority_fingerprint: state.authority_fingerprint.clone(),
            authority_epoch: state.authority_epoch,
            generation: state.generation,
            checkpoint_digest: state.checkpoint_digest.clone(),
            maintenance_window_expiry: state.caller_eligibility.maintenance_window_expiry,
            journal_health: EvidenceJournal::health(state)?.into(),
            active_sessions: state
                .sessions
                .values()
                .filter(|session| session.state == SessionState::Active)
                .count() as u64,
            initialization: state.initialization.clone(),
            classification: state.classification.clone(),
        })
    }
    pub fn verify_persisted_state(&self, root: &Path) -> Result<PersistentAuthorityState, Refusal> {
        self.store.inspect_verified_state(|state| {
            Self::verify_state_root_for_initialization(root, state)?;
            verify_initialization_state(state)?;
            verify_continuity(root, &self.store, state)?;
            verify_stored_receipts_state(state)?;
            Ok(state.clone())
        })
    }

    pub fn generate_devices() -> Result<DeviceState, Refusal> {
        DeviceCustody::generate()
    }

    pub fn open_diagnostic_session(
        &self,
        challenge: &str,
        expected_uid: u32,
        context: &crate::model::LaunchContext,
        endpoint: String,
    ) -> Result<SessionLaunch, Refusal> {
        crate::model::DiagnosticInput {
            challenge: challenge.to_owned(),
        }
        .validate()?;
        let launch_time = now_unix();
        self.store.transaction(|state| {
            let expected_persona = "persona:operator:local";
            let project_digest = sha256(context.project_root.as_bytes());
            let worktree_digest = sha256(context.worktree.as_bytes());
            if state.operator_uid != expected_uid
                || state.caller_eligibility.operator_uid != expected_uid
                || state.caller_eligibility.persona_id != expected_persona
                || state.qualification_grant.persona_id != expected_persona
            {
                return Err(Refusal::new("persona_mismatch"));
            }
            if state.caller_eligibility.principal_id != state.qualification_grant.principal_id
                || state.caller_eligibility.persona_id != state.qualification_grant.persona_id
                || state.caller_eligibility.profile_artifact_digest
                    != state.harness_profile_authorization.artifact_digest
                || state.caller_eligibility.executable_digest
                    != state.harness_profile_authorization.executable_digest
                || state.caller_eligibility.trusted_project_digest
                    != crate::initialization::digest_encoded(
                        &crate::initialization::encode_project(&state.trusted_project)?,
                    )
                || state.trusted_project.project_root_digest != project_digest
                || state.trusted_project.worktree_digest != worktree_digest
                || state.trusted_project.profile_artifact_digest
                    != state.harness_profile_authorization.artifact_digest
                || state.route.action_definition_digest
                    != state.qualification_grant.action_definition_digest
                || state.route.runner_class != "builtin"
                || state.route.delivery_lane != "sealed-exec"
                || state.qualification_grant.operation_class != "diagnostic.read"
                || launch_time >= state.caller_eligibility.maintenance_window_expiry
            {
                return Err(Refusal::new("launch_not_authorized"));
            }
            let active_count = state
                .sessions
                .values()
                .filter(|session| session.state != SessionState::Closed)
                .count();
            if active_count >= MAX_ACTIVE_SESSIONS {
                return Err(Refusal::new("session_limit_exceeded"));
            }
            let session_id = uuid::Uuid::new_v4().to_string();
            let persona_id = state.caller_eligibility.persona_id.clone();
            let execution_binding_id = uuid::Uuid::new_v4().to_string();
            let execution_binding_digest = sha256(execution_binding_id.as_bytes());
            let launch = SessionLaunch {
                session_id: session_id.clone(),
                persona_id: persona_id.clone(),
                execution_binding_id,
                endpoint: endpoint.clone(),
            };
            state.sessions.insert(
                session_id.clone(),
                SessionRecord {
                    session_id: session_id.clone(),
                    persona_id,
                    execution_binding_digest,
                    expected_uid,
                    expected_pid: None,
                    expected_pid_version: None,
                    challenge: challenge.to_owned(),
                    grant: GrantUse {
                        grant_use_id: uuid::Uuid::new_v4().to_string(),
                        grant_id: state.qualification_grant.grant_id.clone(),
                        delegation_id: format!("delegation:{session_id}"),
                        session_id: session_id.clone(),
                        target: state.qualification_grant.target.clone(),
                        permission: state.qualification_grant.permission.clone(),
                        material_class: state.qualification_grant.material_class.clone(),
                        provider: state.qualification_grant.provider.clone(),
                        protocol: state.qualification_grant.protocol.clone(),
                        destination: state.qualification_grant.destination.clone(),
                        operation_class: state.qualification_grant.operation_class.clone(),
                        request_count_ceiling: state.qualification_grant.request_count_ceiling,
                        byte_budget: state.qualification_grant.byte_budget,
                        rate_ceiling: state.qualification_grant.rate_ceiling,
                        remaining_uses: state.qualification_grant.request_count_ceiling,
                        offline_bound: state.qualification_grant.offline_bound,
                        expires_at: state
                            .qualification_grant
                            .expiry
                            .min(launch_time.saturating_add(60)),
                        revoked: false,
                    },
                    endpoint,
                    state: SessionState::Opening,
                },
            );
            Ok(launch)
        })
    }

    pub fn activate_session(
        &self,
        session_id: &str,
        execution_binding_id: &str,
        pid: u32,
        pid_version: Option<u64>,
    ) -> Result<(), Refusal> {
        self.store.transaction(|state| {
            let session = state
                .sessions
                .get_mut(session_id)
                .ok_or_else(|| Refusal::new("session_binding_mismatch"))?;
            if sha256(execution_binding_id.as_bytes()) != session.execution_binding_digest
                || session.state != SessionState::Opening
            {
                return Err(Refusal::new("session_binding_mismatch"));
            }
            session.expected_pid = Some(pid);
            session.expected_pid_version = pid_version;
            session.state = SessionState::Active;
            Ok(())
        })
    }

    pub fn close_session(&self, session_id: &str) -> Result<(), Refusal> {
        self.store.transaction(|state| {
            let session = state
                .sessions
                .get_mut(session_id)
                .ok_or_else(|| Refusal::new("session_binding_mismatch"))?;
            session.state = SessionState::Closed;
            session.expected_pid = None;
            session.expected_pid_version = None;
            Ok(())
        })
    }

    pub fn store(&self) -> &Arc<DurableStore> {
        &self.store
    }
    fn verify_state_root_for_initialization(
        root: &Path,
        state: &PersistentAuthorityState,
    ) -> Result<(), Refusal> {
        if matches!(
            state.initialization.evidence,
            InitializationEvidence::Development { .. }
        ) {
            crate::diagnostic_bootstrap::validate_development_state_root(root)?;
        }
        Ok(())
    }
}
fn verify_initialization_state(state: &PersistentAuthorityState) -> Result<(), Refusal> {
    match &state.initialization.evidence {
        InitializationEvidence::Development { .. } => {
            crate::diagnostic_bootstrap::verify_persisted_development(state)
        }
        InitializationEvidence::Release { .. } => Ok(()),
    }
}

fn verify_stored_receipts(store: &DurableStore) -> Result<(), Refusal> {
    let state = store.snapshot()?;
    verify_stored_receipts_state(&state)
}

fn verify_stored_receipts_state(state: &PersistentAuthorityState) -> Result<(), Refusal> {
    for receipt_id in state.receipts.keys() {
        ReceiptProjection::verify_state(state, receipt_id)?;
    }
    Ok(())
}

fn continuity_path(root: &Path) -> Result<PathBuf, Refusal> {
    let parent = root
        .parent()
        .ok_or_else(|| Refusal::new("continuity_unavailable"))?;
    let name = root
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| Refusal::new("continuity_unavailable"))?;
    Ok(parent.join(format!("{name}.continuity.json")))
}

fn verify_continuity(
    root: &Path,
    store: &DurableStore,
    state: &PersistentAuthorityState,
) -> Result<(), Refusal> {
    let path = continuity_path(root)?;
    let bytes = crate::audit::read_bounded(&path, 16_384)
        .map_err(|_| Refusal::new("continuity_unavailable"))?;
    let continuity: RootContinuityRecord =
        crate::audit::decode_canonical(&bytes, 16_384, "continuity_unavailable")?;
    let expected_generation = state
        .generation
        .checked_add(1)
        .ok_or_else(|| Refusal::new("continuity_unavailable"))?;
    let slot_matches = state
        .development_initialization
        .as_ref()
        .is_none_or(|proof| continuity.slot_id == proof.prior_continuity.slot_id);
    let prior_matches = if state.generation == 0 {
        continuity.prior_record_digest == state.initialization.continuity_digest
    } else {
        is_sha256_digest(&continuity.prior_record_digest)
    };
    if continuity.schema != "ember.root-continuity-record/v1"
        || continuity.generation != expected_generation
        || !slot_matches
        || !prior_matches
        || continuity.authority_fingerprint != state.authority_fingerprint
        || continuity.protected_tip_digest != store.protected_tip_digest()?
    {
        return Err(Refusal::new("continuity_unavailable"));
    }
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}
