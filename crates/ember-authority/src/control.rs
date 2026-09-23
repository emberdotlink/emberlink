use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    audit::{DurableStore, EvidenceJournal, atomic_write, now_unix, sha256},
    device::{DeviceCustody, DeviceState},
    initialization::{
        InitializationRequest, ReleaseVerificationAnchor, RootContinuityRecord, encode_continuity,
    },
    model::{
        GrantUse, InitializationRecord, PersistentAuthorityState, QualificationCoverage, Refusal,
        SessionRecord, SessionState,
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

impl AuthorityControl {
    pub fn initialize(
        root: &Path,
        request: InitializationRequest,
        anchor: &ReleaseVerificationAnchor,
    ) -> Result<(Self, InitializationReceipt), Refusal> {
        Self::initialize_at(root, request, anchor, now_unix())
    }

    pub fn initialize_at(
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
        let custody = DeviceCustody::restore(&request.devices)?;
        let operation_id = format!("initialization:{}", uuid::Uuid::new_v4());
        let mut state = PersistentAuthorityState {
            schema: "ember.authority-state/v1".into(),
            generation: 0,
            authority_fingerprint: validated.authority_fingerprint.clone(),
            authority_epoch: 1,
            installation_id: uuid::Uuid::new_v4().to_string(),
            release_manifest_digest: validated.release_manifest_digest.clone(),
            daemon_executable_digest: validated.daemon_executable_digest.clone(),
            operator_uid: validated.operator_uid,
            initialized_at: now,
            registry_bytes: validated.registry_bytes,
            registry_sequence: 1,
            qualification_coverage: QualificationCoverage::diagnostic(),
            initialization: InitializationRecord {
                operation_id,
                root_intent_digest: validated.root_intent_digest.clone(),
                release_manifest_digest: validated.release_manifest_digest.clone(),
                release_qualification_digest: validated.release_qualification_digest,
                continuity_digest: validated.continuity_digest,
                initialized_at: now,
                receipt_id: None,
            },
            qualification_grant: validated.qualification_grant,
            caller_eligibility: validated.caller_eligibility,
            harness_profile_authorization: validated.harness_profile_authorization,
            trusted_project: validated.trusted_project,
            route: validated.route,
            devices: request.devices,
            sessions: BTreeMap::new(),
            submissions: BTreeMap::new(),
            operations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            used_permit_nonces: BTreeMap::new(),
            sequence: 0,
            checkpoint_digest: format!("sha256:{}", "0".repeat(64)),
        };
        let stored_receipt =
            EvidenceJournal::append_initialization(&mut state, &custody.receipt_signer()?)?;
        let prior_digest = sha256(&encode_continuity(&request.prior_continuity)?);
        let store = DurableStore::initialize(root, state)?;
        let current_continuity = RootContinuityRecord {
            schema: "ember.root-continuity-record/v1".into(),
            generation: 1,
            authority_fingerprint: validated.authority_fingerprint.clone(),
            prior_record_digest: prior_digest,
            protected_tip_digest: store.protected_tip_digest()?,
            slot_id: request.prior_continuity.slot_id,
        };
        let continuity_bytes = serde_jcs::to_vec(&current_continuity)
            .map_err(|_| Refusal::new("continuity_unavailable"))?;
        if atomic_write(&continuity_path, &continuity_bytes).is_err() {
            let _ = fs::remove_dir_all(root);
            return Err(Refusal::new("continuity_unavailable"));
        }
        let control = Self {
            store: Arc::new(store),
        };
        Ok((
            control,
            InitializationReceipt {
                authority_fingerprint: validated.authority_fingerprint,
                authority_epoch: 1,
                generation: 1,
                receipt_id: stored_receipt.row.receipt_id,
                root_intent_digest: validated.root_intent_digest,
            },
        ))
    }

    pub fn restore(root: &Path) -> Result<Self, Refusal> {
        let store = Arc::new(DurableStore::restore(root)?);
        verify_continuity(root, &store)?;
        verify_stored_receipts(&store)?;
        OperationSettlement::recover_running(&store)?;
        Ok(Self { store })
    }

    pub fn restore_read_only(root: &Path) -> Result<Self, Refusal> {
        let store = Arc::new(DurableStore::restore(root)?);
        verify_continuity(root, &store)?;
        verify_stored_receipts(&store)?;
        Ok(Self { store })
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
        self.store.transaction(|state| {
            let expected_persona = format!("persona:operator:{expected_uid}");
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
                || now_unix() >= state.caller_eligibility.maintenance_window_expiry
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
                        expires_at: state
                            .qualification_grant
                            .expiry
                            .min(now_unix().saturating_add(300)),
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
}

fn verify_stored_receipts(store: &DurableStore) -> Result<(), Refusal> {
    let receipt_ids = store.snapshot()?.receipts.into_keys().collect::<Vec<_>>();
    for receipt_id in receipt_ids {
        ReceiptProjection::verify(store, &receipt_id)?;
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

fn verify_continuity(root: &Path, store: &DurableStore) -> Result<(), Refusal> {
    let path = continuity_path(root)?;
    let bytes = fs::read(path).map_err(|_| Refusal::new("continuity_unavailable"))?;
    if bytes.len() > 16_384 {
        return Err(Refusal::new("continuity_unavailable"));
    }
    let continuity: RootContinuityRecord =
        crate::audit::decode_canonical(&bytes, 16_384, "continuity_unavailable")?;
    let state = store.snapshot()?;
    if continuity.schema != "ember.root-continuity-record/v1"
        || continuity.generation == 0
        || continuity.authority_fingerprint != state.authority_fingerprint
        || continuity.protected_tip_digest != store.protected_tip_digest()?
    {
        return Err(Refusal::new("continuity_unavailable"));
    }
    Ok(())
}
