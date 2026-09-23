use core_events::receipt::{
    ReceiptEnvelope, ReceiptVersion, TerminationAuthority, sign_receipt_v2,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::Mutex,
};

use crate::{
    canonical::{LenEncoder, encode_action_permit, encode_qualification_coverage},
    device::{DeviceCustody, PurposeSigner},
    model::{
        DiagnosticFacts, OperationRecord, OperationStatus, PersistentAuthorityState,
        ReceiptIndexRow, Refusal, StoredReceipt,
    },
};

const STATE_SCHEMA: &str = "ember.authority-state/v1";
const TIP_SCHEMA: &str = "ember.authority-protected-tip/v1";
const RECEIPT_BODY_LIMIT: usize = 1_048_576;
const RECEIPT_ENVELOPE_LIMIT: usize = 2_097_152;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedTip {
    schema: String,
    generation: u64,
    state_digest: String,
}

pub struct DurableStore {
    root: PathBuf,
    state: Mutex<PersistentAuthorityState>,
}

impl DurableStore {
    pub fn initialize(root: &Path, state: PersistentAuthorityState) -> Result<Self, Refusal> {
        if state.schema != STATE_SCHEMA || state.generation != 0 {
            return Err(Refusal::new("initialization_invalid"));
        }
        ensure_private_directory(root)?;
        let generations = root.join("generations");
        ensure_private_directory(&generations)?;
        if root.join("protected-tip.json").exists() {
            return Err(Refusal::new("already_initialized"));
        }
        persist_generation(root, &state)?;
        Ok(Self {
            root: root.to_owned(),
            state: Mutex::new(state),
        })
    }

    pub fn restore(root: &Path) -> Result<Self, Refusal> {
        let tip_bytes = read_bounded(&root.join("protected-tip.json"), 16_384)?;
        let tip: ProtectedTip = decode_canonical(&tip_bytes, 16_384, "restore_failed")?;
        if tip.schema != TIP_SCHEMA {
            return Err(Refusal::new("restore_failed"));
        }
        let path = generation_path(root, tip.generation);
        let state_bytes = read_bounded(&path, RECEIPT_ENVELOPE_LIMIT * 8)?;
        if sha256(&state_bytes) != tip.state_digest {
            return Err(Refusal::new("restore_failed"));
        }
        let state: PersistentAuthorityState =
            decode_canonical(&state_bytes, RECEIPT_ENVELOPE_LIMIT * 8, "restore_failed")?;
        if state.schema != STATE_SCHEMA || state.generation != tip.generation {
            return Err(Refusal::new("restore_failed"));
        }
        crate::action_definition::ActionDefinitionRegistry::restore(&state.registry_bytes)?;
        DeviceCustody::restore(&state.devices)?;
        Ok(Self {
            root: root.to_owned(),
            state: Mutex::new(state),
        })
    }

    pub fn snapshot(&self) -> Result<PersistentAuthorityState, Refusal> {
        self.state
            .lock()
            .map_err(|_| Refusal::new("state_unavailable"))
            .map(|state| state.clone())
    }

    pub fn transaction<T>(
        &self,
        apply: impl FnOnce(&mut PersistentAuthorityState) -> Result<T, Refusal>,
    ) -> Result<T, Refusal> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| Refusal::new("state_unavailable"))?;
        let mut next = guard.clone();
        let result = apply(&mut next)?;
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or_else(|| Refusal::new("state_unavailable"))?;
        persist_generation(&self.root, &next)?;
        *guard = next;
        Ok(result)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn protected_tip_digest(&self) -> Result<String, Refusal> {
        let bytes = read_bounded(&self.root.join("protected-tip.json"), 16_384)?;
        Ok(sha256(&bytes))
    }
}

pub struct EvidenceJournal;

impl EvidenceJournal {
    pub fn health(state: &PersistentAuthorityState) -> Result<&'static str, Refusal> {
        if state.schema == STATE_SCHEMA {
            Ok("ready")
        } else {
            Err(Refusal::new("runner_failed"))
        }
    }

    pub fn append_terminal(
        state: &mut PersistentAuthorityState,
        operation: &OperationRecord,
        facts: Option<&DiagnosticFacts>,
        status: OperationStatus,
        failure_code: Option<&str>,
        signer: &PurposeSigner,
        completed_at: u64,
    ) -> Result<StoredReceipt, Refusal> {
        if signer.purpose() != crate::device::PURPOSE_RECEIPT {
            return Err(Refusal::new("device_purpose_mismatch"));
        }
        operation
            .authorization
            .qualification_coverage
            .validate_diagnostic()?;
        let terminal_sequence = state
            .sequence
            .checked_add(1)
            .ok_or_else(|| Refusal::new("journal_unavailable"))?;
        let fact_digests = operation_fact_digests(
            &state.authority_fingerprint,
            operation,
            facts,
            status.clone(),
            failure_code,
            completed_at,
            terminal_sequence,
        )?;
        let linked_fact_set_digest = linked_fact_set_digest(
            &state.authority_fingerprint,
            &operation.operation_id,
            "action.operation",
            &fact_digests,
        )?;
        let checkpoint_digest = sha256(
            &serde_jcs::to_vec(&serde_json::json!({
                "schema": "ember.audit-checkpoint/v1",
                "previous_checkpoint_digest": state.checkpoint_digest,
                "operation_id": operation.operation_id,
                "terminal_sequence": terminal_sequence,
                "fact_digests": fact_digests,
            }))
            .map_err(|_| Refusal::new("journal_unavailable"))?,
        );
        let body = operation_receipt_body(
            operation,
            facts,
            status.clone(),
            failure_code,
            completed_at,
            terminal_sequence,
            &checkpoint_digest,
            &linked_fact_set_digest,
            signer.generation(),
        )?;
        let body_bytes = serde_jcs::to_vec(&body).map_err(|_| Refusal::new("receipt_invalid"))?;
        if body_bytes.len() > RECEIPT_BODY_LIMIT || body_bytes.len() > 65_536 {
            return Err(Refusal::new("receipt_too_large"));
        }
        let mut envelope = ReceiptEnvelope {
            version: ReceiptVersion::default(),
            kind: "action.operation".into(),
            receipt_id: String::new(),
            daemon_root_id: state.authority_fingerprint.clone(),
            traceparent: None,
            termination_authority: TerminationAuthority::UserSession,
            presence_kind: None,
            body,
            signature: None,
            calling_principal: None,
            presence_reason: None,
            handle_id: None,
            challenge_hash: None,
            verifier_aaguid: None,
        };
        sign_receipt_v2(&mut envelope, signer)
            .map_err(|_| Refusal::new("receipt_signing_failed"))?;
        let canonical =
            serde_jcs::to_vec(&envelope).map_err(|_| Refusal::new("receipt_invalid"))?;
        if canonical.len() > RECEIPT_ENVELOPE_LIMIT {
            return Err(Refusal::new("receipt_too_large"));
        }
        let canonical_bytes =
            String::from_utf8(canonical.clone()).map_err(|_| Refusal::new("receipt_invalid"))?;
        let row = ReceiptIndexRow {
            receipt_id: envelope.receipt_id.clone(),
            operation_id: operation.operation_id.clone(),
            action_ref: operation.action_ref.clone(),
            definition_digest: operation.definition_digest.clone(),
            terminal_status: status,
            started_at: operation.started_at,
            completed_at,
            signed_receipt_digest: sha256(&canonical),
            terminal_sequence,
        };
        let stored = StoredReceipt {
            row,
            canonical_bytes,
            fact_digests,
            checkpoint_digest: checkpoint_digest.clone(),
        };
        state.sequence = terminal_sequence;
        state.checkpoint_digest = checkpoint_digest;
        state
            .receipts
            .insert(envelope.receipt_id.clone(), stored.clone());
        Ok(stored)
    }

    pub fn append_initialization(
        state: &mut PersistentAuthorityState,
        signer: &PurposeSigner,
    ) -> Result<StoredReceipt, Refusal> {
        if signer.purpose() != crate::device::PURPOSE_RECEIPT
            || state.sequence != 0
            || !state.receipts.is_empty()
            || state.initialization.receipt_id.is_some()
        {
            return Err(Refusal::new("initialization_receipt_invalid"));
        }
        let terminal_sequence = 1;
        let mut fact_digests = [
            &state.initialization.root_intent_digest,
            &state.initialization.release_manifest_digest,
            &state.initialization.release_qualification_digest,
            &state.initialization.continuity_digest,
        ]
        .into_iter()
        .map(|digest| {
            digest
                .strip_prefix("sha256:")
                .filter(|value| value.len() == 64 && hex::decode(value).is_ok())
                .map(str::to_owned)
                .ok_or_else(|| Refusal::new("initialization_receipt_invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
        fact_digests.sort();
        fact_digests.dedup();
        if fact_digests.len() != 4 {
            return Err(Refusal::new("initialization_receipt_invalid"));
        }
        let linked_fact_set_digest = linked_fact_set_digest(
            &state.authority_fingerprint,
            &state.initialization.operation_id,
            "authority.initialization",
            &fact_digests,
        )?;
        let checkpoint_digest = sha256(
            &serde_jcs::to_vec(&serde_json::json!({
                "schema": "ember.audit-checkpoint/v1",
                "previous_checkpoint_digest": state.checkpoint_digest,
                "operation_id": state.initialization.operation_id,
                "terminal_sequence": terminal_sequence,
                "fact_digests": fact_digests,
            }))
            .map_err(|_| Refusal::new("journal_unavailable"))?,
        );
        let body = initialization_receipt_body(
            state,
            &linked_fact_set_digest,
            &checkpoint_digest,
            terminal_sequence,
            signer.generation(),
        );
        let mut envelope = ReceiptEnvelope {
            version: ReceiptVersion::default(),
            kind: "authority.initialization".into(),
            receipt_id: String::new(),
            daemon_root_id: state.authority_fingerprint.clone(),
            traceparent: None,
            termination_authority: TerminationAuthority::UserSession,
            presence_kind: None,
            body,
            signature: None,
            calling_principal: None,
            presence_reason: None,
            handle_id: None,
            challenge_hash: None,
            verifier_aaguid: None,
        };
        sign_receipt_v2(&mut envelope, signer)
            .map_err(|_| Refusal::new("receipt_signing_failed"))?;
        let canonical =
            serde_jcs::to_vec(&envelope).map_err(|_| Refusal::new("receipt_invalid"))?;
        if canonical.len() > RECEIPT_ENVELOPE_LIMIT {
            return Err(Refusal::new("receipt_too_large"));
        }
        let row = ReceiptIndexRow {
            receipt_id: envelope.receipt_id.clone(),
            operation_id: state.initialization.operation_id.clone(),
            action_ref: crate::model::ActionRef {
                action_key: "authority.initialize_empty".into(),
                action_version: "v1".into(),
                plugin_address: "builtin.authority".into(),
            },
            definition_digest: state.initialization.root_intent_digest.clone(),
            terminal_status: OperationStatus::Success,
            started_at: state.initialization.initialized_at,
            completed_at: state.initialization.initialized_at,
            signed_receipt_digest: sha256(&canonical),
            terminal_sequence,
        };
        let stored = StoredReceipt {
            row,
            canonical_bytes: String::from_utf8(canonical)
                .map_err(|_| Refusal::new("receipt_invalid"))?,
            fact_digests,
            checkpoint_digest: checkpoint_digest.clone(),
        };
        state.initialization.receipt_id = Some(envelope.receipt_id.clone());
        state.sequence = terminal_sequence;
        state.checkpoint_digest = checkpoint_digest;
        state.receipts.insert(envelope.receipt_id, stored.clone());
        Ok(stored)
    }
}

pub fn initialization_receipt_body(
    state: &PersistentAuthorityState,
    linked_fact_set_digest: &str,
    checkpoint_digest: &str,
    terminal_sequence: u64,
    signer_generation: u64,
) -> serde_json::Value {
    serde_json::json!({
        "schema": "ember.authority-initialization-receipt-body/v1",
        "operation_id": state.initialization.operation_id,
        "root_intent_digest": state.initialization.root_intent_digest,
        "release_manifest_digest": state.initialization.release_manifest_digest,
        "release_qualification_digest": state.initialization.release_qualification_digest,
        "continuity_digest": state.initialization.continuity_digest,
        "initialized_at": state.initialization.initialized_at,
        "terminal_sequence": terminal_sequence,
        "checkpoint_digest": checkpoint_digest,
        "linked_fact_set_digest": linked_fact_set_digest,
        "signer_generation": signer_generation,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn operation_receipt_body(
    operation: &OperationRecord,
    facts: Option<&DiagnosticFacts>,
    status: OperationStatus,
    failure_code: Option<&str>,
    completed_at: u64,
    terminal_sequence: u64,
    checkpoint_digest: &str,
    linked_fact_set_digest: &str,
    signer_generation: u64,
) -> Result<serde_json::Value, Refusal> {
    let action_boundary = match status {
        OperationStatus::Success => "effect_committed",
        OperationStatus::CancelledBeforeEffect => "cancelled_before_effect",
        OperationStatus::Running => return Err(Refusal::new("settlement_invalid")),
        OperationStatus::ExecutionFailure | OperationStatus::EffectUnknown => "effect_unknown",
    };
    let permit = &operation.authorization.permit;
    Ok(serde_json::json!({
        "schema": "ember.action-operation-receipt-body/v1",
        "operation_id": operation.operation_id,
        "submission_id": operation.submission_id,
        "canonical_request_digest": operation.authorization.canonical_request_digest,
        "action_ref": operation.action_ref,
        "definition_digest": operation.definition_digest,
        "registry_sequence": operation.authorization.registry_sequence,
        "definition_resolved_at": operation.authorization.definition_resolved_at,
        "persona_id": operation.authorization.persona_id,
        "session_id": operation.session_id,
        "execution_binding_digest": operation.execution_binding_digest,
        "assurance_profile_id": permit.assurance_profile_id,
        "assurance_profile_digest": permit.assurance_profile_digest,
        "canonicalizer_id": permit.canonicalizer_id,
        "canonicalizer_digest": permit.canonicalizer_digest,
        "grant_use_id": operation.authorization.grant_use.grant_use_id,
        "grant_use_ceilings": permit.grant_use_id_and_ceiling_list,
        "delegation_id": operation.authorization.delegation_id,
        "target": permit.target,
        "derived_need": operation.authorization.need,
        "consequence_class": permit.consequence_class,
        "authorization_expiry": permit.expiry,
        "terminal_status": status,
        "action_boundary": action_boundary,
        "cleanup_status": operation.cleanup_state,
        "cleanup_debt": null,
        "facts": facts,
        "failure_code": failure_code,
        "runner_key": crate::runner::DIAGNOSTIC_RUNNER,
        "handler_key": "builtin.diagnostic.authority-status/v1",
        "started_at": operation.started_at,
        "completed_at": completed_at,
        "terminal_journal_sequence": terminal_sequence,
        "checkpoint_digest": checkpoint_digest,
        "linked_fact_set_digest": linked_fact_set_digest,
        "signer_generation": signer_generation,
    }))
}

pub fn operation_fact_digests(
    authority_fingerprint: &str,
    operation: &OperationRecord,
    facts: Option<&DiagnosticFacts>,
    status: OperationStatus,
    failure_code: Option<&str>,
    completed_at: u64,
    terminal_sequence: u64,
) -> Result<Vec<String>, Refusal> {
    let permit_digest = sha256(&encode_action_permit(
        &operation.authorization.permit,
        true,
    )?);
    let coverage_digest = sha256(&encode_qualification_coverage(
        authority_fingerprint,
        &operation.operation_id,
        &operation.authorization.qualification_coverage,
    )?);
    let authorization_fact = serde_json::json!({
        "schema": "ember.audit.authorization/v1",
        "operation_id": operation.operation_id,
        "permit_digest": permit_digest,
        "need": operation.authorization.need,
        "grant_use": operation.authorization.grant_use,
        "qualification_coverage_digest": coverage_digest,
    });
    let outcome_fact = serde_json::json!({
        "schema": "ember.audit.runner-outcome/v1",
        "operation_id": operation.operation_id,
        "facts": facts,
        "failure_code": failure_code,
    });
    let terminal_fact = serde_json::json!({
        "schema": "ember.audit.operation-terminal/v1",
        "operation_id": operation.operation_id,
        "status": status,
        "completed_at": completed_at,
        "sequence": terminal_sequence,
    });
    let mut fact_digests = [authorization_fact, outcome_fact, terminal_fact]
        .into_iter()
        .map(|fact| {
            serde_jcs::to_vec(&fact)
                .map(|bytes| sha256_hex(&bytes))
                .map_err(|_| Refusal::new("journal_unavailable"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    fact_digests.sort();
    Ok(fact_digests)
}

pub fn linked_fact_set_digest(
    authority_fingerprint: &str,
    operation_id: &str,
    receipt_kind: &str,
    fact_digests: &[String],
) -> Result<String, Refusal> {
    if !fact_digests.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(Refusal::new("receipt_invalid"));
    }
    let mut encoded = LenEncoder::new("ember/receipt-linked-fact-set/v1")?;
    encoded
        .digest(authority_fingerprint)?
        .string(operation_id)?
        .string(receipt_kind)?
        .list(fact_digests, |digest| {
            let bytes = hex::decode(digest).map_err(|_| Refusal::new("receipt_invalid"))?;
            if bytes.len() != 32 {
                return Err(Refusal::new("receipt_invalid"));
            }
            Ok(bytes)
        })?;
    Ok(sha256_hex(&encoded.finish()))
}

pub fn decode_canonical<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
    limit: usize,
    code: &'static str,
) -> Result<T, Refusal> {
    if bytes.len() > limit {
        return Err(Refusal::new(if limit == 16_384 {
            "frame_too_large"
        } else {
            "input_too_large"
        }));
    }
    let value: T = serde_json::from_slice(bytes).map_err(|_| Refusal::new(code))?;
    let canonical = serde_jcs::to_vec(&value).map_err(|_| Refusal::new(code))?;
    if canonical != bytes {
        return Err(Refusal::new(code));
    }
    Ok(value)
}

fn persist_generation(root: &Path, state: &PersistentAuthorityState) -> Result<(), Refusal> {
    let bytes = serde_jcs::to_vec(state).map_err(|_| Refusal::new("state_unavailable"))?;
    let path = generation_path(root, state.generation);
    atomic_write(&path, &bytes)?;
    let tip = ProtectedTip {
        schema: TIP_SCHEMA.into(),
        generation: state.generation,
        state_digest: sha256(&bytes),
    };
    let tip_bytes = serde_jcs::to_vec(&tip).map_err(|_| Refusal::new("state_unavailable"))?;
    atomic_write(&root.join("protected-tip.json"), &tip_bytes)?;
    advance_continuity(root, state, &tip_bytes)
}

fn generation_path(root: &Path, generation: u64) -> PathBuf {
    root.join("generations")
        .join(format!("{generation:020}.json"))
}

fn advance_continuity(
    root: &Path,
    state: &PersistentAuthorityState,
    protected_tip_bytes: &[u8],
) -> Result<(), Refusal> {
    let Some(parent) = root.parent() else {
        return Err(Refusal::new("continuity_unavailable"));
    };
    let Some(name) = root.file_name().and_then(|value| value.to_str()) else {
        return Err(Refusal::new("continuity_unavailable"));
    };
    let path = parent.join(format!("{name}.continuity.json"));
    if !path.exists() {
        return Ok(());
    }
    let prior_bytes =
        read_bounded(&path, 16_384).map_err(|_| Refusal::new("continuity_unavailable"))?;
    let prior: crate::initialization::RootContinuityRecord =
        decode_canonical(&prior_bytes, 16_384, "continuity_unavailable")?;
    if prior.authority_fingerprint != state.authority_fingerprint {
        return Err(Refusal::new("continuity_unavailable"));
    }
    let next = crate::initialization::RootContinuityRecord {
        schema: "ember.root-continuity-record/v1".into(),
        generation: prior
            .generation
            .checked_add(1)
            .ok_or_else(|| Refusal::new("continuity_unavailable"))?,
        authority_fingerprint: state.authority_fingerprint.clone(),
        prior_record_digest: sha256(&prior_bytes),
        protected_tip_digest: sha256(protected_tip_bytes),
        slot_id: prior.slot_id,
    };
    let bytes = serde_jcs::to_vec(&next).map_err(|_| Refusal::new("continuity_unavailable"))?;
    atomic_write(&path, &bytes).map_err(|_| Refusal::new("continuity_unavailable"))
}

fn ensure_private_directory(path: &Path) -> Result<(), Refusal> {
    fs::create_dir_all(path).map_err(|_| Refusal::new("state_unavailable"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| Refusal::new("state_unavailable"))
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), Refusal> {
    let parent = path
        .parent()
        .ok_or_else(|| Refusal::new("state_unavailable"))?;
    ensure_private_directory(parent)?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|v| v.to_str()).unwrap_or("state"),
        uuid::Uuid::new_v4()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|_| Refusal::new("state_unavailable"))?;
    file.write_all(bytes)
        .map_err(|_| Refusal::new("state_unavailable"))?;
    file.sync_all()
        .map_err(|_| Refusal::new("state_unavailable"))?;
    fs::rename(&temp, path).map_err(|_| Refusal::new("state_unavailable"))?;
    let directory = OpenOptions::new()
        .read(true)
        .open(parent)
        .map_err(|_| Refusal::new("state_unavailable"))?;
    directory
        .sync_all()
        .map_err(|_| Refusal::new("state_unavailable"))
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Refusal> {
    let metadata = fs::metadata(path).map_err(|_| Refusal::new("restore_failed"))?;
    if metadata.len() > limit as u64 {
        return Err(Refusal::new("input_too_large"));
    }
    fs::read(path).map_err(|_| Refusal::new("restore_failed"))
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn now_unix() -> u64 {
    time::OffsetDateTime::now_utc().unix_timestamp().max(0) as u64
}

impl From<io::Error> for Refusal {
    fn from(_: io::Error) -> Self {
        Refusal::new("state_unavailable")
    }
}
