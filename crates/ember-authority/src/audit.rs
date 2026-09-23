use core_events::receipt::{
    ReceiptEnvelope, ReceiptVersion, TerminationAuthority, sign_receipt_v2,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
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
    daemon_executable_digest: String,
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
        create_private_directory(root)?;
        let generations = root.join("generations");
        create_private_directory(&generations)?;
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
        enforce_high_water(root, tip.generation, &tip_bytes)?;
        commit_continuity(root, Some((tip.generation, sha256(&tip_bytes))))?;
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

    /// Return the manifest-pinned daemon digest without decoding authority
    /// owner state or Device custody into the client process.
    pub fn installed_daemon_executable_digest(root: &Path) -> Result<String, Refusal> {
        let tip_bytes = read_bounded(&root.join("protected-tip.json"), 16_384)?;
        let tip: ProtectedTip = decode_canonical(&tip_bytes, 16_384, "restore_failed")?;
        if tip.schema != TIP_SCHEMA {
            return Err(Refusal::new("restore_failed"));
        }
        enforce_high_water(root, tip.generation, &tip_bytes)?;
        Ok(tip.daemon_executable_digest)
    }

    pub fn snapshot(&self) -> Result<PersistentAuthorityState, Refusal> {
        self.state
            .lock()
            .map_err(|_| Refusal::new("state_unavailable"))
            .map(|state| state.clone())
    }
    pub fn verify_persisted_state(&self) -> Result<(), Refusal> {
        let state = self
            .state
            .lock()
            .map_err(|_| Refusal::new("state_unavailable"))?;
        let tip_bytes = read_bounded(&self.root.join("protected-tip.json"), 16_384)?;
        let tip: ProtectedTip = decode_canonical(&tip_bytes, 16_384, "restore_failed")?;
        enforce_high_water(&self.root, tip.generation, &tip_bytes)?;
        let state_bytes = read_bounded(
            &generation_path(&self.root, tip.generation),
            RECEIPT_ENVELOPE_LIMIT * 8,
        )?;
        let live_state_bytes =
            serde_jcs::to_vec(&*state).map_err(|_| Refusal::new("state_unavailable"))?;
        if tip.schema != TIP_SCHEMA
            || tip.generation != state.generation
            || tip.state_digest != sha256(&state_bytes)
            || tip.state_digest != sha256(&live_state_bytes)
            || tip.daemon_executable_digest != state.daemon_executable_digest
        {
            return Err(Refusal::new("restore_failed"));
        }
        Ok(())
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
            &state.classification,
            &state.initialization.evidence,
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
        ensure_receipt_show_frame_fits(&canonical)?;
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
            classification: state.classification.clone(),
            initialization_evidence: state.initialization.evidence.clone(),
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
        let classification_digest = classification_digest(&state.classification)?;
        let expected_fact_count = 3 + state.initialization.evidence.fact_digests().len();
        let mut initialization_facts = vec![
            state.initialization.root_intent_digest.as_str(),
            state.initialization.continuity_digest.as_str(),
            classification_digest.as_str(),
        ];
        initialization_facts.extend(state.initialization.evidence.fact_digests());
        let mut fact_digests = initialization_facts
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
        if fact_digests.len() != expected_fact_count {
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
        ensure_receipt_show_frame_fits(&canonical)?;
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
            classification: state.classification.clone(),
            initialization_evidence: state.initialization.evidence.clone(),
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
        "initialization_evidence": state.initialization.evidence,
        "classification": state.classification,
        "continuity_digest": state.initialization.continuity_digest,
        "initialized_at": state.initialization.initialized_at,
        "terminal_sequence": terminal_sequence,
        "checkpoint_digest": checkpoint_digest,
        "linked_fact_set_digest": linked_fact_set_digest,
        "signer_generation": signer_generation,
    })
}
pub fn classification_digest(
    classification: &crate::model::ProductClassification,
) -> Result<String, Refusal> {
    let bytes =
        serde_jcs::to_vec(classification).map_err(|_| Refusal::new("classification_invalid"))?;
    Ok(sha256(&bytes))
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
    classification: &crate::model::ProductClassification,
    initialization_evidence: &crate::model::InitializationEvidence,
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
        "classification": classification,
        "initialization_evidence": initialization_evidence,
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

fn ensure_receipt_show_frame_fits(canonical_receipt: &[u8]) -> Result<(), Refusal> {
    let canonical_receipt =
        std::str::from_utf8(canonical_receipt).map_err(|_| Refusal::new("receipt_invalid"))?;
    let response = serde_json::json!({
        "canonical_receipt": canonical_receipt,
        "result": "receipt_show",
    });
    let bytes = serde_jcs::to_vec(&response).map_err(|_| Refusal::new("receipt_invalid"))?;
    if bytes.len() > crate::ipc::CONTROL_FRAME_LIMIT {
        return Err(Refusal::new("receipt_too_large"));
    }
    Ok(())
}

pub fn decode_canonical<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
    limit: usize,
    code: &'static str,
) -> Result<T, Refusal> {
    let size_code = if limit == 16_384 {
        "frame_too_large"
    } else {
        "input_too_large"
    };
    if bytes.len() > limit {
        return Err(Refusal::new(size_code));
    }
    let started = Instant::now();
    enforce_json_shape(
        bytes,
        if limit == 16_384 { 16 } else { 32 },
        size_code,
        code,
        limit,
        started,
    )?;
    let value: T = serde_json::from_slice(bytes).map_err(|_| Refusal::new(code))?;
    let canonical = serde_jcs::to_vec(&value).map_err(|_| Refusal::new(code))?;
    let complete_deadline = Duration::from_millis(2_000);
    if started.elapsed() > complete_deadline {
        return Err(Refusal::new(size_code));
    }
    if canonical != bytes {
        return Err(Refusal::new(code));
    }
    Ok(value)
}

#[derive(Clone, Copy, Default)]
struct KeySpan {
    start: usize,
    end: usize,
}

fn enforce_json_shape(
    bytes: &[u8],
    max_depth: usize,
    limit_code: &'static str,
    syntax_code: &'static str,
    boundary_limit: usize,
    started: Instant,
) -> Result<(), Refusal> {
    let (arena_limit, deadline) = match boundary_limit {
        1_048_576 => (8_454_144_usize, Duration::from_millis(1_000)),
        2_097_152 => (12_648_448_usize, Duration::from_millis(2_000)),
        _ => (
            boundary_limit.saturating_mul(8),
            Duration::from_millis(1_000),
        ),
    };
    let mut parser = BoundedJsonParser {
        bytes,
        index: 0,
        max_depth,
        values: 0,
        members: 0,
        work: 0,
        started,
        deadline,
        limit_code,
        syntax_code,
        receipt_body_limit: (boundary_limit == 2_097_152).then_some(1_048_576),
    };
    std::str::from_utf8(bytes).map_err(|_| Refusal::new(syntax_code))?;
    parser.skip_whitespace()?;
    parser.parse_value(0)?;
    parser.skip_whitespace()?;
    if parser.index != bytes.len() {
        return Err(Refusal::new(syntax_code));
    }
    let estimated_live = bytes
        .len()
        .checked_mul(2)
        .and_then(|size| size.checked_add(parser.values.checked_mul(64)?))
        .and_then(|size| size.checked_add(parser.members.checked_mul(32)?))
        .ok_or_else(|| Refusal::new(limit_code))?;
    if estimated_live > arena_limit {
        return Err(Refusal::new(limit_code));
    }
    Ok(())
}

struct BoundedJsonParser<'a> {
    bytes: &'a [u8],
    index: usize,
    max_depth: usize,
    values: usize,
    members: usize,
    work: usize,
    started: Instant,
    deadline: Duration,
    limit_code: &'static str,
    syntax_code: &'static str,
    receipt_body_limit: Option<usize>,
}

impl BoundedJsonParser<'_> {
    fn charge(&mut self, units: usize) -> Result<(), Refusal> {
        self.work = self
            .work
            .checked_add(units)
            .ok_or_else(|| Refusal::new(self.limit_code))?;
        if self.work > 50_000_000 || self.started.elapsed() > self.deadline {
            return Err(Refusal::new(self.limit_code));
        }
        Ok(())
    }

    fn byte(&mut self) -> Result<Option<u8>, Refusal> {
        self.charge(1)?;
        Ok(self.bytes.get(self.index).copied())
    }

    fn bump(&mut self) -> Result<u8, Refusal> {
        let byte = self.byte()?.ok_or_else(|| Refusal::new(self.syntax_code))?;
        self.index += 1;
        Ok(byte)
    }

    fn skip_whitespace(&mut self) -> Result<(), Refusal> {
        while self.byte()?.is_some_and(|byte| byte.is_ascii_whitespace()) {
            self.index += 1;
        }
        Ok(())
    }

    fn parse_value(&mut self, depth: usize) -> Result<(), Refusal> {
        self.charge(1)?;
        self.values = self
            .values
            .checked_add(1)
            .ok_or_else(|| Refusal::new(self.limit_code))?;
        if self.values > 65_536 {
            return Err(Refusal::new(self.limit_code));
        }
        match self.byte()? {
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'"') => self.parse_string(false).map(|_| ()),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            Some(b't') => self.parse_literal(b"true"),
            Some(b'f') => self.parse_literal(b"false"),
            Some(b'n') => self.parse_literal(b"null"),
            _ => Err(Refusal::new(self.syntax_code)),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<(), Refusal> {
        if depth > self.max_depth {
            return Err(Refusal::new(self.limit_code));
        }
        self.bump()?;
        self.skip_whitespace()?;
        if self.byte()? == Some(b'}') {
            self.index += 1;
            return Ok(());
        }
        let mut keys = [KeySpan::default(); 256];
        let mut key_count = 0_usize;
        loop {
            self.charge(1)?;
            if self.byte()? != Some(b'"') || key_count == keys.len() {
                return Err(Refusal::new(if key_count == keys.len() {
                    self.limit_code
                } else {
                    self.syntax_code
                }));
            }
            let key = self.parse_string(true)?;
            for prior in &keys[..key_count] {
                self.charge(key.end.saturating_sub(key.start).max(1))?;
                if self.bytes[prior.start..prior.end] == self.bytes[key.start..key.end] {
                    return Err(Refusal::new(self.syntax_code));
                }
            }
            keys[key_count] = key;
            key_count += 1;
            self.members = self
                .members
                .checked_add(1)
                .ok_or_else(|| Refusal::new(self.limit_code))?;
            self.skip_whitespace()?;
            if self.bump()? != b':' {
                return Err(Refusal::new(self.syntax_code));
            }
            self.skip_whitespace()?;
            let value_start = self.index;
            self.parse_value(depth)?;
            if depth == 1
                && self.bytes[key.start..key.end] == *b"body"
                && self
                    .receipt_body_limit
                    .is_some_and(|limit| self.index.saturating_sub(value_start) > limit)
            {
                return Err(Refusal::new(self.limit_code));
            }
            self.skip_whitespace()?;
            match self.bump()? {
                b'}' => return Ok(()),
                b',' => self.skip_whitespace()?,
                _ => return Err(Refusal::new(self.syntax_code)),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<(), Refusal> {
        if depth > self.max_depth {
            return Err(Refusal::new(self.limit_code));
        }
        self.bump()?;
        self.skip_whitespace()?;
        if self.byte()? == Some(b']') {
            self.index += 1;
            return Ok(());
        }
        let mut items = 0_usize;
        loop {
            self.charge(1)?;
            if items == 65_535 {
                return Err(Refusal::new(self.limit_code));
            }
            self.parse_value(depth)?;
            items += 1;
            self.skip_whitespace()?;
            match self.bump()? {
                b']' => return Ok(()),
                b',' => self.skip_whitespace()?,
                _ => return Err(Refusal::new(self.syntax_code)),
            }
        }
    }

    fn parse_string(&mut self, object_key: bool) -> Result<KeySpan, Refusal> {
        if self.bump()? != b'"' {
            return Err(Refusal::new(self.syntax_code));
        }
        let start = self.index;
        loop {
            match self.bump()? {
                b'"' => {
                    return Ok(KeySpan {
                        start,
                        end: self.index - 1,
                    });
                }
                0x00..=0x1f => return Err(Refusal::new(self.syntax_code)),
                b'\\' => {
                    if object_key {
                        // Closed production schemas contain only unescaped
                        // ASCII field names. Rejecting escaped keys also
                        // prevents semantic duplicate aliases before decode.
                        return Err(Refusal::new(self.syntax_code));
                    }
                    match self.bump()? {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {}
                        b'u' => self.parse_unicode_escape()?,
                        _ => return Err(Refusal::new(self.syntax_code)),
                    }
                }
                _ => {}
            }
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<(), Refusal> {
        let first = self.read_hex_quad()?;
        if (0xd800..=0xdbff).contains(&first) {
            if self.bump()? != b'\\' || self.bump()? != b'u' {
                return Err(Refusal::new(self.syntax_code));
            }
            let second = self.read_hex_quad()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(Refusal::new(self.syntax_code));
            }
        } else if (0xdc00..=0xdfff).contains(&first) {
            return Err(Refusal::new(self.syntax_code));
        }
        Ok(())
    }

    fn read_hex_quad(&mut self) -> Result<u16, Refusal> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let digit = (self.bump()? as char)
                .to_digit(16)
                .ok_or_else(|| Refusal::new(self.syntax_code))? as u16;
            value = value
                .checked_mul(16)
                .and_then(|value| value.checked_add(digit))
                .ok_or_else(|| Refusal::new(self.syntax_code))?;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<(), Refusal> {
        let start = self.index;
        if self.byte()? == Some(b'-') {
            self.index += 1;
        }
        match self.bump()? {
            b'0' => {
                if self.byte()?.is_some_and(|byte| byte.is_ascii_digit()) {
                    return Err(Refusal::new(self.syntax_code));
                }
            }
            b'1'..=b'9' => {
                while self.byte()?.is_some_and(|byte| byte.is_ascii_digit()) {
                    self.index += 1;
                }
            }
            _ => return Err(Refusal::new(self.syntax_code)),
        }
        if self
            .byte()?
            .is_some_and(|byte| matches!(byte, b'.' | b'e' | b'E'))
        {
            return Err(Refusal::new(self.syntax_code));
        }
        let number = std::str::from_utf8(&self.bytes[start..self.index])
            .ok()
            .and_then(|text| text.parse::<i128>().ok())
            .ok_or_else(|| Refusal::new(self.syntax_code))?;
        if !(-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&number) {
            return Err(Refusal::new(self.syntax_code));
        }
        Ok(())
    }

    fn parse_literal(&mut self, literal: &[u8]) -> Result<(), Refusal> {
        for expected in literal {
            if self.bump()? != *expected {
                return Err(Refusal::new(self.syntax_code));
            }
        }
        Ok(())
    }
}

fn persist_generation(root: &Path, state: &PersistentAuthorityState) -> Result<(), Refusal> {
    let bytes = serde_jcs::to_vec(state).map_err(|_| Refusal::new("state_unavailable"))?;
    let path = generation_path(root, state.generation);
    let tip = ProtectedTip {
        schema: TIP_SCHEMA.into(),
        generation: state.generation,
        state_digest: sha256(&bytes),
        daemon_executable_digest: state.daemon_executable_digest.clone(),
    };
    let tip_bytes = serde_jcs::to_vec(&tip).map_err(|_| Refusal::new("state_unavailable"))?;
    // Order matters: the generation body and the next continuity record are
    // written before the protected tip, and only the tip rename publishes the
    // transaction. A fault before that rename leaves unreferenced bytes and the
    // prior committed generation, never a mixed committed state.
    atomic_write(&path, &bytes)?;
    stage_continuity(root, state, &tip_bytes)?;
    atomic_write(&root.join("protected-tip.json"), &tip_bytes)?;
    commit_continuity(root, Some((state.generation, sha256(&tip_bytes))))
}

fn generation_path(root: &Path, generation: u64) -> PathBuf {
    root.join("generations")
        .join(format!("{generation:020}.json"))
}

fn continuity_paths(root: &Path) -> Result<(PathBuf, PathBuf, PathBuf), Refusal> {
    let parent = root
        .parent()
        .ok_or_else(|| Refusal::new("continuity_unavailable"))?;
    let name = root
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| Refusal::new("continuity_unavailable"))?;
    Ok((
        parent.join(format!("{name}.continuity.json")),
        parent.join(format!("{name}.continuity.next.json")),
        parent.join(format!("{name}.high-water.json")),
    ))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HighWaterMark {
    schema: String,
    generation: u64,
    protected_tip_digest: String,
}

fn stage_continuity(
    root: &Path,
    state: &PersistentAuthorityState,
    protected_tip_bytes: &[u8],
) -> Result<(), Refusal> {
    let (path, staged, _) = continuity_paths(root)?;
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
    atomic_write(&staged, &bytes).map_err(|_| Refusal::new("continuity_unavailable"))
}

/// Publishes the staged continuity record and only then advances the
/// high-water mark. The mark therefore never exceeds the committed protected
/// tip, so a crash before tip publication still restores the prior committed
/// generation instead of tripping rollback detection.
fn record_high_water(root: &Path, generation: u64, tip_digest: String) -> Result<(), Refusal> {
    let (_, _, high_water) = continuity_paths(root)?;
    let mark = HighWaterMark {
        schema: "ember.authority-high-water/v1".into(),
        generation,
        protected_tip_digest: tip_digest,
    };
    let mark_bytes =
        serde_jcs::to_vec(&mark).map_err(|_| Refusal::new("continuity_unavailable"))?;
    atomic_write(&high_water, &mark_bytes).map_err(|_| Refusal::new("continuity_unavailable"))
}

fn commit_continuity(root: &Path, mark: Option<(u64, String)>) -> Result<(), Refusal> {
    let (path, staged, _) = continuity_paths(root)?;
    if staged.exists() {
        let staged_bytes =
            read_bounded(&staged, 16_384).map_err(|_| Refusal::new("continuity_unavailable"))?;
        let staged_record: crate::initialization::RootContinuityRecord =
            decode_canonical(&staged_bytes, 16_384, "continuity_unavailable")?;
        let staged_matches_published_tip = mark
            .as_ref()
            .is_some_and(|(_, tip_digest)| staged_record.protected_tip_digest == *tip_digest);
        if staged_matches_published_tip {
            fs::rename(&staged, &path).map_err(|_| Refusal::new("continuity_unavailable"))?;
        } else {
            fs::remove_file(&staged).map_err(|_| Refusal::new("continuity_unavailable"))?;
        }
        let parent = path
            .parent()
            .ok_or_else(|| Refusal::new("continuity_unavailable"))?;
        OpenOptions::new()
            .read(true)
            .open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| Refusal::new("continuity_unavailable"))?;
    }
    match mark {
        Some((generation, tip_digest)) => record_high_water(root, generation, tip_digest),
        None => Ok(()),
    }
}

/// Restore-time anti-rollback: the published tip must be at or above the last
/// recorded high-water generation, and an equal generation must carry the exact
/// recorded tip bytes. A restored older generation/tip/continuity triple is
/// refused instead of silently reactivating superseded authority state.
fn enforce_high_water(root: &Path, tip_generation: u64, tip_bytes: &[u8]) -> Result<(), Refusal> {
    let (_, _, high_water) = continuity_paths(root)?;
    if !high_water.exists() {
        return Err(Refusal::new("state_rollback_detected"));
    }
    let bytes =
        read_bounded(&high_water, 16_384).map_err(|_| Refusal::new("state_rollback_detected"))?;
    let mark: HighWaterMark = decode_canonical(&bytes, 16_384, "state_rollback_detected")?;
    if mark.schema != "ember.authority-high-water/v1"
        || tip_generation < mark.generation
        || (tip_generation == mark.generation && sha256(tip_bytes) != mark.protected_tip_digest)
    {
        return Err(Refusal::new("state_rollback_detected"));
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), Refusal> {
    DirBuilder::new().mode(0o700).create(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            Refusal::new("already_initialized")
        } else {
            Refusal::new("state_unavailable")
        }
    })
}

fn ensure_private_directory(path: &Path) -> Result<(), Refusal> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Refusal::new("state_unavailable"))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != crate::effective_uid()
        || metadata.mode() & 0o022 != 0
    {
        return Err(Refusal::new("state_unavailable"));
    }
    Ok(())
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

pub(crate) fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Refusal> {
    let file = fs::File::open(path).map_err(|_| Refusal::new("restore_failed"))?;
    let metadata = file
        .metadata()
        .map_err(|_| Refusal::new("restore_failed"))?;
    if metadata.len() > limit as u64 {
        return Err(Refusal::new("input_too_large"));
    }
    let mut bytes = Vec::with_capacity(limit.saturating_add(1));
    file.take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Refusal::new("restore_failed"))?;
    if bytes.len() > limit {
        return Err(Refusal::new("input_too_large"));
    }
    Ok(bytes)
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
