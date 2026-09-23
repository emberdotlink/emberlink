use core_events::receipt::{ReceiptEnvelope, verify_receipt_v2};

use crate::{
    action_definition::ActionDefinitionRegistry,
    audit::{
        DurableStore, classification_digest, decode_canonical, initialization_receipt_body,
        linked_fact_set_digest, operation_fact_digests, operation_receipt_body, sha256,
    },
    device::DeviceCustody,
    model::{ReceiptIndexRow, Refusal},
};

const RECEIPT_ENVELOPE_LIMIT: usize = 2_097_152;
const BODY_KEYS: &[&str] = &[
    "schema",
    "operation_id",
    "submission_id",
    "canonical_request_digest",
    "action_ref",
    "definition_digest",
    "registry_sequence",
    "definition_resolved_at",
    "persona_id",
    "session_id",
    "execution_binding_digest",
    "assurance_profile_id",
    "assurance_profile_digest",
    "canonicalizer_id",
    "canonicalizer_digest",
    "grant_use_id",
    "grant_use_ceilings",
    "delegation_id",
    "target",
    "derived_need",
    "consequence_class",
    "authorization_expiry",
    "terminal_status",
    "action_boundary",
    "cleanup_status",
    "cleanup_debt",
    "facts",
    "failure_code",
    "runner_key",
    "handler_key",
    "started_at",
    "completed_at",
    "terminal_journal_sequence",
    "checkpoint_digest",
    "linked_fact_set_digest",
    "signer_generation",
    "classification",
    "initialization_evidence",
];

pub struct ReceiptProjection;

impl ReceiptProjection {
    pub fn list(store: &DurableStore) -> Result<Vec<ReceiptIndexRow>, Refusal> {
        let state = store.snapshot()?;
        validate_sequence(
            &state
                .receipts
                .values()
                .map(|receipt| &receipt.row)
                .collect::<Vec<_>>(),
        )?;
        let mut rows = state
            .receipts
            .values()
            .map(|receipt| receipt.row.clone())
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            right
                .terminal_sequence
                .cmp(&left.terminal_sequence)
                .then_with(|| left.receipt_id.cmp(&right.receipt_id))
        });
        Ok(rows)
    }

    /// `show` discloses durable bytes only after the same full verification
    /// `verify` performs, so altered stored Receipt bytes are refused on both
    /// read paths.
    pub fn show(store: &DurableStore, receipt_id: &str) -> Result<String, Refusal> {
        Self::verify(store, receipt_id)?;
        store
            .snapshot()?
            .receipts
            .get(receipt_id)
            .map(|receipt| receipt.canonical_bytes.clone())
            .ok_or_else(|| Refusal::new("receipt_not_found"))
    }

    pub fn verify(store: &DurableStore, receipt_id: &str) -> Result<(), Refusal> {
        let state = store.snapshot()?;
        let stored = state
            .receipts
            .get(receipt_id)
            .ok_or_else(|| Refusal::new("receipt_not_found"))?;
        let bytes = stored.canonical_bytes.as_bytes();
        if bytes.len() > RECEIPT_ENVELOPE_LIMIT {
            return Err(Refusal::new("receipt_too_large"));
        }
        let envelope: ReceiptEnvelope =
            decode_canonical(bytes, RECEIPT_ENVELOPE_LIMIT, "receipt_invalid")?;
        if envelope.version != core_events::receipt::ReceiptVersion::default()
            || envelope.receipt_id != stored.row.receipt_id
            || sha256(bytes) != stored.row.signed_receipt_digest
            || envelope.daemon_root_id != state.authority_fingerprint
            || envelope.traceparent.is_some()
            || envelope.termination_authority
                != core_events::receipt::TerminationAuthority::UserSession
            || envelope.presence_kind.is_some()
            || envelope.calling_principal.is_some()
            || envelope.presence_reason.is_some()
            || envelope.handle_id.is_some()
            || envelope.challenge_hash.is_some()
            || envelope.verifier_aaguid.is_some()
        {
            return Err(Refusal::new("receipt_invalid"));
        }
        if envelope.kind == "authority.initialization" {
            return verify_initialization(&state, stored, &envelope);
        }
        if envelope.kind != "action.operation" {
            return Err(Refusal::new("receipt_invalid"));
        }
        let body = envelope
            .body
            .as_object()
            .ok_or_else(|| Refusal::new("receipt_invalid"))?;
        if body.len() != BODY_KEYS.len() || BODY_KEYS.iter().any(|key| !body.contains_key(*key)) {
            return Err(Refusal::new("receipt_invalid"));
        }
        let operation = state
            .operations
            .get(&stored.row.operation_id)
            .ok_or_else(|| Refusal::new("receipt_invalid"))?;
        let expected_facts = operation_fact_digests(
            &state.authority_fingerprint,
            operation,
            operation.facts.as_ref(),
            operation.status.clone(),
            operation.failure_code.as_deref(),
            operation
                .completed_at
                .ok_or_else(|| Refusal::new("receipt_invalid"))?,
            stored.row.terminal_sequence,
        )?;
        let linked_digest = linked_fact_set_digest(
            &state.authority_fingerprint,
            &operation.operation_id,
            "action.operation",
            &expected_facts,
        )?;
        let completed_at = operation
            .completed_at
            .ok_or_else(|| Refusal::new("receipt_invalid"))?;
        let expected_body = operation_receipt_body(
            operation,
            operation.facts.as_ref(),
            operation.status.clone(),
            operation.failure_code.as_deref(),
            completed_at,
            stored.row.terminal_sequence,
            &stored.checkpoint_digest,
            &linked_digest,
            state.devices.receipt.generation,
            &state.classification,
            &state.initialization.evidence,
        )?;
        if expected_facts != stored.fact_digests || envelope.body != expected_body {
            return Err(Refusal::new("receipt_invalid"));
        }
        let registry = ActionDefinitionRegistry::restore(&state.registry_bytes)?;
        registry.resolve(
            &operation.action_ref,
            &operation.definition_digest,
            operation.authorization.definition_resolved_at,
        )?;
        let custody = DeviceCustody::restore(&state.devices)?;
        verify_receipt_v2(
            &envelope,
            &custody.receipt_public_key(),
            &core_crypto::Ed25519Verifier,
        )
        .map_err(|_| Refusal::new("receipt_invalid"))?;
        verify_checkpoint_chain(&state)?;
        Ok(())
    }
}

fn validate_sequence(rows: &[&ReceiptIndexRow]) -> Result<(), Refusal> {
    let mut sequences = rows
        .iter()
        .map(|row| row.terminal_sequence)
        .collect::<Vec<_>>();
    sequences.sort_unstable();
    if sequences
        .iter()
        .enumerate()
        .any(|(index, sequence)| *sequence != index as u64 + 1)
    {
        return Err(Refusal::new("receipt_index_invalid"));
    }
    Ok(())
}

fn verify_initialization(
    state: &crate::model::PersistentAuthorityState,
    stored: &crate::model::StoredReceipt,
    envelope: &ReceiptEnvelope,
) -> Result<(), Refusal> {
    let record = &state.initialization;
    if record.receipt_id.as_deref() != Some(envelope.receipt_id.as_str())
        || stored.row.operation_id != record.operation_id
        || stored.row.definition_digest != record.root_intent_digest
        || stored.row.terminal_sequence != 1
        || stored.row.terminal_status != crate::model::OperationStatus::Success
    {
        return Err(Refusal::new("receipt_invalid"));
    }
    let classification_digest = classification_digest(&state.classification)
        .map_err(|_| Refusal::new("receipt_invalid"))?;
    let expected_fact_count = 3 + record.evidence.fact_digests().len();
    let mut initialization_facts = vec![
        record.root_intent_digest.as_str(),
        record.continuity_digest.as_str(),
        classification_digest.as_str(),
    ];
    initialization_facts.extend(record.evidence.fact_digests());
    let mut facts = initialization_facts
        .into_iter()
        .map(|value| {
            value
                .strip_prefix("sha256:")
                .map(str::to_owned)
                .ok_or_else(|| Refusal::new("receipt_invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    facts.sort();
    facts.dedup();
    if facts.len() != expected_fact_count || facts != stored.fact_digests {
        return Err(Refusal::new("receipt_invalid"));
    }
    let linked_digest = linked_fact_set_digest(
        &state.authority_fingerprint,
        &record.operation_id,
        "authority.initialization",
        &facts,
    )?;
    let expected_body = initialization_receipt_body(
        state,
        &linked_digest,
        &stored.checkpoint_digest,
        1,
        state.devices.receipt.generation,
    );
    if envelope.body != expected_body {
        return Err(Refusal::new("receipt_invalid"));
    }
    let custody = DeviceCustody::restore(&state.devices)?;
    verify_receipt_v2(
        envelope,
        &custody.receipt_public_key(),
        &core_crypto::Ed25519Verifier,
    )
    .map_err(|_| Refusal::new("receipt_invalid"))?;
    verify_checkpoint_chain(state)
}

fn verify_checkpoint_chain(state: &crate::model::PersistentAuthorityState) -> Result<(), Refusal> {
    let mut receipts = state.receipts.values().collect::<Vec<_>>();
    receipts.sort_by_key(|receipt| receipt.row.terminal_sequence);
    validate_sequence(
        &receipts
            .iter()
            .map(|receipt| &receipt.row)
            .collect::<Vec<_>>(),
    )?;
    let mut prior = format!("sha256:{}", "0".repeat(64));
    for receipt in receipts {
        let expected = sha256(
            &serde_jcs::to_vec(&serde_json::json!({
                "schema": "ember.audit-checkpoint/v1",
                "previous_checkpoint_digest": prior,
                "operation_id": receipt.row.operation_id,
                "terminal_sequence": receipt.row.terminal_sequence,
                "fact_digests": receipt.fact_digests,
            }))
            .map_err(|_| Refusal::new("receipt_invalid"))?,
        );
        if expected != receipt.checkpoint_digest {
            return Err(Refusal::new("receipt_invalid"));
        }
        prior = expected;
    }
    if prior != state.checkpoint_digest {
        return Err(Refusal::new("receipt_invalid"));
    }
    Ok(())
}
