use crate::{
    action_admission::AdmissionDecision,
    action_definition::ResolvedDefinition,
    audit::sha256,
    canonical::encode_action_permit,
    device::DeviceCustody,
    initialization::RouteAuthorization,
    model::{
        ActionPermit, ActionRef, ActionRequest, DiagnosticFacts, DiagnosticInput, Refusal,
        SessionRecord,
    },
    network_enforcement::NetworkEnforcement,
};

pub const DIAGNOSTIC_RUNNER: &str = "builtin.diagnostic.authority-status/v1";
const RESULT_SCHEMA_IDENTIFIER: &str = "emberlink.diagnostic-facts";
const RESULT_SCHEMA_VERSION: &str = "v1";
const RESULT_SEMANTICS: &str = "diagnostic-facts";

#[derive(Clone, Debug)]
pub struct RawResultFrame {
    pub payload_schema_identifier: String,
    pub payload_schema_version: String,
    pub payload_semantics: String,
    pub payload: DiagnosticFacts,
}

pub trait JournalHealth: Send + Sync {
    fn health(&self) -> Result<&'static str, Refusal>;

    fn raw_result_frames(&self, facts: DiagnosticFacts) -> Vec<RawResultFrame> {
        vec![RawResultFrame {
            payload_schema_identifier: RESULT_SCHEMA_IDENTIFIER.into(),
            payload_schema_version: RESULT_SCHEMA_VERSION.into(),
            payload_semantics: RESULT_SEMANTICS.into(),
            payload: facts,
        }]
    }
}

pub struct RunnerRegistry;

impl RunnerRegistry {
    #[allow(clippy::too_many_arguments)]
    pub fn resolve(
        permit: &ActionPermit,
        authority_fingerprint: &str,
        authority_epoch: u64,
        installation_id: &str,
        release_manifest_digest: &str,
        session: &SessionRecord,
        request: &ActionRequest,
        definition: &ResolvedDefinition,
        decision: &AdmissionDecision,
        typed_input_digest: &str,
        custody: &DeviceCustody,
        route: &RouteAuthorization,
        now: u64,
    ) -> Result<DiagnosticRunner, Refusal> {
        NetworkEnforcement::verify_action_permit(
            permit,
            authority_fingerprint,
            authority_epoch,
            installation_id,
            release_manifest_digest,
            session,
            request,
            definition,
            decision,
            typed_input_digest,
            custody,
            now,
        )?;
        let allowlist = definition.definition["result_frame_payload_allowlist"]
            .as_array()
            .ok_or_else(|| Refusal::new("unsupported_result_frame"))?;
        let frame = allowlist
            .first()
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| Refusal::new("unsupported_result_frame"))?;
        if allowlist.len() != 1
            || definition.definition["runner_adapter"] != DIAGNOSTIC_RUNNER
            || definition.definition["handler_ref"] != DIAGNOSTIC_RUNNER
            || definition.definition["result_frame_count_ceiling"] != 1
            || frame.len() != 3
            || frame
                .get("payload_schema_identifier")
                .and_then(serde_json::Value::as_str)
                != Some(RESULT_SCHEMA_IDENTIFIER)
            || frame
                .get("payload_schema_version")
                .and_then(serde_json::Value::as_str)
                != Some(RESULT_SCHEMA_VERSION)
            || frame
                .get("payload_semantics")
                .and_then(serde_json::Value::as_str)
                != Some(RESULT_SEMANTICS)
            || route.runner_class != "builtin"
            || route.delivery_lane != permit.execution_lane
            || route.action_definition_digest != permit.action_definition_digest
        {
            return Err(Refusal::new("unsupported_runner"));
        }
        let canonical = encode_action_permit(permit, true)
            .map_err(|_| Refusal::new("authorization_invalid"))?;
        Ok(DiagnosticRunner {
            authorized_permit_digest: sha256(&canonical),
        })
    }
}

pub struct DiagnosticRunner {
    authorized_permit_digest: String,
}

impl DiagnosticRunner {
    pub fn run(
        self,
        permit: &ActionPermit,
        input: &DiagnosticInput,
        journal: &dyn JournalHealth,
        registry: &crate::action_definition::ActionDefinitionRegistry,
        current_authority_epoch: u64,
        now: u64,
    ) -> Result<DiagnosticFacts, Refusal> {
        let canonical = encode_action_permit(permit, true)
            .map_err(|_| Refusal::new("authorization_invalid"))?;
        if sha256(&canonical) != self.authorized_permit_digest
            || permit.signature.is_empty()
            || current_authority_epoch != permit.authority_epoch
            || sha256(&serde_jcs::to_vec(input).map_err(|_| Refusal::new("authorization_invalid"))?)
                != permit.canonical_typed_input_digest
        {
            return Err(Refusal::new("authorization_invalid"));
        }
        registry
            .resolve(
                &ActionRef::diagnostic(),
                &permit.action_definition_digest,
                now,
            )
            .map_err(|_| Refusal::new("unsupported_result_frame"))?;
        input.validate()?;
        let health = journal
            .health()
            .map_err(|_| Refusal::new("runner_failed"))?;
        if health != "ready" {
            return Err(Refusal::new("runner_failed"));
        }
        let facts = DiagnosticFacts {
            challenge: input.challenge.clone(),
            journal_health: health.into(),
        };
        let frames = journal.raw_result_frames(facts);
        if frames.len() != 1 {
            return Err(Refusal::new("unsupported_result_frame"));
        }
        let frame = frames.into_iter().next().expect("length checked");
        if frame.payload_schema_identifier != RESULT_SCHEMA_IDENTIFIER
            || frame.payload_schema_version != RESULT_SCHEMA_VERSION
            || frame.payload_semantics != RESULT_SEMANTICS
        {
            return Err(Refusal::new("unsupported_result_frame"));
        }
        let encoded = serde_jcs::to_vec(&frame.payload)
            .map_err(|_| Refusal::new("unsupported_result_frame"))?;
        if encoded.len() as u64 > permit.byte_budget {
            return Err(Refusal::new("unsupported_result_frame"));
        }
        Ok(frame.payload)
    }
}
