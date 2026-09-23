use core_crypto::{Signature, Signer as _, Verifier as _};

use crate::{
    action_admission::AdmissionDecision,
    action_definition::ResolvedDefinition,
    audit::sha256,
    canonical::encode_action_permit,
    device::{DeviceCustody, PURPOSE_ACTION_PERMIT},
    model::{ActionPermit, ActionRequest, Refusal, SessionRecord},
};

const CANONICALIZER_ID: &str = "rfc8785";
const CANONICALIZER_DIGEST: &str =
    "sha256:3f80f5ca8df174967282922461590b56f846db74be6cbd411e9dc74adf58bb9a";
const PERMIT_SIGNATURE_DOMAIN: &[u8] = b"ember/action-permit-signature-input/v1\0";

pub struct NetworkEnforcement;

impl NetworkEnforcement {
    #[allow(clippy::too_many_arguments)]
    pub fn issue_action_permit(
        authority_fingerprint: &str,
        authority_epoch: u64,
        installation_id: &str,
        release_manifest_digest: Option<&str>,
        session: &SessionRecord,
        _request: &ActionRequest,
        definition: &ResolvedDefinition,
        decision: &AdmissionDecision,
        typed_input_digest: &str,
        custody: &DeviceCustody,
        now: u64,
    ) -> Result<ActionPermit, Refusal> {
        let signer = custody.action_permit_signer()?;
        let qualification_coverage_digest = sha256(
            &serde_jcs::to_vec(&decision.qualification_coverage)
                .map_err(|_| Refusal::new("qualification_mismatch"))?,
        );
        let expiry = decision.grant.expires_at;
        let mut permit = ActionPermit {
            permit_kind: "one-shot".into(),
            authority_fingerprint: authority_fingerprint.into(),
            authority_epoch,
            installation_id: installation_id.into(),
            proxy_instance_id: None,
            session_id: session.session_id.clone(),
            operation_id: Some(uuid::Uuid::new_v4().to_string()),
            execution_ordinal_first: None,
            execution_ordinal_count: None,
            execution_binding_digest: session.execution_binding_digest.clone(),
            assurance_profile_id: decision.assurance_profile_id.clone(),
            assurance_profile_digest: decision.assurance_profile_digest.clone(),
            qualification_coverage_digest,
            action_definition_id: definition.action_ref.identity(),
            action_definition_version: definition.action_ref.action_version.clone(),
            action_definition_digest: definition.digest.clone(),
            canonicalizer_id: CANONICALIZER_ID.into(),
            canonicalizer_digest: CANONICALIZER_DIGEST.into(),
            canonical_typed_input_digest: typed_input_digest.into(),
            need_item_id_list: vec![decision.need.need_item_id.clone()],
            grant_use_id_and_ceiling_list: vec![decision.grant_use_ceiling.clone()],
            credential_slot: None,
            credential_revision: None,
            execution_lane: "sealed-exec".into(),
            recipient_key_fingerprint: None,
            provider_route_id: None,
            route_qualification_version: None,
            release_manifest_digest: release_manifest_digest.map(str::to_owned),
            profile_artifact_digest: None,
            target: decision.need.target.clone(),
            protocol: decision.need.protocol.clone(),
            destination: decision.need.destination.clone(),
            operation_class: decision.need.operation_class.clone(),
            request_count_ceiling: decision.grant.request_count_ceiling,
            byte_budget: decision.grant.byte_budget,
            rate_ceiling: decision.grant.rate_ceiling,
            remaining_use_ceiling: decision.grant.remaining_uses,
            expiry,
            offline_bound: decision.grant.offline_bound,
            consequence_class: decision.consequence_class.clone(),
            capability: decision.need.permission.clone(),
            nonce: uuid::Uuid::new_v4().to_string(),
            issuance: now,
            signer_key_id: signer.key_id().into(),
            signature: String::new(),
        };
        let mut preimage = PERMIT_SIGNATURE_DOMAIN.to_vec();
        preimage.extend_from_slice(&encode_action_permit(&permit, false)?);
        permit.signature = signer.sign(&preimage).0;
        Ok(permit)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_action_permit(
        permit: &ActionPermit,
        authority_fingerprint: &str,
        authority_epoch: u64,
        installation_id: &str,
        release_manifest_digest: Option<&str>,
        session: &SessionRecord,
        request: &ActionRequest,
        definition: &ResolvedDefinition,
        decision: &AdmissionDecision,
        typed_input_digest: &str,
        custody: &DeviceCustody,
        now: u64,
    ) -> Result<(), Refusal> {
        if permit.authority_epoch != authority_epoch {
            return Err(Refusal::new("stale_authority_epoch"));
        }
        let signer = custody.action_permit_signer()?;
        let expected_ceiling = &decision.grant_use_ceiling;
        let fields_match = permit.permit_kind == "one-shot"
            && permit.authority_fingerprint == authority_fingerprint
            && permit.authority_epoch == authority_epoch
            && permit.installation_id == installation_id
            && permit.proxy_instance_id.is_none()
            && permit.session_id == session.session_id
            && permit.execution_ordinal_first.is_none()
            && permit.execution_ordinal_count.is_none()
            && permit
                .operation_id
                .as_ref()
                .is_some_and(|id| !id.is_empty() && id.len() <= 256)
            && permit.execution_binding_digest == session.execution_binding_digest
            && permit.assurance_profile_id == decision.assurance_profile_id
            && permit.assurance_profile_digest == decision.assurance_profile_digest
            && permit.qualification_coverage_digest
                == sha256(
                    &serde_jcs::to_vec(&decision.qualification_coverage)
                        .map_err(|_| Refusal::new("qualification_mismatch"))?,
                )
            && permit.action_definition_id == definition.action_ref.identity()
            && permit.action_definition_version == definition.action_ref.action_version
            && permit.action_definition_digest == definition.digest
            && request.definition_digest.as_deref()
                == Some(permit.action_definition_digest.as_str())
            && permit.canonicalizer_id == CANONICALIZER_ID
            && permit.canonicalizer_digest == CANONICALIZER_DIGEST
            && permit.canonical_typed_input_digest == typed_input_digest
            && permit.need_item_id_list == [decision.need.need_item_id.clone()]
            && permit.grant_use_id_and_ceiling_list == [expected_ceiling.clone()]
            && permit.credential_slot.is_none()
            && permit.credential_revision.is_none()
            && permit.execution_lane == "sealed-exec"
            && permit.recipient_key_fingerprint.is_none()
            && permit.provider_route_id.is_none()
            && permit.route_qualification_version.is_none()
            && permit.release_manifest_digest.as_deref() == release_manifest_digest
            && permit.profile_artifact_digest.is_none()
            && permit.target == decision.need.target
            && permit.protocol == decision.need.protocol
            && permit.destination == decision.need.destination
            && permit.operation_class == decision.need.operation_class
            && permit.request_count_ceiling == decision.grant.request_count_ceiling
            && permit.byte_budget == decision.grant.byte_budget
            && permit.rate_ceiling == decision.grant.rate_ceiling
            && permit.remaining_use_ceiling == decision.grant.remaining_uses
            && permit.expiry == decision.grant.expires_at
            && permit.expiry > permit.issuance
            && permit.issuance <= now
            && permit.offline_bound == decision.grant.offline_bound
            && permit.consequence_class == decision.consequence_class
            && permit.capability == decision.need.permission
            && !permit.nonce.is_empty()
            && permit.nonce.len() <= 256
            && permit.signer_key_id == signer.key_id();
        if !fields_match {
            return Err(Refusal::new("authorization_invalid"));
        }
        if now >= permit.expiry {
            return Err(Refusal::new("authorization_expired"));
        }
        let signature = Signature(permit.signature.clone());
        let mut preimage = PERMIT_SIGNATURE_DOMAIN.to_vec();
        preimage.extend_from_slice(&encode_action_permit(permit, false)?);
        if !core_crypto::Ed25519Verifier.verify(&signer.public_key(), &preimage, &signature)
            || signer.purpose() != PURPOSE_ACTION_PERMIT
        {
            return Err(Refusal::new("authorization_invalid"));
        }
        Ok(())
    }
}
