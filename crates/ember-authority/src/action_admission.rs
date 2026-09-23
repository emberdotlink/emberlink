use crate::{
    action_definition::ResolvedDefinition,
    audit::sha256,
    canonical::LenEncoder,
    model::{
        DiagnosticInput, GrantUse, GrantUseCeiling, Need, QualificationCoverage, Refusal,
        SessionRecord, SessionState,
    },
};

#[derive(Clone, Debug)]
pub struct AdmissionDecision {
    pub need: Need,
    pub grant: GrantUse,
    pub grant_use_ceiling: GrantUseCeiling,
    pub consequence_class: String,
    pub assurance_profile_id: String,
    pub assurance_profile_digest: String,
    pub qualification_coverage: QualificationCoverage,
}

pub struct ActionAdmission;

impl ActionAdmission {
    pub fn derive_need(
        definition: &ResolvedDefinition,
        input: &DiagnosticInput,
    ) -> Result<Need, Refusal> {
        if definition.definition["material_classes"] != serde_json::json!(["non_secret"]) {
            return Err(Refusal::new("unsupported_material_class"));
        }
        match definition.definition["delivery_lane"].as_str() {
            Some("sealed-exec") => {}
            Some("proxy" | "sign-through" | "federation") => {
                return Err(Refusal::new("unsupported_lane"));
            }
            _ => return Err(Refusal::new("unsupported_lane")),
        }
        let mut encoded = LenEncoder::new("ember/need-item/v1")?;
        encoded
            .string("authority.status.read")?
            .string(&input.challenge)?
            .string("non_secret")?
            .string("ember.local")?
            .string("local")?
            .string("daemon")?
            .string("read_only_diagnostic")?
            .u64(1)
            .u64(4096)
            .u64(1);
        Ok(Need {
            need_item_id: sha256(&encoded.finish()),
            permission: "authority.status.read".into(),
            target: input.challenge.clone(),
            material_class: "non_secret".into(),
            provider: "ember.local".into(),
            protocol: "local".into(),
            destination: "daemon".into(),
            operation_class: "read_only_diagnostic".into(),
            request_count: 1,
            byte_count: 4096,
            rate: 1,
        })
    }

    pub fn admit(
        session: &SessionRecord,
        definition: &ResolvedDefinition,
        input: &DiagnosticInput,
        now: u64,
        qualification_coverage: &QualificationCoverage,
    ) -> Result<AdmissionDecision, Refusal> {
        if session.state != SessionState::Active {
            return Err(Refusal::new("session_binding_mismatch"));
        }
        qualification_coverage.validate_diagnostic()?;
        let need = Self::derive_need(definition, input)?;
        let grant = &session.grant;
        let covered = grant.session_id == session.session_id
            && grant.delegation_id.starts_with("delegation:")
            && grant.permission == need.permission
            && grant.target.as_bytes() == need.target.as_bytes()
            && grant.material_class == need.material_class
            && grant.provider == need.provider
            && grant.protocol == need.protocol
            && grant.destination == need.destination
            && grant.operation_class == need.operation_class
            && grant.request_count_ceiling >= need.request_count
            && grant.byte_budget >= need.byte_count
            && grant.rate_ceiling >= need.rate
            && grant.remaining_uses > 0
            && !grant.revoked
            && now < grant.expires_at;
        if !covered {
            return Err(Refusal::new("uncovered_need"));
        }
        let grant_use_ceiling = grant.ceiling(need.need_item_id.clone());
        Ok(AdmissionDecision {
            need,
            grant: grant.clone(),
            grant_use_ceiling,
            consequence_class: "read_only_local_diagnostic".into(),
            assurance_profile_id: "productbase-s4-diagnostic".into(),
            assurance_profile_digest:
                "sha256:83487995fa88b0aa999fe0862c5fcc0ca2ef6ad0cd01f729b46f3f6b90a4f8c0".into(),
            qualification_coverage: qualification_coverage.clone(),
        })
    }
}
