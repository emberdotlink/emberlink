use crate::model::{
    ActionPermit, GrantUseCeiling, QualificationAxis, QualificationCoverage, Refusal,
};

const MAX_STRING: usize = 4096;
const MAX_LIST: usize = 64;

#[derive(Default)]
pub struct LenEncoder {
    bytes: Vec<u8>,
}

impl LenEncoder {
    pub fn new(label: &str) -> Result<Self, Refusal> {
        let mut this = Self::default();
        this.string(label)?;
        Ok(this)
    }

    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }

    pub fn string(&mut self, value: &str) -> Result<&mut Self, Refusal> {
        if value.len() > MAX_STRING {
            return Err(Refusal::new("canonical_value_too_large"));
        }
        self.bytes
            .extend_from_slice(&(value.len() as u64).to_be_bytes());
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(self)
    }

    pub fn digest(&mut self, value: &str) -> Result<&mut Self, Refusal> {
        let text = value
            .strip_prefix("sha256:")
            .ok_or_else(|| Refusal::new("canonical_digest_invalid"))?;
        let decoded = hex::decode(text).map_err(|_| Refusal::new("canonical_digest_invalid"))?;
        if decoded.len() != 32 {
            return Err(Refusal::new("canonical_digest_invalid"));
        }
        self.bytes.extend_from_slice(&decoded);
        Ok(self)
    }

    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub fn bool(&mut self, value: bool) -> &mut Self {
        self.bytes.push(u8::from(value));
        self
    }

    pub fn optional_string(&mut self, value: Option<&str>) -> Result<&mut Self, Refusal> {
        match value {
            Some(value) => {
                self.bytes.push(1);
                self.string(value)?;
            }
            None => self.bytes.push(0),
        }
        Ok(self)
    }

    pub fn optional_digest(&mut self, value: Option<&str>) -> Result<&mut Self, Refusal> {
        match value {
            Some(value) => {
                self.bytes.push(1);
                self.digest(value)?;
            }
            None => self.bytes.push(0),
        }
        Ok(self)
    }

    pub fn optional_u64(&mut self, value: Option<u64>) -> &mut Self {
        match value {
            Some(value) => {
                self.bytes.push(1);
                self.u64(value);
            }
            None => self.bytes.push(0),
        }
        self
    }

    pub fn list<T>(
        &mut self,
        values: &[T],
        encode: impl Fn(&T) -> Result<Vec<u8>, Refusal>,
    ) -> Result<&mut Self, Refusal> {
        if values.len() > MAX_LIST {
            return Err(Refusal::new("canonical_value_too_large"));
        }
        self.u64(values.len() as u64);
        for value in values {
            self.bytes.extend_from_slice(&encode(value)?);
        }
        Ok(self)
    }
}

pub fn encode_grant_use_ceiling(value: &GrantUseCeiling) -> Result<Vec<u8>, Refusal> {
    let mut e = LenEncoder::new("ember/grant-use-ceiling/v1")?;
    e.string(&value.grant_use_id)?
        .string(&value.need_item_id)?
        .u64(value.request_count_ceiling)
        .u64(value.byte_budget)
        .u64(value.rate_ceiling)
        .u64(value.remaining_use_ceiling)
        .u64(value.expires_at);
    Ok(e.finish())
}

pub fn encode_action_permit(
    permit: &ActionPermit,
    include_signature: bool,
) -> Result<Vec<u8>, Refusal> {
    let mut e = LenEncoder::new("ember/action-permit/v1")?;
    e.string(&permit.permit_kind)?
        .digest(&permit.authority_fingerprint)?
        .u64(permit.authority_epoch)
        .string(&permit.installation_id)?
        .optional_string(permit.proxy_instance_id.as_deref())?
        .string(&permit.session_id)?
        .optional_string(permit.operation_id.as_deref())?
        .optional_u64(permit.execution_ordinal_first)
        .optional_u64(permit.execution_ordinal_count)
        .digest(&permit.execution_binding_digest)?
        .string(&permit.assurance_profile_id)?
        .digest(&permit.assurance_profile_digest)?
        .digest(&permit.qualification_coverage_digest)?
        .string(&permit.action_definition_id)?
        .string(&permit.action_definition_version)?
        .digest(&permit.action_definition_digest)?
        .string(&permit.canonicalizer_id)?
        .digest(&permit.canonicalizer_digest)?
        .digest(&permit.canonical_typed_input_digest)?
        .list(&permit.need_item_id_list, |item| {
            let mut item_encoder = LenEncoder::new("ember/need-item-reference/v1")?;
            item_encoder.string(item)?;
            Ok(item_encoder.finish())
        })?
        .list(
            &permit.grant_use_id_and_ceiling_list,
            encode_grant_use_ceiling,
        )?
        .optional_string(permit.credential_slot.as_deref())?
        .optional_u64(permit.credential_revision)
        .string(&permit.execution_lane)?
        .optional_digest(permit.recipient_key_fingerprint.as_deref())?
        .optional_string(permit.provider_route_id.as_deref())?
        .optional_u64(permit.route_qualification_version)
        .optional_digest(permit.release_manifest_digest.as_deref())?
        .optional_digest(permit.profile_artifact_digest.as_deref())?
        .string(&permit.target)?
        .string(&permit.protocol)?
        .string(&permit.destination)?
        .string(&permit.operation_class)?
        .u64(permit.request_count_ceiling)
        .u64(permit.byte_budget)
        .u64(permit.rate_ceiling)
        .u64(permit.remaining_use_ceiling)
        .u64(permit.expiry)
        .bool(permit.offline_bound)
        .string(&permit.consequence_class)?
        .string(&permit.capability)?
        .string(&permit.nonce)?
        .u64(permit.issuance)
        .string(&permit.signer_key_id)?;
    if include_signature {
        e.string(&permit.signature)?;
    }
    Ok(e.finish())
}

fn encode_axis(name: &str, axis: &QualificationAxis) -> Result<Vec<u8>, Refusal> {
    let mut e = LenEncoder::new("ember/qualification-axis/v1")?;
    let state = serde_json::to_value(&axis.state)
        .map_err(|_| Refusal::new("qualification_mismatch"))?
        .as_str()
        .ok_or_else(|| Refusal::new("qualification_mismatch"))?
        .to_owned();
    e.string(name)?
        .string(&state)?
        .optional_digest(axis.record_digest.as_deref())?;
    Ok(e.finish())
}

pub fn encode_qualification_coverage(
    authority_fingerprint: &str,
    operation_id: &str,
    coverage: &QualificationCoverage,
) -> Result<Vec<u8>, Refusal> {
    let mut e = LenEncoder::new("ember/qualification-coverage/v1")?;
    e.digest(authority_fingerprint)?.string(operation_id)?;
    e.bytes
        .extend_from_slice(&encode_axis("actor_lane", &coverage.actor_lane)?);
    e.bytes
        .extend_from_slice(&encode_axis("credential_lane", &coverage.credential_lane)?);
    e.bytes
        .extend_from_slice(&encode_axis("federation", &coverage.federation)?);
    e.bytes.extend_from_slice(&encode_axis(
        "production_cluster",
        &coverage.production_cluster,
    )?);
    Ok(e.finish())
}
