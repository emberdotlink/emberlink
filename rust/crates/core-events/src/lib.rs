use core_crypto::{PublicKey, Signature, Signer};
use core_types::{CanonicalEncode, EventType, SchemaVersion, Validate, ValidationError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRef {
    pub relation: String,
    pub target_event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEnvelope {
    pub schema_version: SchemaVersion,
    pub event_id: String,
    pub event_type: EventType,
    pub signer: PublicKey,
    pub payload: Vec<u8>,
    pub refs: Vec<EventRef>,
    pub signature: Signature,
}

impl EventEnvelope {
    pub fn new<T>(event_id: impl Into<String>, event_type: EventType, body: &T, signer: &impl Signer) -> Self
    where
        T: CanonicalEncode + Validate,
    {
        let payload = body.canonical_encode();
        let signature = signer.sign(&payload);
        Self {
            schema_version: SchemaVersion::V0_1_0,
            event_id: event_id.into(),
            event_type,
            signer: signer.public_key(),
            payload,
            refs: Vec::new(),
            signature,
        }
    }
}

impl Validate for EventEnvelope {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.event_id.is_empty() {
            return Err(ValidationError::new("event id must not be empty"));
        }
        if self.payload.is_empty() {
            return Err(ValidationError::new("event payload must not be empty"));
        }
        Ok(())
    }
}

pub trait AppliesToState {
    fn entity_key(&self) -> String;
}

#[cfg(test)]
mod tests {
    use core_crypto::{FixtureSigner, Verifier};
    use core_types::{IdentityRoot, VisibilityPreset, Persona, SurvivalMode};

    use super::*;

    #[test]
    fn event_envelope_signs_canonical_payload() {
        let signer = FixtureSigner::new("fixture_signer");
        let root = IdentityRoot {
            id: "root-1".into(),
            display_name: "Primary".into(),
        };

        let envelope = EventEnvelope::new("evt-1", EventType::RootCreated, &root, &signer);
        let verifier = core_crypto::FixtureVerifier;

        assert!(verifier.verify(&envelope.signer, &envelope.payload, &envelope.signature));
    }

    #[test]
    fn event_validation_rejects_empty_payload() {
        let envelope = EventEnvelope {
            schema_version: SchemaVersion::V0_1_0,
            event_id: "evt-2".into(),
            event_type: EventType::PersonaCreated,
            signer: PublicKey("fixture_signer".into()),
            payload: Vec::new(),
            refs: Vec::new(),
            signature: Signature("fixture:0".into()),
        };

        assert!(envelope.validate().is_err());
    }

    #[test]
    fn persona_payload_can_be_wrapped() {
        let signer = FixtureSigner::new("fixture_signer");
        let persona = Persona {
            id: "persona-1".into(),
            root_id: "root-1".into(),
            label: "professional".into(),
            preset: VisibilityPreset::Professional,
            survival_mode: SurvivalMode::Strict,
        };

        let envelope = EventEnvelope::new("evt-3", EventType::PersonaCreated, &persona, &signer);
        assert_eq!(envelope.schema_version, SchemaVersion::V0_1_0);
    }
}

