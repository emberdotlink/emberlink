use core_crypto::{PublicKey, Signature, Signer};
use core_types::{
    CanonicalEncode, EventBody, EventRefRelation, EventSubject, EventType, KeyRole, SchemaVersion,
    SignerBinding, Validate, ValidationError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRef {
    pub relation: EventRefRelation,
    pub target_event_id: String,
}

impl EventRef {
    pub fn previous(target_event_id: impl Into<String>) -> Self {
        Self {
            relation: EventRefRelation::Previous,
            target_event_id: target_event_id.into(),
        }
    }
}

impl Validate for EventRef {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.target_event_id.trim().is_empty() {
            return Err(ValidationError::new("event ref target must not be empty"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEnvelope {
    pub schema_version: SchemaVersion,
    pub event_id: String,
    pub event_type: EventType,
    pub subject: EventSubject,
    pub signer_binding: SignerBinding,
    pub signer: PublicKey,
    pub payload: Vec<u8>,
    pub refs: Vec<EventRef>,
    pub signature: Signature,
    pub body: EventBody,
}

impl EventEnvelope {
    pub fn from_body(
        event_id: impl Into<String>,
        body: EventBody,
        refs: Vec<EventRef>,
        signer_binding: SignerBinding,
        signer: &impl Signer,
    ) -> Result<Self, ValidationError> {
        body.validate()?;
        signer_binding.validate()?;
        for reference in &refs {
            reference.validate()?;
        }

        let event_id = event_id.into();
        let payload = body.canonical_encode();
        let event_type = body.event_type();
        let subject = body.subject();
        let signer_public_key = signer.public_key();
        let signed_bytes = canonical_signed_bytes(
            SchemaVersion::V0_1_0,
            &event_id,
            event_type,
            &subject,
            &signer_binding,
            &refs,
            &payload,
        );
        let signature = signer.sign(&signed_bytes);

        Ok(Self {
            schema_version: SchemaVersion::V0_1_0,
            event_id,
            event_type,
            subject,
            signer_binding,
            signer: signer_public_key,
            payload,
            refs,
            signature,
            body,
        })
    }

    pub fn new<T>(
        event_id: impl Into<String>,
        event_type: EventType,
        body: &T,
        signer: &impl Signer,
    ) -> Self
    where
        T: CanonicalEncode + Validate,
    {
        body.validate()
            .expect("legacy event bodies must validate before wrapping");

        let event_id = event_id.into();
        let subject = EventSubject::unknown(event_type.as_str());
        let signer_public_key = signer.public_key();
        let signer_binding = SignerBinding {
            signer: subject.clone(),
            key_id: signer_public_key.0.clone(),
            role: KeyRole::Unknown,
        };
        let body = EventBody::LegacyOpaque {
            declared_type: event_type,
            subject,
            canonical_payload: body.canonical_encode(),
        };
        let payload = body.canonical_encode();
        let refs = Vec::new();
        let signed_bytes = canonical_signed_bytes(
            SchemaVersion::V0_1_0,
            &event_id,
            event_type,
            &body.subject(),
            &signer_binding,
            &refs,
            &payload,
        );
        let signature = signer.sign(&signed_bytes);

        Self {
            schema_version: SchemaVersion::V0_1_0,
            event_id,
            event_type,
            subject: body.subject(),
            signer_binding,
            signer: signer_public_key,
            payload,
            refs,
            signature,
            body,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_stored_parts(
        schema_version: SchemaVersion,
        event_id: impl Into<String>,
        event_type: EventType,
        subject: EventSubject,
        signer_binding: SignerBinding,
        signer: PublicKey,
        payload: Vec<u8>,
        refs: Vec<EventRef>,
        signature: Signature,
    ) -> Result<Self, ValidationError> {
        let body = EventBody::decode_canonical(&payload)?;
        let envelope = Self {
            schema_version,
            event_id: event_id.into(),
            event_type,
            subject,
            signer_binding,
            signer,
            payload,
            refs,
            signature,
            body,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn signed_bytes(&self) -> Vec<u8> {
        canonical_signed_bytes(
            self.schema_version,
            &self.event_id,
            self.event_type,
            &self.subject,
            &self.signer_binding,
            &self.refs,
            &self.payload,
        )
    }
}

impl Validate for EventEnvelope {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.event_id.trim().is_empty() {
            return Err(ValidationError::new("event id must not be empty"));
        }
        if self.payload.is_empty() {
            return Err(ValidationError::new("event payload must not be empty"));
        }
        self.subject.validate()?;
        self.signer_binding.validate()?;
        self.body.validate()?;
        if self.event_type != self.body.event_type() {
            return Err(ValidationError::new(
                "event type must match the typed event body",
            ));
        }
        if self.subject != self.body.subject() {
            return Err(ValidationError::new(
                "event subject must match the typed event body",
            ));
        }
        if self.payload != self.body.canonical_encode() {
            return Err(ValidationError::new(
                "event payload must match canonical body encoding",
            ));
        }
        for reference in &self.refs {
            reference.validate()?;
        }
        for (index, reference) in self.refs.iter().enumerate() {
            if self.refs[..index].iter().any(|existing| {
                existing.relation == reference.relation
                    && existing.target_event_id == reference.target_event_id
            }) {
                return Err(ValidationError::new(
                    "duplicate event refs with the same relation and target are not allowed",
                ));
            }
        }
        Ok(())
    }
}

fn canonical_signed_bytes(
    schema_version: SchemaVersion,
    event_id: &str,
    event_type: EventType,
    subject: &EventSubject,
    signer_binding: &SignerBinding,
    refs: &[EventRef],
    payload: &[u8],
) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("schema_version=");
    out.push_str(&schema_version.to_string());
    out.push('\n');
    out.push_str("event_id=");
    out.push_str(event_id);
    out.push('\n');
    out.push_str("event_type=");
    out.push_str(event_type.as_str());
    out.push('\n');
    out.push_str("subject_kind=");
    out.push_str(subject.kind.as_str());
    out.push('\n');
    out.push_str("subject_id=");
    out.push_str(&subject.subject_id);
    out.push('\n');
    out.push_str("signer_kind=");
    out.push_str(signer_binding.signer.kind.as_str());
    out.push('\n');
    out.push_str("signer_id=");
    out.push_str(&signer_binding.signer.subject_id);
    out.push('\n');
    out.push_str("signer_key_id=");
    out.push_str(&signer_binding.key_id);
    out.push('\n');
    out.push_str("signer_role=");
    out.push_str(signer_binding.role.as_str());
    out.push('\n');
    out.push_str("ref_count=");
    out.push_str(&refs.len().to_string());
    out.push('\n');
    for (index, reference) in refs.iter().enumerate() {
        out.push_str("ref.");
        out.push_str(&index.to_string());
        out.push_str(".relation=");
        out.push_str(reference.relation.as_str());
        out.push('\n');
        out.push_str("ref.");
        out.push_str(&index.to_string());
        out.push_str(".target=");
        out.push_str(&reference.target_event_id);
        out.push('\n');
    }
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(b"payload=\n");
    bytes.extend_from_slice(payload);
    bytes
}

#[cfg(test)]
mod tests {
    use core_crypto::{FixtureSigner, Verifier};
    use core_types::{
        DeviceAddedEvent, EventBody, KeyAlgorithm, PersonaCreatedEvent, PublicKeyMaterial,
        RootCreatedEvent, SurvivalMode,
    };

    use super::*;

    fn test_key(key_id: &str) -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: key_id.into(),
            algorithm: KeyAlgorithm::DevEd25519Like,
            public_key: format!("devpub:{key_id}"),
        }
    }

    fn test_encryption_key(key_id: &str) -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: format!("enc-{key_id}"),
            algorithm: KeyAlgorithm::AgeX25519,
            public_key: format!("age1{key_id}fixture"),
        }
    }

    #[test]
    fn typed_event_envelope_signs_metadata_and_payload() {
        let signer = FixtureSigner::new("fixture-root-key");
        let body = EventBody::RootCreated(RootCreatedEvent {
            root_id: "root-1".into(),
            display_name: "Primary".into(),
            initial_key: test_key("key-root-1"),
        });

        let envelope = EventEnvelope::from_body(
            "evt-1",
            body,
            vec![EventRef::previous("evt-0")],
            SignerBinding::root("root-1", "key-root-1"),
            &signer,
        )
        .unwrap();
        let verifier = core_crypto::FixtureVerifier;

        assert!(verifier.verify(
            &envelope.signer,
            &envelope.signed_bytes(),
            &envelope.signature,
        ));
        assert_eq!(envelope.subject, EventSubject::root("root-1"));
    }

    #[test]
    fn legacy_constructor_keeps_older_call_sites_working() {
        let signer = FixtureSigner::new("fixture_signer");
        let envelope = EventEnvelope::new(
            "evt-legacy",
            EventType::DeviceAdded,
            &DeviceAddedEvent {
                root_id: "root-1".into(),
                device_id: "device-1".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-1"),
                initial_encryption_key: test_encryption_key("key-device-1"),
            },
            &signer,
        );

        assert_eq!(envelope.event_type, EventType::DeviceAdded);
        assert!(matches!(envelope.body, EventBody::LegacyOpaque { .. }));
    }

    #[test]
    fn validation_rejects_duplicate_refs() {
        let signer = FixtureSigner::new("fixture-persona-key");
        let envelope = EventEnvelope::from_body(
            "evt-2",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-1".into(),
                persona_id: "persona-1".into(),
                label: "Work".into(),
                disclosure_profile: Some("work-public".into()),
                survival_mode: SurvivalMode::Strict,
                initial_key: test_key("key-persona-1"),
            }),
            vec![EventRef::previous("evt-0"), EventRef::previous("evt-0")],
            SignerBinding::root("root-1", "key-root-1"),
            &signer,
        )
        .unwrap();

        assert!(envelope.validate().is_err());
    }
}
