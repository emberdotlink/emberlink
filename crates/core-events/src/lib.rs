use core_crypto::{DOMAIN_EVENT, PublicKey, Signature, Signer};
use core_event_types::{EventBody, EventRefRelation, EventSubject, EventType, SignerBinding};
use core_types::{
    CanonicalEncode, SchemaVersion, Validate, ValidationError,
    size_limits::validate_envelope_payload_size,
};

pub mod construct_toml;
pub mod receipt;
pub mod rollup;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRef {
    pub relation: EventRefRelation,
    pub target_event_id: String,
    /// Per-root monotonic sequence number. For `Previous` refs this is the
    /// sequence number of the event being created (i.e. `head_seq + 1`).
    /// For non-`Previous` refs the value is `0` (unused / not enforced).
    pub seq: u64,
}

impl EventRef {
    pub fn previous(target_event_id: impl Into<String>, seq: u64) -> Self {
        Self {
            relation: EventRefRelation::Previous,
            target_event_id: target_event_id.into(),
            seq,
        }
    }

    pub fn other(relation: EventRefRelation, target_event_id: impl Into<String>) -> Self {
        Self {
            relation,
            target_event_id: target_event_id.into(),
            seq: 0,
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
        let signature = core_crypto::sign_with_context(DOMAIN_EVENT, signer, &signed_bytes);

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

    /// Assemble an envelope from an **out-of-band** signature (ADR 200 §5 —
    /// operator IdentityRoot genesis / presence-device enrollment). Parallel to
    /// [`Self::from_body`], but the daemon does NOT hold the signing key: it
    /// computes the canonical signing pre-image, hands it to `oob_sign` (which in
    /// production marshals the bytes to the operator's presence device — YubiKey
    /// PIV / Secure Enclave — and returns the `p256sig:` device signature), and
    /// assembles the result. The signature is verified at append time
    /// (`append_with_authorizer` → `verify_with_context`), so a signature not
    /// produced by `signer`'s key fails closed — this constructor performs no
    /// crypto itself and grants no authority on its own.
    ///
    /// `oob_sign` receives the canonical signing bytes and MUST return
    /// `core_crypto::sign_with_context(core_crypto::DOMAIN_EVENT, device_key, bytes)`
    /// — the exact domain-separated scheme [`Self::from_body`] uses internally.
    /// Anything else (raw sign, wrong domain, wrong key) fails the append-time
    /// verification.
    ///
    /// Like [`Self::from_body`], this constructor binds the supplied `signer`
    /// pubkey into the envelope but does NOT cross-check it against any field of
    /// `body` (e.g. a genesis `RootCreated.initial_key`). Append-time verification
    /// proves signature↔`signer`, not `signer`↔body; callers minting self-rooted
    /// genesis MUST enforce `signer == initial_key` themselves (see
    /// `operator_identity::append_root_oob_signed`).
    pub fn from_oob_signed(
        event_id: impl Into<String>,
        body: EventBody,
        refs: Vec<EventRef>,
        signer_binding: SignerBinding,
        signer: PublicKey,
        oob_sign: impl FnOnce(&[u8]) -> Signature,
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
        let signed_bytes = canonical_signed_bytes(
            SchemaVersion::V0_1_0,
            &event_id,
            event_type,
            &subject,
            &signer_binding,
            &refs,
            &payload,
        );
        let signature = oob_sign(&signed_bytes);

        Ok(Self {
            schema_version: SchemaVersion::V0_1_0,
            event_id,
            event_type,
            subject,
            signer_binding,
            signer,
            payload,
            refs,
            signature,
            body,
        })
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

    /// The canonical bytes an **out-of-band** signer must sign for an event with
    /// these parts — the exact input to
    /// `core_crypto::sign_with_context(core_crypto::DOMAIN_EVENT, device, _)` that
    /// [`Self::from_oob_signed`] (and [`Self::from_body`]) verify against on
    /// append. Exposed so a daemon can compute, *without* mutating state or
    /// holding any key, precisely what to hand an off-host presence device (the
    /// "prepare" half of a prepare→sign→commit enrollment ceremony, ADR 200 §5).
    /// Pure; performs no signing and grants no authority. Returns the same bytes a
    /// later `from_oob_signed(event_id, body, refs, signer_binding, …)` produces
    /// for the identical parts.
    pub fn signing_pre_image(
        event_id: &str,
        body: &EventBody,
        refs: &[EventRef],
        signer_binding: &SignerBinding,
    ) -> Result<Vec<u8>, ValidationError> {
        body.validate()?;
        signer_binding.validate()?;
        for reference in refs {
            reference.validate()?;
        }
        Ok(canonical_signed_bytes(
            SchemaVersion::V0_1_0,
            event_id,
            body.event_type(),
            &body.subject(),
            signer_binding,
            refs,
            &body.canonical_encode(),
        ))
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
        // Envelope-level backstop: per-field caps in core-types limit each
        // attacker-controlled field individually; this gate catches any
        // shape we missed (or any future field that forgets a per-field
        // cap). See `core_types::size_limits` for rationale.
        validate_envelope_payload_size(self.payload.len())?;
        self.subject.validate()?;
        self.signer_binding.validate()?;
        self.body.validate()?;
        if self.event_type != self.body.event_type() {
            return Err(ValidationError::new(
                "event type must match the typed event body",
            ));
        }
        // event_subject_validator_alias_aware — checkpoint for
        // META-AP-EVENT-SUBJECT-VALIDATOR-ALIAS-AWARE.
        //
        // Body emission canonicalizes principal subjects to
        // `SubjectKind::Principal` per PR #6065 (Canonicalize principal event
        // subjects). Pre-#6065 on-disk envelopes were stored with the wire
        // aliases `SubjectKind::Root` / `SubjectKind::Persona`. PR #6065
        // documented these as "compatibility wire aliases that continue to
        // verify byte-for-byte" but the equality check here was left strict —
        // so any upgraded operator with an existing event log (every member
        // of the team running an upgraded daemon over an existing dev store)
        // hit `event subject must match the typed event body` at startup and
        // could not open their identity substrate.
        //
        // Canonicalize both sides before comparing. The on-wire signed bytes
        // still use the stored `subject_kind` so signatures over pre-#6065
        // events continue to verify against `signed_bytes()` (which reads
        // `self.subject.kind.as_str()` verbatim). Strict byte-form is
        // preserved through the signing-bytes path; alias acceptance only
        // applies to the typed-body equivalence check the validator owns.
        let body_subject = self.body.subject();
        if self.subject.clone().canonical_principal_alias()
            != body_subject.clone().canonical_principal_alias()
        {
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
        out.push_str("ref.");
        out.push_str(&index.to_string());
        out.push_str(".seq=");
        out.push_str(&reference.seq.to_string());
        out.push('\n');
    }
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(b"payload=\n");
    bytes.extend_from_slice(payload);
    bytes
}

#[cfg(test)]
mod tests {
    use core_crypto::FixtureSigner;
    use core_event_types::{EventBody, PersonaCreatedEvent, RootCreatedEvent, SubjectKind};
    use core_principals::{KeyAlgorithm, PublicKeyMaterial, SurvivalMode};

    use super::*;

    fn test_key(key_id: &str) -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: key_id.into(),
            algorithm: KeyAlgorithm::DevEd25519Like,
            public_key: format!("devpub:{key_id}"),
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
            vec![EventRef::previous("evt-0", 1)],
            SignerBinding::root("root-1", "key-root-1"),
            &signer,
        )
        .unwrap();
        let verifier = core_crypto::FixtureVerifier;

        assert!(core_crypto::verify_with_context(
            DOMAIN_EVENT,
            &verifier,
            &envelope.signer,
            &envelope.signed_bytes(),
            &envelope.signature,
        ));
        assert_eq!(envelope.subject, EventSubject::principal("root-1"));
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
            vec![
                EventRef::previous("evt-0", 1),
                EventRef::previous("evt-0", 1),
            ],
            SignerBinding::root("root-1", "key-root-1"),
            &signer,
        )
        .unwrap();

        assert!(envelope.validate().is_err());
    }

    #[test]
    fn validator_accepts_legacy_root_alias_subject() {
        // event_subject_validator_alias_aware — regression for
        // META-AP-EVENT-SUBJECT-VALIDATOR-ALIAS-AWARE.
        //
        // Pre-#6065 daemons wrote RootCreated events with
        // `subject.kind = SubjectKind::Root`. PR #6065 changed `body.subject()`
        // to emit `SubjectKind::Principal` canonically. Without alias-aware
        // equality, every pre-#6065 event fails validation at replay and the
        // daemon refuses to open its identity substrate.
        //
        // Construct an envelope with the legacy Root-kind subject paired with
        // a RootCreated body (whose `body.subject()` returns Principal). Pass
        // through `from_stored_parts` (which is the production read path —
        // `EventStore::open` rebuilds envelopes from SQLite rows via this
        // constructor and calls `validate()` on each).
        let signer = FixtureSigner::new("fixture-root-key");
        let body = EventBody::RootCreated(RootCreatedEvent {
            root_id: "root-1".into(),
            display_name: "Primary".into(),
            initial_key: test_key("key-root-1"),
        });
        // Build a canonical envelope first so we get a valid signature over
        // the legacy `subject_kind=root` bytes (signed_bytes uses
        // subject.kind.as_str() verbatim — i.e. "root" — when the stored
        // subject is the legacy alias).
        let payload = body.canonical_encode();
        let event_id = "evt-legacy-root".to_string();
        let signer_binding = SignerBinding::root("root-1", "key-root-1");
        let refs = vec![EventRef::previous("evt-0", 1)];
        let legacy_subject = EventSubject::root("root-1");
        let signed_bytes = canonical_signed_bytes(
            SchemaVersion::V0_1_0,
            &event_id,
            EventType::RootCreated,
            &legacy_subject,
            &signer_binding,
            &refs,
            &payload,
        );
        let signature = core_crypto::sign_with_context(DOMAIN_EVENT, &signer, &signed_bytes);

        let envelope = EventEnvelope::from_stored_parts(
            SchemaVersion::V0_1_0,
            event_id,
            EventType::RootCreated,
            legacy_subject.clone(),
            signer_binding,
            signer.public_key(),
            payload,
            refs,
            signature,
        )
        .expect(
            "legacy SubjectKind::Root subject must validate against \
             canonical Principal-emitting body (alias-aware equality)",
        );
        // Stored subject is preserved as-deserialized (alias form), per the
        // PR #6065 byte-for-byte signature contract — only the equality check
        // is alias-aware, not the storage shape.
        assert_eq!(envelope.subject.kind, SubjectKind::Root);
        assert_eq!(envelope.subject.subject_id, "root-1");
    }

    #[test]
    fn validator_accepts_legacy_persona_alias_subject() {
        // Companion to the Root-alias regression: PersonaCreated events
        // pre-#6065 wrote `subject.kind = SubjectKind::Persona`, which
        // body.subject() now canonicalizes to Principal. Validate must accept.
        let signer = FixtureSigner::new("fixture-persona-key");
        let body = EventBody::PersonaCreated(PersonaCreatedEvent {
            root_id: "root-1".into(),
            persona_id: "persona-1".into(),
            label: "Work".into(),
            disclosure_profile: Some("work-public".into()),
            survival_mode: SurvivalMode::Strict,
            initial_key: test_key("key-persona-1"),
        });
        let payload = body.canonical_encode();
        let event_id = "evt-legacy-persona".to_string();
        let signer_binding = SignerBinding::root("root-1", "key-root-1");
        let refs = vec![EventRef::previous("evt-0", 1)];
        let legacy_subject = EventSubject::persona("persona-1");
        let signed_bytes = canonical_signed_bytes(
            SchemaVersion::V0_1_0,
            &event_id,
            EventType::PersonaCreated,
            &legacy_subject,
            &signer_binding,
            &refs,
            &payload,
        );
        let signature = core_crypto::sign_with_context(DOMAIN_EVENT, &signer, &signed_bytes);

        let envelope = EventEnvelope::from_stored_parts(
            SchemaVersion::V0_1_0,
            event_id,
            EventType::PersonaCreated,
            legacy_subject,
            signer_binding,
            signer.public_key(),
            payload,
            refs,
            signature,
        )
        .expect(
            "legacy SubjectKind::Persona subject must validate against \
             canonical Principal-emitting body (alias-aware equality)",
        );
        assert_eq!(envelope.subject.kind, SubjectKind::Persona);
        assert_eq!(envelope.subject.subject_id, "persona-1");
    }

    #[test]
    fn validator_still_rejects_mismatched_subject_id_even_with_alias() {
        // The alias-aware equality canonicalizes the kind, but the subject_id
        // still has to match the body's id. A Root-kind alias with the wrong
        // subject_id must NOT validate just because the kind canonicalizes.
        let signer = FixtureSigner::new("fixture-root-key");
        let body = EventBody::RootCreated(RootCreatedEvent {
            root_id: "root-1".into(),
            display_name: "Primary".into(),
            initial_key: test_key("key-root-1"),
        });
        let payload = body.canonical_encode();
        let event_id = "evt-mismatched".to_string();
        let signer_binding = SignerBinding::root("root-1", "key-root-1");
        // Wrong subject_id — body says root-1, subject says root-WRONG.
        let bad_subject = EventSubject::root("root-WRONG");
        let signed_bytes = canonical_signed_bytes(
            SchemaVersion::V0_1_0,
            &event_id,
            EventType::RootCreated,
            &bad_subject,
            &signer_binding,
            &[],
            &payload,
        );
        let signature = core_crypto::sign_with_context(DOMAIN_EVENT, &signer, &signed_bytes);

        let err = EventEnvelope::from_stored_parts(
            SchemaVersion::V0_1_0,
            event_id,
            EventType::RootCreated,
            bad_subject,
            signer_binding,
            signer.public_key(),
            payload,
            vec![],
            signature,
        )
        .expect_err("subject_id mismatch must still be rejected");
        assert!(
            err.to_string().contains("event subject must match"),
            "expected subject-mismatch rejection, got: {err}"
        );
    }

    #[test]
    fn envelope_payload_size_cap_rejects_oversized_canonical_blob() {
        // Backstop test for EVENTS-H1: even if every per-field cap is
        // bypassed, the envelope-level MAX_EVENT_PAYLOAD_BYTES backstop
        // must reject oversized payloads.
        use core_types::size_limits::MAX_EVENT_PAYLOAD_BYTES;

        let signer = FixtureSigner::new("fixture-root-key");
        let body = EventBody::RootCreated(RootCreatedEvent {
            root_id: "root-1".into(),
            display_name: "Primary".into(),
            initial_key: test_key("key-root-1"),
        });
        let mut envelope = EventEnvelope::from_body(
            "evt-bomb",
            body,
            vec![],
            SignerBinding::root("root-1", "key-root-1"),
            &signer,
        )
        .unwrap();
        // Force-inflate the stored payload bytes past the envelope cap.
        // Real attackers reach this state via `from_stored_parts` with a
        // crafted SQLite row; we simulate by direct-mutating the field.
        envelope.payload = vec![b'a'; MAX_EVENT_PAYLOAD_BYTES + 1];
        let err = envelope.validate().unwrap_err();
        assert!(
            err.to_string().contains("event payload exceeds"),
            "expected envelope-cap rejection, got: {err}"
        );
    }
}
