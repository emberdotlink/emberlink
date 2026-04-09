use core_types::{
    EventBody, Persona, PersonaCreatedEvent, PersonaKeyRotatedEvent, PersonaRevokedEvent,
    PublicKeyMaterial, SurvivalMode,
};

pub fn create_persona(
    id: impl Into<String>,
    root_id: impl Into<String>,
    label: impl Into<String>,
    disclosure_profile: Option<String>,
    survival_mode: SurvivalMode,
    active_key: PublicKeyMaterial,
) -> Persona {
    Persona {
        id: id.into(),
        root_id: root_id.into(),
        label: label.into(),
        disclosure_profile,
        survival_mode,
        active_key,
    }
}

pub fn persona_created_event(
    root_id: impl Into<String>,
    persona_id: impl Into<String>,
    label: impl Into<String>,
    disclosure_profile: Option<String>,
    survival_mode: SurvivalMode,
    initial_key: PublicKeyMaterial,
) -> EventBody {
    EventBody::PersonaCreated(PersonaCreatedEvent {
        root_id: root_id.into(),
        persona_id: persona_id.into(),
        label: label.into(),
        disclosure_profile,
        survival_mode,
        initial_key,
    })
}

pub fn persona_key_rotated_event(
    root_id: impl Into<String>,
    persona_id: impl Into<String>,
    previous_key_id: impl Into<String>,
    new_key: PublicKeyMaterial,
) -> EventBody {
    EventBody::PersonaKeyRotated(PersonaKeyRotatedEvent {
        root_id: root_id.into(),
        persona_id: persona_id.into(),
        previous_key_id: previous_key_id.into(),
        new_key,
    })
}

pub fn persona_revoked_event(
    root_id: impl Into<String>,
    persona_id: impl Into<String>,
    reason: impl Into<String>,
) -> EventBody {
    EventBody::PersonaRevoked(PersonaRevokedEvent {
        root_id: root_id.into(),
        persona_id: persona_id.into(),
        reason: reason.into(),
    })
}

pub fn revoke_persona(personas: &mut Vec<Persona>, persona_id: &str) -> Option<Persona> {
    let index = personas
        .iter()
        .position(|persona| persona.id == persona_id)?;
    Some(personas.remove(index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::{EventType, KeyAlgorithm};

    #[test]
    fn revoke_persona_removes_matching_entry() {
        let mut personas = vec![
            create_persona(
                "persona-1",
                "root-1",
                "professional",
                Some("persona.professional".into()),
                SurvivalMode::Strict,
                PublicKeyMaterial {
                    key_id: "key-1".into(),
                    algorithm: core_types::KeyAlgorithm::DevEd25519Like,
                    public_key: "devpub:1".into(),
                },
            ),
            create_persona(
                "persona-2",
                "root-1",
                "friends",
                Some("persona.friends".into()),
                SurvivalMode::Strict,
                PublicKeyMaterial {
                    key_id: "key-2".into(),
                    algorithm: core_types::KeyAlgorithm::DevEd25519Like,
                    public_key: "devpub:2".into(),
                },
            ),
        ];

        let removed = revoke_persona(&mut personas, "persona-1");

        assert!(removed.is_some());
        assert_eq!(personas.len(), 1);
        assert_eq!(personas[0].id, "persona-2");
    }

    #[test]
    fn persona_event_builders_emit_typed_events() {
        let key = PublicKeyMaterial {
            key_id: "key-persona-1-v1".into(),
            algorithm: KeyAlgorithm::DevEd25519Like,
            public_key: "devpub:persona-1-v1".into(),
        };

        let created = persona_created_event(
            "root-1",
            "persona-1",
            "Work",
            Some("work-public".into()),
            SurvivalMode::Strict,
            key.clone(),
        );
        let rotated = persona_key_rotated_event(
            "root-1",
            "persona-1",
            "key-persona-1-v1",
            PublicKeyMaterial {
                key_id: "key-persona-1-v2".into(),
                algorithm: KeyAlgorithm::DevEd25519Like,
                public_key: "devpub:persona-1-v2".into(),
            },
        );
        let revoked = persona_revoked_event("root-1", "persona-1", "compromised");

        assert_eq!(created.event_type(), EventType::PersonaCreated);
        assert_eq!(rotated.event_type(), EventType::PersonaKeyRotated);
        assert_eq!(revoked.event_type(), EventType::PersonaRevoked);
    }

    #[test]
    fn persona_lifecycle_create_rotate_revoke_extracts_fields() {
        let key_v1 = PublicKeyMaterial {
            key_id: "key-p1-v1".into(),
            algorithm: KeyAlgorithm::DevEd25519Like,
            public_key: "devpub:p1-v1".into(),
        };
        let key_v2 = PublicKeyMaterial {
            key_id: "key-p1-v2".into(),
            algorithm: KeyAlgorithm::DevEd25519Like,
            public_key: "devpub:p1-v2".into(),
        };

        let created = persona_created_event(
            "root-a",
            "persona-work",
            "Work",
            Some("persona.professional".into()),
            SurvivalMode::Strict,
            key_v1.clone(),
        );
        if let EventBody::PersonaCreated(e) = &created {
            assert_eq!(e.root_id, "root-a");
            assert_eq!(e.persona_id, "persona-work");
            assert_eq!(e.label, "Work");
            assert_eq!(
                e.disclosure_profile.as_deref(),
                Some("persona.professional")
            );
            assert_eq!(e.initial_key.key_id, "key-p1-v1");
        } else {
            panic!("expected PersonaCreated");
        }

        let rotated = persona_key_rotated_event("root-a", "persona-work", "key-p1-v1", key_v2);
        if let EventBody::PersonaKeyRotated(e) = &rotated {
            assert_eq!(e.persona_id, "persona-work");
            assert_eq!(e.previous_key_id, "key-p1-v1");
            assert_eq!(e.new_key.key_id, "key-p1-v2");
        } else {
            panic!("expected PersonaKeyRotated");
        }

        let revoked = persona_revoked_event("root-a", "persona-work", "user-request");
        if let EventBody::PersonaRevoked(e) = &revoked {
            assert_eq!(e.persona_id, "persona-work");
            assert_eq!(e.reason, "user-request");
        } else {
            panic!("expected PersonaRevoked");
        }
    }

    #[test]
    fn revoke_persona_returns_none_for_unknown_id() {
        let mut personas = vec![create_persona(
            "persona-1",
            "root-1",
            "pro",
            None,
            SurvivalMode::Strict,
            PublicKeyMaterial {
                key_id: "key-1".into(),
                algorithm: KeyAlgorithm::DevEd25519Like,
                public_key: "devpub:1".into(),
            },
        )];

        assert!(revoke_persona(&mut personas, "persona-nonexistent").is_none());
        assert_eq!(personas.len(), 1);
    }
}
