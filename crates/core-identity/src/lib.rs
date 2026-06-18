use core_event_types::{
    DeviceAddedEvent, DeviceEncryptionKeyRotatedEvent, DeviceFrozenEvent, DeviceKeyRotatedEvent,
    DeviceReplacedEvent, DeviceRevokedEvent, EventBody, RootCreatedEvent, RootKeyRotatedEvent,
    RootRevokedEvent,
};
use core_principals::{
    DisclosedLinkage, DisclosedPersona, DisclosureView, IdentityRoot, LinkageAssertion, Persona,
    PublicKeyMaterial, SurvivalMode,
};

pub fn create_root(
    id: impl Into<String>,
    display_name: impl Into<String>,
    active_key: PublicKeyMaterial,
) -> IdentityRoot {
    // Per ADR 200 2026-06-15 amendment: `IdentityRoot` is a transitional
    // alias for a self-parented `Principal` (`id == parent_id`). The
    // root's display-name maps onto the unified `label` slot;
    // `survival_mode` defaults to `Strict` (a root has no continuity
    // policy of its own).
    let id_str: String = id.into();
    IdentityRoot {
        parent_id: id_str.clone(),
        id: id_str,
        label: display_name.into(),
        disclosure_profile: None,
        survival_mode: SurvivalMode::Strict,
        active_key,
    }
}

pub fn root_created_event(
    root_id: impl Into<String>,
    display_name: impl Into<String>,
    initial_key: PublicKeyMaterial,
) -> EventBody {
    EventBody::RootCreated(RootCreatedEvent {
        root_id: root_id.into(),
        display_name: display_name.into(),
        initial_key,
    })
}

pub fn root_key_rotated_event(
    root_id: impl Into<String>,
    previous_key_id: impl Into<String>,
    new_key: PublicKeyMaterial,
) -> EventBody {
    EventBody::RootKeyRotated(RootKeyRotatedEvent {
        root_id: root_id.into(),
        previous_key_id: previous_key_id.into(),
        new_key,
    })
}

pub fn root_revoked_event(root_id: impl Into<String>, reason: impl Into<String>) -> EventBody {
    EventBody::RootRevoked(RootRevokedEvent {
        root_id: root_id.into(),
        reason: reason.into(),
    })
}

pub fn device_added_event(
    root_id: impl Into<String>,
    device_id: impl Into<String>,
    label: impl Into<String>,
    initial_key: PublicKeyMaterial,
    initial_encryption_key: PublicKeyMaterial,
) -> EventBody {
    EventBody::DeviceAdded(DeviceAddedEvent {
        root_id: root_id.into(),
        device_id: device_id.into(),
        label: label.into(),
        initial_key,
        initial_encryption_key,
    })
}

pub fn device_key_rotated_event(
    root_id: impl Into<String>,
    device_id: impl Into<String>,
    previous_key_id: impl Into<String>,
    new_key: PublicKeyMaterial,
) -> EventBody {
    EventBody::DeviceKeyRotated(DeviceKeyRotatedEvent {
        root_id: root_id.into(),
        device_id: device_id.into(),
        previous_key_id: previous_key_id.into(),
        new_key,
    })
}

pub fn device_encryption_key_rotated_event(
    root_id: impl Into<String>,
    device_id: impl Into<String>,
    previous_encryption_key_id: impl Into<String>,
    new_encryption_key: PublicKeyMaterial,
) -> EventBody {
    EventBody::DeviceEncryptionKeyRotated(DeviceEncryptionKeyRotatedEvent {
        root_id: root_id.into(),
        device_id: device_id.into(),
        previous_encryption_key_id: previous_encryption_key_id.into(),
        new_encryption_key,
    })
}

pub fn device_revoked_event(
    root_id: impl Into<String>,
    device_id: impl Into<String>,
    reason: impl Into<String>,
) -> EventBody {
    EventBody::DeviceRevoked(DeviceRevokedEvent {
        root_id: root_id.into(),
        device_id: device_id.into(),
        reason: reason.into(),
    })
}

pub fn device_frozen_event(
    root_id: impl Into<String>,
    device_id: impl Into<String>,
    reason: impl Into<String>,
) -> EventBody {
    EventBody::DeviceFrozen(DeviceFrozenEvent {
        root_id: root_id.into(),
        device_id: device_id.into(),
        reason: reason.into(),
    })
}

pub fn device_replaced_event(
    root_id: impl Into<String>,
    replaced_device_id: impl Into<String>,
    replacement_device_id: impl Into<String>,
) -> EventBody {
    EventBody::DeviceReplaced(DeviceReplacedEvent {
        root_id: root_id.into(),
        replaced_device_id: replaced_device_id.into(),
        replacement_device_id: replacement_device_id.into(),
    })
}

pub fn local_linkage(
    source_root_id: impl Into<String>,
    target_root_id: impl Into<String>,
) -> LinkageAssertion {
    LinkageAssertion {
        source_root_id: source_root_id.into(),
        target_root_id: target_root_id.into(),
        disclosed: false,
    }
}

pub fn disclosure_view(
    root_id: &str,
    personas: &[Persona],
    linkages: &[LinkageAssertion],
) -> DisclosureView {
    let personas = personas
        .iter()
        // Persona is a `Principal` alias post ADR 200 2026-06-15;
        // `root_id` migrated to the recursive `parent_id` slot.
        .filter(|persona| persona.parent_id == root_id)
        .map(|persona| DisclosedPersona {
            persona_id: persona.id.clone(),
            label: persona.label.clone(),
            disclosure_profile: persona.disclosure_profile.clone(),
        })
        .collect();

    let disclosed_links = linkages
        .iter()
        .filter(|linkage| linkage.source_root_id == root_id && linkage.disclosed)
        .map(|linkage| DisclosedLinkage {
            target_root_id: linkage.target_root_id.clone(),
        })
        .collect();

    DisclosureView {
        root_id: root_id.to_string(),
        personas,
        disclosed_links,
    }
}

#[cfg(test)]
mod tests {
    use core_event_types::EventType;
    use core_principals::{KeyAlgorithm, SurvivalMode};

    use super::*;

    fn test_encryption_key(key_id: &str) -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: format!("enc-{key_id}"),
            algorithm: KeyAlgorithm::AgeX25519,
            public_key: format!("age1{key_id}fixture"),
        }
    }

    #[test]
    fn local_only_linkage_is_hidden_from_outward_view_by_default() {
        let personas = vec![
            Persona {
                id: "persona-a1".into(),
                parent_id: "root-a".into(),
                label: "professional".into(),
                disclosure_profile: Some("persona.professional".into()),
                survival_mode: SurvivalMode::Strict,
                active_key: PublicKeyMaterial {
                    key_id: "key-persona-a1".into(),
                    algorithm: core_principals::KeyAlgorithm::DevEd25519Like,
                    public_key: "devpub:a1".into(),
                },
            },
            Persona {
                id: "persona-a2".into(),
                parent_id: "root-a".into(),
                label: "friends".into(),
                disclosure_profile: Some("persona.friends".into()),
                survival_mode: SurvivalMode::Strict,
                active_key: PublicKeyMaterial {
                    key_id: "key-persona-a2".into(),
                    algorithm: core_principals::KeyAlgorithm::DevEd25519Like,
                    public_key: "devpub:a2".into(),
                },
            },
            Persona {
                id: "persona-b1".into(),
                parent_id: "root-b".into(),
                label: "pseudonymous".into(),
                disclosure_profile: Some("persona.pseudonymous".into()),
                survival_mode: SurvivalMode::Strict,
                active_key: PublicKeyMaterial {
                    key_id: "key-persona-b1".into(),
                    algorithm: core_principals::KeyAlgorithm::DevEd25519Like,
                    public_key: "devpub:b1".into(),
                },
            },
        ];
        let linkages = vec![local_linkage("root-a", "root-b")];

        let view = disclosure_view("root-a", &personas, &linkages);

        assert_eq!(view.personas.len(), 2);
        assert!(view.disclosed_links.is_empty());
    }

    #[test]
    fn identity_event_builders_emit_typed_lifecycle_events() {
        let key = PublicKeyMaterial {
            key_id: "key-root-a-v1".into(),
            algorithm: KeyAlgorithm::DevEd25519Like,
            public_key: "devpub:root-a-v1".into(),
        };

        let created = root_created_event("root-a", "Root A", key.clone());
        let rotated = root_key_rotated_event(
            "root-a",
            "key-root-a-v1",
            PublicKeyMaterial {
                key_id: "key-root-a-v2".into(),
                algorithm: KeyAlgorithm::DevEd25519Like,
                public_key: "devpub:root-a-v2".into(),
            },
        );
        let encryption_rotated = device_encryption_key_rotated_event(
            "root-a",
            "device-a",
            "enc-key-device-a-v1",
            test_encryption_key("key-device-a-v2"),
        );
        let device_added = device_added_event(
            "root-a",
            "device-a",
            "Laptop",
            key,
            test_encryption_key("key-device-a-v1"),
        );

        assert_eq!(created.event_type(), EventType::RootCreated);
        assert_eq!(rotated.event_type(), EventType::RootKeyRotated);
        assert_eq!(
            encryption_rotated.event_type(),
            EventType::DeviceEncryptionKeyRotated
        );
        assert_eq!(device_added.event_type(), EventType::DeviceAdded);
    }

    #[test]
    fn device_lifecycle_events_cover_add_freeze_replace_revoke() {
        let key_v1 = PublicKeyMaterial {
            key_id: "key-device-a-v1".into(),
            algorithm: KeyAlgorithm::DevEd25519Like,
            public_key: "devpub:device-a-v1".into(),
        };
        let key_v2 = PublicKeyMaterial {
            key_id: "key-device-a-v2".into(),
            algorithm: KeyAlgorithm::DevEd25519Like,
            public_key: "devpub:device-a-v2".into(),
        };

        let added = device_added_event(
            "root-a",
            "device-a",
            "Laptop",
            key_v1.clone(),
            test_encryption_key("device-a-v1"),
        );
        let frozen = device_frozen_event("root-a", "device-a", "suspicious-activity");
        let rotated = device_key_rotated_event("root-a", "device-a", "key-device-a-v1", key_v2);
        let replaced = device_replaced_event("root-a", "device-a", "device-b");
        let revoked = device_revoked_event("root-a", "device-a", "recovery-execution");

        assert_eq!(added.event_type(), EventType::DeviceAdded);
        assert_eq!(frozen.event_type(), EventType::DeviceFrozen);
        assert_eq!(rotated.event_type(), EventType::DeviceKeyRotated);
        assert_eq!(replaced.event_type(), EventType::DeviceReplaced);
        assert_eq!(revoked.event_type(), EventType::DeviceRevoked);

        // Verify subject extraction on key events
        if let EventBody::DeviceKeyRotated(e) = &rotated {
            assert_eq!(e.device_id, "device-a");
            assert_eq!(e.previous_key_id, "key-device-a-v1");
            assert_eq!(e.new_key.key_id, "key-device-a-v2");
        } else {
            panic!("expected DeviceKeyRotated");
        }

        if let EventBody::DeviceReplaced(e) = &replaced {
            assert_eq!(e.replaced_device_id, "device-a");
            assert_eq!(e.replacement_device_id, "device-b");
        } else {
            panic!("expected DeviceReplaced");
        }
    }

    #[test]
    fn root_revoked_event_emits_typed_event() {
        let revoked = root_revoked_event("root-a", "compromised-key");
        assert_eq!(revoked.event_type(), EventType::RootRevoked);
        if let EventBody::RootRevoked(e) = &revoked {
            assert_eq!(e.root_id, "root-a");
            assert_eq!(e.reason, "compromised-key");
        } else {
            panic!("expected RootRevoked");
        }
    }

    #[test]
    fn disclosure_view_includes_only_disclosed_links() {
        let personas = vec![Persona {
            id: "persona-a1".into(),
            parent_id: "root-a".into(),
            label: "work".into(),
            disclosure_profile: Some("persona.professional".into()),
            survival_mode: SurvivalMode::Strict,
            active_key: PublicKeyMaterial {
                key_id: "key-a1".into(),
                algorithm: KeyAlgorithm::DevEd25519Like,
                public_key: "devpub:a1".into(),
            },
        }];
        let linkages = vec![
            local_linkage("root-a", "root-b"),
            LinkageAssertion {
                source_root_id: "root-a".into(),
                target_root_id: "root-c".into(),
                disclosed: true,
            },
        ];

        let view = disclosure_view("root-a", &personas, &linkages);
        assert_eq!(view.disclosed_links.len(), 1);
        assert_eq!(view.disclosed_links[0].target_root_id, "root-c");
    }
}
