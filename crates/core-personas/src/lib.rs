use core_event_types::{
    EventBody, PersonaCreatedEvent, PersonaKeyRotatedEvent, PersonaRevokedEvent,
};
use core_principals::{Persona, PublicKeyMaterial, SurvivalMode};

pub fn create_persona(
    id: impl Into<String>,
    root_id: impl Into<String>,
    label: impl Into<String>,
    disclosure_profile: Option<String>,
    survival_mode: SurvivalMode,
    active_key: PublicKeyMaterial,
) -> Persona {
    // Per ADR 200 2026-06-15 amendment: Persona is a transitional alias
    // for the unified `Principal` type; `root_id` becomes the recursive
    // `parent_id` slot. Wire/canonical attribution remains the same.
    Persona {
        id: id.into(),
        parent_id: root_id.into(),
        label: label.into(),
        disclosure_profile,
        survival_mode,
        active_key,
    }
}

/// SCION-FOUNDATION-AGENT-PERSONA-RPC (ADR 140 §9 + §6) — factory for
/// a workload Persona bound to a SCION agent's container identity.
///
/// Returns the persona alongside the container_id + parent_grant_id
/// binding it was minted under. The caller (daemon `create_agent_persona`
/// RPC handler) persists the binding into BOTH the `personas` SQLite
/// row AND a timestamped audit-log row so the reconciler can
/// reconstruct the binding from either source.
///
/// This is the pure factory — it does not touch the event store or
/// the SQLite layer. The two-phase commit (`enrolling -> active`)
/// and container-id uniqueness enforcement happens at the daemon
/// boundary, where the SQLite transaction lives.
#[allow(clippy::too_many_arguments)]
pub fn create_agent_persona(
    id: impl Into<String>,
    root_id: impl Into<String>,
    label: impl Into<String>,
    container_id: impl Into<String>,
    parent_grant_id: impl Into<String>,
    disclosure_profile: Option<String>,
    survival_mode: SurvivalMode,
    active_key: PublicKeyMaterial,
) -> AgentPersona {
    AgentPersona {
        persona: Persona {
            id: id.into(),
            parent_id: root_id.into(),
            label: label.into(),
            disclosure_profile,
            survival_mode,
            active_key,
        },
        container_id: container_id.into(),
        parent_grant_id: parent_grant_id.into(),
    }
}

/// SCION-FOUNDATION-AGENT-PERSONA-RPC — workload Persona + container
/// binding metadata. Returned by [`create_agent_persona`] so the
/// daemon can persist the binding atomically with the persona row.
///
/// The struct deliberately wraps the base [`Persona`] rather than
/// extending it so the protocol-level Persona type stays unchanged
/// (no new variant in `core-types`, no migration of the canonical
/// event encoding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPersona {
    pub persona: Persona,
    /// Container identity this persona was minted for. Used by the
    /// reconciler to refuse a duplicate spawn into the same slot.
    pub container_id: String,
    /// Parent grant whose authority is being attenuated to this
    /// persona's child grant. Lets the reconciler + receipt pipeline
    /// correlate the agent's grant lineage without walking the chain.
    pub parent_grant_id: String,
}

/// ADR 154 component 4 — kernel-attested-equivalent principal resolved
/// from an mTLS client certificate presented on the cross-uid bridge
/// listener. `MtlsPrincipal` is to the mTLS lane what
/// `EnrolledPrincipal` (in `ember-daemon::infra::handler`) is to the
/// per-agent UDS lane: an identity-claim binding that the dispatcher
/// trusts in place of wire-claimed `caller_persona_id`.
///
/// DO NOT redefine this type. It MUST live in `core-personas` so the
/// daemon, the bridge listener, and any future consumer (dashboard
/// extract, audit replay, fed-relay) all import a single canonical
/// definition. A CI grep-lint refuses `pub struct MtlsPrincipal`
/// declarations outside this crate; redefinitions silently fork the
/// identity model and would let a downstream consumer over-trust a
/// look-alike struct that does NOT carry the cert-fingerprint binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsPrincipal {
    /// Persona id resolved from the SPIFFE URI SAN of the client cert
    /// (ADR 154 component 1 — see `META-AP-CORE-CRYPTO-SAN-SPIFFE-SHAPE`).
    pub persona_id: String,
    /// Container id resolved from the secondary SAN entry. Cross-checked
    /// against the persona's `agent_personas.container_id` binding to
    /// refuse mismatched-SAN certs at dispatch time (ADR 154 ESC-3).
    pub container_id: String,
    /// BLAKE3 of the DER-encoded client cert. This matches the persona
    /// row's `client_cert_fingerprint` pin so refresh handlers can compare
    /// the presented cert to daemon-side state without converting hash
    /// algorithms at the trust boundary.
    pub cert_fingerprint: [u8; 32],
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
    use core_event_types::EventType;
    use core_principals::KeyAlgorithm;

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
                    algorithm: core_principals::KeyAlgorithm::DevEd25519Like,
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
                    algorithm: core_principals::KeyAlgorithm::DevEd25519Like,
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

    // SCION-FOUNDATION-AGENT-PERSONA-RPC tests.

    #[test]
    fn create_agent_persona_carries_container_binding() {
        let ap = create_agent_persona(
            "persona-agent-1",
            "root-1",
            "scion-ml-eval",
            "ctr-abc123",
            "grant-parent-001",
            Some("agent.ml-eval".into()),
            SurvivalMode::Strict,
            PublicKeyMaterial {
                key_id: "key-agent-1".into(),
                algorithm: KeyAlgorithm::Ed25519,
                public_key: "ed25519:agent-pubkey".into(),
            },
        );

        assert_eq!(ap.persona.id, "persona-agent-1");
        // Per ADR 200 2026-06-15 amendment: `root_id` → `parent_id`.
        assert_eq!(ap.persona.parent_id, "root-1");
        assert_eq!(ap.persona.label, "scion-ml-eval");
        assert_eq!(ap.container_id, "ctr-abc123");
        assert_eq!(ap.parent_grant_id, "grant-parent-001");
        assert_eq!(
            ap.persona.disclosure_profile.as_deref(),
            Some("agent.ml-eval")
        );
    }

    #[test]
    fn create_agent_persona_inner_persona_matches_create_persona() {
        // The factory's inner Persona must be wire-compatible with
        // the legacy `create_persona` shape — the daemon's `personas`
        // table row reads the same fields regardless of which factory
        // built it.
        let active_key = PublicKeyMaterial {
            key_id: "key-2".into(),
            algorithm: KeyAlgorithm::Ed25519,
            public_key: "ed25519:pubkey-2".into(),
        };
        let legacy = create_persona(
            "persona-2",
            "root-2",
            "label",
            None,
            SurvivalMode::Strict,
            active_key.clone(),
        );
        let agent = create_agent_persona(
            "persona-2",
            "root-2",
            "label",
            "ctr-xyz",
            "grant-xyz",
            None,
            SurvivalMode::Strict,
            active_key,
        );
        assert_eq!(legacy, agent.persona);
    }
}
