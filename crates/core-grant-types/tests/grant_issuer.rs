use core_grant_types::{AccessGrant, GrantLink, ResourceSelector, ResourceType, Statement, Usage};
use core_types::{CanonicalEncode, Validate};

fn statement() -> Statement {
    Statement {
        sid: "GitHubRead".into(),
        resource_type: ResourceType::Credential,
        actions: vec!["github:repo:read".into()],
        resource: ResourceSelector::Glob {
            pattern: "emberlink/*".into(),
        },
        budget: None,
        usage: Usage::default(),
        conditions: Vec::new(),
        can_delegate: None,
    }
}

fn grant_for_issuer(issuer_principal_id: &str) -> AccessGrant {
    AccessGrant::single_statement(
        format!("grant-{issuer_principal_id}"),
        issuer_principal_id,
        "github",
        statement(),
        "ed25519-next-key",
        "ed25519-signature",
        1_800_000_000,
    )
}

fn link_for_issuer(issuer_principal_id: &str) -> GrantLink {
    GrantLink {
        offer_id: format!("offer-{issuer_principal_id}"),
        ephemeral_public_key_hex: "deadbeef".into(),
        expires_at: 1_800_000_900,
        issuer_signature: "sig0011".into(),
        relay_hint: None,
        issuer_persona_id: issuer_principal_id.into(),
        issuer_public_key_hex: "ed25519-issuer-key".into(),
        recipient_pubkey_hex: String::new(),
    }
}

#[test]
fn grant_issuer_is_unified_principal_id() {
    // identity_root_persona_core_grant_types_adaptation_landed
    let self_parented_root_principal_id = "principal-root-self-parented";
    let child_durable_persona_principal_id = "principal-operator-role";

    for issuer_principal_id in [
        self_parented_root_principal_id,
        child_durable_persona_principal_id,
    ] {
        let grant = grant_for_issuer(issuer_principal_id);

        grant.validate().unwrap();
        assert_eq!(grant.issuer_principal_id(), issuer_principal_id);
        assert_eq!(grant.blocks[0].block.issued_by, issuer_principal_id);

        let encoded = String::from_utf8(grant.blocks[0].block.canonical_encode()).unwrap();
        let (_, canonical_json) = encoded.split_once('\n').unwrap();
        let canonical: serde_json::Value = serde_json::from_str(canonical_json).unwrap();

        assert_eq!(canonical["issued_by"], issuer_principal_id);
        assert!(canonical.get("issuer_persona_id").is_none());
        assert!(canonical.get("identity_root_id").is_none());
        assert!(!canonical_json.contains("IdentityRoot"));
        assert!(!canonical_json.contains("PersonaId"));

        let decoded_block: core_grant_types::Block = serde_json::from_str(canonical_json).unwrap();
        assert_eq!(decoded_block.issued_by, issuer_principal_id);

        let link = link_for_issuer(issuer_principal_id);
        let url = link.to_url();
        assert!(url.contains(&format!("issuer={issuer_principal_id}")));
        assert!(!url.contains("issuer_persona_id"));

        let parsed = GrantLink::parse(&url).unwrap();
        assert_eq!(parsed.issuer_principal_id(), issuer_principal_id);
    }
}
