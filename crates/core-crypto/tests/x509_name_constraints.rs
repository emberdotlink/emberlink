//! CLASSIFICATION: PUBLIC
//!
//! T1 property tests for per-agent X.509 CA with nameConstraints.
//!
//! All tests are pure — no filesystem, no network, no SystemTime::now().

use core_crypto::x509::{X509Error, mint_per_agent_ca_with_name_constraints};
use proptest::prelude::*;
use x509_parser::prelude::*;

/// Decode a PEM block and return the contained DER bytes.
fn pem_to_der(pem_str: &str) -> Vec<u8> {
    let (_, pem) = parse_x509_pem(pem_str.as_bytes()).expect("PEM parse must succeed");
    pem.contents
}

// ─── prop_minted_ca_is_self_signed ──────────────────────────────────────────

proptest! {
    /// Issuer == Subject (self-signed invariant).
    ///
    /// A per-agent CA must be self-signed: the Issuer and Subject distinguished
    /// names must be identical so the CA cert is its own trust anchor.
    #[test]
    fn prop_minted_ca_is_self_signed(
        agent_id in "[a-z][a-z0-9-]{1,15}",
        validity_hours in 1u32..=168,
    ) {
        let permitted = ["api.anthropic.com", "*.anthropic.com"];
        let (cert_pem, _key_pem) =
            mint_per_agent_ca_with_name_constraints(&agent_id, &permitted, validity_hours)
                .expect("mint must succeed");

        let der = pem_to_der(cert_pem.as_str());
        let (_, cert) = X509Certificate::from_der(&der).expect("DER parse must succeed");

        prop_assert_eq!(
            cert.issuer().to_string(),
            cert.subject().to_string(),
            "Issuer must equal Subject for a self-signed CA cert"
        );
    }
}

// ─── prop_minted_ca_has_pathlen_zero ────────────────────────────────────────

proptest! {
    /// BasicConstraints: cA=TRUE, pathLenConstraint=0.
    ///
    /// pathlen 0 means the per-agent CA can sign leaf certs but cannot issue
    /// further CAs — limiting blast radius.
    #[test]
    fn prop_minted_ca_has_pathlen_zero(
        agent_id in "[a-z][a-z0-9-]{1,15}",
        validity_hours in 1u32..=168,
    ) {
        let permitted = ["api.anthropic.com", "github.com"];
        let (cert_pem, _key_pem) =
            mint_per_agent_ca_with_name_constraints(&agent_id, &permitted, validity_hours)
                .expect("mint must succeed");

        let der = pem_to_der(cert_pem.as_str());
        let (_, cert) = X509Certificate::from_der(&der).expect("DER parse must succeed");

        let bc = cert
            .basic_constraints()
            .expect("BasicConstraints extension must parse cleanly")
            .expect("BasicConstraints extension must be present");

        prop_assert!(bc.value.ca, "cA flag must be true");
        prop_assert_eq!(
            bc.value.path_len_constraint,
            Some(0),
            "pathLenConstraint must be 0"
        );
    }
}

// ─── prop_minted_ca_has_name_constraints ────────────────────────────────────

proptest! {
    /// NameConstraints: permittedSubtrees matches input; excludedSubtrees empty.
    ///
    /// Every DNS name supplied to `mint_per_agent_ca_with_name_constraints`
    /// must appear verbatim in the cert's NameConstraints permittedSubtrees,
    /// and excludedSubtrees must be absent (empty).
    #[test]
    fn prop_minted_ca_has_name_constraints(
        agent_id in "[a-z][a-z0-9-]{1,15}",
        validity_hours in 1u32..=168,
    ) {
        let permitted: &[&str] = &["api.anthropic.com", "*.anthropic.com", "github.com"];
        let (cert_pem, _key_pem) =
            mint_per_agent_ca_with_name_constraints(&agent_id, permitted, validity_hours)
                .expect("mint must succeed");

        let der = pem_to_der(cert_pem.as_str());
        let (_, cert) = X509Certificate::from_der(&der).expect("DER parse must succeed");

        let nc_ext = cert
            .name_constraints()
            .expect("NameConstraints extension must parse cleanly")
            .expect("NameConstraints extension must be present");
        let nc = nc_ext.value;

        let subtrees = nc
            .permitted_subtrees
            .as_ref()
            .expect("permittedSubtrees must be present");

        // Collect DNS names from the permitted subtrees.
        let dns_names: Vec<&str> = subtrees
            .iter()
            .filter_map(|s| {
                if let GeneralName::DNSName(name) = s.base {
                    Some(name)
                } else {
                    None
                }
            })
            .collect();

        for expected in permitted {
            prop_assert!(
                dns_names.contains(expected),
                "permitted DNS name {:?} must appear in NameConstraints permittedSubtrees; got {:?}",
                expected,
                dns_names
            );
        }

        // excludedSubtrees must be absent (None or empty).
        let excluded_empty = nc
            .excluded_subtrees
            .as_ref()
            .map(|v| v.is_empty())
            .unwrap_or(true);
        prop_assert!(excluded_empty, "excludedSubtrees must be absent/empty");
    }
}

// ─── mint_rejects_invalid_validity_hours ────────────────────────────────────

#[test]
fn mint_rejects_invalid_validity_hours_zero() {
    let err = mint_per_agent_ca_with_name_constraints("agent-test", &["api.anthropic.com"], 0)
        .expect_err("validity_hours=0 must fail");
    assert!(
        matches!(err, X509Error::InvalidValidity(0)),
        "expected InvalidValidity(0), got {err:?}"
    );
}

#[test]
fn mint_rejects_invalid_validity_hours_over_limit() {
    let err = mint_per_agent_ca_with_name_constraints("agent-test", &["api.anthropic.com"], 169)
        .expect_err("validity_hours=169 must fail");
    assert!(
        matches!(err, X509Error::InvalidValidity(169)),
        "expected InvalidValidity(169), got {err:?}"
    );
}

// ─── mint_rejects_empty_permitted_names ─────────────────────────────────────

#[test]
fn mint_rejects_empty_permitted_names() {
    let err = mint_per_agent_ca_with_name_constraints("agent-test", &[], 24)
        .expect_err("empty permitted_dns_names must fail");
    assert!(
        matches!(err, X509Error::EmptyPermittedNames),
        "expected EmptyPermittedNames, got {err:?}"
    );
}
