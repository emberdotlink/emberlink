//! CLASSIFICATION: PUBLIC
//!
//! T1 unit tests for per-agent mTLS client cert minting.
//!
//! All tests are pure — no filesystem, no network, no SystemTime::now().

use core_crypto::x509::{X509Error, mint_per_agent_client_cert};
use proptest::prelude::*;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PKCS_ED25519};
use x509_parser::prelude::*;

/// Decode a PEM block and return the contained DER bytes.
fn pem_to_der(pem_str: &str) -> Vec<u8> {
    let (_, pem) = parse_x509_pem(pem_str.as_bytes()).expect("PEM parse must succeed");
    pem.contents
}

/// Build a self-signed CA key + cert for use as a client-auth signer in tests.
fn make_signer_ca() -> (KeyPair, rcgen::Certificate) {
    let key = KeyPair::generate_for(&PKCS_ED25519).expect("keygen must succeed");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params must succeed");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    params.not_after = rcgen::date_time_ymd(9999, 12, 31);
    let cert = params.self_signed(&key).expect("self_signed must succeed");
    (key, cert)
}

// ─── prop_client_cert_has_client_auth_eku ────────────────────────────────────

proptest! {
    /// ClientAuth EKU must be present on every minted client cert.
    ///
    /// The ExtendedKeyUsage extension must include the OID for clientAuth
    /// (1.3.6.1.5.5.7.3.2). Absence would let the proxy accept the cert for
    /// any purpose rather than specifically client authentication.
    #[test]
    fn prop_client_cert_has_client_auth_eku(
        agent_id in "[a-z][a-z0-9-]{1,15}",
        validity_hours in 1u32..=168,
    ) {
        let (key, cert) = make_signer_ca();
        let (cert_pem, _key_pem) =
            mint_per_agent_client_cert(&agent_id, None, &key, &cert, validity_hours)
                .expect("mint must succeed");

        let der = pem_to_der(cert_pem.as_str());
        let (_, parsed) = X509Certificate::from_der(&der).expect("DER parse must succeed");

        let eku_ext = parsed
            .extended_key_usage()
            .expect("EKU extension must parse cleanly")
            .expect("EKU extension must be present");

        // x509_parser represents clientAuth as the dedicated bool field `client_auth`.
        prop_assert!(
            eku_ext.value.client_auth,
            "clientAuth must be set in ExtendedKeyUsage; got {:?}",
            eku_ext.value
        );
    }
}

// ─── prop_client_cert_san_has_urn_emberlink_agent ────────────────────────────

proptest! {
    /// SAN URI must be urn:emberlink:agent:<agent_id>.
    ///
    /// The proxy reads this SAN URI post-handshake to resolve which agent is
    /// authenticated. The exact URI format is the contract between
    /// `mint_per_agent_client_cert` and `extract_agent_id_from_cert`.
    #[test]
    fn prop_client_cert_san_has_urn_emberlink_agent(
        agent_id in "[a-z][a-z0-9-]{1,15}",
        validity_hours in 1u32..=168,
    ) {
        let (key, cert) = make_signer_ca();
        let (cert_pem, _key_pem) =
            mint_per_agent_client_cert(&agent_id, None, &key, &cert, validity_hours)
                .expect("mint must succeed");

        let der = pem_to_der(cert_pem.as_str());
        let (_, parsed) = X509Certificate::from_der(&der).expect("DER parse must succeed");

        let san_ext = parsed
            .subject_alternative_name()
            .expect("SAN extension must parse cleanly")
            .expect("SAN extension must be present");

        let expected_uri = format!("urn:emberlink:agent:{agent_id}");
        let found = san_ext.value.general_names.iter().any(|gn| {
            matches!(gn, GeneralName::URI(uri) if *uri == expected_uri.as_str())
        });

        prop_assert!(
            found,
            "SAN must contain URI {:?}; got {:?}",
            expected_uri,
            san_ext.value.general_names
        );
    }
}

// ─── prop_client_cert_subject_cn_matches_persona ─────────────────────────────

proptest! {
    /// Subject CN must be ember-persona-<agent_id> (META-AP-CORE-CRYPTO-SAN-SPIFFE-SHAPE).
    #[test]
    fn prop_client_cert_subject_cn_matches_persona(
        agent_id in "[a-z][a-z0-9-]{1,15}",
        validity_hours in 1u32..=168,
    ) {
        let (key, cert) = make_signer_ca();
        let (cert_pem, _key_pem) =
            mint_per_agent_client_cert(&agent_id, None, &key, &cert, validity_hours)
                .expect("mint must succeed");

        let der = pem_to_der(cert_pem.as_str());
        let (_, parsed) = X509Certificate::from_der(&der).expect("DER parse must succeed");

        let expected_cn = format!("ember-persona-{agent_id}");
        let subject = parsed.subject().to_string();
        prop_assert!(
            subject.contains(&expected_cn),
            "Subject CN must contain {:?}; got {:?}",
            expected_cn,
            subject
        );
    }
}

// ─── prop_client_cert_is_not_ca ──────────────────────────────────────────────

proptest! {
    /// BasicConstraints cA must be false — client cert is NOT a CA.
    ///
    /// A client cert that is also a CA would allow the agent to issue further
    /// certs, widening the blast radius beyond what mTLS auth requires.
    #[test]
    fn prop_client_cert_is_not_ca(
        agent_id in "[a-z][a-z0-9-]{1,15}",
        validity_hours in 1u32..=168,
    ) {
        let (key, cert) = make_signer_ca();
        let (cert_pem, _key_pem) =
            mint_per_agent_client_cert(&agent_id, None, &key, &cert, validity_hours)
                .expect("mint must succeed");

        let der = pem_to_der(cert_pem.as_str());
        let (_, parsed) = X509Certificate::from_der(&der).expect("DER parse must succeed");

        // BasicConstraints may be absent (leaf cert) or present with ca=false.
        // Either is acceptable — what is NOT acceptable is ca=true.
        if let Ok(Some(bc)) = parsed.basic_constraints() {
            prop_assert!(
                !bc.value.ca,
                "BasicConstraints cA must be false for a client cert; got ca=true"
            );
        }
        // Absence of BasicConstraints also means not a CA — no assertion needed.
    }
}

// ─── mint_rejects_invalid_validity ───────────────────────────────────────────

#[test]
fn mint_rejects_invalid_validity_zero() {
    let (key, cert) = make_signer_ca();
    let err = mint_per_agent_client_cert("agent-test", None, &key, &cert, 0)
        .expect_err("validity_hours=0 must fail");
    assert!(
        matches!(err, X509Error::InvalidValidity(0)),
        "expected InvalidValidity(0), got {err:?}"
    );
}

#[test]
fn mint_rejects_invalid_validity_over_limit() {
    let (key, cert) = make_signer_ca();
    let err = mint_per_agent_client_cert("agent-test", None, &key, &cert, 169)
        .expect_err("validity_hours=169 must fail");
    assert!(
        matches!(err, X509Error::InvalidValidity(169)),
        "expected InvalidValidity(169), got {err:?}"
    );
}

// ─── prop_client_cert_san_has_spiffe_persona_container ───────────────────────
//
// META-AP-CORE-CRYPTO-SAN-SPIFFE-SHAPE: when container_id is Some, the cert
// MUST carry both SPIFFE URI SANs in addition to the URN compat URI.

proptest! {
    /// When container_id is Some, SAN must include spiffe persona + container URIs.
    #[test]
    fn prop_client_cert_san_has_spiffe_persona_container(
        agent_id in "[a-z][a-z0-9-]{1,15}",
        container_id in "[a-z][a-z0-9-]{1,15}",
        validity_hours in 1u32..=168,
    ) {
        let (key, cert) = make_signer_ca();
        let (cert_pem, _key_pem) = mint_per_agent_client_cert(
            &agent_id,
            Some(&container_id),
            &key,
            &cert,
            validity_hours,
        )
        .expect("mint must succeed");

        let der = pem_to_der(cert_pem.as_str());
        let (_, parsed) = X509Certificate::from_der(&der).expect("DER parse must succeed");

        let san_ext = parsed
            .subject_alternative_name()
            .expect("SAN extension must parse cleanly")
            .expect("SAN extension must be present");

        let expected_persona = format!("spiffe://emberd/persona/{agent_id}");
        let expected_container = format!("spiffe://emberd/container/{container_id}");
        let expected_urn = format!("urn:emberlink:agent:{agent_id}");

        let mut found_persona = false;
        let mut found_container = false;
        let mut found_urn = false;
        for gn in san_ext.value.general_names.iter() {
            if let GeneralName::URI(uri) = gn {
                if *uri == expected_persona.as_str() { found_persona = true; }
                if *uri == expected_container.as_str() { found_container = true; }
                if *uri == expected_urn.as_str() { found_urn = true; }
            }
        }

        prop_assert!(
            found_persona,
            "SAN must contain {expected_persona:?}; got {:?}",
            san_ext.value.general_names
        );
        prop_assert!(
            found_container,
            "SAN must contain {expected_container:?}; got {:?}",
            san_ext.value.general_names
        );
        prop_assert!(
            found_urn,
            "SAN must retain URN compat {expected_urn:?}; got {:?}",
            san_ext.value.general_names
        );
    }
}

proptest! {
    /// When container_id is None, SAN must carry URN only — no SPIFFE URIs leak.
    #[test]
    fn prop_client_cert_san_none_container_id_emits_urn_only(
        agent_id in "[a-z][a-z0-9-]{1,15}",
        validity_hours in 1u32..=168,
    ) {
        let (key, cert) = make_signer_ca();
        let (cert_pem, _key_pem) =
            mint_per_agent_client_cert(&agent_id, None, &key, &cert, validity_hours)
                .expect("mint must succeed");

        let der = pem_to_der(cert_pem.as_str());
        let (_, parsed) = X509Certificate::from_der(&der).expect("DER parse must succeed");
        let san_ext = parsed
            .subject_alternative_name()
            .expect("SAN extension must parse cleanly")
            .expect("SAN extension must be present");

        let mut spiffe_count = 0;
        for gn in san_ext.value.general_names.iter() {
            if let GeneralName::URI(uri) = gn {
                if uri.starts_with("spiffe://") {
                    spiffe_count += 1;
                }
            }
        }

        prop_assert_eq!(
            spiffe_count,
            0,
            "SPIFFE URIs must NOT leak when container_id is None; SAN names = {:?}",
            san_ext.value.general_names
        );
    }
}
