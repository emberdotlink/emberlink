//! CLASSIFICATION: PUBLIC
//!
//! Per-agent X.509 CA with RFC 5280 §4.2.1.10 nameConstraints.
//!
//! Mints a self-signed CA scoped to a set of permitted DNS names so a
//! compromised proxy cannot issue valid certs for arbitrary hosts. The
//! pathlen constraint (0) prevents the per-agent CA from issuing further
//! CAs — it can only issue leaf certs.
//!
//! **WASM-safe**: no SystemTime, no filesystem I/O.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa,
    Issuer, KeyPair, NameConstraints, PKCS_ED25519, SanType,
};
use thiserror::Error;
use zeroize::Zeroizing;

/// Errors produced by per-agent CA minting.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum X509Error {
    #[error("validity_hours out of range (must be 1..=168, got {0})")]
    InvalidValidity(u32),
    #[error("permitted_dns_names must not be empty")]
    EmptyPermittedNames,
    #[error("cert generation failed: {0}")]
    CertGen(String),
    #[error("key generation failed: {0}")]
    KeyGen(String),
}

/// Mint a per-agent X.509 CA scoped via RFC 5280 §4.2.1.10 nameConstraints.
///
/// Returns `(ca_cert_pem, ca_key_pem)` — both `Zeroizing<String>` so key
/// material is wiped on drop.
///
/// # Parameters
///
/// - `agent_id` — embedded in the CA Subject CN for audit correlation.
/// - `permitted_dns_names` — the exhaustive set of DNS names this CA may
///   sign for (e.g. `["api.anthropic.com", "*.anthropic.com"]`). Must be
///   non-empty. The wildcard form `*.example.com` is recorded as-is; X.509
///   NameConstraints uses the label-prefix interpretation (RFC 5280 §4.2.1.10
///   final paragraph — a constraint of `.example.com` matches all subdomains,
///   but most implementations also accept `*.example.com` literally).
/// - `validity_hours` — how long the CA cert is valid; clamped to 1–168
///   hours (1 week). Expressed as offset from the Unix epoch (1970-01-01)
///   for WASM safety — no SystemTime call.
///
/// # Errors
///
/// - [`X509Error::InvalidValidity`] — `validity_hours` is 0 or > 168.
/// - [`X509Error::EmptyPermittedNames`] — `permitted_dns_names` is empty.
/// - [`X509Error::KeyGen`] — Ed25519 key generation failed.
/// - [`X509Error::CertGen`] — certificate encoding or signing failed.
pub fn mint_per_agent_ca_with_name_constraints(
    agent_id: &str,
    permitted_dns_names: &[&str],
    validity_hours: u32,
) -> Result<(Zeroizing<String>, Zeroizing<String>), X509Error> {
    if validity_hours == 0 || validity_hours > 168 {
        return Err(X509Error::InvalidValidity(validity_hours));
    }
    if permitted_dns_names.is_empty() {
        return Err(X509Error::EmptyPermittedNames);
    }

    let key_pair =
        KeyPair::generate_for(&PKCS_ED25519).map_err(|e| X509Error::KeyGen(e.to_string()))?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| X509Error::CertGen(e.to_string()))?;

    // CA with pathlen 0 — cannot issue further CAs.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));

    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];

    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(DnType::CommonName, format!("ember-agent-ca:{agent_id}"));
        dn
    };

    // nameConstraints: permitted subtrees only, no excluded subtrees.
    let permitted_subtrees: Vec<GeneralSubtree> = permitted_dns_names
        .iter()
        .map(|name| GeneralSubtree::DnsName(name.to_string()))
        .collect();
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees,
        excluded_subtrees: vec![],
    });

    // Validity window anchored at Unix epoch to avoid SystemTime.
    // not_before = 1970-01-01; not_after = epoch + validity_hours.
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    let not_after_secs = i64::from(validity_hours) * 3600;
    params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after_secs)
        .map_err(|e| X509Error::CertGen(e.to_string()))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| X509Error::CertGen(e.to_string()))?;

    let cert_pem = Zeroizing::new(cert.pem());
    let key_pem = Zeroizing::new(key_pair.serialize_pem());

    Ok((cert_pem, key_pem))
}

/// Mint per-agent mTLS client cert signed by daemon's client-auth signer key
/// (held in emberd mlock'd buffer; never on disk).
///
/// SAN URIs emitted, per ADR 154 component 2 / META-AP-CORE-CRYPTO-SAN-SPIFFE-SHAPE:
/// - Always: `urn:emberlink:agent:<agent_id>` (URN compat, retained one release for downstream consumers).
/// - When `container_id` is `Some`: also `spiffe://emberd/persona/<agent_id>` and `spiffe://emberd/container/<container_id>` (SPIFFE shape, per KMS-edge precedent in `core_crypto::ca::parse_spiffe_uri`).
///
/// Subject CN: `ember-persona-<agent_id>` (renamed from `ember-agent-<id>` per
/// ADR 154 — drops the `persona-` value prefix the v1 proposal had).
///
/// Anchor: `san_shape_spiffe_persona_container`.
///
/// # Parameters
///
/// - `agent_id` — embedded in CN and SAN URIs for audit correlation. In the
///   SPIFFE shape this is the persona-id.
/// - `container_id` — `Some(id)` triggers the SPIFFE SAN URIs; `None` keeps
///   the cert URN-only for callers that don't yet have container context.
/// - `signer_key` — the client-auth CA signing key (caller holds in mlock'd memory).
/// - `signer_cert` — the client-auth CA certificate.
/// - `validity_hours` — how long the cert is valid; clamped to 1–168 hours.
///
/// # Returns
///
/// `(cert_pem, key_pem)` — both `Zeroizing<String>` so key material is wiped on drop.
///
/// # Errors
///
/// - [`X509Error::InvalidValidity`] — `validity_hours` is 0 or > 168.
/// - [`X509Error::KeyGen`] — Ed25519 key generation failed.
/// - [`X509Error::CertGen`] — certificate encoding or signing failed.
pub fn mint_per_agent_client_cert(
    agent_id: &str,
    container_id: Option<&str>,
    signer_key: &KeyPair,
    signer_cert: &rcgen::Certificate,
    validity_hours: u32,
) -> Result<(Zeroizing<String>, Zeroizing<String>), X509Error> {
    if validity_hours == 0 || validity_hours > 168 {
        return Err(X509Error::InvalidValidity(validity_hours));
    }

    let key_pair =
        KeyPair::generate_for(&PKCS_ED25519).map_err(|e| X509Error::KeyGen(e.to_string()))?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| X509Error::CertGen(e.to_string()))?;

    // Client leaf cert — not a CA.
    params.is_ca = IsCa::NoCa;

    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(DnType::CommonName, format!("ember-persona-{agent_id}"));
        dn
    };

    // SAN URIs: san_shape_spiffe_persona_container.
    //
    // URN is always emitted for downstream compat (one-release transition).
    // SPIFFE persona + container URIs are emitted when container_id is
    // available; callers without container context pass None and get URN
    // only, which matches the pre-ADR-154 behaviour.
    let mut san_uris: Vec<SanType> = Vec::with_capacity(3);

    let urn_str = format!("urn:emberlink:agent:{agent_id}");
    let urn_ia5: rcgen::string::Ia5String = urn_str
        .as_str()
        .try_into()
        .map_err(|e: rcgen::Error| X509Error::CertGen(e.to_string()))?;
    san_uris.push(SanType::URI(urn_ia5));

    if let Some(container) = container_id {
        let persona_uri = format!("spiffe://emberd/persona/{agent_id}");
        let persona_ia5: rcgen::string::Ia5String = persona_uri
            .as_str()
            .try_into()
            .map_err(|e: rcgen::Error| X509Error::CertGen(e.to_string()))?;
        san_uris.push(SanType::URI(persona_ia5));

        let container_uri = format!("spiffe://emberd/container/{container}");
        let container_ia5: rcgen::string::Ia5String = container_uri
            .as_str()
            .try_into()
            .map_err(|e: rcgen::Error| X509Error::CertGen(e.to_string()))?;
        san_uris.push(SanType::URI(container_ia5));
    }

    params.subject_alt_names = san_uris;

    // Validity window anchored at Unix epoch to avoid SystemTime.
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    let not_after_secs = i64::from(validity_hours) * 3600;
    params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after_secs)
        .map_err(|e| X509Error::CertGen(e.to_string()))?;

    let issuer = Issuer::from_ca_cert_pem(signer_cert.pem().as_str(), signer_key)
        .map_err(|e| X509Error::CertGen(e.to_string()))?;

    let cert = params
        .signed_by(&key_pair, &issuer)
        .map_err(|e| X509Error::CertGen(e.to_string()))?;

    let cert_pem = Zeroizing::new(cert.pem());
    let key_pem = Zeroizing::new(key_pair.serialize_pem());

    Ok((cert_pem, key_pem))
}
