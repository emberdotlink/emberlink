//! CLASSIFICATION: PUBLIC
//!
//! Edge CA primitives for emberd-internal mTLS — ADR 100 Amendment 1 v3.
//!
//! Provides Ed25519 CA generation, X.509 client cert minting from CSRs, CA
//! fingerprint computation, and SPIFFE URI parsing.  No filesystem I/O, no
//! `SystemTime::now()` — WASM-safe.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    PKCS_ED25519, SanType, SerialNumber,
};
use regex::Regex;
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use thiserror::Error;
use time::OffsetDateTime;
use x509_parser::prelude::FromDer;

/// Errors produced by CA operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CaError {
    #[error("persona label out of grammar: {0:?}")]
    OutOfGrammarPersona(String),
    #[error("hostname label out of grammar: {0:?}")]
    OutOfGrammarHostname(String),
    #[error("CSR signature could not be verified against the supplied public key")]
    InvalidCsrSignature,
    #[error("SPIFFE URI failed strict parse")]
    SpiffeUriParseFailed,
    #[error("cert encode failed: {0}")]
    CertEncodeFailed(String),
    /// No bridge-identity SAN URI (SPIFFE or `urn:emberlink:agent:`) was found
    /// on the certificate. Used by [`extract_bridge_identity`] when the cert
    /// SAN extension is missing or carries no URI in either accepted grammar.
    #[error("no bridge identity SAN URI on certificate")]
    NoBridgeIdentity,
    /// The certificate's SAN extension itself failed to parse — distinct from
    /// "no matching URI present" so callers can distinguish a malformed cert
    /// (operator error) from a valid cert with the wrong identity shape.
    #[error("SAN extension parse failed: {0}")]
    SanParseFailed(String),
}

/// A generated edge CA with its signing material.
pub struct EdgeCa {
    pub signing_key: SigningKey,
    /// DER-encoded CA certificate.
    pub cert_der: Vec<u8>,
    /// SHA-256 of `cert_der`.
    pub fingerprint: [u8; 32],
}

/// Parameters for signing a client certificate.
pub struct ClientCertSpec {
    /// Persona label — must match `^[a-z][a-z0-9-]{0,62}$`.
    pub persona: String,
    /// Peer hostname label — must match `^[a-z][a-z0-9-]{0,62}$`.
    pub peer_hostname: String,
    /// Certificate validity window in seconds from Unix epoch.
    pub ttl_seconds: u64,
}

/// A signed client certificate.
#[derive(Debug)]
pub struct SignedClientCert {
    /// DER-encoded certificate.
    pub cert_der: Vec<u8>,
    /// `spiffe://emberd/persona/<persona>/peer/<peer-hostname>`
    pub spiffe_uri: String,
    /// Serial number embedded in the certificate.
    pub serial: u64,
}

/// A parsed and signature-verified CSR.
#[derive(Debug)]
pub struct Csr {
    /// The CSR's public key.
    pub public_key: VerifyingKey,
    /// The SPIFFE URI requested in the CSR's Subject Alternative Name.
    pub spiffe_uri_requested: String,
}

/// A parsed SPIFFE identity.
#[derive(Debug)]
pub struct SpiffeIdentity {
    pub persona: String,
    pub peer_hostname: String,
}

/// Typed SPIFFE URI shape parsed by [`parse_spiffe_uri_container`].
///
/// ADR 154 §Component 2 specifies two co-SAN URI shapes on the bridge-client +
/// SCION-agent certs:
///
/// - `spiffe://emberd/persona/<persona>/peer/<peer-hostname>` — the persona
///   shape preserved verbatim from the original KMS-edge precedent. Parsed
///   into [`SpiffeUri::Persona`] wrapping a [`SpiffeIdentity`] so existing
///   callers can pattern-match and recover the same `{persona, peer_hostname}`
///   pair they got from [`parse_spiffe_uri`].
/// - `spiffe://emberd/container/<container-ref>` — the container shape this
///   variant adds. `<container-ref>` is an opaque per-runtime identifier
///   (Docker hash, OrbStack VM uuid, k3s pod uid, etc. per the
///   `20260516-222000-container-identity` grill matrix) and is preserved
///   verbatim into [`SpiffeUri::Container::container_ref`].
///
/// Anchor: `parse_spiffe_uri_container` — META-AP-CORE-CRYPTO-SAN-CONTAINER-URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpiffeUri {
    /// `spiffe://emberd/persona/<persona>/peer/<peer-hostname>` shape.
    Persona {
        persona: String,
        peer_hostname: String,
    },
    /// `spiffe://emberd/container/<container-ref>` shape (ADR 154 §Component 2).
    Container { container_ref: String },
}

// ─── Grammar helpers ────────────────────────────────────────────────────────

static LABEL_RE: OnceLock<Regex> = OnceLock::new();

fn label_regex() -> &'static Regex {
    LABEL_RE.get_or_init(|| Regex::new(r"^[a-z][a-z0-9-]{0,62}$").expect("label regex is valid"))
}

fn validate_persona(persona: &str) -> Result<(), CaError> {
    if label_regex().is_match(persona) {
        Ok(())
    } else {
        Err(CaError::OutOfGrammarPersona(persona.to_owned()))
    }
}

fn validate_hostname(hostname: &str) -> Result<(), CaError> {
    if label_regex().is_match(hostname) {
        Ok(())
    } else {
        Err(CaError::OutOfGrammarHostname(hostname.to_owned()))
    }
}

// ─── PKCS8 encoding ─────────────────────────────────────────────────────────

/// Encode a 32-byte Ed25519 seed as a PKCS#8 v1 DER document.
///
/// Structure:
/// ```text
/// OneAsymmetricKey ::= SEQUENCE {          ; 30 2e
///   version      INTEGER 0,                ; 02 01 00
///   algorithm    SEQUENCE { OID 1.3.101.112 }, ; 30 05 06 03 2b 65 70
///   privateKey   OCTET STRING {            ; 04 22
///                  OCTET STRING { seed }   ; 04 20 <32 bytes>
///                }
/// }
/// ```
/// `ring`'s `Ed25519KeyPair::from_pkcs8_maybe_unchecked` accepts this v1 format,
/// which rcgen uses internally when creating a `KeyPair`.
fn seed_to_pkcs8_v1_der(seed: &[u8; 32]) -> Vec<u8> {
    // Inner bytes total = 3 + 7 + 36 = 46 = 0x2e
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&[0x30, 0x2e]); // SEQUENCE 46 bytes
    der.extend_from_slice(&[0x02, 0x01, 0x00]); // INTEGER 0
    der.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]); // OID 1.3.101.112
    der.extend_from_slice(&[0x04, 0x22, 0x04, 0x20]); // OCTET STRING wrappers
    der.extend_from_slice(seed);
    der
}

// ─── rcgen KeyPair from dalek SigningKey ─────────────────────────────────────

fn signing_key_to_rcgen_keypair(signing_key: &SigningKey) -> Result<KeyPair, CaError> {
    let seed: [u8; 32] = signing_key.to_bytes();
    let pkcs8 = seed_to_pkcs8_v1_der(&seed);
    KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8.as_slice()),
        &PKCS_ED25519,
    )
    .map_err(|e| CaError::CertEncodeFailed(e.to_string()))
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Generate a self-signed edge CA.
///
/// If `seed` is `Some(bytes)`, the CA signing key is derived deterministically
/// from those bytes (same seed → same `cert_der` and `fingerprint`).
/// If `None`, a random seed is drawn from OS entropy.
///
/// **WASM-safe**: no `SystemTime`, no filesystem I/O.
pub fn generate_edge_ca(seed: Option<[u8; 32]>) -> Result<EdgeCa, CaError> {
    let signing_key = match seed {
        Some(s) => SigningKey::from_bytes(&s),
        None => {
            let mut buf = [0u8; 32];
            getrandom::fill(&mut buf).map_err(|e| CaError::CertEncodeFailed(e.to_string()))?;
            SigningKey::from_bytes(&buf)
        }
    };

    let key_pair = signing_key_to_rcgen_keypair(&signing_key)?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| CaError::CertEncodeFailed(e.to_string()))?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(DnType::CommonName, "emberd edge CA");
        dn
    };
    // Use epoch-based fixed dates — no SystemTime call needed.
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    params.not_after = rcgen::date_time_ymd(9999, 12, 31);

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| CaError::CertEncodeFailed(e.to_string()))?;

    let cert_der: Vec<u8> = cert.der().to_vec();
    let fingerprint = ca_fingerprint(&cert_der);

    Ok(EdgeCa {
        signing_key,
        cert_der,
        fingerprint,
    })
}

/// Parse a PEM-encoded CSR and verify its signature against `expected_public`.
///
/// Returns a [`Csr`] containing the verified public key and the first SPIFFE
/// URI SAN found in the CSR.  Returns `Err(CaError::InvalidCsrSignature)` if
/// the CSR's self-signature does not verify with `expected_public`.
pub fn parse_csr_signed_by(csr_pem: &[u8], expected_public: &VerifyingKey) -> Result<Csr, CaError> {
    // Decode PEM → DER.
    let pem_str = std::str::from_utf8(csr_pem).map_err(|_| CaError::InvalidCsrSignature)?;
    let pem_block = pem::parse(pem_str).map_err(|_| CaError::InvalidCsrSignature)?;
    let der_bytes = pem_block.contents();

    // Parse the CSR with x509-parser (pure ASN.1, no ring).
    let (_, csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(der_bytes)
            .map_err(|_| CaError::InvalidCsrSignature)?;

    // Extract the raw Ed25519 public key (32 bytes) from SubjectPublicKeyInfo.
    let spki_key_bytes: &[u8] = csr
        .certification_request_info
        .subject_pki
        .subject_public_key
        .data
        .as_ref();

    if spki_key_bytes.len() != 32 {
        return Err(CaError::InvalidCsrSignature);
    }

    let csr_public: [u8; 32] = spki_key_bytes
        .try_into()
        .map_err(|_| CaError::InvalidCsrSignature)?;
    let csr_verifying_key =
        VerifyingKey::from_bytes(&csr_public).map_err(|_| CaError::InvalidCsrSignature)?;

    // Verify the CSR's public key matches the expected key.
    if csr_verifying_key.to_bytes() != expected_public.to_bytes() {
        return Err(CaError::InvalidCsrSignature);
    }

    // Verify the CSR's self-signature using ed25519-dalek directly.
    // signed_data = DER of CertificationRequestInfo (the .raw field).
    let signed_data = csr.certification_request_info.raw;
    let sig_bytes: &[u8] = csr.signature_value.data.as_ref();
    if sig_bytes.len() != 64 {
        return Err(CaError::InvalidCsrSignature);
    }
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| CaError::InvalidCsrSignature)?;
    let dalek_sig = Signature::from_bytes(&sig_array);
    expected_public
        .verify_strict(signed_data, &dalek_sig)
        .map_err(|_| CaError::InvalidCsrSignature)?;

    // Extract the first SPIFFE URI SAN from the CSR (may be empty if none).
    let spiffe_uri = extract_spiffe_uri_from_csr(&csr)?;

    Ok(Csr {
        public_key: csr_verifying_key,
        spiffe_uri_requested: spiffe_uri,
    })
}

fn extract_spiffe_uri_from_csr(
    csr: &x509_parser::certification_request::X509CertificationRequest<'_>,
) -> Result<String, CaError> {
    if let Some(extensions) = csr.requested_extensions() {
        for ext in extensions {
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = ext {
                for gn in &san.general_names {
                    if let x509_parser::extensions::GeneralName::URI(uri) = gn
                        && uri.starts_with("spiffe://")
                    {
                        return Ok(uri.to_string());
                    }
                }
            }
        }
    }
    Ok(String::new())
}

/// Sign a client certificate from a verified CSR using the edge CA.
///
/// The certificate will have:
/// - Subject CN = `spec.persona`
/// - SAN URI = `spiffe://emberd/persona/<persona>/peer/<peer-hostname>`
/// - Validity: Unix epoch to `spec.ttl_seconds` seconds past epoch
/// - Serial: first 8 bytes of SHA-256(SPIFFE URI) as big-endian u64
///
/// **WASM-safe**: no `SystemTime`, no filesystem I/O.
pub fn sign_client_cert(
    ca: &EdgeCa,
    csr: &Csr,
    spec: &ClientCertSpec,
) -> Result<SignedClientCert, CaError> {
    validate_persona(&spec.persona)?;
    validate_hostname(&spec.peer_hostname)?;

    let spiffe_uri = format!(
        "spiffe://emberd/persona/{}/peer/{}",
        spec.persona, spec.peer_hostname
    );

    // Derive a deterministic serial from the SPIFFE URI hash.
    let hash = Sha256::digest(spiffe_uri.as_bytes());
    let serial = u64::from_be_bytes(hash[..8].try_into().expect("sha256 has >= 8 bytes"));

    // Build end-entity cert params.
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| CaError::CertEncodeFailed(e.to_string()))?;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(DnType::CommonName, spec.persona.clone());
        dn
    };

    // Build SPIFFE URI SAN via rcgen's Ia5String.
    let san_uri: rcgen::string::Ia5String = spiffe_uri
        .as_str()
        .try_into()
        .map_err(|e: rcgen::Error| CaError::CertEncodeFailed(e.to_string()))?;
    params.subject_alt_names = vec![SanType::URI(san_uri)];
    params.serial_number = Some(SerialNumber::from(serial));

    // not_before = Unix epoch; not_after = epoch + ttl_seconds (pure math, no OS call).
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    params.not_after = OffsetDateTime::from_unix_timestamp(spec.ttl_seconds as i64)
        .map_err(|e| CaError::CertEncodeFailed(e.to_string()))?;

    // Build the CA issuer from the CA cert DER + CA signing key.
    let ca_key_pair = signing_key_to_rcgen_keypair(&ca.signing_key)?;
    let ca_cert_der_typed = CertificateDer::from(ca.cert_der.as_slice());
    let ca_issuer = Issuer::from_ca_cert_der(&ca_cert_der_typed, ca_key_pair)
        .map_err(|e| CaError::CertEncodeFailed(e.to_string()))?;

    // Sign the leaf cert using the CSR's public key as subject SPKI.
    // `signed_by(&subject_key_data, &issuer)` uses:
    //   - `subject_key_data` for the SubjectPublicKeyInfo (public key only)
    //   - `issuer.signing_key` for the actual cert signature
    let subject_key = Ed25519SubjectKey {
        bytes: csr.public_key.to_bytes(),
    };

    let cert = params
        .signed_by(&subject_key, &ca_issuer)
        .map_err(|e| CaError::CertEncodeFailed(e.to_string()))?;

    Ok(SignedClientCert {
        cert_der: cert.der().to_vec(),
        spiffe_uri,
        serial,
    })
}

/// A minimal wrapper implementing rcgen's `SigningKey` (and `PublicKeyData`) for
/// an Ed25519 subject public key sourced from a verified CSR.
///
/// Only the `PublicKeyData` surface is exercised when the CA signs a leaf cert —
/// the CA's own `KeyPair` (held by `Issuer`) produces the actual signature.
/// The `sign` method here is unreachable during cert issuance but is required
/// by the `SigningKey` trait bound on `CertificateParams::signed_by`.
struct Ed25519SubjectKey {
    bytes: [u8; 32],
}

impl rcgen::PublicKeyData for Ed25519SubjectKey {
    fn der_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &PKCS_ED25519
    }
}

impl rcgen::SigningKey for Ed25519SubjectKey {
    fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        // Unreachable: the CA's Issuer signing key signs the cert; this
        // wrapper only provides the subject public key to the cert encoder.
        unreachable!("Ed25519SubjectKey::sign must not be called — CA Issuer key signs the cert")
    }
}

/// Generate a PEM-encoded CSR for the given signing key.
///
/// The CSR includes a Subject Alternative Name URI extension with `spiffe_uri`.
/// The CSR is self-signed by `signing_key`, as required by PKCS#10.
///
/// Used by the CLI peer-enroll flow and by tests to set up round-trip scenarios.
pub fn generate_csr_pem(signing_key: &SigningKey, spiffe_uri: &str) -> Result<Vec<u8>, CaError> {
    let key_pair = signing_key_to_rcgen_keypair(signing_key)?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| CaError::CertEncodeFailed(e.to_string()))?;
    params.subject_alt_names =
        vec![SanType::URI(spiffe_uri.try_into().map_err(
            |e: rcgen::Error| CaError::CertEncodeFailed(e.to_string()),
        )?)];

    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| CaError::CertEncodeFailed(e.to_string()))?;
    let pem_str = csr
        .pem()
        .map_err(|e| CaError::CertEncodeFailed(e.to_string()))?;

    Ok(pem_str.into_bytes())
}

/// Compute SHA-256 of a DER-encoded certificate.
pub fn ca_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    Sha256::digest(cert_der).into()
}

/// Parse a strict SPIFFE URI of the form:
/// `spiffe://emberd/persona/<persona>/peer/<peer-hostname>`
///
/// Rejects:
/// - Uppercase letters anywhere in the URI
/// - URL-encoded characters (`%xx`)
/// - Double-slash collapse or extra path segments
/// - Missing persona or peer-hostname fields
pub fn parse_spiffe_uri(uri: &str) -> Result<SpiffeIdentity, CaError> {
    static SPIFFE_RE: OnceLock<Regex> = OnceLock::new();
    let re = SPIFFE_RE.get_or_init(|| {
        Regex::new(r"^spiffe://emberd/persona/([a-z][a-z0-9-]{0,62})/peer/([a-z][a-z0-9-]{0,62})$")
            .expect("SPIFFE URI regex is valid")
    });

    // Reject any URL-encoded characters before regex match.
    if uri.contains('%') {
        return Err(CaError::SpiffeUriParseFailed);
    }

    let caps = re.captures(uri).ok_or(CaError::SpiffeUriParseFailed)?;
    let persona = caps[1].to_owned();
    let peer_hostname = caps[2].to_owned();

    Ok(SpiffeIdentity {
        persona,
        peer_hostname,
    })
}

/// Parse a SPIFFE URI under the `spiffe://emberd/` trust domain and return its
/// typed shape. Accepts both the persona and container URI shapes specified by
/// ADR 154 §Component 2:
///
/// - `spiffe://emberd/persona/<persona>/peer/<peer-hostname>` —
///   [`SpiffeUri::Persona`] (delegates to [`parse_spiffe_uri`] verbatim so the
///   existing strict grammar is preserved bit-for-bit).
/// - `spiffe://emberd/container/<container-ref>` —
///   [`SpiffeUri::Container`]. `<container-ref>` is an opaque per-runtime
///   identifier (Docker hash, OrbStack VM uuid, k3s pod uid, etc.). The
///   grammar is intentionally permissive — lowercase alphanumerics plus
///   `[:_-]`, 1–128 chars, no slashes, no `%` escapes — because the source of
///   truth for the value is the runtime control plane, not this parser.
///
/// Rejects everything else with [`CaError::SpiffeUriParseFailed`], including
/// URIs that match the SPIFFE prefix but use a path other than `/persona/...`
/// or `/container/...`. Leaves room for future shapes (e.g. `/spawn/...` per
/// ADR 166's spawn-uuid rename) — adding a variant here is purely additive.
///
/// Anchor: `parse_spiffe_uri_container` — META-AP-CORE-CRYPTO-SAN-CONTAINER-URI.
pub fn parse_spiffe_uri_container(uri: &str) -> Result<SpiffeUri, CaError> {
    // Reject URL-encoding up front, matching parse_spiffe_uri's invariant.
    if uri.contains('%') {
        return Err(CaError::SpiffeUriParseFailed);
    }

    // Persona shape — delegate to the existing strict parser so its grammar
    // (and every existing parse + reject case) is preserved verbatim.
    if let Ok(persona_id) = parse_spiffe_uri(uri) {
        return Ok(SpiffeUri::Persona {
            persona: persona_id.persona,
            peer_hostname: persona_id.peer_hostname,
        });
    }

    // Container shape — `spiffe://emberd/container/<container-ref>`.
    // Container-ref grammar is intentionally permissive: lowercase letters,
    // digits, and `:_-`, 1–128 chars total. This admits Docker hashes
    // (64 hex), UUIDs (with dashes), and the `orbstack:5f3a-…` style without
    // pinning to a single runtime's id format. Slashes and `%` are excluded
    // (the latter caught above) so the URI cannot smuggle extra path
    // segments or percent-encoded surprises past this gate.
    static CONTAINER_RE: OnceLock<Regex> = OnceLock::new();
    let re = CONTAINER_RE.get_or_init(|| {
        Regex::new(r"^spiffe://emberd/container/([a-z0-9][a-z0-9:_-]{0,127})$")
            .expect("SPIFFE container URI regex is valid")
    });

    let caps = re.captures(uri).ok_or(CaError::SpiffeUriParseFailed)?;
    let container_ref = caps[1].to_owned();

    Ok(SpiffeUri::Container { container_ref })
}

// ─── Consolidated bridge-identity SAN parser ────────────────────────────────
//
// san_parser_consolidated_core_crypto_ca — META-AP-CORE-CRYPTO-SAN-PARSER-CONSOLIDATE
//
// Single entry point for extracting an agent/persona identity from a parsed
// X.509 client cert's Subject Alternative Name extension. Replaces the
// per-caller hand-rolled SAN walks previously living in the retired
// `ember-proxy` crate's `mtls::extract_agent_id_from_cert` (ADR 154
// component 2).
//
// Accepts two SAN URI grammars:
//   1. `spiffe://emberd/persona/<persona>/peer/<peer-hostname>`
//      → `persona_id = <persona>`, `container_id = Some(<peer-hostname>)`
//   2. `urn:emberlink:agent:<agent_id>`
//      → `persona_id = <agent_id>`, `container_id = None`
//
// Both grammars enforce `^[a-z][a-z0-9-]{0,62}$` on captured labels, so
// callers can trust that `BridgeIdentity.persona_id` is grammar-conformant
// without re-validating.
//
// TODO: KMS-edge parser
// should switch to extract_bridge_identity once located.

/// The identity extracted from a bridge client certificate's SAN extension.
///
/// `persona_id` is always grammar-conformant (`^[a-z][a-z0-9-]{0,62}$`).
/// `container_id` is `Some` only when the cert carries a SPIFFE URI whose
/// `peer/<peer-hostname>` segment names a specific worker container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeIdentity {
    pub persona_id: String,
    pub container_id: Option<String>,
}

/// Extract a [`BridgeIdentity`] from the SAN extension of a parsed X.509 cert.
///
/// Walks the cert's Subject Alternative Name URI entries and returns the first
/// URI that matches a supported grammar (SPIFFE or `urn:emberlink:agent:`).
///
/// # Errors
///
/// - [`CaError::SanParseFailed`] — the SAN extension itself is malformed.
/// - [`CaError::NoBridgeIdentity`] — the cert has no SAN extension, or the
///   SAN extension carries no URI entry matching either accepted grammar.
pub fn extract_bridge_identity(
    cert: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<BridgeIdentity, CaError> {
    let san_ext = cert
        .subject_alternative_name()
        .map_err(|e| CaError::SanParseFailed(e.to_string()))?
        .ok_or(CaError::NoBridgeIdentity)?;

    for gn in &san_ext.value.general_names {
        if let x509_parser::extensions::GeneralName::URI(uri) = gn {
            // Try SPIFFE grammar first.
            if uri.starts_with("spiffe://")
                && let Ok(spiffe) = parse_spiffe_uri(uri)
            {
                return Ok(BridgeIdentity {
                    persona_id: spiffe.persona,
                    container_id: Some(spiffe.peer_hostname),
                });
            }
            // Then the URN grammar.
            if let Some(agent_id) = parse_emberlink_agent_urn(uri) {
                return Ok(BridgeIdentity {
                    persona_id: agent_id,
                    container_id: None,
                });
            }
        }
    }

    Err(CaError::NoBridgeIdentity)
}

/// Parse `urn:emberlink:agent:<agent_id>` and return the agent ID portion.
///
/// Returns `None` if the URI does not match the grammar. Mirrors the regex
/// previously defined inline in the retired `ember-proxy` crate's `mtls`
/// module so the two SAN parsers share a single grammar source of truth.
fn parse_emberlink_agent_urn(uri: &str) -> Option<String> {
    static URN_RE: OnceLock<Regex> = OnceLock::new();
    let re = URN_RE.get_or_init(|| {
        Regex::new(r"^urn:emberlink:agent:([a-z][a-z0-9-]{0,62})$")
            .expect("agent URN regex is valid")
    });
    re.captures(uri)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_owned())
}
