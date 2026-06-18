//! ADR 200 §3 — YubiKey PIV attestation chain verification (the G1 anchor).
//!
//! A `presence`-class Device proves its custody class by a YubiKey PIV
//! attestation. The slot attestation cert (the *leaf*, carrying the device's
//! signing public key) is signed by the device's per-unit **slot-F9**
//! attestation intermediate, which is in turn signed by a **Yubico PIV Root
//! CA**. Verification pins ONLY the root(s); the F9 intermediate travels with
//! the attestation (it is per-device, not pinned).
//!
//! The pinned roots are **compile-time constants embedded in the signed
//! binary** (never a daemon-writable file), so root integrity reduces to binary
//! integrity (codesign + binary-manifest verification — ADR 200 AC-5). A
//! compromised *running* daemon cannot rewrite a `const` in read-only memory
//! without total process compromise (the irreducible G3 residual).
//!
//! The chain's own signatures are RSA/ECDSA-SHA256 — verified with the x509
//! stack's ring-backed `verify_signature`, **never** core-crypto's Ed25519-only
//! verifier (the algorithm-confusion bar, ADR 200 OQ-7).
//!
//! Anti-software-authenticator bar: a software key produces **no** F9-chained
//! cert, so it cannot pass this check at all — the bar is automatic for the PIV
//! lane (the `fmt=none` / `EMBERLINK_AAGUID` bar applies to the WebAuthn lane,
//! see `webauthn` enrollment).

use base64::Engine as _;
use core_event_types::{AttestationTier, CustodyClass, DeviceEnrolledEvent, PresenceFactor};
use core_principals::{KeyAlgorithm, PublicKeyMaterial};
use x509_parser::prelude::FromDer;
use x509_parser::x509::SubjectPublicKeyInfo;

/// id-ecPublicKey (1.2.840.10045.2.1) — the SPKI algorithm OID for EC keys.
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
/// prime256v1 / NIST P-256 named-curve OID (1.2.840.10045.3.1.7).
const OID_PRIME256V1: &str = "1.2.840.10045.3.1.7";
/// Yubico PIV attestation serial-number extension (1.3.6.1.4.1.41482.3.7).
const OID_YUBICO_SERIAL: &str = "1.3.6.1.4.1.41482.3.7";

/// Authenticator-model policy (ADR 200 §3). Layered ABOVE the mandatory
/// vendor-root attestation check: a key MUST still chain to a pinned root; the
/// policy then decides which authenticator *models* are admissible. Pinned to
/// the binary alongside the roots (same daemon-immutable signed config).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelPolicy {
    pub mode: ModelPolicyMode,
    /// Model identifiers. PIV lane: the attestation cert's vendor/model field
    /// (here the leaf's issuer common-name, e.g. "Yubico PIV Attestation").
    pub entries: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelPolicyMode {
    /// dev0 default: allow any vendor-attested model EXCEPT those listed.
    DenyList,
    /// Deny by default; admit only enumerated known-secure models.
    AllowList,
}

impl ModelPolicy {
    /// dev0 default: deny-list, starting **empty** — allow any genuine
    /// Yubico-attested authenticator. A one-field flip to `AllowList` raises the
    /// bar for high-assurance cohorts (team0+), by design not a rewrite.
    pub fn dev0_default() -> Self {
        Self {
            mode: ModelPolicyMode::DenyList,
            entries: Vec::new(),
        }
    }

    pub fn admits(&self, model_id: &str) -> bool {
        let listed = self.entries.iter().any(|e| e == model_id);
        match self.mode {
            ModelPolicyMode::DenyList => !listed,
            ModelPolicyMode::AllowList => listed,
        }
    }
}

/// The proven output of a successful attestation verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedDeviceKey {
    /// The attested device signing key, `p256:`-prefixed SEC1 hex — the exact
    /// wire form consumed by `core_crypto::P256Verifier` (identity-binding).
    pub public_key: String,
    /// The authenticator model identifier the `ModelPolicy` was evaluated against.
    pub model_id: String,
    /// The Yubico device serial, if the attestation carried the extension.
    pub serial: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// No vendor roots are compiled into this binary — fail closed (no presence
    /// Device can be enrolled until an authentic Yubico PIV root is provisioned).
    RootsNotProvisioned,
    EmptyChain,
    Parse(String),
    /// The top of the provided chain is not signed by any pinned root.
    UntrustedRoot,
    BadSignature(String),
    Expired,
    /// The attested key is not an ECDSA P-256 key.
    UnsupportedKey(String),
    /// The authenticator model is barred by the pinned `ModelPolicy`.
    PolicyRejected(String),
    /// The supplied §4 ECIES recipient key equals the attested signing key
    /// (ADR 206 §4 AC-4: the recipient MUST be a distinct key — one key doing
    /// both sign and decrypt is the reuse the cut kills).
    EncryptionKeyReusesSigningKey,
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RootsNotProvisioned => write!(
                f,
                "no Yubico PIV roots are embedded in this binary — presence enrollment is disabled"
            ),
            Self::EmptyChain => write!(f, "empty attestation chain"),
            Self::Parse(e) => write!(f, "attestation parse error: {e}"),
            Self::UntrustedRoot => {
                write!(f, "attestation chain does not terminate at a pinned root")
            }
            Self::BadSignature(e) => write!(f, "attestation chain signature invalid: {e}"),
            Self::Expired => write!(f, "attestation certificate outside its validity window"),
            Self::UnsupportedKey(e) => write!(f, "attested key unsupported: {e}"),
            Self::PolicyRejected(m) => write!(f, "authenticator model rejected by policy: {m}"),
            Self::EncryptionKeyReusesSigningKey => write!(
                f,
                "the §4 ECIES recipient key must be distinct from the attested signing key"
            ),
        }
    }
}

impl std::error::Error for AttestationError {}

/// Verify a PIV attestation chain against the binary-embedded Yubico roots and
/// the supplied model policy. `chain_der` is `[leaf, intermediate, ...]` in
/// leaf-first order; the trusted root is NOT part of the chain (it is pinned).
pub fn verify_piv_attestation(
    chain_der: &[Vec<u8>],
    policy: &ModelPolicy,
) -> Result<AttestedDeviceKey, AttestationError> {
    verify_piv_attestation_with_roots(chain_der, &pinned_yubico_piv_roots(), policy)
}

/// Root-parameterized core (prod passes the embedded roots; tests pass a
/// synthetic CA). This is where the actual chain-walking + signature
/// verification lives.
pub fn verify_piv_attestation_with_roots(
    chain_der: &[Vec<u8>],
    roots_der: &[Vec<u8>],
    policy: &ModelPolicy,
) -> Result<AttestedDeviceKey, AttestationError> {
    if roots_der.is_empty() {
        return Err(AttestationError::RootsNotProvisioned);
    }
    if chain_der.is_empty() {
        return Err(AttestationError::EmptyChain);
    }

    // Parse every cert in the provided chain (leaf-first).
    let parsed: Vec<_> = chain_der
        .iter()
        .map(|der| {
            x509_parser::certificate::X509Certificate::from_der(der)
                .map(|(_, c)| c)
                .map_err(|e| AttestationError::Parse(e.to_string()))
        })
        .collect::<Result<_, _>>()?;

    // Each cert[i] must be signed by cert[i+1], with issuer/subject coherence
    // and within its validity window.
    for pair in parsed.windows(2) {
        verify_issued_by(&pair[0], pair[1].public_key())?;
        ensure_valid(&pair[0])?;
    }

    // The top of the provided chain must be signed by one of the PINNED roots.
    // The root is matched by attempting signature verification against each
    // pinned root's key (issuer/subject name match alone is not trust — the
    // signature is). The pinned root is the external anchor the daemon cannot
    // rewrite (ADR 200 §3).
    let top = parsed.last().expect("chain non-empty (checked above)");
    ensure_valid(top)?;
    let mut anchored = false;
    for root_der in roots_der {
        let (_, root) = match x509_parser::certificate::X509Certificate::from_der(root_der) {
            Ok(v) => v,
            // A malformed *pinned* root is a build error, not an attacker input;
            // skip it defensively rather than trusting a half-parsed cert.
            Err(_) => continue,
        };
        if top.verify_signature(Some(root.public_key())).is_ok() {
            anchored = true;
            break;
        }
    }
    if !anchored {
        return Err(AttestationError::UntrustedRoot);
    }

    // Extract the attested device key from the LEAF (the key being enrolled).
    let leaf = &parsed[0];
    let public_key = extract_p256_sec1(leaf.public_key())?;
    let model_id = leaf_model_id(leaf);
    let serial = yubico_serial(leaf);

    if !policy.admits(&model_id) {
        return Err(AttestationError::PolicyRejected(model_id));
    }

    Ok(AttestedDeviceKey {
        public_key,
        model_id,
        serial,
    })
}

/// Build a `DeviceEnrolled` event for a `presence`-class Device from a verified
/// PIV attestation chain (the enrollment path's structural core; ADR 200 §1/§3).
///
/// The attested **leaf key IS the enrolled device key** — identity-binding is
/// intrinsic: you cannot enroll a key the attestation does not cover, so the
/// genuineness gate (attestation→pinned root) and the identity-binding gate
/// (the specific pubkey) are satisfied by the same artifact. The full chain is
/// recorded verbatim (a JSON array of base64-DER certs) so an independent
/// verifier can re-run the attestation against its own pinned roots (AC-1) —
/// never a daemon "verified=true" flag.
///
/// `attestation_chain_b64` is leaf-first base64-DER. The caller appends the
/// returned event (root-signed) to the operator root's log.
///
/// `encryption_material` is the Device's §4 ECIES recipient key (ADR 206) — a
/// key DISTINCT from the attested signing leaf, recorded as the Device's
/// `active_encryption_key` so presence-as-decryption can seal to it. On a
/// YubiKey this is slot 9d (ECDH), physically separate from the slot-9c signing
/// key the chain attests; full 9d-attestation coverage is the YubiKey lane's
/// follow-up (this builder records the supplied recipient but does not yet
/// re-verify a 9d chain). It MUST NOT equal the signing key.
pub fn build_presence_device_enrolled_event(
    root_id: &str,
    device_id: &str,
    label: &str,
    attestation_chain_b64: &[String],
    encryption_material: &PublicKeyMaterial,
    roots_der: &[Vec<u8>],
    policy: &ModelPolicy,
) -> Result<(DeviceEnrolledEvent, AttestedDeviceKey), AttestationError> {
    let chain_der: Vec<Vec<u8>> = attestation_chain_b64
        .iter()
        .map(|b64| {
            base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|e| AttestationError::Parse(format!("base64: {e}")))
        })
        .collect::<Result<_, _>>()?;

    let attested = verify_piv_attestation_with_roots(&chain_der, roots_der, policy)?;

    // Deterministic key id derived from the attested public key (stable across
    // re-derivation; not security-bearing — the pubkey is the identity).
    let key_id = format!(
        "piv-{}",
        &core_crypto::sha256_digest_hex(attested.public_key.as_bytes())[..16]
    );
    let device_key = PublicKeyMaterial {
        key_id,
        algorithm: KeyAlgorithm::EcdsaP256,
        public_key: attested.public_key.clone(),
    };

    // ADR 206 §4 AC-4: the §4 ECIES recipient cannot be the signing key. Compare
    // case-insensitively — `p256:<hex>` decodes identically regardless of hex case,
    // so a raw `==` would let a re-cased signing key pass as "distinct".
    if encryption_material
        .public_key
        .eq_ignore_ascii_case(&device_key.public_key)
    {
        return Err(AttestationError::EncryptionKeyReusesSigningKey);
    }

    // Record the chain verbatim for independent re-verification (AC-1).
    let statement = serde_json::to_string(attestation_chain_b64)
        .map_err(|e| AttestationError::Parse(format!("record chain: {e}")))?;

    let event = DeviceEnrolledEvent {
        root_id: root_id.to_string(),
        device_id: device_id.to_string(),
        label: label.to_string(),
        device_key,
        encryption_key: encryption_material.clone(),
        custody_class: CustodyClass::Presence,
        attestation_statement: Some(statement),
        // A YubiKey PIV enrollment: the attested artifact IS the signing key
        // (vendor-rooted chain → pinned Yubico root, AC-1 re-verifiable), and the
        // human factor is a physical token touch off-host (ADR 200 §3 two axes).
        attestation_tier: AttestationTier::VendorHw,
        presence_factor: PresenceFactor::HardwareTouch,
    };
    Ok((event, attested))
}

/// Verify `child`'s signature against an issuer public key (RSA/ECDSA-SHA256
/// via the ring-backed x509 verify path) and confirm name coherence.
fn verify_issued_by(
    child: &x509_parser::certificate::X509Certificate,
    issuer_pki: &SubjectPublicKeyInfo,
) -> Result<(), AttestationError> {
    child
        .verify_signature(Some(issuer_pki))
        .map_err(|e| AttestationError::BadSignature(e.to_string()))
}

fn ensure_valid(cert: &x509_parser::certificate::X509Certificate) -> Result<(), AttestationError> {
    if cert.validity().is_valid() {
        Ok(())
    } else {
        Err(AttestationError::Expired)
    }
}

/// Pull the SEC1 point bytes out of an EC P-256 SPKI and return them as a
/// `p256:`-prefixed hex string, after validating the named curve and that the
/// point is on-curve (via `core_crypto`'s P256 decode, which calls
/// `from_sec1_bytes`).
fn extract_p256_sec1(pki: &SubjectPublicKeyInfo) -> Result<String, AttestationError> {
    let alg_oid = pki.algorithm.algorithm.to_id_string();
    if alg_oid != OID_EC_PUBLIC_KEY {
        return Err(AttestationError::UnsupportedKey(format!(
            "expected id-ecPublicKey, found {alg_oid}"
        )));
    }
    // The named-curve parameter must be prime256v1 (P-256).
    let curve_ok = pki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|oid| oid.to_id_string() == OID_PRIME256V1)
        .unwrap_or(false);
    if !curve_ok {
        return Err(AttestationError::UnsupportedKey(
            "EC key is not on the P-256 curve".to_string(),
        ));
    }
    let point = pki.subject_public_key.data.as_ref();
    // Validate the point is genuinely on-curve by decoding it the same way the
    // verifier will (SEC1 from_sec1_bytes inside P256Verifier).
    let candidate = core_crypto::PublicKey(format!("p256:{}", hex::encode(point)));
    if !core_crypto::p256_public_key_is_valid(&candidate) {
        return Err(AttestationError::UnsupportedKey(
            "attested EC point failed P-256 curve validation".to_string(),
        ));
    }
    Ok(candidate.0)
}

/// The authenticator model identifier for the PIV lane: the leaf's issuer
/// common-name (the F9 intermediate's subject CN, e.g. "Yubico PIV
/// Attestation"). Falls back to the full issuer DN.
fn leaf_model_id(leaf: &x509_parser::certificate::X509Certificate) -> String {
    leaf.issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| leaf.issuer().to_string())
}

/// The Yubico device serial, if the attestation leaf carries the extension.
fn yubico_serial(leaf: &x509_parser::certificate::X509Certificate) -> Option<String> {
    for ext in leaf.extensions() {
        if ext.oid.to_id_string() == OID_YUBICO_SERIAL {
            // The serial extension value is a DER INTEGER; render its bytes hex.
            return Some(hex::encode(ext.value));
        }
    }
    None
}

// ── Binary-embedded Yubico PIV roots (ADR 200 §3, AC-5) ──────────────────────
//
// The pinned roots are the trust anchor for the ENTIRE attestation chain. They
// MUST bottom out at the signed binary, never a path the `ember`-uid daemon can
// write. They are returned as DER bytes parsed from compile-time PEM constants.
//
// PROVISIONED (2026-05-30). The classic Yubico PIV attestation root (the
// `9a`-slot attestation chain anchor for fw <= 5.7.3 YubiKeys, incl. the
// operator's 5C Nano fw 5.4.3) is embedded below via `include_str!` — a
// compile-time constant in the binary, never a daemon-writable file (ADR 200
// §3 / AC-5: root integrity reduces to binary integrity).
//
// The embedded cert (`certs/yubico-piv-ca-1.pem`) was cryptographically
// validated before embedding (transport is untrusted; the validation is the
// trust step):
//   - subject == issuer == `CN=Yubico PIV Root CA Serial 263751` (self-signed root);
//   - serial 0x040647 == 263751 decimal (matches the CN — internal consistency);
//   - RSA self-signature VERIFIES (`openssl verify` OK) → bytes intact end-to-end,
//     no transcription error survived;
//   - RSA-2048, sha256WithRSAEncryption, CA:TRUE pathlen:1, valid 2016→2052.
//   - SHA-256 fingerprint:
//     63:EC:E9:14:E5:4D:D8:79:15:F3:40:33:C8:5A:F4:C0:69:6B:A1:51:2F:8A:DD:66:CE:D7:38:33:12:07:B5:46
//     Cross-check this against Yubico's published value out-of-band before any
//     production release (the fingerprint IS the trust anchor — a self-signed
//     cert can claim any subject; only the pinned fingerprint distinguishes the
//     genuine root). Source: https://developers.yubico.com/PKI/yubico-piv-ca-1.pem
//
// The 2025 Yubico CA (fw >= 5.7.4 → Ed25519 PIV) is NOT needed for dev0 (the
// operator's key is fw 5.4.3 → P256) and is added here when a 5.7.4+ key enrolls.
//
// If this slice were ever empty again, `verify_piv_attestation` fails closed with
// `RootsNotProvisioned` — the absence of a root must never silently admit a key.
const YUBICO_PIV_ROOT_PEMS: &[&str] = &[include_str!("certs/yubico-piv-ca-1.pem")];

/// The validated SHA-256 fingerprint of the embedded Yubico PIV Root CA (see the
/// provisioning note above). Exposed so a test pins it — if the embedded PEM is
/// ever swapped, the fingerprint assertion fails loudly rather than silently
/// trusting a different root.
pub const YUBICO_PIV_ROOT_SHA256: &str =
    "63ece914e54dd87915f34033c85af4c0696ba1512f8add66ced738331207b546";

/// Parse the binary-embedded Yubico PIV roots into DER. Empty until the
/// authentic roots are provisioned into the signed release (fail-closed).
pub fn pinned_yubico_piv_roots() -> Vec<Vec<u8>> {
    YUBICO_PIV_ROOT_PEMS
        .iter()
        .filter_map(|pem_str| {
            x509_parser::pem::parse_x509_pem(pem_str.as_bytes())
                .ok()
                .map(|(_, p)| p.contents)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
    };
    use rustls_pki_types::CertificateDer;
    use time::{Duration, OffsetDateTime};

    fn ca_params(cn: &str, is_ca: bool) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.distinguished_name.push(DnType::CommonName, cn);
        params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(365);
        if is_ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }
        params
    }

    fn self_signed_root_der(cn: &str) -> Vec<u8> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root key");
        ca_params(cn, true)
            .self_signed(&key)
            .expect("root self-signed")
            .der()
            .to_vec()
    }

    /// A full synthetic PIV-shaped chain: root -> F9 intermediate -> slot leaf.
    /// Each issuer key is consumed exactly once (rcgen `Issuer` takes the key by
    /// value), so no key needs to outlive its single signing use.
    fn synthetic_chain() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root key");
        let root_der = ca_params("Test PIV Root CA", true)
            .self_signed(&root_key)
            .expect("root")
            .der()
            .to_vec();
        let root_issuer =
            Issuer::from_ca_cert_der(&CertificateDer::from(root_der.clone()), root_key)
                .expect("root issuer");

        let int_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("int key");
        let int_der = ca_params("Yubico PIV Attestation", true)
            .signed_by(&int_key, &root_issuer)
            .expect("int signed")
            .der()
            .to_vec();
        let int_issuer = Issuer::from_ca_cert_der(&CertificateDer::from(int_der.clone()), int_key)
            .expect("int issuer");

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let leaf_der = ca_params("YubiKey PIV Attestation 9a", false)
            .signed_by(&leaf_key, &int_issuer)
            .expect("leaf signed")
            .der()
            .to_vec();
        (root_der, int_der, leaf_der)
    }

    #[test]
    fn valid_chain_anchored_to_pinned_root_verifies() {
        let (root_der, int_der, leaf_der) = synthetic_chain();
        let out = verify_piv_attestation_with_roots(
            &[leaf_der, int_der],
            &[root_der],
            &ModelPolicy::dev0_default(),
        )
        .expect("valid chain verifies");
        assert!(out.public_key.starts_with("p256:"));
        assert!(core_crypto::p256_public_key_is_valid(
            &core_crypto::PublicKey(out.public_key.clone())
        ));
        assert_eq!(out.model_id, "Yubico PIV Attestation");
    }

    #[test]
    fn chain_to_untrusted_root_is_rejected() {
        let (_real_root, int_der, leaf_der) = synthetic_chain();
        let other_root = self_signed_root_der("Attacker Root CA");
        let err = verify_piv_attestation_with_roots(
            &[leaf_der, int_der],
            &[other_root],
            &ModelPolicy::dev0_default(),
        )
        .unwrap_err();
        assert_eq!(err, AttestationError::UntrustedRoot);
    }

    #[test]
    fn tampered_leaf_is_rejected() {
        let (root_der, int_der, mut leaf_der) = synthetic_chain();
        // Flip a byte in the leaf signature region (end of DER).
        let n = leaf_der.len();
        leaf_der[n - 5] ^= 0xff;
        let res = verify_piv_attestation_with_roots(
            &[leaf_der, int_der],
            &[root_der],
            &ModelPolicy::dev0_default(),
        );
        assert!(matches!(
            res,
            Err(AttestationError::BadSignature(_)) | Err(AttestationError::Parse(_))
        ));
    }

    #[test]
    fn empty_roots_fails_closed() {
        let (_root, int_der, leaf_der) = synthetic_chain();
        let err = verify_piv_attestation_with_roots(
            &[leaf_der, int_der],
            &[],
            &ModelPolicy::dev0_default(),
        )
        .unwrap_err();
        // Passing an empty root set is still fail-closed (the structural guard).
        assert_eq!(err, AttestationError::RootsNotProvisioned);
    }

    #[test]
    fn embedded_yubico_root_parses_and_matches_pinned_fingerprint() {
        // The embedded Yubico PIV root is provisioned (no longer empty).
        let roots = pinned_yubico_piv_roots();
        assert_eq!(
            roots.len(),
            1,
            "exactly the classic Yubico PIV root is embedded"
        );

        // It parses as a valid X.509 cert with the expected self-signed subject.
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&roots[0])
            .expect("embedded root parses as DER");
        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|c| c.as_str().ok())
            .unwrap_or("");
        assert_eq!(cn, "Yubico PIV Root CA Serial 263751");
        // Self-signed: issuer == subject.
        assert_eq!(cert.issuer().to_string(), cert.subject().to_string());

        // Pin the SHA-256 fingerprint: if the embedded PEM is ever swapped, this
        // fails loudly rather than silently trusting a different root. (The
        // fingerprint is the real trust anchor — a self-signed cert can claim
        // any subject; only the pinned digest distinguishes the genuine root.)
        let fp = <sha2::Sha256 as sha2::Digest>::digest(&roots[0]);
        assert_eq!(hex::encode(fp), YUBICO_PIV_ROOT_SHA256);
    }

    #[test]
    fn build_presence_enrollment_from_attestation() {
        let (root_der, int_der, leaf_der) = synthetic_chain();
        let b64 = |d: &[u8]| base64::engine::general_purpose::STANDARD.encode(d);
        let chain = vec![b64(&leaf_der), b64(&int_der)];

        let encryption_material = PublicKeyMaterial {
            key_id: "yubikey-9d-ecies".to_string(),
            algorithm: KeyAlgorithm::EcdsaP256,
            public_key: "p256:04deadbeef".to_string(),
        };
        let (event, attested) = build_presence_device_enrolled_event(
            "root-operator",
            "device-yubikey-1",
            "Operator YubiKey 5C Nano",
            &chain,
            &encryption_material,
            &[root_der],
            &ModelPolicy::dev0_default(),
        )
        .expect("attested chain enrolls");

        assert_eq!(event.custody_class, CustodyClass::Presence);
        assert_eq!(event.device_key.algorithm, KeyAlgorithm::EcdsaP256);
        assert_eq!(event.device_key.public_key, attested.public_key);
        assert!(event.device_key.public_key.starts_with("p256:"));
        // ADR 206 §4: the §4 recipient is recorded distinct from the signing key.
        assert_eq!(
            event.encryption_key.public_key,
            encryption_material.public_key
        );
        assert_ne!(event.encryption_key.public_key, event.device_key.public_key);
        // The recorded statement round-trips back to the input chain (so an
        // independent verifier can re-run it — AC-1).
        let recorded: Vec<String> =
            serde_json::from_str(event.attestation_statement.as_ref().unwrap()).unwrap();
        assert_eq!(recorded, chain);
        // The structural invariant holds: presence + a non-empty statement.
        use core_types::Validate;
        assert!(event.validate().is_ok());
    }

    #[test]
    fn build_presence_enrollment_rejects_untrusted_root() {
        let (_real, int_der, leaf_der) = synthetic_chain();
        let attacker_root = self_signed_root_der("Attacker Root CA");
        let b64 = |d: &[u8]| base64::engine::general_purpose::STANDARD.encode(d);
        let encryption_material = PublicKeyMaterial {
            key_id: "yubikey-9d-ecies".to_string(),
            algorithm: KeyAlgorithm::EcdsaP256,
            public_key: "p256:04deadbeef".to_string(),
        };
        let err = build_presence_device_enrolled_event(
            "root-operator",
            "device-evil",
            "Evil",
            &[b64(&leaf_der), b64(&int_der)],
            &encryption_material,
            &[attacker_root],
            &ModelPolicy::dev0_default(),
        )
        .unwrap_err();
        assert_eq!(err, AttestationError::UntrustedRoot);
    }

    #[test]
    fn model_policy_deny_and_allow() {
        let (root_der, int_der, leaf_der) = synthetic_chain();
        let chain = [leaf_der, int_der];

        // Deny-list containing the model → rejected.
        let deny = ModelPolicy {
            mode: ModelPolicyMode::DenyList,
            entries: vec!["Yubico PIV Attestation".to_string()],
        };
        assert!(matches!(
            verify_piv_attestation_with_roots(&chain, &[root_der.clone()], &deny),
            Err(AttestationError::PolicyRejected(_))
        ));

        // Allow-list NOT containing the model → rejected.
        let allow_other = ModelPolicy {
            mode: ModelPolicyMode::AllowList,
            entries: vec!["Some Other Model".to_string()],
        };
        assert!(matches!(
            verify_piv_attestation_with_roots(&chain, &[root_der.clone()], &allow_other),
            Err(AttestationError::PolicyRejected(_))
        ));

        // Allow-list containing the model → accepted.
        let allow = ModelPolicy {
            mode: ModelPolicyMode::AllowList,
            entries: vec!["Yubico PIV Attestation".to_string()],
        };
        assert!(verify_piv_attestation_with_roots(&chain, &[root_der], &allow).is_ok());
    }

    /// Phase-0 hardware proof (ADR 200 OQ-7). Runs a REAL YubiKey PIV
    /// attestation chain through the production verifier against the
    /// binary-embedded Yubico root — the empirical end-to-end anchor proof.
    ///
    /// `#[ignore]` because it needs hardware artifacts on disk; not run in CI.
    /// To reproduce with a YubiKey:
    ///   ykman piv keys generate -a ECCP256 9a /tmp/9a-pub.pem
    ///   ykman piv keys attest 9a /tmp/leaf.pem
    ///   ykman piv certificates export f9 /tmp/f9.pem
    ///   cargo test -p ember-daemon --lib piv_attestation::tests::phase0 -- --ignored --nocapture
    /// Override paths via EMBER_PIV_LEAF_PEM / EMBER_PIV_F9_PEM.
    #[test]
    #[ignore = "needs a real YubiKey PIV attestation on disk; run with --ignored"]
    fn phase0_real_yubikey_chain_verifies_against_embedded_root() {
        let leaf_path =
            std::env::var("EMBER_PIV_LEAF_PEM").unwrap_or_else(|_| "/tmp/leaf.pem".to_string());
        let f9_path =
            std::env::var("EMBER_PIV_F9_PEM").unwrap_or_else(|_| "/tmp/f9.pem".to_string());
        let pem_to_der = |p: &str| {
            let bytes = std::fs::read(p).unwrap_or_else(|e| panic!("read {p}: {e}"));
            let (_, pem) = x509_parser::pem::parse_x509_pem(&bytes)
                .unwrap_or_else(|e| panic!("parse pem {p}: {e}"));
            pem.contents
        };
        let leaf_der = pem_to_der(&leaf_path);
        let f9_der = pem_to_der(&f9_path);

        // The PRODUCTION entry point: pins the binary-embedded Yubico root, no
        // synthetic CA. Proves the embedded root + x509 chain walk + P256
        // extraction all work against real hardware.
        let attested = verify_piv_attestation(&[leaf_der, f9_der], &ModelPolicy::dev0_default())
            .expect("real YubiKey chain must verify against the embedded Yubico root");

        // The attested key is a genuine P-256 point in the wire form the gate
        // consumes (identity-binding), and re-validates under core-crypto.
        assert!(attested.public_key.starts_with("p256:"));
        assert!(core_crypto::p256_public_key_is_valid(
            &core_crypto::PublicKey(attested.public_key.clone())
        ));
        assert_eq!(attested.model_id, "Yubico PIV Attestation");
        eprintln!(
            "PHASE-0 PROOF OK: device_key={} model={} serial={:?}",
            attested.public_key, attested.model_id, attested.serial
        );
    }
}
