//! bridge_ca_se_sealed_persistent
//! ember_rpc_sibling_server_cert_minted_at_startup
//!
//! SE-sealed-persistent client-auth CA per design component 3 (reversed from
//! v1 ephemeral mlock'd). Private key encrypted at rest via design ember-kms
//! Vault Transit; in-memory only while daemon running; mlock'd page. Sealed
//! material persists across daemon restart (no per-restart cert wipe).
//!
//! ## Why SE-sealed (not ephemeral mlock'd)
//!
//! Daemon restart (macOS update, ember upgrade, MEK rotation, crash +
//! KeepAlive) must NOT wipe outstanding per-agent client certs. The CA's
//! persistence is what makes the cert chain stable across restart.
//!
//! ## This file (scaffold)
//!
//! Provides the `BridgeCa` type with SE-sealed API surface (`load_or_mint`,
//! `seal`, `unseal`, `fingerprint`, `pubkey_path`). Real ember-kms wiring
//! is a follow-up task; stubs are used here.
//!
//! Also provides lower-level crypto primitives (`mint`, `seal_with_key`,
//! `unseal_from_key`, `verifying_key`, `trust_root_cert_pem`) used by
//! `infra::runtime`'s vault-sealed persistence layer until the ember-kms path
//! supersedes it.
//!
//! ## Sibling server-cert mint (implementation-note-98)
//!
//! Anchor: `ember_rpc_sibling_server_cert_minted_at_startup`.
//!
//! The ember-rpc sibling process (design amendment) terminates mTLS on
//! behalf of emberd core. Its TLS server identity is a leaf cert signed by
//! this `BridgeCa`. `sign_server_cert` below is the primitive; the wiring
//! that calls it at daemon startup (and writes the PEM-pair under
//! `<data_dir>/ember-rpc/`) lives in `infra::runtime`. The cert chain is:
//!
//!   BridgeCa (self-signed root, SE-sealed) → ember-rpc server leaf (30-day TTL)
//!
//! Runtime publishes the same root in two on-disk shapes:
//!
//! - `bridge_ca.pub` — raw 32-byte ed25519 verifying-key bytes for
//!   fingerprint caching / Spawn Receipt continuity.
//! - `bridge_ca.pem` — PEM-encoded self-signed root cert for rustls clients
//!   like `ember-rpc`.
//!
//! Honest scope: `sign_server_cert` only mints. It does NOT enforce the
//! chain-validation invariants the listener relies on at handshake time —
//! that's the listener's job (`crates/ember-rpc/src/listener.rs`). What this
//! function DOES guarantee structurally:
//!
//! - The leaf cert's signature is verifiable against `BridgeCa`'s
//!   verifying key (the math is rcgen's, not ours).
//! - The leaf carries `serverAuth` EKU (so a client rejecting non-server
//!   EKUs refuses it on the wrong lane).
//! - The leaf is not a CA (`IsCa::NoCa`) and cannot issue further certs.
//!
//! What this function does NOT enforce:
//!
//! - Operator-supplied SANs are NOT validated for shape. The caller in
//!   `infra::runtime` is responsible for SAN content (it derives them from
//!   `EMBER_BRIDGE_BIND`). A malformed SAN string surfaces as
//!   `BridgeCaError::CertGen` from rcgen.
//! - TTL bounds are NOT enforced here — the caller picks 30 days for the
//!   ember-rpc sibling cert; other callers picking absurd TTLs would
//!   produce certs that still validate cryptographically but trip
//!   handshake-time `not_after` checks.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ED25519, SanType,
};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use zeroize::{Zeroize, Zeroizing};

/// SE-sealed Bridge CA.
///
/// `pubkey_path` — path to the on-disk pubkey file (`<data_dir>/bridge_ca.pub`).
/// `fingerprint` — 32-byte blake3 fingerprint for Spawn Receipt embedding.
/// `sealed`      — true when pubkey material has been published to disk.
///
/// The ed25519 private key is held in-memory and zeroized on drop.
pub struct BridgeCa {
    /// On-disk pubkey path (`<data_dir>/bridge_ca.pub`).
    pub pubkey_path: PathBuf,
    /// Cached blake3 fingerprint of the public-key bytes.
    /// Slice C reads this to embed in Spawn Receipts; Slice D compares.
    pub fingerprint: [u8; 32],
    /// True when pubkey material has been published to disk.
    pub sealed: bool,
    /// ed25519 signing key (private + public). Held in-memory only.
    key: SigningKey,
}

impl std::fmt::Debug for BridgeCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print private key material — only the fingerprint.
        f.debug_struct("BridgeCa")
            .field("pubkey_path", &self.pubkey_path)
            .field("fingerprint_hex", &hex::encode(self.fingerprint))
            .field("sealed", &self.sealed)
            .finish()
    }
}

impl Drop for BridgeCa {
    fn drop(&mut self) {
        // ed25519-dalek's SigningKey's internal ScalarBytes is dropped and
        // zeroized automatically via its ZeroizeOnDrop impl. We scribble the
        // fingerprint (not sensitive, but signals intent).
        self.fingerprint.zeroize();
    }
}

/// Errors from BridgeCa operations.
#[derive(Debug, thiserror::Error)]
pub enum BridgeCaError {
    /// Failed to publish pubkey file to disk.
    #[error("failed to publish pubkey file")]
    PubkeyPublishFailed,
    /// KMS (ember-kms Vault Transit) is unreachable.
    #[error("KMS unreachable")]
    KmsUnreachable,
    /// Sealed material is corrupted or unrecognizable.
    #[error("sealed material corrupted")]
    MaterialCorrupted,
    /// Attempted to unseal material that was never sealed.
    #[error("not sealed")]
    NotSealed,
    /// AEAD encrypt or decrypt failed (wrong key, tampered ciphertext, or
    /// wrong nonce). Used by the lower-level `seal_with_key`/`unseal_from_key`
    /// crypto primitives.
    #[error("AEAD failure: {0}")]
    Aead(String),
    /// Wrapping key is the wrong length (must be 32 bytes).
    #[error("wrapping key must be 32 bytes (got {0})")]
    InvalidWrappingKey(usize),
    /// Sealed blob is malformed (wrong nonce length, truncated).
    #[error("sealed blob malformed: {0}")]
    MalformedSealed(String),
    /// Sealed bytes don't decode to a valid ed25519 SigningKey.
    #[error("sealed blob doesn't decode to a valid ed25519 key")]
    InvalidKeyMaterial,
    /// Server cert minting failed (rcgen / key encoding / SAN encoding /
    /// signature). Surfaced as `BridgeCaError` so callers in
    /// `infra::runtime` can wrap it in `DaemonError::BridgeCaInit` and
    /// fail-closed at startup rather than booting a daemon that the
    /// ember-rpc sibling cannot bind against.
    #[error("server cert generation failed: {0}")]
    CertGen(String),
    /// Subject CN was empty. The CN is load-bearing for operator
    /// log-readability ("which cert just rotated?"); rcgen would accept
    /// an empty CN but we refuse it here so a bug in the caller cannot
    /// silently produce a CN-less cert.
    #[error("server cert subject must not be empty")]
    EmptySubject,
    /// SAN list was empty. mTLS handshake validation requires SAN entries
    /// matching the server hostname; a cert with no SANs is unusable.
    #[error("server cert SAN list must not be empty")]
    EmptySanList,
}

impl BridgeCa {
    // ── SE-sealed API (scaffold — real ember-kms wiring is a follow-up) ──

    /// Load or mint the Bridge CA.
    ///
    /// TODO: real ember-kms seal/unseal. For now: deterministic stub that
    /// writes a placeholder pubkey file at `data_dir/bridge_ca.pub` (mode
    /// 0644). Returns `BridgeCaError::PubkeyPublishFailed` if the file write
    /// fails. Sets `sealed: true` when pubkey content is non-empty.
    pub fn load_or_mint(kms_path: &Path, data_dir: &Path) -> Result<Self, BridgeCaError> {
        let _ = kms_path; // TODO: wire ember-kms Vault Transit
        let pubkey_path = data_dir.join("bridge_ca.pub");

        let placeholder = b"bridge_ca_placeholder_pubkey";
        std::fs::write(&pubkey_path, placeholder)
            .map_err(|_| BridgeCaError::PubkeyPublishFailed)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o644);
            std::fs::set_permissions(&pubkey_path, perms)
                .map_err(|_| BridgeCaError::PubkeyPublishFailed)?;
        }

        let sealed = !placeholder.is_empty();
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("OS entropy failure");
        let key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let fingerprint = compute_fingerprint(&key.verifying_key());

        Ok(BridgeCa {
            pubkey_path,
            fingerprint,
            sealed,
            key,
        })
    }

    /// Fingerprint accessor for Spawn Receipt embedding.
    /// Per the existing `ca_fingerprint` field in `core-receipts`.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Path to the on-disk pubkey file for operator visibility
    /// (operator can `cat <data_dir>/bridge_ca.pub`).
    pub fn pubkey_path(&self) -> &Path {
        &self.pubkey_path
    }

    /// Shutdown hook — seal the CA material under ember-kms.
    ///
    /// TODO: real ember-kms wrap. For now: idempotent no-op.
    pub fn seal(&mut self, kms_path: &Path) -> Result<(), BridgeCaError> {
        let _ = kms_path; // TODO: wire ember-kms Vault Transit
        Ok(())
    }

    /// Startup hook — unseal the CA material from ember-kms.
    ///
    /// TODO: real ember-kms unwrap. For now: idempotent no-op.
    pub fn unseal(&mut self, kms_path: &Path) -> Result<(), BridgeCaError> {
        let _ = kms_path; // TODO: wire ember-kms Vault Transit
        Ok(())
    }

    // ── Lower-level crypto primitives (used by infra::runtime until ember-kms) ──

    /// Mint a fresh Bridge CA keypair from OS entropy.
    pub fn mint() -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("OS entropy failure");
        let key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let fingerprint = compute_fingerprint(&key.verifying_key());
        Self {
            pubkey_path: PathBuf::new(),
            fingerprint,
            sealed: false,
            key,
        }
    }

    /// Public verifying key. Published to `<data_dir>/bridge_ca.pub` by
    /// `infra::runtime::load_or_mint_bridge_ca`.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Seal the private-key bytes under a 32-byte wrapping key using
    /// XChaCha20-Poly1305. Returns `(nonce, ciphertext)`.
    ///
    /// Used by `infra::runtime::load_or_mint_bridge_ca` until ember-kms lands.
    pub fn seal_with_key(&self, wrapping_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), BridgeCaError> {
        if wrapping_key.len() != 32 {
            return Err(BridgeCaError::InvalidWrappingKey(wrapping_key.len()));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key)
            .expect("wrapping_key length validated above");
        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).expect("OS entropy failure");
        let nonce = XNonce::from_slice(&nonce_bytes);
        let secret_bytes = self.key.to_bytes();
        let ciphertext = cipher
            .encrypt(nonce, secret_bytes.as_slice())
            .map_err(|e| BridgeCaError::Aead(e.to_string()))?;
        Ok((nonce_bytes.to_vec(), ciphertext))
    }

    /// Inverse of [`Self::seal_with_key`].
    ///
    /// Used by `infra::runtime::load_or_mint_bridge_ca` until ember-kms lands.
    pub fn unseal_from_key(
        nonce_bytes: &[u8],
        ciphertext: &[u8],
        wrapping_key: &[u8],
    ) -> Result<Self, BridgeCaError> {
        if wrapping_key.len() != 32 {
            return Err(BridgeCaError::InvalidWrappingKey(wrapping_key.len()));
        }
        if nonce_bytes.len() != 24 {
            return Err(BridgeCaError::MalformedSealed(format!(
                "invalid nonce length: {}",
                nonce_bytes.len()
            )));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key)
            .expect("wrapping_key length validated above");
        let nonce = XNonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| BridgeCaError::Aead(e.to_string()))?;
        if plaintext.len() != 32 {
            return Err(BridgeCaError::InvalidKeyMaterial);
        }
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&plaintext);
        let key = SigningKey::from_bytes(&secret_bytes);
        secret_bytes.zeroize();
        let fingerprint = compute_fingerprint(&key.verifying_key());
        Ok(Self {
            pubkey_path: PathBuf::new(),
            fingerprint,
            sealed: false,
            key,
        })
    }
}

/// Subject Alternative Name entry for [`BridgeCa::sign_server_cert`].
///
/// Mirrors the subset of `rcgen::SanType` we actually emit for the
/// ember-rpc sibling server cert: DNS hostnames + IP literals. URI SANs
/// (used elsewhere for SPIFFE identities) are intentionally not exposed
/// here; this primitive's job is server-side identity, not persona
/// identity.
#[derive(Debug, Clone)]
pub enum ServerSan {
    /// DNS hostname, e.g. `host.docker.internal` or `localhost`.
    Dns(String),
    /// IPv4 or IPv6 address literal, e.g. `127.0.0.1` or `::1`.
    Ip(IpAddr),
}

impl BridgeCa {
    /// Mint an ed25519 server keypair, build an X.509 leaf cert with the
    /// supplied subject CN + SAN entries + TTL, sign it with this
    /// `BridgeCa`'s signing key, and return `(cert_pem, key_pem)`.
    ///
    /// The returned key PEM is wrapped in `Zeroizing` so it is wiped on
    /// drop; the caller is responsible for not leaving plaintext copies
    /// of the bytes around (e.g. write to disk + `Zeroizing` drops; do
    /// not hold an unzeroed `String::from(...)`).
    ///
    /// # Parameters
    ///
    /// - `subject` — CN string embedded in the leaf's distinguished name.
    ///   Must not be empty (operator-visible identifier in logs +
    ///   `openssl x509 -in server.crt -noout -subject` output).
    /// - `sans` — Subject Alternative Names. Must not be empty. mTLS
    ///   handshake validation requires the server hostname/IP to match
    ///   one of these entries; an empty list would produce a cert that
    ///   no client could validate.
    /// - `ttl` — validity duration from now. The cert's `not_before` is
    ///   the current wall-clock time; `not_after` is `now + ttl`. The
    ///   caller picks the TTL: ember-rpc's sibling cert uses 30 days
    ///   (operator-friendly, with daemon-boot rotation when `<24h` to
    ///   expiry).
    ///
    /// # What this DOES guarantee
    ///
    /// - The returned cert's signature is verifiable against this
    ///   `BridgeCa`'s `verifying_key()` (rcgen's signing math, not ours).
    /// - The cert carries `serverAuth` EKU.
    /// - The cert is not a CA (`IsCa::NoCa`).
    ///
    /// # What this does NOT enforce
    ///
    /// - SAN content shape — operator-supplied `Dns` strings are passed
    ///   through to rcgen verbatim. A malformed DNS label surfaces as
    ///   [`BridgeCaError::CertGen`] from rcgen.
    /// - TTL bounds — passing an absurd TTL produces a cert that still
    ///   validates cryptographically but trips handshake-time `not_after`
    ///   checks.
    /// - Wall-clock monotonicity — `not_before = SystemTime::now()` is
    ///   subject to clock skew. The 30-day ember-rpc TTL has a 24h
    ///   rotation slack precisely to absorb this.
    ///
    /// # Errors
    ///
    /// - [`BridgeCaError::EmptySubject`] — `subject` is empty.
    /// - [`BridgeCaError::EmptySanList`] — `sans` is empty.
    /// - [`BridgeCaError::CertGen`] — rcgen key generation, SAN encoding,
    ///   issuer construction, or signing failed.
    pub fn sign_server_cert(
        &self,
        subject: &str,
        sans: &[ServerSan],
        ttl: std::time::Duration,
    ) -> Result<(Zeroizing<String>, Zeroizing<String>), BridgeCaError> {
        if subject.is_empty() {
            return Err(BridgeCaError::EmptySubject);
        }
        if sans.is_empty() {
            return Err(BridgeCaError::EmptySanList);
        }

        // Generate a fresh ed25519 leaf keypair via rcgen. We use rcgen's
        // KeyPair (not ed25519-dalek) on the leaf so the signing math
        // stays inside rcgen — same pattern as `core_crypto::x509::
        // mint_per_agent_client_cert`.
        let leaf_key = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|e| BridgeCaError::CertGen(format!("leaf keygen: {e}")))?;

        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| BridgeCaError::CertGen(format!("params: {e}")))?;

        // Server leaf cert — not a CA, serverAuth EKU only.
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        params.distinguished_name = {
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(DnType::CommonName, subject.to_string());
            dn
        };

        // Translate ServerSan → rcgen::SanType. DNS strings are passed
        // verbatim; rcgen validates them as Ia5String when serializing.
        let mut san_entries: Vec<SanType> = Vec::with_capacity(sans.len());
        for san in sans {
            match san {
                ServerSan::Dns(name) => {
                    let ia5: rcgen::string::Ia5String =
                        name.as_str().try_into().map_err(|e: rcgen::Error| {
                            BridgeCaError::CertGen(format!("DNS SAN {name:?}: {e}"))
                        })?;
                    san_entries.push(SanType::DnsName(ia5));
                }
                ServerSan::Ip(addr) => {
                    san_entries.push(SanType::IpAddress(*addr));
                }
            }
        }
        params.subject_alt_names = san_entries;

        // Validity window. `not_before = now`, `not_after = now + ttl`.
        // SystemTime is wall-clock and subject to skew — the 24h rotation
        // slack at the caller absorbs typical drift.
        let now = std::time::SystemTime::now();
        let not_before_offset = time::OffsetDateTime::from(now);
        let not_after = now
            .checked_add(ttl)
            .ok_or_else(|| BridgeCaError::CertGen("ttl overflow".to_string()))?;
        let not_after_offset = time::OffsetDateTime::from(not_after);
        params.not_before = not_before_offset;
        params.not_after = not_after_offset;

        // Build the CA Issuer from the BridgeCa signing key. We hand
        // rcgen the self-signed CA-cert-DER (built on-the-fly from the
        // ed25519 verifying key) plus a `KeyPair` re-derived from the
        // BridgeCa seed. The CA cert produced for the issuer side is
        // ephemeral and not persisted — it exists only as the
        // SubjectIssuer field for the leaf.
        let ca_key_pair = signing_key_to_rcgen_keypair(&self.key)?;
        let ca_cert = build_ca_cert_for_issuer(&ca_key_pair)?;
        let ca_cert_der_typed = CertificateDer::from(ca_cert.der().to_vec());
        let issuer = Issuer::from_ca_cert_der(&ca_cert_der_typed, ca_key_pair)
            .map_err(|e| BridgeCaError::CertGen(format!("issuer: {e}")))?;

        let cert = params
            .signed_by(&leaf_key, &issuer)
            .map_err(|e| BridgeCaError::CertGen(format!("sign: {e}")))?;

        let cert_pem = Zeroizing::new(cert.pem());
        let key_pem = Zeroizing::new(leaf_key.serialize_pem());
        Ok((cert_pem, key_pem))
    }
}

/// Re-derive an rcgen `KeyPair` from a dalek `SigningKey`'s 32-byte seed.
///
/// Same pattern as `core_crypto::ca::signing_key_to_rcgen_keypair`. We
/// duplicate it here (rather than depend on `core_crypto` for one
/// helper) because this crate already pulls in `rcgen` directly for the
/// per-agent client-cert path and `core_crypto::ca` is not in
/// `ember-daemon`'s dep tree.
fn signing_key_to_rcgen_keypair(signing_key: &SigningKey) -> Result<KeyPair, BridgeCaError> {
    let seed: [u8; 32] = signing_key.to_bytes();
    let pkcs8 = seed_to_pkcs8_v1_der(&seed);
    let kp = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8.as_slice()),
        &PKCS_ED25519,
    )
    .map_err(|e| BridgeCaError::CertGen(format!("ed25519 pkcs8: {e}")))?;
    Ok(kp)
}

/// Encode a 32-byte ed25519 seed as a PKCS#8 v1 DER document.
///
/// Mirrors `core_crypto::ca::seed_to_pkcs8_v1_der`. See that file for the
/// ASN.1 structure breakdown; the bytes here are verbatim.
fn seed_to_pkcs8_v1_der(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&[0x30, 0x2e]);
    der.extend_from_slice(&[0x02, 0x01, 0x00]);
    der.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    der.extend_from_slice(&[0x04, 0x22, 0x04, 0x20]);
    der.extend_from_slice(seed);
    der
}

/// Build the self-signed CA-side certificate the leaf-cert Issuer wraps.
///
/// rcgen requires an `Issuer` to be constructed from a CA-cert + signing
/// key pair. The same self-signed cert also backs the published
/// `bridge_ca.pem` trust root that rustls clients load. The raw
/// `bridge_ca.pub` file remains the fingerprint/cache artifact.
fn build_ca_cert_for_issuer(ca_key: &KeyPair) -> Result<rcgen::Certificate, BridgeCaError> {
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| BridgeCaError::CertGen(format!("ca params: {e}")))?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(DnType::CommonName, "emberd bridge CA");
        dn
    };
    // Wide validity window — this cert is never persisted and is only
    // used as the leaf's issuer field. The leaf's own not_before /
    // not_after are what matters at handshake time.
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    params.not_after = rcgen::date_time_ymd(9999, 12, 31);
    params
        .self_signed(ca_key)
        .map_err(|e| BridgeCaError::CertGen(format!("ca self_signed: {e}")))
}

impl BridgeCa {
    /// PEM-encoded self-signed root cert suitable for rustls trust stores.
    ///
    /// The runtime publishes this as `<data_dir>/bridge_ca.pem` alongside the
    /// raw `bridge_ca.pub` fingerprint cache so bridge consumers can use the
    /// standard PEM-loading path without losing the 32-byte raw-key contract.
    pub fn trust_root_cert_pem(&self) -> Result<Zeroizing<String>, BridgeCaError> {
        let ca_key_pair = signing_key_to_rcgen_keypair(&self.key)?;
        let ca_cert = build_ca_cert_for_issuer(&ca_key_pair)?;
        Ok(Zeroizing::new(ca_cert.pem()))
    }
}

/// blake3-256 of the verifying key bytes.
fn compute_fingerprint(vk: &VerifyingKey) -> [u8; 32] {
    *blake3::hash(vk.as_bytes()).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Pre: empty data_dir. Post: bridge_ca.pub exists after load_or_mint.
    #[test]
    fn load_or_mint_publishes_pubkey_file() {
        let dir = TempDir::new().expect("tempdir");
        let kms_path = Path::new("/dev/null");
        let ca = BridgeCa::load_or_mint(kms_path, dir.path()).expect("load_or_mint succeeds");
        assert!(
            ca.pubkey_path().exists(),
            "pubkey file must exist after load_or_mint"
        );
    }

    /// Pre: data_dir. Post: pubkey_path is data_dir/bridge_ca.pub.
    #[test]
    fn pubkey_path_returns_join_with_data_dir() {
        let dir = TempDir::new().expect("tempdir");
        let kms_path = Path::new("/dev/null");
        let ca = BridgeCa::load_or_mint(kms_path, dir.path()).expect("load_or_mint succeeds");
        let expected = dir.path().join("bridge_ca.pub");
        assert_eq!(ca.pubkey_path(), expected.as_path());
    }

    /// Pre: any load_or_mint. Post: fingerprint() returns exactly 32 bytes.
    #[test]
    fn fingerprint_is_32_bytes() {
        let dir = TempDir::new().expect("tempdir");
        let kms_path = Path::new("/dev/null");
        let ca = BridgeCa::load_or_mint(kms_path, dir.path()).expect("load_or_mint succeeds");
        let fp = ca.fingerprint();
        assert_eq!(fp.len(), 32);
    }

    /// Pre: any load_or_mint. Post: seal/unseal are idempotent no-ops.
    #[test]
    fn seal_unseal_idempotent() {
        let dir = TempDir::new().expect("tempdir");
        let kms_path = Path::new("/dev/null");
        let mut ca = BridgeCa::load_or_mint(kms_path, dir.path()).expect("load_or_mint succeeds");
        ca.seal(kms_path).expect("seal is a no-op");
        ca.unseal(kms_path).expect("unseal is a no-op");
        ca.seal(kms_path).expect("seal idempotent second call");
        ca.unseal(kms_path).expect("unseal idempotent second call");
    }

    // ─── sign_server_cert (implementation-note-98 T2) ───

    /// Pre: minted BridgeCa, valid subject + SANs + TTL.
    /// Post: returned PEMs parse; leaf cert validates against the BridgeCa's
    /// signing key; SAN matches expected entries.
    #[test]
    fn sign_server_cert_minted_validates_against_bridge_ca() {
        use std::time::Duration;
        use x509_parser::prelude::*;

        let ca = BridgeCa::mint();
        let sans = vec![
            ServerSan::Dns("host.docker.internal".to_string()),
            ServerSan::Dns("localhost".to_string()),
            ServerSan::Ip("127.0.0.1".parse().unwrap()),
        ];
        let (cert_pem, key_pem) = ca
            .sign_server_cert("ember-rpc", &sans, Duration::from_secs(30 * 24 * 3600))
            .expect("sign_server_cert succeeds");

        // PEM parses + DER decodes.
        let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).expect("PEM parses");
        let (_, parsed) = X509Certificate::from_der(&pem.contents).expect("DER parses");

        // Subject CN matches.
        let cn = parsed
            .subject()
            .iter_common_name()
            .next()
            .expect("CN present")
            .as_str()
            .expect("CN is utf8");
        assert_eq!(cn, "ember-rpc");

        // SANs include all three entries.
        let san_ext = parsed
            .subject_alternative_name()
            .expect("SAN parses")
            .expect("SAN present");
        let names: Vec<String> = san_ext
            .value
            .general_names
            .iter()
            .map(|gn| format!("{:?}", gn))
            .collect();
        let joined = names.join(",");
        assert!(
            joined.contains("host.docker.internal"),
            "DNS SAN host.docker.internal: {joined}"
        );
        assert!(joined.contains("localhost"), "DNS SAN localhost: {joined}");
        // x509-parser renders IPv4 SANs as the raw octet array, not dotted-quad.
        assert!(
            joined.contains("[127, 0, 0, 1]"),
            "IP SAN 127.0.0.1 (rendered as [127, 0, 0, 1]): {joined}"
        );

        // Signature verifies against BridgeCa's verifying key. Use
        // ed25519-dalek (already a direct dep) rather than ring so the
        // test compiles without expanding the dep graph.
        let vk = ca.verifying_key();
        let tbs = parsed.tbs_certificate.as_ref();
        let sig_bytes = parsed.signature_value.as_ref();
        let sig = ed25519_dalek::Signature::try_from(sig_bytes)
            .expect("signature bytes decode as ed25519::Signature");
        ed25519_dalek::Verifier::verify(&vk, tbs, &sig)
            .expect("BridgeCa verifying key validates leaf sig");

        // Key PEM parses as an Ed25519 PKCS#8 document.
        let (_, key_pem_parsed) = parse_x509_pem(key_pem.as_bytes()).expect("key PEM parses");
        assert!(
            !key_pem_parsed.contents.is_empty(),
            "key PEM has DER contents"
        );

        // EKU is serverAuth (not clientAuth).
        let eku = parsed
            .extended_key_usage()
            .expect("EKU parses")
            .expect("EKU present");
        assert!(eku.value.server_auth, "serverAuth EKU set");
        assert!(!eku.value.client_auth, "clientAuth NOT set");
    }

    /// Pre: empty subject string. Post: EmptySubject error.
    #[test]
    fn sign_server_cert_rejects_empty_subject() {
        use std::time::Duration;
        let ca = BridgeCa::mint();
        let sans = vec![ServerSan::Dns("localhost".to_string())];
        let err = ca
            .sign_server_cert("", &sans, Duration::from_secs(3600))
            .expect_err("empty subject must fail");
        assert!(matches!(err, BridgeCaError::EmptySubject));
    }

    /// Pre: empty SAN list. Post: EmptySanList error.
    #[test]
    fn sign_server_cert_rejects_empty_sans() {
        use std::time::Duration;
        let ca = BridgeCa::mint();
        let err = ca
            .sign_server_cert("ember-rpc", &[], Duration::from_secs(3600))
            .expect_err("empty SAN list must fail");
        assert!(matches!(err, BridgeCaError::EmptySanList));
    }
}
