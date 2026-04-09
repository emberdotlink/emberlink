use age::Decryptor;
use age::secrecy::ExposeSecret;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use core_types::{KeyAlgorithm, ValidationError, bytes_to_hex, hex_to_bytes};
use ed25519_dalek::{
    Signature as DalekSignature, Signer as DalekSigner, SigningKey, Verifier as DalekVerifier,
    VerifyingKey,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

const PUBLIC_KEY_PREFIX: &str = "ed25519:";
const PRIVATE_KEY_PREFIX: &str = "ed25519-secret:";
const SIGNATURE_PREFIX: &str = "ed25519sig:";
const CONTENT_KEY_PREFIX: &str = "xchacha20-key:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedContent {
    pub nonce_hex: String,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalKeyPair {
    pub key_id: String,
    pub algorithm: KeyAlgorithm,
    pub public_key: String,
    pub private_key: String,
}

impl LocalKeyPair {
    pub fn public_key_handle(&self) -> PublicKey {
        PublicKey(self.public_key.clone())
    }
}

pub trait Signer {
    fn sign(&self, payload: &[u8]) -> Signature;
    fn public_key(&self) -> PublicKey;
}

pub trait Verifier {
    fn verify(&self, public_key: &PublicKey, payload: &[u8], signature: &Signature) -> bool;
}

#[derive(Debug, Clone)]
pub struct LocalKeySigner {
    public_key: PublicKey,
    signing_key: SigningKey,
}

impl LocalKeySigner {
    pub fn from_local_key_pair(key_pair: &LocalKeyPair) -> Result<Self, ValidationError> {
        if key_pair.algorithm != KeyAlgorithm::Ed25519 {
            return Err(ValidationError::new(
                "local signer requires an ed25519 key pair",
            ));
        }
        let secret_bytes = decode_prefixed_hex(&key_pair.private_key, PRIVATE_KEY_PREFIX, 32)?;
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let derived_public = encode_public_key(&signing_key.verifying_key());
        if derived_public != key_pair.public_key {
            return Err(ValidationError::new(
                "local key pair private and public key material do not match",
            ));
        }

        Ok(Self {
            public_key: PublicKey(derived_public),
            signing_key,
        })
    }
}

impl Signer for LocalKeySigner {
    fn sign(&self, payload: &[u8]) -> Signature {
        let signature = self.signing_key.sign(payload);
        Signature(encode_signature(&signature))
    }

    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }
}

pub fn generate_local_key_pair(owner_kind: &str, owner_id: &str) -> LocalKeyPair {
    generate_local_key_pair_version(owner_kind, owner_id, 1)
}

pub fn generate_local_encryption_key_pair(owner_kind: &str, owner_id: &str) -> LocalKeyPair {
    generate_local_encryption_key_pair_version(owner_kind, owner_id, 1)
}

pub fn generate_local_key_pair_version(
    owner_kind: &str,
    owner_id: &str,
    version: u32,
) -> LocalKeyPair {
    let key_id = format!(
        "key-{owner_kind}-{owner_id}-v{version}-{}",
        random_hex_segment(8)
    );
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    local_key_pair_from_secret_bytes(key_id, secret_bytes)
}

pub fn generate_local_encryption_key_pair_version(
    owner_kind: &str,
    owner_id: &str,
    version: u32,
) -> LocalKeyPair {
    let key_id = format!(
        "key-{owner_kind}-{owner_id}-enc-v{version}-{}",
        random_hex_segment(8)
    );
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    LocalKeyPair {
        key_id,
        algorithm: KeyAlgorithm::AgeX25519,
        public_key: recipient.to_string(),
        private_key: identity.to_string().expose_secret().to_string(),
    }
}

pub fn generate_random_identifier(prefix: &str) -> String {
    format!("{prefix}-{}", random_hex_segment(8))
}

/// Generate a content encryption key using HKDF-SHA256.
///
/// Random input keying material is fed through HKDF with a domain-separation
/// info string so the output is a proper KDF-derived key rather than raw
/// random bytes.
pub fn generate_content_key() -> String {
    let mut ikm = [0u8; 32];
    OsRng.fill_bytes(&mut ikm);
    derive_content_key(&ikm, b"emberlink-manifest-content-key")
}

/// Derive a content key from input keying material and an info context using
/// HKDF-SHA256. Exposed for deterministic testing.
pub fn derive_content_key(ikm: &[u8], info: &[u8]) -> String {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 expand should never fail for 32-byte output");
    format!("{CONTENT_KEY_PREFIX}{}", bytes_to_hex(&okm))
}

/// Encrypt content using XChaCha20-Poly1305 with a random 192-bit nonce.
///
/// # Nonce security model
///
/// XChaCha20-Poly1305 uses a 192-bit (24-byte) nonce generated from `OsRng`.
/// With 2^192 possible nonces, the birthday-bound collision probability stays
/// below 2^{-64} even after 2^{64} encryptions under the same key — far beyond
/// any realistic workload in Emberlink. By comparison, standard ChaCha20 has
/// only a 96-bit nonce where collision risk becomes non-negligible after ~2^{32}
/// messages per key.
///
/// Each manifest chunk is encrypted with a fresh random nonce and authenticated
/// with associated data (`aad`) binding the ciphertext to its chunk ordinal,
/// preventing reordering or substitution attacks. The `aad` is not encrypted
/// but is covered by the Poly1305 authentication tag.
///
/// For the theoretical worst case of one key encrypting 2^{40} (~1 trillion)
/// chunks, the nonce collision probability is approximately:
///   P ≈ (2^40)^2 / (2 × 2^192) ≈ 2^{-113}
///
/// This is negligible for all practical purposes.
pub fn encrypt_content(
    content_key: &str,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedContent, ValidationError> {
    let key_bytes = decode_prefixed_hex::<32>(content_key, CONTENT_KEY_PREFIX, 32)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|err| ValidationError::new(format!("invalid content key: {err}")))?;
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|err| ValidationError::new(format!("content encryption failed: {err}")))?;
    Ok(EncryptedContent {
        nonce_hex: bytes_to_hex(&nonce),
        ciphertext,
    })
}

pub fn decrypt_content(
    content_key: &str,
    encrypted: &EncryptedContent,
    aad: &[u8],
) -> Result<Vec<u8>, ValidationError> {
    let key_bytes = decode_prefixed_hex::<32>(content_key, CONTENT_KEY_PREFIX, 32)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|err| ValidationError::new(format!("invalid content key: {err}")))?;
    let nonce = decode_hex_to_array::<24>(&encrypted.nonce_hex)?;
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: encrypted.ciphertext.as_ref(),
                aad,
            },
        )
        .map_err(|err| ValidationError::new(format!("content decryption failed: {err}")))
}

pub fn sha256_digest_hex(bytes: &[u8]) -> String {
    bytes_to_hex(&Sha256::digest(bytes))
}

pub fn sha256_digest_raw(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Extract raw 32-byte Ed25519 public key bytes from a `PublicKey` handle.
pub fn public_key_raw_bytes(public_key: &PublicKey) -> Result<[u8; 32], ValidationError> {
    let bytes = decode_prefixed_hex(&public_key.0, PUBLIC_KEY_PREFIX, 32)?;
    Ok(bytes)
}

pub fn wrap_secret_to_recipient(
    recipient_public_key: &str,
    plaintext: &[u8],
) -> Result<String, ValidationError> {
    let recipient = recipient_public_key
        .parse::<age::x25519::Recipient>()
        .map_err(|err| ValidationError::new(format!("invalid x25519 recipient: {err}")))?;
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|err| ValidationError::new(format!("create recipient encryptor: {err}")))?;
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|err| ValidationError::new(format!("open recipient wrapper: {err}")))?;
    writer
        .write_all(plaintext)
        .map_err(|err| ValidationError::new(format!("write wrapped secret: {err}")))?;
    writer
        .finish()
        .map_err(|err| ValidationError::new(format!("finish wrapped secret: {err}")))?;
    Ok(bytes_to_hex(&encrypted))
}

pub fn unwrap_secret_with_identity(
    identity_private_key: &str,
    wrapped_hex: &str,
) -> Result<Vec<u8>, ValidationError> {
    let identity = identity_private_key
        .parse::<age::x25519::Identity>()
        .map_err(|err| ValidationError::new(format!("invalid x25519 identity: {err}")))?;
    let encrypted = hex_to_bytes(wrapped_hex)?;
    let decryptor = Decryptor::new(encrypted.as_slice())
        .map_err(|err| ValidationError::new(format!("open wrapped secret: {err}")))?;
    let mut plaintext = Vec::new();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|err| ValidationError::new(format!("decrypt wrapped secret: {err}")))?;
    reader
        .read_to_end(&mut plaintext)
        .map_err(|err| ValidationError::new(format!("read wrapped secret: {err}")))?;
    Ok(plaintext)
}

#[derive(Debug, Clone)]
pub struct FixtureSigner {
    public_key: PublicKey,
    signing_key: SigningKey,
}

impl FixtureSigner {
    pub fn new(seed_label: impl AsRef<str>) -> Self {
        let seed_label = seed_label.as_ref();
        let signing_key = derive_fixture_signing_key(seed_label);
        let public_key = PublicKey(encode_public_key(&signing_key.verifying_key()));
        Self {
            public_key,
            signing_key,
        }
    }
}

impl Signer for FixtureSigner {
    fn sign(&self, payload: &[u8]) -> Signature {
        let signature = self.signing_key.sign(payload);
        Signature(encode_signature(&signature))
    }

    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FixtureVerifier;

impl Verifier for FixtureVerifier {
    fn verify(&self, public_key: &PublicKey, payload: &[u8], signature: &Signature) -> bool {
        Ed25519Verifier.verify(public_key, payload, signature)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn verify(&self, public_key: &PublicKey, payload: &[u8], signature: &Signature) -> bool {
        let verifying_key = match decode_public_key(public_key) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let signature = match decode_signature(signature) {
            Ok(value) => value,
            Err(_) => return false,
        };
        verifying_key.verify(payload, &signature).is_ok()
    }
}

fn local_key_pair_from_secret_bytes(key_id: String, secret_bytes: [u8; 32]) -> LocalKeyPair {
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    LocalKeyPair {
        key_id,
        algorithm: KeyAlgorithm::Ed25519,
        public_key: encode_public_key(&verifying_key),
        private_key: encode_private_key(&secret_bytes),
    }
}

fn random_hex_segment(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    OsRng.fill_bytes(&mut bytes);
    bytes_to_hex(&bytes)
}

fn derive_fixture_signing_key(seed_label: &str) -> SigningKey {
    let digest = Sha256::digest(format!("emberlink-fixture-signer:{seed_label}").as_bytes());
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest[..32]);
    SigningKey::from_bytes(&seed)
}

fn encode_public_key(verifying_key: &VerifyingKey) -> String {
    format!(
        "{PUBLIC_KEY_PREFIX}{}",
        bytes_to_hex(&verifying_key.to_bytes())
    )
}

fn encode_private_key(secret_bytes: &[u8; 32]) -> String {
    format!("{PRIVATE_KEY_PREFIX}{}", bytes_to_hex(secret_bytes))
}

fn encode_signature(signature: &DalekSignature) -> String {
    format!("{SIGNATURE_PREFIX}{}", bytes_to_hex(&signature.to_bytes()))
}

fn decode_public_key(public_key: &PublicKey) -> Result<VerifyingKey, ValidationError> {
    let bytes = decode_prefixed_hex(&public_key.0, PUBLIC_KEY_PREFIX, 32)?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|err| ValidationError::new(format!("invalid public key bytes: {err}")))
}

fn decode_signature(signature: &Signature) -> Result<DalekSignature, ValidationError> {
    let bytes = decode_prefixed_hex(&signature.0, SIGNATURE_PREFIX, 64)?;
    Ok(DalekSignature::from_bytes(&bytes))
}

fn decode_prefixed_hex<const N: usize>(
    value: &str,
    prefix: &str,
    expected_len: usize,
) -> Result<[u8; N], ValidationError> {
    let encoded = value
        .strip_prefix(prefix)
        .ok_or_else(|| ValidationError::new(format!("value must start with {prefix}")))?;
    let bytes = hex_to_bytes(encoded)?;
    if bytes.len() != expected_len {
        return Err(ValidationError::new(format!(
            "expected {expected_len} bytes but found {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex_to_array<const N: usize>(value: &str) -> Result<[u8; N], ValidationError> {
    let bytes = hex_to_bytes(value)?;
    if bytes.len() != N {
        return Err(ValidationError::new(format!(
            "expected {N} bytes but found {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_signatures_are_deterministic_and_verifiable() {
        let signer = FixtureSigner::new("fixture_signer");
        let signature = signer.sign(b"root_created");
        let verifier = FixtureVerifier;

        assert!(verifier.verify(&signer.public_key(), b"root_created", &signature));
        assert_eq!(signer.sign(b"root_created"), signature);
    }

    #[test]
    fn local_key_pairs_are_real_signing_material() {
        let key_pair = generate_local_key_pair("root", "root-a");
        let signer = LocalKeySigner::from_local_key_pair(&key_pair).unwrap();
        let signature = signer.sign(b"root_created");
        let verifier = Ed25519Verifier;

        assert_eq!(key_pair.algorithm, KeyAlgorithm::Ed25519);
        assert!(verifier.verify(&signer.public_key(), b"root_created", &signature));
    }

    #[test]
    fn local_key_generation_is_not_deterministic_per_owner() {
        let a = generate_local_key_pair("root", "root-a");
        let b = generate_local_key_pair("root", "root-a");

        assert_ne!(a.key_id, b.key_id);
        assert_ne!(a.public_key, b.public_key);
        assert_ne!(a.private_key, b.private_key);
    }

    #[test]
    fn rotated_key_versions_change_ids_and_material() {
        let v1 = generate_local_key_pair_version("device", "device-1", 1);
        let v2 = generate_local_key_pair_version("device", "device-1", 2);

        assert_ne!(v1.key_id, v2.key_id);
        assert_ne!(v1.public_key, v2.public_key);
    }

    #[test]
    fn random_identifier_generation_is_not_deterministic() {
        let a = generate_random_identifier("root");
        let b = generate_random_identifier("root");

        assert!(a.starts_with("root-"));
        assert!(b.starts_with("root-"));
        assert_ne!(a, b);
    }

    #[test]
    fn malformed_local_key_pairs_are_rejected() {
        let key_pair = LocalKeyPair {
            key_id: "key-root-a-v1".into(),
            algorithm: KeyAlgorithm::Ed25519,
            public_key: "ed25519:deadbeef".into(),
            private_key: "ed25519-secret:0011".into(),
        };

        assert!(LocalKeySigner::from_local_key_pair(&key_pair).is_err());
    }

    #[test]
    fn content_encryption_round_trips() {
        let key = generate_content_key();
        let encrypted = encrypt_content(&key, b"hello storage", b"manifest-1:0").unwrap();
        let decrypted = decrypt_content(&key, &encrypted, b"manifest-1:0").unwrap();

        assert_eq!(decrypted, b"hello storage");
    }

    #[test]
    fn content_encryption_rejects_wrong_aad() {
        let key = generate_content_key();
        let encrypted = encrypt_content(&key, b"hello storage", b"manifest-1:0").unwrap();

        assert!(decrypt_content(&key, &encrypted, b"manifest-1:1").is_err());
    }

    #[test]
    fn content_encryption_uses_random_nonces() {
        let key = generate_content_key();
        let first = encrypt_content(&key, b"same payload", b"manifest-1:0").unwrap();
        let second = encrypt_content(&key, b"same payload", b"manifest-1:0").unwrap();

        assert_ne!(first.nonce_hex, second.nonce_hex);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn derive_content_key_is_deterministic() {
        let ikm = [0xab_u8; 32];
        let key1 = derive_content_key(&ikm, b"test-info");
        let key2 = derive_content_key(&ikm, b"test-info");
        assert_eq!(key1, key2);
        assert!(key1.starts_with("xchacha20-key:"));
    }

    #[test]
    fn derive_content_key_varies_with_info() {
        let ikm = [0xcd_u8; 32];
        let key_a = derive_content_key(&ikm, b"info-a");
        let key_b = derive_content_key(&ikm, b"info-b");
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn generate_content_key_produces_unique_keys() {
        let key1 = generate_content_key();
        let key2 = generate_content_key();
        assert_ne!(key1, key2);
        assert!(key1.starts_with("xchacha20-key:"));
    }
}
