// `ca` and `x509` are daemon-side X.509 / SPIFFE cert minting. They depend
// on `rcgen`, which transitively requires ring's `SystemRandom` to satisfy
// the sealed `SecureRandom` trait — only true on non-wasm32 targets. Gate
// the modules and their re-exports off the wasm32 path so the ember-ext
// browser extension + the website's /verify-receipt.html WASM module build.
// Daemon binaries (ember-daemon, emberlink-cli, ember-proxy) keep full
// access on their native targets.
pub mod backup_envelope;
#[cfg(not(target_arch = "wasm32"))]
pub mod ca;
pub mod canonicalize;
pub mod did;
pub mod grant_chain;
pub mod persona;
pub mod presence;
pub mod secret_handle;
#[cfg(not(target_arch = "wasm32"))]
pub mod x509;

#[cfg(not(target_arch = "wasm32"))]
pub use ca::{
    BridgeIdentity, CaError, ca_fingerprint, extract_bridge_identity, generate_edge_ca,
    parse_csr_signed_by, parse_spiffe_uri, sign_client_cert,
};
pub use canonicalize::{CanonicalizeError, canonicalize_jcs};
pub use did::{
    DID_EMBERLINK_PREFIX, DidEmberlink, DidError, did_from_root_pubkey, parse_did, resolve_did_jwks,
};
pub use persona::{daemon_persona_sign_receipt, daemon_persona_verify_receipt};
#[cfg(not(target_arch = "wasm32"))]
pub use x509::{X509Error, mint_per_agent_ca_with_name_constraints, mint_per_agent_client_cert};

use age::Decryptor;
use age::secrecy::ExposeSecret;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use core_principals::KeyAlgorithm;
use core_types::{ValidationError, bytes_to_hex, hex_to_bytes};
use ed25519_dalek::{Signature as DalekSignature, Signer as DalekSigner, SigningKey, VerifyingKey};
use hkdf::Hkdf;
// `rand_core 0.10` removed `OsRng` and the `getrandom` feature. We use the
// `getrandom` crate directly for OS entropy — infallible on the platforms we
// target; `expect` here matches the previous behavior of `OsRng.fill_bytes`
// (which panicked internally on OS entropy failure).
use getrandom::fill as os_fill;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Domain separator constants.
//
// Every signed-message type in the protocol must bind a context tag so that
// a valid signature produced in one context cannot be replayed in another.
// All constants follow the `emberlink/v1/<context>` namespace established by
// the HKDF info-string registry above.
pub const DOMAIN_EVENT: &[u8] = b"emberlink/v1/event";
pub const DOMAIN_GRANT_OFFER: &[u8] = b"emberlink/v1/grant-offer";
pub const DOMAIN_GRANT_CHAIN: &[u8] = b"emberlink/v1/grant-chain";
pub const DOMAIN_PRESENTATION: &[u8] = b"emberlink/v1/presentation";
pub const DOMAIN_RECOVERY: &[u8] = b"emberlink/v1/recovery";

/// Sign `payload` under `signer` with a domain prefix.
///
/// The actual bytes fed to the signing primitive are `ctx || b"||" || payload`.
/// The `b"||"` separator ensures that no choice of `ctx` and `payload` can
/// produce the same byte sequence as a different `(ctx2, payload2)` pair.
pub fn sign_with_context(ctx: &[u8], signer: &(impl Signer + ?Sized), payload: &[u8]) -> Signature {
    let mut msg = Vec::with_capacity(ctx.len() + 2 + payload.len());
    msg.extend_from_slice(ctx);
    msg.extend_from_slice(b"||");
    msg.extend_from_slice(payload);
    signer.sign(&msg)
}

/// Verify `signature` over `payload` under `verifier` with a domain prefix.
///
/// Uses the same prefixing scheme as [`sign_with_context`].
pub fn verify_with_context(
    ctx: &[u8],
    verifier: &(impl Verifier + ?Sized),
    public_key: &PublicKey,
    payload: &[u8],
    sig: &Signature,
) -> bool {
    let mut msg = Vec::with_capacity(ctx.len() + 2 + payload.len());
    msg.extend_from_slice(ctx);
    msg.extend_from_slice(b"||");
    msg.extend_from_slice(payload);
    verifier.verify(public_key, &msg, sig)
}

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

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct LocalKeyPair {
    pub key_id: String,
    #[zeroize(skip)]
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

/// implementation-note-33 C6: probe trait that lets `LocalKeySigner`
/// refuse to sign when the underlying persona's status is anything
/// other than `active` (revoked, enrolling, archived, …). Injected at
/// signer construction time so `core-crypto` does not pull a SQLite or
/// `ember-daemon` dependency — the probe lives in whichever crate owns
/// the persona-status source-of-truth (typically `ember-daemon`).
///
/// Implementations are expected to be cheap (a single SQLite point
/// lookup, or a cached in-memory check). The probe is consulted on
/// every `try_sign` call so revocations land immediately rather than
/// surviving until the next signer rebuild.
pub trait PersonaActiveProbe: Send + Sync {
    /// Return `true` when the persona is in `active` status and signing
    /// is allowed; `false` for any other status (revoked, enrolling,
    /// archived, missing).
    fn is_active(&self) -> bool;
}

/// implementation-note-33 C6: error variant returned from
/// [`LocalKeySigner::try_sign`] when the attached
/// [`PersonaActiveProbe`] reports the persona is not active. Surfaced as
/// a fresh error rather than reusing `ValidationError` so call sites
/// can match on the specific "persona inactive" cause without parsing
/// strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerError {
    /// The probe attached to the signer reported the persona is not in
    /// `active` status. The signing operation refuses to proceed.
    PersonaNotActive,
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerError::PersonaNotActive => {
                write!(f, "signer refused: persona is not active")
            }
        }
    }
}

impl std::error::Error for SignerError {}

#[derive(Clone)]
pub struct LocalKeySigner {
    public_key: PublicKey,
    signing_key: SigningKey,
    /// implementation-note-33 C6 — optional probe consulted by
    /// [`LocalKeySigner::try_sign`]. `None` for legacy construction
    /// paths (tests + any caller predating C6) which means try_sign
    /// always succeeds. Production callers attach a probe via
    /// [`LocalKeySigner::with_probe`] so signing fails closed when the
    /// persona is revoked.
    probe: Option<std::sync::Arc<dyn PersonaActiveProbe>>,
}

impl std::fmt::Debug for LocalKeySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // SigningKey doesn't implement Debug in ed25519-dalek; the
        // probe is a trait object that doesn't implement Debug either.
        // Print only the public key so we don't leak private material.
        f.debug_struct("LocalKeySigner")
            .field("public_key", &self.public_key)
            .field("probe_attached", &self.probe.is_some())
            .finish()
    }
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
            probe: None,
        })
    }

    /// implementation-note-33 C6: attach a [`PersonaActiveProbe`] so
    /// [`Self::try_sign`] consults it before signing. Returns the same
    /// signer with the probe set — chains naturally off
    /// `from_local_key_pair`.
    pub fn with_probe(mut self, probe: std::sync::Arc<dyn PersonaActiveProbe>) -> Self {
        self.probe = Some(probe);
        self
    }

    /// implementation-note-33 C6: fallible signing entry point.
    /// Consults the attached [`PersonaActiveProbe`] (if any) and
    /// refuses to sign when the persona is not active. When no probe
    /// is attached, behaves identically to [`Signer::sign`].
    pub fn try_sign(&self, payload: &[u8]) -> Result<Signature, SignerError> {
        if let Some(ref probe) = self.probe
            && !probe.is_active()
        {
            return Err(SignerError::PersonaNotActive);
        }
        let signature = self.signing_key.sign(payload);
        Ok(Signature(encode_signature(&signature)))
    }
}

impl Signer for LocalKeySigner {
    /// implementation-note-33 C6 note: the legacy infallible `sign`
    /// remains for call sites that have not migrated to [`Self::try_sign`].
    /// When a probe is attached and reports the persona is inactive,
    /// this method panics with a clear message — fail-loud is preferred
    /// over silently producing a signature an inactive persona was not
    /// authorized to mint. Callers that need to handle the refusal
    /// gracefully must use [`Self::try_sign`].
    fn sign(&self, payload: &[u8]) -> Signature {
        if let Some(ref probe) = self.probe
            && !probe.is_active()
        {
            panic!(
                "LocalKeySigner::sign called on inactive persona — \
                 callers that may face an inactive persona must use \
                 LocalKeySigner::try_sign and handle SignerError::PersonaNotActive"
            );
        }
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
    os_fill(&mut secret_bytes).expect("OS entropy failure");
    let pair = local_key_pair_from_secret_bytes(key_id, secret_bytes);
    secret_bytes.zeroize();
    pair
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

// HKDF-SHA256 derivation registry.
//
// Every call site that calls `Hkdf::<Sha256>::new(...)` MUST use a unique,
// namespaced info string from this table. Adding a new derivation context
// requires adding a row here first to prevent cross-context key reuse.
//
// | info string (prefix)                         | output purpose                          |
// |----------------------------------------------|-----------------------------------------|
// | `emberlink/v1/content-key/<purpose>`         | XChaCha20-Poly1305 content key          |
//
// The `purpose` suffix is caller-supplied and MUST be a stable, lowercase
// hyphenated label (e.g. "vault-catalog", "vault-payload", "local-state").
// Info strings are intentionally stable. Never reuse or rename one once it
// has been used to derive keys in production.

/// Generate a content encryption key using HKDF-SHA256.
///
/// Random input keying material is fed through HKDF with a domain-separation
/// info string that incorporates `purpose` so keys for different contexts are
/// cryptographically independent even when the IKM source is the same.
///
/// `purpose` MUST be a stable, lowercase hyphenated label identifying the
/// encryption context (e.g. `"vault-catalog"`, `"vault-payload"`).
pub fn generate_content_key(purpose: &str) -> String {
    let mut ikm = [0u8; 32];
    os_fill(&mut ikm).expect("OS entropy failure");
    let info = format!("emberlink/v1/content-key/{purpose}");
    derive_content_key(&ikm, info.as_bytes())
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
    os_fill(&mut nonce).expect("OS entropy failure");
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

// HKDF info-string registry addition:
// | `ember-seal-v1`                               | Daemon Persona snapshot encryption key  |

/// Derive the 32-byte snapshot-encryption content key from an Ed25519 seed.
///
/// Uses HKDF-SHA256 with info string `"ember-seal-v1"`, mirroring the X25519
/// derivation described in design §The primitive and design. The result is
/// returned as an `xchacha20-key:...` prefixed string compatible with
/// [`encrypt_content`] and [`decrypt_content`].
///
/// This is the key used to seal vault snapshots — only the holder of the
/// Ed25519 seed (the Daemon Persona) can derive it and decrypt the snapshot.
pub fn derive_snapshot_encryption_key(ed25519_seed: &[u8]) -> String {
    let hk = Hkdf::<Sha256>::new(None, ed25519_seed);
    let mut okm = [0u8; 32];
    hk.expand(b"ember-seal-v1", &mut okm)
        .expect("HKDF-SHA256 expand cannot fail for 32-byte output");
    format!("{CONTENT_KEY_PREFIX}{}", bytes_to_hex(&okm))
}

/// Derive the EmberSeal X25519 recipient from an Ed25519 Daemon Persona seed.
///
/// Per design §The primitive and design:
///   1. HKDF-SHA256(seed, info="ember-seal-v1") → 32-byte X25519 private scalar.
///   2. Scalar × Curve25519 basepoint → X25519 public key (32 bytes, hex-encoded).
///
/// The returned string is the `recipientPubkey` value for the EmberSeal CR
/// (hex-encoded raw X25519 public key bytes, 64 hex chars).
///
/// Note: this is the *public key* for asymmetric encryption (NaCl box), not
/// the symmetric snapshot-encryption key from [`derive_snapshot_encryption_key`].
/// Both are derived from the same HKDF expansion of the Ed25519 seed but serve
/// different purposes.
pub fn derive_emberseal_x25519_recipient(ed25519_seed: &[u8]) -> String {
    let hk = Hkdf::<Sha256>::new(None, ed25519_seed);
    let mut scalar_bytes = [0u8; 32];
    hk.expand(b"ember-seal-v1", &mut scalar_bytes)
        .expect("HKDF-SHA256 expand cannot fail for 32-byte output");

    let static_secret = x25519_dalek::StaticSecret::from(scalar_bytes);
    let x25519_pubkey = x25519_dalek::PublicKey::from(&static_secret);
    bytes_to_hex(x25519_pubkey.as_bytes())
}

/// Extract raw 32-byte Ed25519 public key bytes from a `PublicKey` handle.
pub fn public_key_raw_bytes(public_key: &PublicKey) -> Result<[u8; 32], ValidationError> {
    let bytes = decode_prefixed_hex(&public_key.0, PUBLIC_KEY_PREFIX, 32)?;
    Ok(bytes)
}

/// An ephemeral X25519 keypair for grant offer exchange.
///
/// The public key is shared in the grant link. The private key is held
/// locally until the offer is claimed or expires, at which point it can
/// be discarded.
#[derive(Debug, Clone)]
pub struct EphemeralKeyPair {
    /// Hex-encoded age X25519 public key (the recipient address).
    pub public_key_hex: String,
    /// The raw age X25519 public key string (for encryption).
    pub public_key_age: String,
    /// The raw age X25519 private key string (for decryption).
    pub private_key_age: String,
}

/// Generate an ephemeral X25519 keypair for grant offer exchange.
///
/// Returns an [`EphemeralKeyPair`] whose public key can be embedded in
/// a grant link and whose private key can decrypt claim responses.
pub fn generate_ephemeral_keypair() -> EphemeralKeyPair {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    let public_key_age = recipient.to_string();
    // Hash the age public key string to get a stable hex representation
    let public_key_hex = sha256_digest_hex(public_key_age.as_bytes());
    EphemeralKeyPair {
        public_key_hex,
        public_key_age,
        private_key_age: identity.to_string().expose_secret().to_string(),
    }
}

/// Seal a grant offer payload to an ephemeral public key.
///
/// The payload (JSON-serialized grant parameters) is encrypted using
/// age X25519 so only the holder of the corresponding private key
/// can decrypt it.
pub fn seal_grant_payload(
    ephemeral_public_key_age: &str,
    payload: &[u8],
) -> Result<String, ValidationError> {
    wrap_secret_to_recipient(ephemeral_public_key_age, payload)
}

/// Unseal a grant offer payload using the ephemeral private key.
pub fn unseal_grant_payload(
    ephemeral_private_key_age: &str,
    sealed_hex: &str,
) -> Result<Vec<u8>, ValidationError> {
    unwrap_secret_with_identity(ephemeral_private_key_age, sealed_hex)
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

/// Encrypt `plaintext` to an age x25519 recipient and return the ciphertext
/// as an ASCII-armored age block (`-----BEGIN AGE ENCRYPTED FILE-----`...).
///
/// Used by the `ember vault export` operator-facing surface so the resulting
/// JSON envelope carries each value as a self-describing armored blob that
/// `ember vault import` can re-open with the corresponding x25519 identity.
/// See [`unwrap_armored_with_identity`] for the inverse.
pub fn wrap_secret_to_recipient_armored(
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
    let armored =
        age::armor::ArmoredWriter::wrap_output(&mut encrypted, age::armor::Format::AsciiArmor)
            .map_err(|err| ValidationError::new(format!("open armor wrapper: {err}")))?;
    let mut writer = encryptor
        .wrap_output(armored)
        .map_err(|err| ValidationError::new(format!("open recipient wrapper: {err}")))?;
    writer
        .write_all(plaintext)
        .map_err(|err| ValidationError::new(format!("write wrapped secret: {err}")))?;
    let armored = writer
        .finish()
        .map_err(|err| ValidationError::new(format!("finish wrapped secret: {err}")))?;
    armored
        .finish()
        .map_err(|err| ValidationError::new(format!("finish armor wrapper: {err}")))?;
    String::from_utf8(encrypted)
        .map_err(|err| ValidationError::new(format!("armored output not utf-8: {err}")))
}

/// Decrypt an ASCII-armored age block produced by
/// [`wrap_secret_to_recipient_armored`] using the matching x25519 identity.
pub fn unwrap_armored_with_identity(
    identity_private_key: &str,
    armored: &str,
) -> Result<Vec<u8>, ValidationError> {
    let identity = identity_private_key
        .parse::<age::x25519::Identity>()
        .map_err(|err| ValidationError::new(format!("invalid x25519 identity: {err}")))?;
    let armor_reader = age::armor::ArmoredReader::new(armored.as_bytes());
    let decryptor = Decryptor::new(armor_reader)
        .map_err(|err| ValidationError::new(format!("open armored secret: {err}")))?;
    let mut plaintext = Vec::new();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|err| ValidationError::new(format!("decrypt armored secret: {err}")))?;
    reader
        .read_to_end(&mut plaintext)
        .map_err(|err| ValidationError::new(format!("read armored secret: {err}")))?;
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
        verifying_key.verify_strict(payload, &signature).is_ok()
    }
}

fn local_key_pair_from_secret_bytes(key_id: String, mut secret_bytes: [u8; 32]) -> LocalKeyPair {
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    let pair = LocalKeyPair {
        key_id,
        algorithm: KeyAlgorithm::Ed25519,
        public_key: encode_public_key(&verifying_key),
        private_key: encode_private_key(&secret_bytes),
    };
    secret_bytes.zeroize();
    pair
}

fn random_hex_segment(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    os_fill(&mut bytes).expect("OS entropy failure");
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
    use std::sync::Arc;

    /// implementation-note-33 C6: `LocalKeySigner::try_sign` consults
    /// the attached `PersonaActiveProbe` and refuses to sign when the
    /// persona is not active. The test injects two probes (active and
    /// inactive) and asserts the corresponding outcome.
    #[test]
    fn sign_checks_persona_active() {
        struct InactiveProbe;
        impl PersonaActiveProbe for InactiveProbe {
            fn is_active(&self) -> bool {
                false
            }
        }
        struct ActiveProbe;
        impl PersonaActiveProbe for ActiveProbe {
            fn is_active(&self) -> bool {
                true
            }
        }

        let key_pair = generate_local_key_pair("root", "root-c6");

        // Inactive probe → try_sign refuses with SignerError::PersonaNotActive.
        let inactive_signer = LocalKeySigner::from_local_key_pair(&key_pair)
            .unwrap()
            .with_probe(Arc::new(InactiveProbe));
        assert_eq!(
            inactive_signer.try_sign(b"should-not-sign"),
            Err(SignerError::PersonaNotActive)
        );

        // Active probe → try_sign succeeds.
        let active_signer = LocalKeySigner::from_local_key_pair(&key_pair)
            .unwrap()
            .with_probe(Arc::new(ActiveProbe));
        let sig = active_signer
            .try_sign(b"should-sign")
            .expect("active probe should allow signing");
        let verifier = Ed25519Verifier;
        assert!(verifier.verify(&active_signer.public_key(), b"should-sign", &sig));

        // No probe attached → try_sign succeeds (legacy backward-compat).
        let no_probe_signer = LocalKeySigner::from_local_key_pair(&key_pair).unwrap();
        assert!(no_probe_signer.try_sign(b"legacy-no-probe").is_ok());
    }

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
        let key = generate_content_key("test");
        let encrypted = encrypt_content(&key, b"hello storage", b"manifest-1:0").unwrap();
        let decrypted = decrypt_content(&key, &encrypted, b"manifest-1:0").unwrap();

        assert_eq!(decrypted, b"hello storage");
    }

    #[test]
    fn content_encryption_rejects_wrong_aad() {
        let key = generate_content_key("test");
        let encrypted = encrypt_content(&key, b"hello storage", b"manifest-1:0").unwrap();

        assert!(decrypt_content(&key, &encrypted, b"manifest-1:1").is_err());
    }

    #[test]
    fn content_encryption_uses_random_nonces() {
        let key = generate_content_key("test");
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

    /// Info-string binding test: distinct HKDF info strings produce distinct keys.
    ///
    /// Verifies that the `emberlink/v1/content-key/<purpose>` info strings are
    /// unique per purpose. Same IKM with different purpose labels must produce
    /// cryptographically independent keys.
    #[test]
    fn hkdf_distinct_info_contexts_produce_distinct_keys() {
        let ikm = [0x5e_u8; 32];
        let content_key = derive_content_key(&ikm, b"emberlink/v1/content-key/vault-catalog");
        // A hand-rolled second context: same IKM, different info.
        let other_context = derive_content_key(&ikm, b"emberlink/v1/content-key/vault-payload");
        assert_ne!(
            content_key, other_context,
            "same IKM with different info strings must produce different keys"
        );
        assert!(content_key.starts_with("xchacha20-key:"));
        assert!(other_context.starts_with("xchacha20-key:"));
    }

    /// Same IKM + different `purpose` labels → different derived keys.
    #[test]
    fn generate_content_key_different_purposes_produce_different_keys() {
        let ikm = [0xa7_u8; 32];
        let key_catalog = derive_content_key(&ikm, b"emberlink/v1/content-key/vault-catalog");
        let key_payload = derive_content_key(&ikm, b"emberlink/v1/content-key/vault-payload");
        let key_state = derive_content_key(&ikm, b"emberlink/v1/content-key/local-state");
        assert_ne!(
            key_catalog, key_payload,
            "vault-catalog vs vault-payload must differ"
        );
        assert_ne!(
            key_catalog, key_state,
            "vault-catalog vs local-state must differ"
        );
        assert_ne!(
            key_payload, key_state,
            "vault-payload vs local-state must differ"
        );
    }

    #[test]
    fn generate_content_key_produces_unique_keys() {
        let key1 = generate_content_key("test");
        let key2 = generate_content_key("test");
        assert_ne!(key1, key2);
        assert!(key1.starts_with("xchacha20-key:"));
    }

    /// Domain-separation property: a signature produced under one domain does NOT verify
    /// under a different domain.
    #[test]
    fn cross_context_signatures_are_rejected() {
        let signer = FixtureSigner::new("sec1-cross-context");
        let payload = b"shared payload bytes";

        let sig_event = sign_with_context(DOMAIN_EVENT, &signer, payload);
        let sig_grant_offer = sign_with_context(DOMAIN_GRANT_OFFER, &signer, payload);

        let verifier = FixtureVerifier;

        // Each signature verifies in its own domain.
        assert!(
            verify_with_context(
                DOMAIN_EVENT,
                &verifier,
                &signer.public_key(),
                payload,
                &sig_event
            ),
            "DOMAIN_EVENT signature must verify in DOMAIN_EVENT"
        );
        assert!(
            verify_with_context(
                DOMAIN_GRANT_OFFER,
                &verifier,
                &signer.public_key(),
                payload,
                &sig_grant_offer
            ),
            "DOMAIN_GRANT_OFFER signature must verify in DOMAIN_GRANT_OFFER"
        );

        // Cross-domain: DOMAIN_EVENT signature must NOT verify under DOMAIN_GRANT_OFFER.
        assert!(
            !verify_with_context(
                DOMAIN_GRANT_OFFER,
                &verifier,
                &signer.public_key(),
                payload,
                &sig_event
            ),
            "DOMAIN_EVENT signature must NOT verify under DOMAIN_GRANT_OFFER"
        );

        // Cross-domain: DOMAIN_GRANT_OFFER signature must NOT verify under DOMAIN_EVENT.
        assert!(
            !verify_with_context(
                DOMAIN_EVENT,
                &verifier,
                &signer.public_key(),
                payload,
                &sig_grant_offer
            ),
            "DOMAIN_GRANT_OFFER signature must NOT verify under DOMAIN_EVENT"
        );
    }

    /// Torsion-point regression: `Ed25519Verifier` uses `verify_strict` which rejects
    /// signatures whose R component is a torsion (small-order) point.
    ///
    /// Signature malleability via torsion: Ed25519 has a cofactor of 8, so
    /// there are 8 small-order (torsion) points on the curve. A signature
    /// `(R, S)` where `R` is replaced by `R + T` (T = torsion point) still
    /// satisfies the cofactor-cleared verification equation used by `verify`,
    /// producing multiple valid signatures for the same message+key pair.
    ///
    /// `verify_strict` adds a low-order check on R: if R is (or contains) a
    /// small-order component, verification fails. This test uses a known
    /// torsion point from the Ed25519 curve as the R component of a crafted
    /// signature and asserts it is rejected.
    #[test]
    fn verify_strict_rejects_torsion_r_component() {
        use ed25519_dalek::SigningKey;

        let seed = [0x42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let public_hex = format!(
            "ed25519:{}",
            core_types::bytes_to_hex(&verifying_key.to_bytes())
        );
        let public_key = PublicKey(public_hex);

        // Known Ed25519 small-order (order-8 torsion) point in compressed form.
        // Source: ed25519-dalek's EIGHT_TORSION test vectors and RFC 8032 §5.1.
        // This point has order 8 on the Edwards curve and is definitively
        // rejected by verify_strict's low-order component check on R.
        let torsion_r_bytes: [u8; 32] = [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ];

        // Craft a 64-byte signature: torsion R || zero S.
        // The scalar S=0 is technically non-canonical but the R check fires
        // first in verify_strict, so the signature is rejected for torsion R.
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&torsion_r_bytes);
        // S bytes remain zero.

        let signature_hex = format!("ed25519sig:{}", core_types::bytes_to_hex(&sig_bytes));
        let signature = Signature(signature_hex);

        let verifier = Ed25519Verifier;
        assert!(
            !verifier.verify(&public_key, b"any message", &signature),
            "verify_strict must reject a signature with a torsion R component"
        );
    }
}
