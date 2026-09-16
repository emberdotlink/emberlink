//! Split custody for daemon-held credentials.
//!
//! The logged-in CLI may create and unwrap only the Secure Enclave outer
//! envelope. The dedicated daemon creates and opens the XChaCha20-Poly1305
//! inner envelope with its owner-private wrap key. The outer plaintext is an
//! encoded inner envelope, never credential plaintext.

use std::{fs, io, path::Path};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use p256::ecdsa::VerifyingKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

pub const CUSTODY_KEY_LABEL: &str = "link.ember.authority.github-app-custody.p256.v2";
pub const OUTER_ENVELOPE_ALGORITHM: &str = "ecies-cofactor-x963-sha256-aes-gcm";
pub const INNER_ENVELOPE_ALGORITHM: &str = "xchacha20-poly1305";
pub const DOUBLE_ENVELOPE_SCHEMA: &str = "ember.custody.double-envelope/v1";
pub const INNER_ENVELOPE_SCHEMA: &str = "ember.custody.inner-envelope/v1";
pub const CUSTODY_CONTEXT_SCHEMA: &str = "ember.custody.context/v1";
const OUTER_PAYLOAD_SCHEMA: &str = "ember.custody.outer-payload/v1";
const INNER_AAD_SCHEMA: &str = "ember.custody.inner-aad/v1";
const UNLOCK_CHALLENGE_SCHEMA: &str = "ember.custody.unlock-challenge/v1";
pub const CUSTODY_PUBLIC_KEY_BYTES: usize = 65;
pub const DAEMON_WRAP_KEY_BYTES: usize = 32;
const XCHACHA_NONCE_BYTES: usize = 24;
pub const MAX_SEALED_CREDENTIAL_BYTES: u64 = 1024 * 1024;
pub const CUSTODY_UNLOCK_CHALLENGE_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyPurpose {
    GithubAppPrivateKey,
}

/// Immutable identities authenticated by both envelope layers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyContext {
    schema: String,
    installation_id: Uuid,
    daemon_id: Uuid,
    purpose: CustodyPurpose,
}

impl CustodyContext {
    pub fn new(
        installation_id: Uuid,
        daemon_id: Uuid,
        purpose: CustodyPurpose,
    ) -> Result<Self, CustodyError> {
        let context = Self {
            schema: CUSTODY_CONTEXT_SCHEMA.to_owned(),
            installation_id,
            daemon_id,
            purpose,
        };
        context.validate()?;
        Ok(context)
    }

    pub fn installation_id(&self) -> Uuid {
        self.installation_id
    }

    pub fn daemon_id(&self) -> Uuid {
        self.daemon_id
    }

    pub fn purpose(&self) -> CustodyPurpose {
        self.purpose
    }

    fn validate(&self) -> Result<(), CustodyError> {
        if self.schema != CUSTODY_CONTEXT_SCHEMA
            || self.installation_id.is_nil()
            || self.daemon_id.is_nil()
        {
            return Err(CustodyError::InvalidContext);
        }
        Ok(())
    }
}

/// The daemon-only symmetric wrapping key. Its allocation zeroizes on drop.
pub struct DaemonWrapKey(Zeroizing<[u8; DAEMON_WRAP_KEY_BYTES]>);

impl DaemonWrapKey {
    /// Generates a wrap key inside the daemon provisioning boundary.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0_u8; DAEMON_WRAP_KEY_BYTES]);
        OsRng.fill_bytes(bytes.as_mut());
        Self(bytes)
    }

    /// Loads the daemon-owned key from owner-private persistent storage,
    /// consuming and zeroizing the file buffer.
    pub fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<Self, CustodyError> {
        if bytes.len() != DAEMON_WRAP_KEY_BYTES {
            return Err(CustodyError::InvalidDaemonWrapKey);
        }
        let mut key = Zeroizing::new([0_u8; DAEMON_WRAP_KEY_BYTES]);
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }
    /// Bytes for initial owner-private persistence. They must never cross the
    /// daemon/installer ownership boundary or appear in protocol payloads.
    pub fn persistence_bytes(&self) -> &[u8; DAEMON_WRAP_KEY_BYTES] {
        &self.0
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InnerEnvelopeWire {
    schema: String,
    algorithm: String,
    context: CustodyContext,
    nonce_hex: String,
    ciphertext_hex: String,
}

/// An opaque inner envelope produced by the dedicated daemon.
pub struct WrappedInner(InnerEnvelopeWire);

impl WrappedInner {
    fn validate(&self, expected_context: &CustodyContext) -> Result<(), CustodyError> {
        self.0.context.validate()?;
        if self.0.schema != INNER_ENVELOPE_SCHEMA
            || self.0.algorithm != INNER_ENVELOPE_ALGORITHM
            || &self.0.context != expected_context
        {
            return Err(CustodyError::MixedEnvelope);
        }
        let nonce = decode_lower_hex(&self.0.nonce_hex)?;
        let ciphertext = decode_lower_hex(&self.0.ciphertext_hex)?;
        if nonce.len() != XCHACHA_NONCE_BYTES
            || ciphertext.len() <= 16
            || ciphertext.len() as u64 > MAX_SEALED_CREDENTIAL_BYTES
        {
            return Err(CustodyError::InvalidCiphertext);
        }
        Ok(())
    }

    /// Canonical opaque bytes sent from the daemon to the logged-in CLI during
    /// provisioning. They contain only authenticated ciphertext.
    pub fn encode_for_relay(&self) -> Result<Vec<u8>, CustodyError> {
        canonical_encode(&self.0)
    }

    fn decode(bytes: &[u8], expected_context: &CustodyContext) -> Result<Self, CustodyError> {
        let inner = Self(canonical_decode(bytes)?);
        inner.validate(expected_context)?;
        Ok(inner)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct InnerAad<'a> {
    schema: &'static str,
    algorithm: &'static str,
    context: &'a CustodyContext,
}

/// Dedicated-daemon operation: encrypts credential plaintext into the inner
/// envelope. The returned value contains ciphertext only.
pub fn daemon_wrap_inner(
    plaintext: &[u8],
    wrap_key: &DaemonWrapKey,
    context: &CustodyContext,
) -> Result<WrappedInner, CustodyError> {
    context.validate()?;
    if plaintext.is_empty() || plaintext.len() as u64 > MAX_SEALED_CREDENTIAL_BYTES {
        return Err(CustodyError::InvalidPlaintext);
    }
    let aad = canonical_encode(&InnerAad {
        schema: INNER_AAD_SCHEMA,
        algorithm: INNER_ENVELOPE_ALGORITHM,
        context,
    })?;
    let mut nonce = [0_u8; XCHACHA_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(wrap_key.0.as_ref())
        .map_err(|_| CustodyError::InvalidDaemonWrapKey)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CustodyError::InnerSeal)?;
    let inner = WrappedInner(InnerEnvelopeWire {
        schema: INNER_ENVELOPE_SCHEMA.to_owned(),
        algorithm: INNER_ENVELOPE_ALGORITHM.to_owned(),
        context: context.clone(),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    });
    inner.validate(context)?;
    Ok(inner)
}

/// Dedicated-daemon operation: consumes only material returned by a fresh
/// outer unwrap relay and returns credential plaintext in zeroizing memory.
pub fn daemon_open_inner(
    relayed_inner: Zeroizing<Vec<u8>>,
    wrap_key: &DaemonWrapKey,
    expected_context: &CustodyContext,
) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
    expected_context.validate()?;
    let inner = WrappedInner::decode(&relayed_inner, expected_context)?;
    let nonce = decode_lower_hex(&inner.0.nonce_hex)?;
    let ciphertext = decode_lower_hex(&inner.0.ciphertext_hex)?;
    let aad = canonical_encode(&InnerAad {
        schema: INNER_AAD_SCHEMA,
        algorithm: INNER_ENVELOPE_ALGORITHM,
        context: expected_context,
    })?;
    let cipher = XChaCha20Poly1305::new_from_slice(wrap_key.0.as_ref())
        .map_err(|_| CustodyError::InvalidDaemonWrapKey)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CustodyError::InnerUnseal)?,
    );
    if plaintext.is_empty() {
        return Err(CustodyError::InvalidPlaintext);
    }
    Ok(plaintext)
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OuterPayload {
    schema: String,
    context: CustodyContext,
    inner_envelope_sha256: String,
    inner: InnerEnvelopeWire,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UnlockChallengePayload {
    schema: String,
    context: CustodyContext,
    unlock_id: String,
    challenge: [u8; CUSTODY_UNLOCK_CHALLENGE_BYTES],
}

impl Drop for UnlockChallengePayload {
    fn drop(&mut self) {
        self.challenge.zeroize();
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DoubleEnvelopeWire {
    schema: String,
    outer_algorithm: String,
    inner_algorithm: String,
    key_label: String,
    context: CustodyContext,
    inner_envelope_sha256: String,
    public_key_sec1_hex: String,
    ciphertext_hex: String,
}

/// Persisted double envelope. It intentionally contains no accessible copy of
/// the inner envelope; Secure Enclave unwrap is required to recover it.
pub struct DoubleEnvelope(DoubleEnvelopeWire);

impl DoubleEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>, CustodyError> {
        canonical_encode(&self.0)
    }

    pub fn decode(bytes: &[u8], expected_context: &CustodyContext) -> Result<Self, CustodyError> {
        let envelope = Self(canonical_decode(bytes)?);
        envelope.validate(expected_context)?;
        Ok(envelope)
    }

    pub fn context(&self) -> &CustodyContext {
        &self.0.context
    }

    pub fn inner_envelope_sha256(&self) -> &str {
        &self.0.inner_envelope_sha256
    }

    pub fn public_key_sec1(&self) -> Result<[u8; CUSTODY_PUBLIC_KEY_BYTES], CustodyError> {
        decode_public_key(&self.0.public_key_sec1_hex)
    }

    fn validate(&self, expected_context: &CustodyContext) -> Result<(), CustodyError> {
        self.0.context.validate()?;
        if self.0.schema != DOUBLE_ENVELOPE_SCHEMA
            || self.0.outer_algorithm != OUTER_ENVELOPE_ALGORITHM
            || self.0.inner_algorithm != INNER_ENVELOPE_ALGORITHM
            || self.0.key_label != CUSTODY_KEY_LABEL
            || &self.0.context != expected_context
        {
            return Err(CustodyError::MixedEnvelope);
        }
        decode_sha256(&self.0.inner_envelope_sha256)?;
        self.public_key_sec1()?;
        let ciphertext = decode_lower_hex(&self.0.ciphertext_hex)?;
        if ciphertext.is_empty() || ciphertext.len() as u64 > MAX_SEALED_CREDENTIAL_BYTES {
            return Err(CustodyError::InvalidCiphertext);
        }
        Ok(())
    }
}

pub(crate) struct SealedUnlockChallenge {
    pub(crate) unlock_id: Uuid,
    pub(crate) challenge: Zeroizing<[u8; CUSTODY_UNLOCK_CHALLENGE_BYTES]>,
    pub(crate) ciphertext: Vec<u8>,
}

/// Dedicated-daemon operation: creates a fresh challenge and encrypts its
/// context-bound payload to the persisted envelope's public key.
pub(crate) fn daemon_seal_unlock_challenge(
    envelope: &DoubleEnvelope,
    expected_context: &CustodyContext,
) -> Result<SealedUnlockChallenge, CustodyError> {
    envelope.validate(expected_context)?;
    let unlock_id = Uuid::new_v4();
    let mut challenge = Zeroizing::new([0_u8; CUSTODY_UNLOCK_CHALLENGE_BYTES]);
    OsRng.fill_bytes(challenge.as_mut());
    let payload = Zeroizing::new(encode_unlock_challenge_payload(
        expected_context,
        unlock_id,
        &challenge,
    )?);
    let ciphertext = platform::seal_to_public_key(&payload, &envelope.public_key_sec1()?)?;
    if ciphertext.is_empty() || ciphertext.len() as u64 > MAX_SEALED_CREDENTIAL_BYTES {
        return Err(CustodyError::InvalidCiphertext);
    }
    Ok(SealedUnlockChallenge {
        unlock_id,
        challenge,
        ciphertext,
    })
}

/// Logged-in CLI operation: decrypts a challenge with the exact Secure
/// Enclave key recorded by the double envelope, then validates every binding.
pub fn cli_unwrap_unlock_challenge(
    envelope: &DoubleEnvelope,
    expected_context: &CustodyContext,
    unlock_id: Uuid,
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; CUSTODY_UNLOCK_CHALLENGE_BYTES]>, CustodyError> {
    envelope.validate(expected_context)?;
    if ciphertext.is_empty() || ciphertext.len() as u64 > MAX_SEALED_CREDENTIAL_BYTES {
        return Err(CustodyError::InvalidCiphertext);
    }
    let public_key = envelope.public_key_sec1()?;
    let plaintext = Zeroizing::new(platform::unwrap_outer(ciphertext, &public_key)?);
    decode_unlock_challenge_payload(&plaintext, expected_context, unlock_id)
}

fn encode_unlock_challenge_payload(
    context: &CustodyContext,
    unlock_id: Uuid,
    challenge: &[u8; CUSTODY_UNLOCK_CHALLENGE_BYTES],
) -> Result<Vec<u8>, CustodyError> {
    context.validate()?;
    if unlock_id.is_nil() {
        return Err(CustodyError::InvalidUnlockChallenge);
    }
    canonical_encode(&UnlockChallengePayload {
        schema: UNLOCK_CHALLENGE_SCHEMA.to_owned(),
        context: context.clone(),
        unlock_id: unlock_id.to_string(),
        challenge: *challenge,
    })
}

fn decode_unlock_challenge_payload(
    bytes: &[u8],
    expected_context: &CustodyContext,
    expected_unlock_id: Uuid,
) -> Result<Zeroizing<[u8; CUSTODY_UNLOCK_CHALLENGE_BYTES]>, CustodyError> {
    expected_context.validate()?;
    if expected_unlock_id.is_nil() {
        return Err(CustodyError::InvalidUnlockChallenge);
    }
    let payload: UnlockChallengePayload = canonical_decode(bytes)?;
    let parsed_unlock_id =
        Uuid::parse_str(&payload.unlock_id).map_err(|_| CustodyError::InvalidUnlockChallenge)?;
    if payload.schema != UNLOCK_CHALLENGE_SCHEMA
        || &payload.context != expected_context
        || parsed_unlock_id != expected_unlock_id
        || payload.unlock_id != expected_unlock_id.to_string()
    {
        return Err(CustodyError::InvalidUnlockChallenge);
    }
    Ok(Zeroizing::new(payload.challenge))
}

/// A newly created outer envelope whose Secure Enclave key is rolled back
/// unless installation reaches its activation commit point.
pub struct PendingOuterSeal {
    envelope: DoubleEnvelope,
    enrollment: Option<platform::Enrollment>,
}

impl PendingOuterSeal {
    pub fn envelope(&self) -> &DoubleEnvelope {
        &self.envelope
    }

    pub fn commit(mut self) {
        if let Some(enrollment) = self.enrollment.take() {
            platform::commit(enrollment);
        }
    }
}

impl Drop for PendingOuterSeal {
    fn drop(&mut self) {
        if let Some(enrollment) = self.enrollment.take() {
            platform::rollback(enrollment);
        }
    }
}

/// Logged-in CLI operation for an inner envelope received over the daemon
/// provisioning relay. Destructive enrollment is permitted only while the
/// canonical installation activation marker is absent.
pub fn cli_wrap_outer_relay(
    relayed_inner: Zeroizing<Vec<u8>>,
    expected_context: &CustodyContext,
) -> Result<PendingOuterSeal, CustodyError> {
    let uid = crate::effective_uid();
    let activation_marker =
        crate::authority_state_directory(uid)?.join(crate::daemon::ACTIVATION_MARKER_FILE);
    cli_wrap_outer_relay_at(relayed_inner, expected_context, &activation_marker)
}

fn cli_wrap_outer_relay_at(
    relayed_inner: Zeroizing<Vec<u8>>,
    expected_context: &CustodyContext,
    activation_marker: &Path,
) -> Result<PendingOuterSeal, CustodyError> {
    require_fresh_enrollment(activation_marker)?;
    let inner_digest = Sha256::digest(relayed_inner.as_slice());
    let inner = WrappedInner::decode(&relayed_inner, expected_context)?;
    let pending = cli_wrap_outer(&inner, expected_context)?;
    if pending.envelope.0.inner_envelope_sha256 != hex::encode(inner_digest) {
        return Err(CustodyError::MixedEnvelope);
    }
    Ok(pending)
}

fn require_fresh_enrollment(activation_marker: &Path) -> Result<(), CustodyError> {
    match fs::symlink_metadata(activation_marker) {
        Ok(_) => Err(CustodyError::ActiveInstallation),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Logged-in CLI operation: applies the Secure Enclave outer envelope to an
/// already encrypted daemon-owned inner envelope.
pub fn cli_wrap_outer(
    inner: &WrappedInner,
    expected_context: &CustodyContext,
) -> Result<PendingOuterSeal, CustodyError> {
    expected_context.validate()?;
    inner.validate(expected_context)?;
    let inner_bytes = Zeroizing::new(inner.encode_for_relay()?);
    let inner_envelope_sha256 = hex::encode(Sha256::digest(inner_bytes.as_slice()));
    let payload = OuterPayload {
        schema: OUTER_PAYLOAD_SCHEMA.to_owned(),
        context: expected_context.clone(),
        inner_envelope_sha256: inner_envelope_sha256.clone(),
        inner: inner.0.clone(),
    };
    let payload = Zeroizing::new(canonical_encode(&payload)?);
    let (enrollment, public_key, ciphertext) = platform::wrap_outer(&payload)?;
    if ciphertext.is_empty() || ciphertext.len() as u64 > MAX_SEALED_CREDENTIAL_BYTES {
        platform::rollback(enrollment);
        return Err(CustodyError::InvalidCiphertext);
    }
    let envelope = DoubleEnvelope(DoubleEnvelopeWire {
        schema: DOUBLE_ENVELOPE_SCHEMA.to_owned(),
        outer_algorithm: OUTER_ENVELOPE_ALGORITHM.to_owned(),
        inner_algorithm: INNER_ENVELOPE_ALGORITHM.to_owned(),
        key_label: CUSTODY_KEY_LABEL.to_owned(),
        context: expected_context.clone(),
        inner_envelope_sha256,
        public_key_sec1_hex: hex::encode(public_key),
        ciphertext_hex: hex::encode(ciphertext),
    });
    envelope.validate(expected_context)?;
    Ok(PendingOuterSeal {
        envelope,
        enrollment: Some(enrollment),
    })
}

/// Logged-in CLI operation: removes only the Secure Enclave outer layer. The
/// returned bytes encode an authenticated inner envelope and are opaque to the
/// CLI; they are the only custody material sent to the dedicated daemon.
pub fn cli_unwrap_outer(
    envelope: &DoubleEnvelope,
    expected_context: &CustodyContext,
) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
    envelope.validate(expected_context)?;
    let ciphertext = decode_lower_hex(&envelope.0.ciphertext_hex)?;
    let public_key = envelope.public_key_sec1()?;
    let plaintext = Zeroizing::new(platform::unwrap_outer(&ciphertext, &public_key)?);
    let payload: OuterPayload = canonical_decode(&plaintext)?;
    if payload.schema != OUTER_PAYLOAD_SCHEMA
        || &payload.context != expected_context
        || payload.inner_envelope_sha256 != envelope.0.inner_envelope_sha256
    {
        return Err(CustodyError::MixedEnvelope);
    }
    let inner = WrappedInner(payload.inner);
    inner.validate(expected_context)?;
    let encoded_inner = Zeroizing::new(inner.encode_for_relay()?);
    if hex::encode(Sha256::digest(encoded_inner.as_slice())) != envelope.0.inner_envelope_sha256 {
        return Err(CustodyError::MixedEnvelope);
    }
    Ok(encoded_inner)
}

fn canonical_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CustodyError> {
    serde_jcs::to_vec(value).map_err(|_| CustodyError::MalformedEnvelope)
}

fn canonical_decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CustodyError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_SEALED_CREDENTIAL_BYTES {
        return Err(CustodyError::MalformedEnvelope);
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| CustodyError::MalformedEnvelope)?;
    if serde_jcs::to_vec(&value).map_err(|_| CustodyError::MalformedEnvelope)? != bytes {
        return Err(CustodyError::MalformedEnvelope);
    }
    serde_json::from_value(value).map_err(|_| CustodyError::MalformedEnvelope)
}

fn decode_lower_hex(value: &str) -> Result<Vec<u8>, CustodyError> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(CustodyError::MalformedEnvelope);
    }
    hex::decode(value).map_err(|_| CustodyError::MalformedEnvelope)
}

fn decode_public_key(value: &str) -> Result<[u8; CUSTODY_PUBLIC_KEY_BYTES], CustodyError> {
    let bytes = decode_lower_hex(value)?;
    validate_public_key(&bytes)?;
    bytes
        .try_into()
        .map_err(|_| CustodyError::MalformedEnvelope)
}

fn decode_sha256(value: &str) -> Result<[u8; 32], CustodyError> {
    decode_lower_hex(value)?
        .try_into()
        .map_err(|_| CustodyError::MalformedEnvelope)
}
fn validate_public_key(bytes: &[u8]) -> Result<(), CustodyError> {
    if bytes.len() != CUSTODY_PUBLIC_KEY_BYTES || bytes.first() != Some(&0x04) {
        return Err(CustodyError::MalformedEnvelope);
    }
    VerifyingKey::from_sec1_bytes(bytes)
        .map(|_| ())
        .map_err(|_| CustodyError::MalformedEnvelope)
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod platform {
    use super::*;
    use core_foundation::{
        base::{CFType, TCFType as _, ToVoid as _},
        data::CFData,
        dictionary::CFDictionary,
        error::{CFError, CFErrorRef},
        number::CFNumber,
        string::CFString,
    };
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::item::{
        ItemClass, ItemSearchOptions, KeyClass, Limit, Location, Reference, SearchResult,
    };
    use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
    use security_framework::passwords_options::AccessControlOptions;
    use security_framework_sys::{
        base::errSecItemNotFound,
        item::{
            kSecAttrKeyClass, kSecAttrKeyClassPublic, kSecAttrKeySizeInBits, kSecAttrKeyType,
            kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave,
        },
        key::SecKeyCreateWithData,
    };

    pub(super) struct Enrollment {
        key: SecKey,
    }

    pub(super) fn wrap_outer(
        opaque_inner: &[u8],
    ) -> Result<(Enrollment, [u8; CUSTODY_PUBLIC_KEY_BYTES], Vec<u8>), CustodyError> {
        let enrollment = enroll_fresh()?;
        let public_key_sec1 = match public_key_bytes(&enrollment.key) {
            Ok(public_key) => public_key,
            Err(error) => {
                rollback(enrollment);
                return Err(error);
            }
        };
        let Some(public_key) = enrollment.key.public_key() else {
            rollback(enrollment);
            return Err(CustodyError::BackendAuthenticity);
        };
        let ciphertext = match public_key.encrypt_data(
            Algorithm::ECIESEncryptionCofactorX963SHA256AESGCM,
            opaque_inner,
        ) {
            Ok(ciphertext) => ciphertext,
            Err(error) => {
                rollback(enrollment);
                return Err(CustodyError::OuterSeal(error.to_string()));
            }
        };
        Ok((enrollment, public_key_sec1, ciphertext))
    }

    pub(super) fn seal_to_public_key(
        plaintext: &[u8],
        public_key_sec1: &[u8; CUSTODY_PUBLIC_KEY_BYTES],
    ) -> Result<Vec<u8>, CustodyError> {
        validate_public_key(public_key_sec1)?;
        import_public_key(public_key_sec1)?
            .encrypt_data(
                Algorithm::ECIESEncryptionCofactorX963SHA256AESGCM,
                plaintext,
            )
            .map_err(|error| CustodyError::OuterSeal(error.to_string()))
    }

    fn import_public_key(
        public_key_sec1: &[u8; CUSTODY_PUBLIC_KEY_BYTES],
    ) -> Result<SecKey, CustodyError> {
        let key_data = CFData::from_buffer(public_key_sec1);
        let key_size = CFNumber::from(256_i32);
        unsafe {
            let attributes = CFDictionary::from_CFType_pairs(&[
                (
                    CFString::wrap_under_get_rule(kSecAttrKeyClass),
                    CFString::wrap_under_get_rule(kSecAttrKeyClassPublic).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrKeyType),
                    CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrKeySizeInBits),
                    key_size.as_CFType(),
                ),
            ]);
            let mut error: CFErrorRef = std::ptr::null_mut();
            let key = SecKeyCreateWithData(
                key_data.as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef(),
                &mut error,
            );
            if key.is_null() {
                if error.is_null() {
                    Err(CustodyError::BackendAuthenticity)
                } else {
                    Err(CustodyError::OuterSeal(
                        CFError::wrap_under_create_rule(error).to_string(),
                    ))
                }
            } else {
                if !error.is_null() {
                    drop(CFError::wrap_under_create_rule(error));
                }
                Ok(SecKey::wrap_under_create_rule(key))
            }
        }
    }

    pub(super) fn unwrap_outer(
        ciphertext: &[u8],
        expected_public_key: &[u8],
    ) -> Result<Vec<u8>, CustodyError> {
        find_exact_key(expected_public_key)?
            .decrypt_data(
                Algorithm::ECIESEncryptionCofactorX963SHA256AESGCM,
                ciphertext,
            )
            .map_err(|error| CustodyError::OuterUnseal(error.to_string()))
    }

    pub(super) fn commit(_enrollment: Enrollment) {}

    pub(super) fn rollback(enrollment: Enrollment) {
        let _ = delete_data_protection_key(&enrollment.key);
    }

    fn delete_data_protection_key(key: &SecKey) -> Result<(), CustodyError> {
        let application_label = key
            .application_label()
            .ok_or(CustodyError::BackendAuthenticity)?;
        let mut query = ItemSearchOptions::new();
        query
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(CUSTODY_KEY_LABEL)
            .application_label(&application_label)
            .ignore_legacy_keychains();
        query
            .delete()
            .map_err(|error| CustodyError::Lookup(error.to_string()))
    }

    fn enroll_fresh() -> Result<Enrollment, CustodyError> {
        // The public fresh-install entry point verifies that no activation
        // marker exists before existing same-label residue can be deleted.
        for key in labeled_keys()? {
            delete_data_protection_key(&key)?;
        }
        if !labeled_keys()?.is_empty() {
            return Err(CustodyError::DuplicateKeys);
        }
        generate_key()
    }

    fn generate_key() -> Result<Enrollment, CustodyError> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            (AccessControlOptions::PRIVATE_KEY_USAGE | AccessControlOptions::USER_PRESENCE).bits(),
        )
        .map_err(|error| CustodyError::Enrollment(error.to_string()))?;
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_label(CUSTODY_KEY_LABEL)
            .set_access_control(access)
            .set_location(Location::DataProtectionKeychain);
        let key =
            SecKey::new(&options).map_err(|error| CustodyError::Enrollment(error.to_string()))?;
        if !is_secure_enclave_key(&key) {
            let _ = delete_data_protection_key(&key);
            return Err(CustodyError::BackendAuthenticity);
        }
        if let Err(error) = public_key_bytes(&key) {
            let _ = delete_data_protection_key(&key);
            return Err(error);
        }
        Ok(Enrollment { key })
    }

    fn find_exact_key(expected_public_key: &[u8]) -> Result<SecKey, CustodyError> {
        let keys = labeled_keys()?;
        if keys.len() != 1 {
            return if keys.len() > 1 {
                Err(CustodyError::DuplicateKeys)
            } else {
                Err(CustodyError::BackendAuthenticity)
            };
        }
        let key = keys.into_iter().next().expect("one key");
        if !is_secure_enclave_key(&key) || public_key_bytes(&key)?.as_slice() != expected_public_key
        {
            return Err(CustodyError::BackendAuthenticity);
        }
        Ok(key)
    }

    fn labeled_keys() -> Result<Vec<SecKey>, CustodyError> {
        let mut query = ItemSearchOptions::new();
        query
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(CUSTODY_KEY_LABEL)
            .load_refs(true)
            .limit(Limit::All)
            .ignore_legacy_keychains();
        let results = match query.search() {
            Ok(results) => results,
            Err(error) if error.code() == errSecItemNotFound => Vec::new(),
            Err(error) => return Err(CustodyError::Lookup(error.to_string())),
        };
        let mut keys = Vec::with_capacity(results.len());
        for result in results {
            let SearchResult::Ref(Reference::Key(key)) = result else {
                return Err(CustodyError::BackendAuthenticity);
            };
            keys.push(key);
        }
        Ok(keys)
    }

    fn public_key_bytes(key: &SecKey) -> Result<[u8; CUSTODY_PUBLIC_KEY_BYTES], CustodyError> {
        let bytes = key
            .public_key()
            .ok_or(CustodyError::BackendAuthenticity)?
            .external_representation()
            .ok_or(CustodyError::BackendAuthenticity)?
            .to_vec();
        validate_public_key(&bytes)?;
        bytes
            .try_into()
            .map_err(|_| CustodyError::BackendAuthenticity)
    }

    fn is_secure_enclave_key(key: &SecKey) -> bool {
        if key.external_representation().is_some() {
            return false;
        }
        let attributes = key.attributes();
        let token_attribute = unsafe { kSecAttrTokenID };
        let Some(token) = attributes.find(token_attribute.to_void()) else {
            return false;
        };
        let actual = unsafe { CFType::wrap_under_get_rule((*token).cast()) };
        let enclave_token = unsafe { kSecAttrTokenIDSecureEnclave };
        let expected = unsafe { CFType::wrap_under_get_rule(enclave_token.cast()) };
        actual == expected
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::*;

    pub(super) struct Enrollment;

    pub(super) fn wrap_outer(
        _opaque_inner: &[u8],
    ) -> Result<(Enrollment, [u8; CUSTODY_PUBLIC_KEY_BYTES], Vec<u8>), CustodyError> {
        Err(CustodyError::UnsupportedPlatform)
    }

    pub(super) fn seal_to_public_key(
        _plaintext: &[u8],
        _public_key_sec1: &[u8; CUSTODY_PUBLIC_KEY_BYTES],
    ) -> Result<Vec<u8>, CustodyError> {
        Err(CustodyError::UnsupportedPlatform)
    }

    pub(super) fn unwrap_outer(
        _ciphertext: &[u8],
        _expected_public_key: &[u8],
    ) -> Result<Vec<u8>, CustodyError> {
        Err(CustodyError::UnsupportedPlatform)
    }

    pub(super) fn commit(_enrollment: Enrollment) {}
    pub(super) fn rollback(_enrollment: Enrollment) {}
}

#[derive(Debug, Error)]
pub enum CustodyError {
    #[error("outer custody requires macOS Secure Enclave in a logged-in user session")]
    UnsupportedPlatform,
    #[error("an active installation forbids destructive custody enrollment")]
    ActiveInstallation,
    #[error("custody activation-state check failed: {0}")]
    Io(#[from] io::Error),
    #[error("custody context is invalid")]
    InvalidContext,
    #[error("daemon wrap key is invalid")]
    InvalidDaemonWrapKey,
    #[error("custody plaintext is empty or oversized")]
    InvalidPlaintext,
    #[error("custody ciphertext is empty, malformed, or oversized")]
    InvalidCiphertext,
    #[error("custody envelope is malformed or non-canonical")]
    MalformedEnvelope,
    #[error("custody envelope layers, algorithms, or contexts do not match")]
    MixedEnvelope,
    #[error("custody unlock challenge is invalid or does not match")]
    InvalidUnlockChallenge,
    #[error("inner envelope encryption failed")]
    InnerSeal,
    #[error("inner envelope authentication failed")]
    InnerUnseal,
    #[error("multiple keys use the dedicated custody label")]
    DuplicateKeys,
    #[error("the located custody key is not the recorded Secure Enclave identity")]
    BackendAuthenticity,
    #[error("custody key enrollment failed: {0}")]
    Enrollment(String),
    #[error("custody key lookup failed: {0}")]
    Lookup(String),
    #[error("outer envelope encryption failed: {0}")]
    OuterSeal(String),
    #[error("outer envelope authentication failed: {0}")]
    OuterUnseal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> CustodyContext {
        CustodyContext::new(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            CustodyPurpose::GithubAppPrivateKey,
        )
        .unwrap()
    }

    #[test]
    fn daemon_inner_round_trip_requires_matching_key_and_context() {
        let context = context();
        let key = DaemonWrapKey::generate();
        let inner = daemon_wrap_inner(b"credential", &key, &context).unwrap();
        let encoded = Zeroizing::new(inner.encode_for_relay().unwrap());
        assert_eq!(
            daemon_open_inner(encoded, &key, &context)
                .unwrap()
                .as_slice(),
            b"credential"
        );

        let swapped =
            CustodyContext::new(Uuid::from_u128(3), context.daemon_id(), context.purpose())
                .unwrap();
        let encoded = Zeroizing::new(inner.encode_for_relay().unwrap());
        assert!(matches!(
            daemon_open_inner(encoded, &key, &swapped),
            Err(CustodyError::MixedEnvelope)
        ));

        let wrong_key = DaemonWrapKey::generate();
        let encoded = Zeroizing::new(inner.encode_for_relay().unwrap());
        assert!(matches!(
            daemon_open_inner(encoded, &wrong_key, &context),
            Err(CustodyError::InnerUnseal)
        ));
    }

    #[test]
    fn inner_envelope_rejects_mixed_algorithm_and_noncanonical_encoding() {
        let context = context();
        let key = DaemonWrapKey::generate();
        let inner = daemon_wrap_inner(b"credential", &key, &context).unwrap();
        let mut wire = inner.0.clone();
        wire.algorithm = OUTER_ENVELOPE_ALGORITHM.to_owned();
        let mixed = Zeroizing::new(canonical_encode(&wire).unwrap());
        assert!(matches!(
            daemon_open_inner(mixed, &key, &context),
            Err(CustodyError::MixedEnvelope)
        ));

        let mut noncanonical = inner.encode_for_relay().unwrap();
        noncanonical.push(b' ');
        assert!(matches!(
            daemon_open_inner(Zeroizing::new(noncanonical), &key, &context),
            Err(CustodyError::MalformedEnvelope)
        ));
    }
    #[test]
    fn outer_metadata_rejects_layer_and_context_swaps_before_platform_access() {
        let context = context();
        let public_key = p256::ecdsa::SigningKey::from_slice(&[7_u8; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_point(false);
        let envelope = DoubleEnvelope(DoubleEnvelopeWire {
            schema: DOUBLE_ENVELOPE_SCHEMA.to_owned(),
            outer_algorithm: OUTER_ENVELOPE_ALGORITHM.to_owned(),
            inner_algorithm: INNER_ENVELOPE_ALGORITHM.to_owned(),
            key_label: CUSTODY_KEY_LABEL.to_owned(),
            context: context.clone(),
            inner_envelope_sha256: hex::encode(Sha256::digest(b"inner")),
            public_key_sec1_hex: hex::encode(public_key.as_bytes()),
            ciphertext_hex: "00".to_owned(),
        });
        let encoded = envelope.encode().unwrap();
        DoubleEnvelope::decode(&encoded, &context).unwrap();

        let swapped = CustodyContext::new(
            context.installation_id(),
            Uuid::from_u128(3),
            context.purpose(),
        )
        .unwrap();
        assert!(matches!(
            DoubleEnvelope::decode(&encoded, &swapped),
            Err(CustodyError::MixedEnvelope)
        ));

        let mut mixed = envelope.0.clone();
        mixed.inner_algorithm = OUTER_ENVELOPE_ALGORITHM.to_owned();
        let mixed = canonical_encode(&mixed).unwrap();
        assert!(matches!(
            DoubleEnvelope::decode(&mixed, &context),
            Err(CustodyError::MixedEnvelope)
        ));
    }

    #[test]
    fn unlock_challenge_payload_round_trip_binds_schema_context_and_unlock_id() {
        let context = context();
        let unlock_id = Uuid::from_u128(9);
        let challenge = [0x5a; CUSTODY_UNLOCK_CHALLENGE_BYTES];
        let encoded = encode_unlock_challenge_payload(&context, unlock_id, &challenge).unwrap();
        assert_eq!(
            decode_unlock_challenge_payload(&encoded, &context, unlock_id)
                .unwrap()
                .as_slice(),
            challenge
        );

        let other_context =
            CustodyContext::new(Uuid::from_u128(3), context.daemon_id(), context.purpose())
                .unwrap();
        assert!(matches!(
            decode_unlock_challenge_payload(&encoded, &other_context, unlock_id),
            Err(CustodyError::InvalidUnlockChallenge)
        ));
        assert!(matches!(
            decode_unlock_challenge_payload(&encoded, &context, Uuid::from_u128(10)),
            Err(CustodyError::InvalidUnlockChallenge)
        ));
    }

    #[test]
    fn unlock_challenge_payload_rejects_noncanonical_id_and_encoding() {
        let context = context();
        let unlock_id = Uuid::from_u128(0xaaaaaaaa_aaaaaaaa_aaaaaaaa_aaaaaaaa);
        let mut payload = UnlockChallengePayload {
            schema: UNLOCK_CHALLENGE_SCHEMA.to_owned(),
            context: context.clone(),
            unlock_id: unlock_id.to_string().to_uppercase(),
            challenge: [7_u8; CUSTODY_UNLOCK_CHALLENGE_BYTES],
        };
        let encoded = canonical_encode(&payload).unwrap();
        assert!(matches!(
            decode_unlock_challenge_payload(&encoded, &context, unlock_id),
            Err(CustodyError::InvalidUnlockChallenge)
        ));

        payload.unlock_id = unlock_id.to_string();
        let mut noncanonical = canonical_encode(&payload).unwrap();
        noncanonical.push(b' ');
        assert!(matches!(
            decode_unlock_challenge_payload(&noncanonical, &context, unlock_id),
            Err(CustodyError::MalformedEnvelope)
        ));
    }

    #[test]
    fn context_requires_exact_non_nil_identities() {
        assert!(matches!(
            CustodyContext::new(
                Uuid::nil(),
                Uuid::from_u128(1),
                CustodyPurpose::GithubAppPrivateKey
            ),
            Err(CustodyError::InvalidContext)
        ));
        assert!(matches!(
            CustodyContext::new(
                Uuid::from_u128(1),
                Uuid::nil(),
                CustodyPurpose::GithubAppPrivateKey
            ),
            Err(CustodyError::InvalidContext)
        ));
    }

    #[test]
    fn fresh_enrollment_refuses_an_active_installation_before_platform_access() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("authority-active.json");
        fs::write(&marker, b"active").unwrap();

        assert!(matches!(
            require_fresh_enrollment(&marker),
            Err(CustodyError::ActiveInstallation)
        ));
    }
}
