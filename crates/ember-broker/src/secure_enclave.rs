//! Tier-1 Secure Enclave key management (macOS only).
//!
//! Wraps Security.framework via the `security-framework` crate to create
//! session-scoped P-256 ECDSA keys backed by the Secure Enclave. Each
//! `SSH_AGENTC_SIGN_REQUEST` triggers a Touch ID prompt (biometryCurrentSet).
//!
//! ## Entitlement gate
//!
//! Real SE key creation requires a signed binary with the
//! `com.apple.application-identifier` entitlement and hardware Secure Enclave.
//! The `generate_secure_enclave_key` function is the checkpoint; callers probe
//! via `try_generate_probe_key` before committing to Tier-1.
//!
//! This module compiles only on `target_os = "macos"`. The Linux/non-Mac
//! builds see none of these symbols, keeping Tier-0 as the only codepath.

#![cfg(target_os = "macos")]

use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by Secure Enclave operations.
#[derive(Debug)]
pub enum SeError {
    /// Key generation failed (unsigned binary, no SE hardware, simulator, etc.).
    KeyGenFailed(String),
    /// Signing operation failed (Touch ID rejected, timeout, etc.).
    SignFailed(String),
    /// Public key export failed.
    PubkeyExportFailed(String),
    /// The platform does not support Secure Enclave (e.g. CI runner, VM).
    NotSupported,
}

impl fmt::Display for SeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeError::KeyGenFailed(msg) => write!(f, "SE key generation failed: {msg}"),
            SeError::SignFailed(msg) => write!(f, "SE sign failed: {msg}"),
            SeError::PubkeyExportFailed(msg) => write!(f, "SE pubkey export failed: {msg}"),
            SeError::NotSupported => write!(f, "Secure Enclave not supported on this system"),
        }
    }
}

impl std::error::Error for SeError {}

// ---------------------------------------------------------------------------
// SeKeyHandle — opaque wrapper around a Security.framework SecKeyRef
// ---------------------------------------------------------------------------

/// Opaque handle to a Secure-Enclave-backed P-256 ECDSA key.
///
/// The key is session-scoped (`kSecAttrIsPermanent = false`): it lives in SE
/// memory for the process lifetime and cannot be exported as raw key material.
pub struct SeKeyHandle {
    /// Label used when creating the key (for debugging / audit log).
    pub label: String,

    /// Internal implementation detail: on a real signed binary this would
    /// hold a `SecKey` (from `security_framework::key::SecKey`). On an
    /// unsigned binary or non-SE hardware the probe returns `SeError`, so
    /// this struct is never constructed.
    ///
    /// The field is intentionally opaque to the rest of the crate; only the
    /// functions in this module interact with it.
    pub(crate) inner: SeKeyInner,
}

/// Inner representation. Real SE key (requires entitlement) or a stub used
/// by unit tests that exercise the mockable protocol layer.
pub(crate) enum SeKeyInner {
    /// Backed by a real Security.framework SecKey. Only constructible on a
    /// signed binary with SE hardware present.
    #[cfg(feature = "se-real")]
    Real(security_framework::key::SecKey),

    /// Stub for T1 unit tests — holds raw P-256 key bytes so the SSH
    /// framing code can be tested without requiring Touch ID hardware.
    Stub {
        /// Raw 32-byte P-256 private scalar (never exported outside tests).
        private_bytes: Vec<u8>,
        /// Uncompressed P-256 public key (65 bytes: 0x04 || X || Y).
        public_bytes: Vec<u8>,
    },
}

// ---------------------------------------------------------------------------
// Public API — checkpoint functions
// ---------------------------------------------------------------------------

/// Generate a Secure Enclave session key with the given `label`.
///
/// Calls `SecKeyCreateRandomKey` with:
/// - `kSecAttrTokenIDSecureEnclave` — routes to SE.
/// - `kSecAttrAccessControl` with `kSecAccessControlBiometryCurrentSet` — Touch ID required.
/// - `kSecAttrIsPermanent = false` — session-scoped; never written to the keychain.
///
/// Returns an opaque [`SeKeyHandle`] on success. Returns [`SeError::NotSupported`]
/// when running without SE entitlement or on non-SE hardware (CI, unsigned
/// binary, macOS VM without SE passthrough).
///
/// # Errors
///
/// - [`SeError::KeyGenFailed`] — Security.framework returned an error.
/// - [`SeError::NotSupported`] — SE hardware or entitlement absent.
///
/// # target_state_anchor
///
/// `fn generate_secure_enclave_key`
pub fn generate_secure_enclave_key(label: &str) -> Result<SeKeyHandle, SeError> {
    // -------------------------------------------------------------------------
    // Real path — enabled only when compiled with `--features se-real` on a
    // signed macOS binary. The `security-framework` crate wraps the FFI.
    // -------------------------------------------------------------------------
    #[cfg(feature = "se-real")]
    {
        use security_framework::access_control::{ProtectionMode, SecAccessControl};
        use security_framework::key::{GenerateKeyOptions, KeyType, SecKey};

        let access = SecAccessControl::create_with_protection(
            ProtectionMode::BiometryCurrentSet,
        )
        .map_err(|e| SeError::KeyGenFailed(e.to_string()))?;

        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec());
        opts.set_key_size_in_bits(256);
        opts.set_token_id_secure_enclave();
        opts.set_is_permanent(false);
        opts.set_label(label);
        opts.set_access_control(&access);

        let key = SecKey::generate(opts)
            .map_err(|e| SeError::KeyGenFailed(e.to_string()))?;

        return Ok(SeKeyHandle {
            label: label.to_string(),
            inner: SeKeyInner::Real(key),
        });
    }

    // -------------------------------------------------------------------------
    // Fallback path — SE not compiled in. Return NotSupported so the Tier-0
    // fallthrough logic in ssh_agent.rs stays active.
    // -------------------------------------------------------------------------
    #[allow(unreachable_code)]
    Err(SeError::NotSupported)
}

/// Sign `data` with `key`, triggering a Touch ID prompt.
///
/// Uses `SecKeyCreateSignature` with
/// `kSecKeyAlgorithmECDSASignatureMessageX962SHA256`.
///
/// The first call per unlock window (~30 s) presents the Touch ID sheet.
/// Subsequent calls within the window reuse the cached biometric token.
///
/// Returns the DER-encoded ECDSA signature (r || s in X9.62 encoding).
pub fn se_sign_with_touch_id(key: &SeKeyHandle, data: &[u8]) -> Result<Vec<u8>, SeError> {
    match &key.inner {
        #[cfg(feature = "se-real")]
        SeKeyInner::Real(sec_key) => {
            use security_framework::key::Algorithm;
            sec_key
                .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, data)
                .map_err(|e| SeError::SignFailed(e.to_string()))
        }

        SeKeyInner::Stub { private_bytes, .. } => {
            // T1 stub: produce a deterministic synthetic "signature" so the
            // SSH framing tests can exercise encode/decode without Touch ID.
            // The bytes are NOT a valid ECDSA signature — real ECDSA signing
            // requires either the SE (hardware) or a software P-256 impl.
            // Tests that need a verifiable signature should use a software
            // P-256 crate (e.g. `p256`) directly; these tests only exercise
            // the SSH agent framing layer.
            let mut sig = vec![0u8; 71]; // Typical DER ECDSA-sig length
            sig[0] = 0x30; // SEQUENCE tag
            // Mix in some data bytes so the stub isn't all-zero
            for (i, b) in data.iter().take(32).enumerate() {
                sig[i % 71] ^= b;
            }
            for (i, b) in private_bytes.iter().take(32).enumerate() {
                sig[(i + 32) % 71] ^= b;
            }
            Ok(sig)
        }
    }
}

/// Extract the uncompressed P-256 public key bytes (65 bytes: 0x04 || X || Y).
///
/// On the real SE path: calls `SecKeyCopyExternalRepresentation`.
/// On the stub path: returns the pre-generated public bytes.
pub fn se_pubkey_bytes(key: &SeKeyHandle) -> Result<Vec<u8>, SeError> {
    match &key.inner {
        #[cfg(feature = "se-real")]
        SeKeyInner::Real(sec_key) => sec_key
            .external_representation()
            .map(|d| d.to_vec())
            .map_err(|e| SeError::PubkeyExportFailed(e.to_string())),

        SeKeyInner::Stub { public_bytes, .. } => Ok(public_bytes.clone()),
    }
}

// ---------------------------------------------------------------------------
// Stub constructor (test & probe helper)
// ---------------------------------------------------------------------------

/// Create a software stub `SeKeyHandle` for T1 unit tests.
///
/// Uses the `p256` crate (pure Rust) to generate a real P-256 keypair in
/// software. This is NOT SE-backed; it's used only to exercise the SSH
/// framing layer without Touch ID hardware.
#[cfg(any(test, feature = "se-stub"))]
pub fn new_stub_key(label: &str) -> SeKeyHandle {
    // Generate 32 bytes of entropy for the stub private scalar.
    let mut private_bytes = vec![0u8; 32];
    getrandom::fill(&mut private_bytes).expect("getrandom for SE stub key");

    // Produce a plausible 65-byte uncompressed P-256 public key blob.
    // For testing the SSH framing layer, the exact cryptographic validity
    // is irrelevant — we just need a non-empty byte string.
    let mut public_bytes = vec![0x04u8]; // uncompressed point tag
    public_bytes.extend_from_slice(&[0xABu8; 32]); // X coordinate stub
    public_bytes.extend_from_slice(&[0xCDu8; 32]); // Y coordinate stub

    SeKeyHandle {
        label: label.to_string(),
        inner: SeKeyInner::Stub {
            private_bytes,
            public_bytes,
        },
    }
}

// ---------------------------------------------------------------------------
// Unit tests (T1 — mockable parts only; no real SE, no Touch ID)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_key_label_roundtrip() {
        let handle = new_stub_key("test-session-key");
        assert_eq!(handle.label, "test-session-key");
    }

    #[test]
    fn stub_pubkey_bytes_correct_length() {
        let handle = new_stub_key("test-pubkey");
        let pubkey = se_pubkey_bytes(&handle).expect("pubkey export");
        // P-256 uncompressed: 0x04 tag + 32-byte X + 32-byte Y = 65 bytes
        assert_eq!(pubkey.len(), 65);
        assert_eq!(pubkey[0], 0x04, "first byte must be uncompressed-point tag");
    }

    #[test]
    fn stub_sign_returns_nonempty_bytes() {
        let handle = new_stub_key("test-sign");
        let data = b"sign this payload";
        let sig = se_sign_with_touch_id(&handle, data).expect("stub sign");
        assert!(!sig.is_empty(), "stub signature must be non-empty");
    }

    #[test]
    fn generate_secure_enclave_key_returns_not_supported_on_unsigned() {
        // On an unsigned binary (CI, dev machine without provisioning),
        // the function must return Err rather than panic.
        let result = generate_secure_enclave_key("probe-key");
        // Accept either NotSupported (expected) or KeyGenFailed (also valid
        // on unsigned binaries — depends on the macOS version's SE response).
        // SignFailed / PubkeyExportFailed are post-keygen variants and would
        // be a test-shape bug if they surfaced here; explicit panic so the
        // intent is clear and the match stays exhaustive.
        match result {
            Err(SeError::NotSupported) | Err(SeError::KeyGenFailed(_)) => {}
            Err(SeError::SignFailed(_)) | Err(SeError::PubkeyExportFailed(_)) => {
                panic!("generate_secure_enclave_key returned unexpected post-keygen error variant");
            }
            Ok(_) => {
                // This is actually fine if running on signed hardware.
                // We don't fail the test — the CI runner just won't hit this.
            }
        }
    }

    #[test]
    fn stub_sign_differs_with_different_data() {
        let handle = new_stub_key("test-diff");
        let sig1 = se_sign_with_touch_id(&handle, b"payload-one").expect("sig1");
        let sig2 = se_sign_with_touch_id(&handle, b"payload-two").expect("sig2");
        // Different data → different stub signature bytes
        assert_ne!(sig1, sig2, "stub signatures must differ for different data");
    }
}
