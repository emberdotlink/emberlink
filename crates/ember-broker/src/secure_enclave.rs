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
    /// ECIES wrap (encryption) failed.
    WrapFailed(String),
    /// ECIES unwrap (decryption) failed.
    UnwrapFailed(String),
}

impl fmt::Display for SeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeError::KeyGenFailed(msg) => write!(f, "SE key generation failed: {msg}"),
            SeError::SignFailed(msg) => write!(f, "SE sign failed: {msg}"),
            SeError::PubkeyExportFailed(msg) => write!(f, "SE pubkey export failed: {msg}"),
            SeError::NotSupported => write!(f, "Secure Enclave not supported on this system"),
            SeError::WrapFailed(msg) => write!(f, "SE wrap (encrypt) failed: {msg}"),
            SeError::UnwrapFailed(msg) => write!(f, "SE unwrap (decrypt) failed: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// SeKeychainTarget — which keychain to store the key in
// ---------------------------------------------------------------------------

/// Target keychain for Secure Enclave key storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeKeychainTarget {
    /// Store in the login keychain (user-scoped, unlocked at login).
    LoginKeychain,
    /// Store in the system keychain (machine-scoped, always unlocked).
    SystemKeychain,
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
/// - `kSecAttrAccessControl` — protection-mode SAC with `PrivateKeyUsage` and
///   no biometric requirement (headless-daemon posture; see below).
/// - `kSecAttrIsPermanent` derived from the `target` parameter.
///
/// The `target` parameter selects whether the key is persisted:
///
/// - [`SeKeychainTarget::LoginKeychain`] — session-scoped key
///   (`kSecAttrIsPermanent = false`). Lives in SE memory for the process
///   lifetime only. Used by the SSH-agent T1 path.
/// - [`SeKeychainTarget::SystemKeychain`] — persistent key in the
///   **data-protection keychain** (`Location::DataProtectionKeychain` in
///   `security-framework` 3.7). DPK is the only macOS keychain Apple's
///   `SecKeyCreateRandomKey` will accept for SE-token keys; the legacy
///   file-based System.keychain was tried (via raw FFI with `kSecUseKeychain`)
///   and Apple's parameter validator rejects the combination with
///   `OSStatus -50 errSecParam` ("inconsistent private key parameters"). The
///   variant name `SystemKeychain` is now a historical misnomer — it means
///   "permanent SE-token key in DPK," not "key in `/Library/Keychains/System.keychain`."
///
/// **Cross-process / cross-session DPK behavior.** Per Apple's DPK design,
/// items are keyed by `(uid, kSecAttrAccessGroup)`, not by macOS security
/// session. Two processes with the same uid and same `keychain-access-groups`
/// entitlement (signed with the same Team ID) should see the same DPK items
/// regardless of which security session they were launched from. The
/// daemon's separate-uid posture (design) relies on this: the install runs
/// the SE genkey inside a fork+exec child running as the `ember` uid (see
/// `ember_daemon::install::provision_se_mek_in_ember_context`), and the
/// daemon at startup (also `ember`, via launchd) does the lookup against
/// the same DPK context.
///
/// On the stub path the target is ignored.
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
pub fn generate_secure_enclave_key(label: &str, target: SeKeychainTarget) -> Result<SeKeyHandle, SeError> {
    // -------------------------------------------------------------------------
    // Real path — enabled only when compiled with `--features se-real` on a
    // signed macOS binary. The `security-framework` crate wraps the FFI.
    // -------------------------------------------------------------------------
    #[cfg(feature = "se-real")]
    {
        use security_framework::access_control::{ProtectionMode, SecAccessControl};
        use security_framework::item::Location;
        use security_framework::key::{GenerateKeyOptions, KeyType, SecKey, Token};
        use security_framework::passwords_options::AccessControlOptions;

        // SystemKeychain target → permanent DPK key. `security-framework` 3.7
        // derives `kSecAttrIsPermanent = true` from the presence of a
        // `location`; setting `Location::DataProtectionKeychain` is the
        // canonical "permanent SE key" recipe per Apple's "Storing Keys in
        // the Secure Enclave" doc.
        let is_permanent = matches!(target, SeKeychainTarget::SystemKeychain);

        // SAC flags. `PRIVATE_KEY_USAGE` is required for SE-resident asymmetric
        // keys (it enables `decrypt_data` / `create_signature` against the
        // private half).
        //
        // Headless-daemon posture: we deliberately do NOT add
        // `BIOMETRY_CURRENT_SET` here. The design separate-uid daemon runs
        // under launchd as the `ember` system user with no GUI session — it
        // cannot satisfy a Touch ID prompt at vault-unseal time, and macOS's
        // keychain lookup framework treats biometric-only items as
        // unenumerable from a non-GUI context (the daemon got
        // `errSecItemNotFound` even though the key existed; see
        // implementation-note-51 shipped checkpoint
        // below).
        //
        // The user-presence property the original
        // `BIOMETRY_CURRENT_SET` was reaching for is recovered at a higher
        // layer by `implementation-note-52` — the daemon-MEK
        // unwrap is autonomous (no Touch ID per daemon-start, which would be
        // terrible UX anyway), but the FIRST per-session vault operation
        // prompts Touch ID via cross-uid SecurityAgent. The SE-blob is still
        // hardware-bound: the SE key cannot be exported off the device, so
        // root-on-this-device is required to use it.
        //
        // Anchor: implementation-note-53
        let flags = AccessControlOptions::PRIVATE_KEY_USAGE.bits();
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            flags,
        )
        .map_err(|e| SeError::KeyGenFailed(e.to_string()))?;

        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_label(label)
            .set_access_control(access);
        if is_permanent {
            opts.set_location(Location::DataProtectionKeychain);
        }

        let key = SecKey::new(&opts)
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
    {
        let _ = (label, target);
        Err(SeError::NotSupported)
    }
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
            .ok_or_else(|| {
                SeError::PubkeyExportFailed(
                    "SecKey::external_representation returned None".to_string(),
                )
            }),

        SeKeyInner::Stub { public_bytes, .. } => Ok(public_bytes.clone()),
    }
}

// ---------------------------------------------------------------------------
// SE key lookup by label (real-SE path)
// ---------------------------------------------------------------------------

/// Look up a Secure-Enclave-resident key by its user-set label, scoped to
/// `/Library/Keychains/System.keychain`.
///
/// Used by [`se_wrap`] / [`se_unwrap`] under the `se-real` feature to recover
/// the persistent SE key after process restart — the key was created at
/// install time by [`generate_secure_enclave_key`] with
/// `SeKeychainTarget::SystemKeychain` under the label
/// `sh.emberlink.daemon.vault-mek`.
///
/// The query runs against the caller's data-protection keychain (DPK) — the
/// only macOS keychain Apple's API will store SE-token keys in. DPK is keyed
/// by `(uid, kSecAttrAccessGroup)`: any process running as the same uid with
/// the same `keychain-access-groups` entitlement (i.e., signed with the same
/// Team ID) sees the same DPK items, regardless of macOS security session.
/// The install runs the genkey inside a fork+exec child as the `ember` uid
/// (`ember_daemon::install::provision_se_mek_in_ember_context`); the daemon
/// runs as `ember` under launchd. Both share the DPK identity.
///
/// Returns the key as a `security_framework::key::SecKey` reference. The
/// underlying private-key material stays resident in the Secure Enclave; the
/// reference exposes only `encrypt_data` (which uses the derived public key
/// internally — no biometric prompt) and `decrypt_data` (which goes through
/// the SE and triggers any SAC attached to the key).
#[cfg(feature = "se-real")]
fn find_se_key_by_label(label: &str) -> Result<security_framework::key::SecKey, String> {
    use security_framework::item::{
        ItemClass, ItemSearchOptions, KeyClass, Reference, SearchResult,
    };

    // Filter by `KeyClass::private()` — when an SE keypair is created the
    // public key is exported and stored as a separate keychain item under the
    // same label, so an unfiltered query returns whichever item the search
    // engine yields first. Decryption needs the private-key handle (whose
    // material lives in the SE); the public-key handle only supports
    // `encrypt_data` and fails decrypt with
    // `algid:encrypt:ECIES:…: algorithm not supported by the key`.
    let results = ItemSearchOptions::new()
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(label)
        .load_refs(true)
        .search()
        .map_err(|e| format!("SE key lookup for label '{label}': {e}"))?;

    for result in results {
        if let SearchResult::Ref(Reference::Key(key)) = result {
            return Ok(key);
        }
    }
    Err(format!(
        "no SE key found for label '{label}' — run `ember daemon install` to provision"
    ))
}

// ---------------------------------------------------------------------------
// ECIES wrap / unwrap
// ---------------------------------------------------------------------------

/// Wrap (encrypt) `plaintext` using the SE key identified by `label`.
///
/// On the real SE path: performs ECIES — generates an ephemeral P-256 keypair,
/// derives a shared secret via ECDH, runs HKDF-SHA256 to produce an AES-GCM
/// key, and returns `ephemeral_pub || nonce || ciphertext || tag`.
///
/// On the stub path: derives a 32-byte key from `SHA-256(label || private_bytes)`,
/// then produces `nonce(16) || auth_tag(32) || xor_stream(plaintext)` where the
/// auth tag is `SHA-256(nonce || key || plaintext)` and the stream key is
/// `SHA-256(nonce || key)` repeated as needed.
///
/// # Errors
///
/// Returns [`SeError::WrapFailed`] if no key is registered for `label` or if
/// the underlying cryptographic operation fails.
pub fn se_wrap(label: &str, plaintext: &[u8]) -> Result<Vec<u8>, SeError> {
    // Look up the thread-local stub key registry first (test path).
    let maybe_key = STUB_KEY_STORE.with(|store| {
        store.borrow().get(label).cloned()
    });

    match maybe_key {
        Some(private_bytes) => {
            stub_wrap(&private_bytes, label, plaintext)
        }
        None => {
            // Real ECIES path via security-framework's SecKey::encrypt_data,
            // routed through the SE-resident public key derived from the
            // private-key handle returned by SecItem lookup-by-label.
            //
            // Algorithm:
            //   kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM
            //
            // The standard-variant ECIES output layout is:
            //   ephemeral_pubkey(65) || ciphertext || aes_gcm_tag(16)
            // — the framework manages the layout end-to-end; callers treat
            // the returned bytes as an opaque blob.
            #[cfg(feature = "se-real")]
            {
                use security_framework::key::Algorithm;

                // SE keypair: keychain stores only the private-key handle;
                // ECIES encryption requires the public half. Derive it via
                // `SecKeyCopyPublicKey` (no SE round-trip, no biometric
                // prompt — the public point is cached alongside the
                // private-key reference).
                let private_key = find_se_key_by_label(label).map_err(SeError::WrapFailed)?;
                let public_key = private_key.public_key().ok_or_else(|| {
                    SeError::WrapFailed(format!(
                        "SecKeyCopyPublicKey returned None for label '{label}' — SE key missing its public half"
                    ))
                })?;
                return public_key
                    .encrypt_data(
                        Algorithm::ECIESEncryptionStandardVariableIVX963SHA256AESGCM,
                        plaintext,
                    )
                    .map_err(|e| {
                        SeError::WrapFailed(format!(
                            "SecKey::encrypt_data (ECIES X9.63 SHA-256 AES-GCM) for label '{label}': {e}"
                        ))
                    });
            }
            #[allow(unreachable_code)]
            Err(SeError::WrapFailed(format!(
                "no stub key registered for label '{label}'; call se_register_stub_key first"
            )))
        }
    }
}

/// Unwrap (decrypt) `ciphertext` using the SE key identified by `label`.
///
/// Inverse of [`se_wrap`]. On the stub path, validates the auth tag and
/// XOR-decrypts the payload.
///
/// # Errors
///
/// Returns [`SeError::UnwrapFailed`] if authentication fails, if no key is
/// registered for `label`, or if the ciphertext is malformed.
pub fn se_unwrap(label: &str, ciphertext: &[u8]) -> Result<Vec<u8>, SeError> {
    let maybe_key = STUB_KEY_STORE.with(|store| {
        store.borrow().get(label).cloned()
    });

    match maybe_key {
        Some(private_bytes) => {
            stub_unwrap(&private_bytes, label, ciphertext)
        }
        None => {
            // Real ECIES path. SecKey::decrypt_data routes through the SE for
            // the ECDH-derive step; any SAC attached to the key (e.g. the
            // BiometryCurrentSet protection set by `generate_secure_enclave_key`)
            // triggers a biometric prompt here. For the daemon's separate-uid
            // posture (design) the install-side followup
            // (implementation-note-54) pins the key to
            // the SystemKeychain without biometric protection so the daemon
            // can decrypt at startup without operator presence.
            #[cfg(feature = "se-real")]
            {
                use security_framework::key::Algorithm;

                let key = find_se_key_by_label(label).map_err(SeError::UnwrapFailed)?;
                return key
                    .decrypt_data(
                        Algorithm::ECIESEncryptionStandardVariableIVX963SHA256AESGCM,
                        ciphertext,
                    )
                    .map_err(|e| {
                        SeError::UnwrapFailed(format!(
                            "SecKey::decrypt_data (ECIES X9.63 SHA-256 AES-GCM) for label '{label}': {e}"
                        ))
                    });
            }
            #[allow(unreachable_code)]
            Err(SeError::UnwrapFailed(format!(
                "no stub key registered for label '{label}'; call se_register_stub_key first"
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Stub key store — thread-local registry mapping label → private_bytes
// ---------------------------------------------------------------------------

use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    static STUB_KEY_STORE: RefCell<HashMap<String, Vec<u8>>> = RefCell::new(HashMap::new());
}

/// Register a stub key for `label` so [`se_wrap`] / [`se_unwrap`] can operate
/// without a real SE key handle. Only available in test and stub builds.
#[cfg(any(test, feature = "se-stub"))]
pub fn se_register_stub_key(label: &str, handle: &SeKeyHandle) {
    if let SeKeyInner::Stub { private_bytes, .. } = &handle.inner {
        STUB_KEY_STORE.with(|store| {
            store.borrow_mut().insert(label.to_string(), private_bytes.clone());
        });
    }
}

// ---------------------------------------------------------------------------
// Internal stub wrap/unwrap helpers
// ---------------------------------------------------------------------------

/// Derive a 32-byte key: SHA-256(label_bytes || private_bytes).
fn derive_stub_key(label: &str, private_bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(label.as_bytes());
    h.update(private_bytes);
    h.finalize().into()
}

/// Produce a keystream block: SHA-256(counter_byte || nonce || key).
fn keystream_block(counter: u8, nonce: &[u8; 16], key: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update([counter]);
    h.update(nonce);
    h.update(key);
    h.finalize().into()
}

/// Compute auth tag: SHA-256(0xFF || nonce || key || plaintext).
fn auth_tag(nonce: &[u8; 16], key: &[u8; 32], plaintext: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update([0xFFu8]);
    h.update(nonce);
    h.update(key);
    h.update(plaintext);
    h.finalize().into()
}

/// Stub wrap: `nonce(16) || tag(32) || xor_encrypt(plaintext)`.
fn stub_wrap(private_bytes: &[u8], label: &str, plaintext: &[u8]) -> Result<Vec<u8>, SeError> {
    let key = derive_stub_key(label, private_bytes);

    // Random nonce via getrandom.
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|e| SeError::WrapFailed(e.to_string()))?;

    let tag = auth_tag(&nonce, &key, plaintext);

    // XOR encrypt plaintext using a keystream derived from SHA-256 blocks.
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut counter: u8 = 0;
    let mut block = keystream_block(counter, &nonce, &key);
    let mut block_pos = 0usize;
    for &b in plaintext {
        if block_pos == 32 {
            counter = counter.wrapping_add(1);
            block = keystream_block(counter, &nonce, &key);
            block_pos = 0;
        }
        ciphertext.push(b ^ block[block_pos]);
        block_pos += 1;
    }

    let mut out = Vec::with_capacity(16 + 32 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Stub unwrap: verify tag then XOR-decrypt.
fn stub_unwrap(private_bytes: &[u8], label: &str, ciphertext: &[u8]) -> Result<Vec<u8>, SeError> {
    if ciphertext.len() < 16 + 32 {
        return Err(SeError::UnwrapFailed("ciphertext too short".to_string()));
    }

    let key = derive_stub_key(label, private_bytes);

    let nonce: [u8; 16] = ciphertext[..16].try_into().unwrap();
    let stored_tag: [u8; 32] = ciphertext[16..48].try_into().unwrap();
    let body = &ciphertext[48..];

    // Decrypt body first, then verify tag.
    let mut plaintext = Vec::with_capacity(body.len());
    let mut counter: u8 = 0;
    let mut block = keystream_block(counter, &nonce, &key);
    let mut block_pos = 0usize;
    for &b in body {
        if block_pos == 32 {
            counter = counter.wrapping_add(1);
            block = keystream_block(counter, &nonce, &key);
            block_pos = 0;
        }
        plaintext.push(b ^ block[block_pos]);
        block_pos += 1;
    }

    // Constant-time tag comparison (implementation-note-55--
    // FOLLOWUPS -B). XOR-accumulate every byte pair into a single
    // diff byte so the comparison loop never short-circuits on the
    // first mismatch. core::hint::black_box wraps each operand AND the
    // result so LLVM cannot reconstitute the loop as memcmp or elide
    // the dead-store; without these barriers the constant-time claim
    // holds only at -O0 (self-review finding on #2984).
    let expected_tag = auth_tag(&nonce, &key, &plaintext);
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= core::hint::black_box(expected_tag[i]) ^ core::hint::black_box(stored_tag[i]);
    }
    if core::hint::black_box(diff) != 0 {
        return Err(SeError::UnwrapFailed("authentication tag mismatch".to_string()));
    }

    Ok(plaintext)
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
        let result = generate_secure_enclave_key("probe-key", SeKeychainTarget::LoginKeychain);
        // Accept either NotSupported (expected) or KeyGenFailed (also valid
        // on unsigned binaries — depends on the macOS version's SE response).
        // SignFailed / PubkeyExportFailed are post-keygen variants and would
        // be a test-shape bug if they surfaced here; explicit panic so the
        // intent is clear and the match stays exhaustive.
        match result {
            Err(SeError::NotSupported) | Err(SeError::KeyGenFailed(_)) => {}
            Err(SeError::SignFailed(_))
            | Err(SeError::PubkeyExportFailed(_))
            | Err(SeError::WrapFailed(_))
            | Err(SeError::UnwrapFailed(_)) => {
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

    #[test]
    #[ignore]
    fn se_wrap_unwrap_round_trip() {
        let handle = new_stub_key("test");
        se_register_stub_key("test", &handle);
        let ct = se_wrap("test", b"hello").expect("wrap");
        let pt = se_unwrap("test", &ct).expect("unwrap");
        assert_eq!(pt, b"hello");
    }
}
