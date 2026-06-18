//! Tier-1 Secure Enclave key management (macOS only).
//!
//! Wraps Security.framework via the `security-framework` crate to create
//! session-scoped P-256 ECDSA keys backed by the Secure Enclave. Interactive
//! keys can be provisioned either as recoverable `userPresence` keys or as
//! strict `biometryCurrentSet` keys depending on the requested policy.
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

/// Access-control posture for a Secure Enclave key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeAccessPolicy {
    /// Headless daemon posture: the key must be usable without a GUI session.
    Headless,
    /// Interactive host posture: Apple-native user presence is required, but
    /// the OS may fall back from biometry to other native proof surfaces.
    UserPresence,
    /// Interactive host posture: private-key use requires Touch ID.
    BiometricCurrentSet,
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
    #[allow(dead_code)]
    Stub {
        /// Raw 32-byte P-256 private scalar (never exported outside tests).
        private_bytes: Vec<u8>,
        /// Uncompressed P-256 public key (65 bytes: 0x04 || X || Y).
        public_bytes: Vec<u8>,
    },
}

// ---------------------------------------------------------------------------
// Role-typed key labels & handles (ADR 206 §4 / AC-3)
//
// macOS Secure Enclave does NOT enforce sign-vs-decrypt usage: one EC key
// performs both ECDSA (sign) and ECDH/ECIES (decrypt), and
// `kSecAttrCanSign`/`kSecAttrCanDecrypt` are keychain metadata hints — not
// enclave constraints — and are not even surfaced by `security-framework`
// 3.7's `GenerateKeyOptions`. So the sign-only vs ECIES-recipient separation a
// `presence` Device requires (ADR 206 AC-3) is enforced HERE, at the Rust
// type boundary: only a provisioning path mints a `SignKeyLabel` /
// `EciesKeyLabel`, the signing entry points take `SignKeyHandle`, and the
// ECIES entry points take `EciesKeyLabel`. Passing a wrong-role label/handle
// to the wrong operation is a COMPILE error — the only code with access to
// these SE keys cannot cross-use them by accident. The per-op guarantee that a
// captured gesture cannot become the other operation comes from the
// no-reuse-window property (`se_unwrap` uses `reuse_window=None`), not usage
// flags. See `reference_macos_se_no_usage_enforcement` and ADR 206 AC-3.
//
// RESIDUAL (closes in the ADR-206 enrollment/provisioning slice): the typed
// constructors below are the *sole* constructors (private fields), but they do
// not *validate* the role — `from_provisioned` stamps the asserted role onto
// whatever label/handle it is handed. `find_secure_enclave_key` /`SeKeyHandle`
// remain public escape hatches, so the "compile-error" guarantee is against
// *accidental* cross-use by code that goes through the typed entry points, NOT
// a hard barrier against a caller who independently re-casts a raw handle. The
// provisioning slice tightens this (constrain minting to the enrollment path).
// ---------------------------------------------------------------------------

/// A keychain label provisioned for a **sign-only** role (§1 presence proofs,
/// SSH-agent T1). Minted only via [`SignKeyLabel::from_provisioned`] by the
/// path that created or located `label` as a signing key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignKeyLabel(String);

impl SignKeyLabel {
    /// Tag `label` as a signing-role key. Call from the provisioning /
    /// enrollment path that owns the sign-key lifecycle — not ad-hoc at a
    /// random call site.
    pub fn from_provisioned(label: impl Into<String>) -> Self {
        Self(label.into())
    }

    /// The underlying keychain label string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A keychain label provisioned for an **ECIES-recipient** role (§4
/// decryption). Minted only via [`EciesKeyLabel::from_provisioned`] by the §4
/// key-provisioning path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EciesKeyLabel(String);

impl EciesKeyLabel {
    /// Tag `label` as an ECIES-recipient key. Call from the §4 provisioning
    /// path that owns the recipient-key lifecycle — not ad-hoc.
    pub fn from_provisioned(label: impl Into<String>) -> Self {
        Self(label.into())
    }

    /// The underlying keychain label string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A [`SeKeyHandle`] confirmed to be a **signing-role** key. The signing entry
/// points ([`se_sign_with_touch_id_reason`], [`se_sign_batch`]) take this, so
/// an ECIES key — reachable only via [`EciesKeyLabel`] — cannot be passed to a
/// signing operation: that is a compile error.
pub struct SignKeyHandle(SeKeyHandle);

impl SignKeyHandle {
    /// Wrap a handle the caller has provisioned/located as a signing key.
    /// The caller asserts the role; thereafter the type carries it.
    pub fn from_provisioned(handle: SeKeyHandle) -> Self {
        Self(handle)
    }

    /// The signing key's keychain label.
    pub fn label(&self) -> &str {
        &self.0.label
    }

    /// Export the uncompressed P-256 public-key bytes of the signing key.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, SeError> {
        se_pubkey_bytes(&self.0)
    }
}

/// Locate a persisted **signing** key by its role-typed label, returning a
/// [`SignKeyHandle`]. Thin wrapper over [`find_secure_enclave_key`] that
/// carries the sign role in the type.
pub fn find_sign_key(label: &SignKeyLabel) -> Result<SignKeyHandle, SeError> {
    find_secure_enclave_key(label.as_str()).map(SignKeyHandle::from_provisioned)
}

/// The set of messages that belong to **one operator intent**, signed under a
/// single Secure Enclave presence evaluation by [`se_sign_batch`].
///
/// Constructing a `SingleIntent` is the caller's explicit assertion that every
/// message is part of the *same* intent (e.g. the RootCreated +
/// PersonaCreated + DeviceEnrolled events of one `ember device enroll`). It
/// exists so the "one intent per call" boundary (ADR 206 §3 / Sequencing
/// step 0) is a **named type at the call site**, not a comment in
/// [`se_sign_batch`]. Per-op **widening** (`create_grant` / `vault_add`) must
/// keep one tap per op (AC-3, no standing window) and therefore MUST use the
/// single-message [`se_sign_with_touch_id_reason`] — it must never assemble a
/// multi-message `SingleIntent` spanning two distinct ops.
pub struct SingleIntent<'a>(&'a [&'a [u8]]);

impl<'a> SingleIntent<'a> {
    /// Declare `messages` as belonging to a single operator intent.
    pub fn new(messages: &'a [&'a [u8]]) -> Self {
        Self(messages)
    }

    fn messages(&self) -> &[&[u8]] {
        self.0
    }
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
/// daemon's separate-uid posture (ADR 131) relies on this: the install runs
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
pub fn generate_secure_enclave_key(
    label: &str,
    target: SeKeychainTarget,
) -> Result<SeKeyHandle, SeError> {
    generate_secure_enclave_key_with_policy(label, target, SeAccessPolicy::Headless)
}

/// Whether this build is compiled against the **real** Secure Enclave backend
/// (`--features se-real` on a signed macOS binary) rather than the in-memory
/// software stub used by tests / CI / unsigned builds.
///
/// Load-bearing for security: a caller that enrolls a key as an operator
/// *presence device* (ADR 200 §3) MUST refuse to proceed when this returns
/// `false`, or it would bind a software key — exportable, not hardware-bound,
/// no human-presence gate — as if it were a Secure-Enclave presence factor. The
/// stub exists only so the orchestration logic is testable headlessly.
pub fn se_backend_is_real() -> bool {
    cfg!(feature = "se-real")
}

/// Whether the **software stub** SE backend is compiled into this build
/// (`feature = "se-stub"`). The stub's `STUB_KEY_STORE` is consulted *before*
/// the real ECIES path by `se_wrap`/`se_unwrap`, and `se_register_stub_key`
/// injects keys into it — so a build with the stub compiled in can have an
/// exportable software key stand in for a hardware presence factor. The stub
/// is therefore a **dev-only** feature (declared in `[dev-dependencies]`, not
/// regular `[dependencies]`, so resolver-2 keeps it out of production builds).
/// Authority-bearing seal paths assert `se_backend_is_real() && !se_stub_is_active()`
/// so a stub that ever leaks into a production build fails closed rather than
/// silently sealing under software. (ADR 206 §4 / closure-pass finding #9.)
pub fn se_stub_is_active() -> bool {
    cfg!(feature = "se-stub")
}

/// Generate a Secure Enclave key with an explicit access-control policy.
pub fn generate_secure_enclave_key_with_policy(
    label: &str,
    target: SeKeychainTarget,
    policy: SeAccessPolicy,
) -> Result<SeKeyHandle, SeError> {
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
        let flags = match policy {
            // Headless-daemon posture: we deliberately do NOT add
            // `BIOMETRY_CURRENT_SET` here. The ADR 131 separate-uid daemon
            // runs under launchd in the **System/0 Mach bootstrap domain**,
            // where macOS DPK returns `-25291 errSecNotAvailable` at session
            // open. The corrected 2026-06-09 7-test probe matrix directly
            // tested SE create + find from System/0 and confirmed both fail;
            // because -25291 is a session-open / domain-level error rather
            // than per-op, every subsequent SE operation (sign, unwrap,
            // public-key wrap, delete) is blocked by construction from this
            // domain.
            //
            // Two earlier comments in this module attributed this constraint
            // incorrectly. First, ADR 151 attributed it to "no GUI session"
            // and Mach-bootstrap-domain partition; PR #5785 then partially
            // corrected ADR 151 to code-identity-as-a-gate but also wrongly
            // DISMISSED "session shape" as a gate at all — that "not session
            // shape" half of #5785 was itself wrong. The 2026-06-09 matrix
            // vindicates ADR 151 V1: both code identity AND Mach bootstrap
            // domain are INDEPENDENT gates (necessary, neither sufficient
            // alone). Second, PR #5788 then attributed the failure to
            // "uid-keyed biometric enrollment" — the 2026-06-08 probe behind
            // that amendment used `sudo -u ember` which inherits the parent
            // shell's Aqua/501 bootstrap domain rather than System/0,
            // masking the System/0 failure. The 2026-06-09 matrix is the
            // third correction in the chain.
            //
            // The matrix proved DPK is partitioned into three mutually-
            // invisible Mach bootstrap session domains: System/0
            // (LaunchDaemon) returns `-25291 errSecNotAvailable`;
            // Background/450 (user/450 domain via `launchctl asuser 450`)
            // returns `-25308 errSecInteractionNotAllowed`; Aqua/501
            // (operator GUI) succeeds. The daemon at System/0 cannot reach
            // the SE at all — this is a Mach-bootstrap-domain DPK partition
            // enforced by securityd, not a policy gate the daemon can
            // override.
            //
            // The user-presence property the original `BIOMETRY_CURRENT_SET`
            // was reaching for is recovered by ADR 216 (double-envelope SE
            // custody via CLI presence relay): outer envelope = SE ECIES
            // sealed in Aqua/501 (where SE works); inner envelope = DWK
            // symmetric daemon-side. The CLI is a pure relay of opaque
            // blobs; the daemon never sees raw key material. See
            // `docs/adr/216-*.md` and ADR 206 §4.
            //
            SeAccessPolicy::Headless => AccessControlOptions::PRIVATE_KEY_USAGE.bits(),
            SeAccessPolicy::UserPresence => (AccessControlOptions::PRIVATE_KEY_USAGE
                | AccessControlOptions::USER_PRESENCE)
                .bits(),
            SeAccessPolicy::BiometricCurrentSet => (AccessControlOptions::PRIVATE_KEY_USAGE
                | AccessControlOptions::BIOMETRY_CURRENT_SET)
                .bits(),
        };
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

        let key = SecKey::new(&opts).map_err(|e| SeError::KeyGenFailed(e.to_string()))?;

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
        let _ = (label, target, policy);
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
pub fn se_sign_with_touch_id(key: &SignKeyHandle, data: &[u8]) -> Result<Vec<u8>, SeError> {
    se_sign_with_touch_id_reason(
        key,
        data,
        "Authenticate to continue the requested Ember operation",
    )
}

/// Sign `data` with `key`, triggering a Touch ID prompt with a caller-supplied
/// localized reason.
pub fn se_sign_with_touch_id_reason(
    key: &SignKeyHandle,
    data: &[u8],
    reason: &str,
) -> Result<Vec<u8>, SeError> {
    let key = &key.0;
    match &key.inner {
        #[cfg(feature = "se-real")]
        SeKeyInner::Real(sec_key) => {
            use security_framework::key::Algorithm;
            let signing_key = find_se_key_by_label_with_reason(&key.label, reason)
                .unwrap_or_else(|_| sec_key.clone());
            signing_key
                .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, data)
                .map_err(|e| SeError::SignFailed(e.to_string()))
        }

        SeKeyInner::Stub { private_bytes, .. } => {
            use p256::SecretKey;
            use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
            use sha2::{Digest, Sha256};

            let secret = SecretKey::from_slice(private_bytes)
                .map_err(|e| SeError::SignFailed(format!("stub secret key decode: {e}")))?;
            let signing_key = SigningKey::from(secret);
            let digest = Sha256::digest(data);
            let signature: Signature = signing_key
                .sign_prehash(&digest)
                .map_err(|e| SeError::SignFailed(format!("stub sign prehash: {e}")))?;
            Ok(signature.to_der().as_bytes().to_vec())
        }
    }
}

/// Sign every message in `messages` with `key` under a **single** Secure Enclave
/// presence evaluation — one Touch ID tap covers all N signatures. Returns one
/// DER-encoded ECDSA signature per input, in order.
///
/// ## Load-bearing security boundary (do not widen)
///
/// Batching the presence proof is valid ONLY because all N messages belong to a
/// SINGLE operator intent (e.g. the RootCreated + PersonaCreated + DeviceEnrolled
/// events of one `ember device enroll`). The reuse window that makes the N rapid
/// signatures ride one tap is created **inside this call**, on a fresh
/// `LAContext` that is dropped on return: the function never accepts, returns, or
/// stores a context, so the window is structurally incapable of outliving a
/// single call — it can never span two distinct intents.
///
/// Per-op **widening** (G1 `create_grant` / `vault_add`) MUST keep one tap per
/// op (ADR 200 AC-3: per-op tap, no standing TTL window — the daemon is both the
/// gate and the dispatcher, so it must not ride an open window to manufacture
/// authority). The widening client driver consumes this primitive with EXACTLY
/// ONE message per call, which yields exactly one tap per op and no cross-op
/// window. Callers must never pass two different ops' blobs in one call.
///
/// "One intent per call" is now carried by the [`SingleIntent`] token in this
/// signature (ADR 206 Sequencing step 0): constructing a `SingleIntent` is the
/// caller's single-intent assertion, so the boundary is a named type at the
/// call site rather than a comment. Per-op **widening** must still use the
/// single-message [`se_sign_with_touch_id_reason`] and must never assemble a
/// multi-op `SingleIntent`. (Full contract on [`SingleIntent`] — kept brief
/// here to avoid two sources of truth.)
pub fn se_sign_batch(
    key: &SignKeyHandle,
    intent: SingleIntent<'_>,
    reason: &str,
) -> Result<Vec<Vec<u8>>, SeError> {
    let messages = intent.messages();
    match &key.0.inner {
        #[cfg(feature = "se-real")]
        SeKeyInner::Real(sec_key) => {
            use security_framework::key::Algorithm;
            // ONE pre-authenticated context, ONE key lookup, N signatures. The
            // first create_signature presents the Touch ID sheet; the rest ride
            // the per-intent reuse window carried by this context.
            //
            // Fallback note: if the keychain lookup fails we sign with the
            // already-held `sec_key`, which carries NO reuse window — each
            // signature would then prompt independently. That degrades toward
            // MORE presence prompts, never fewer, so it is fail-safe for the
            // security boundary (it can only cost extra taps, never skip one).
            let signing_key = find_se_key_by_label_batched(&key.0.label, reason)
                .unwrap_or_else(|_| sec_key.clone());
            let mut out = Vec::with_capacity(messages.len());
            for msg in messages {
                let der = signing_key
                    .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, msg)
                    .map_err(|e| SeError::SignFailed(e.to_string()))?;
                out.push(der);
            }
            Ok(out)
        }

        // Stub path: no biometric prompt exists, so per-message signing is
        // equivalent. Reuse the single-sign path for byte-for-byte parity with
        // the daemon's verifier interop test.
        SeKeyInner::Stub { .. } => messages
            .iter()
            .map(|m| se_sign_with_touch_id_reason(key, m, reason))
            .collect(),
    }
}

/// The two cryptographic operations of **one widening operator intent** (ADR
/// 206 §1 + §4): the §1 authorization signature over the daemon-issued
/// nonce-bound intent bytes, AND the §4 `KEK_s` unwrap that opens the op's
/// sealing/decryption scope. Both ride a SINGLE Secure Enclave presence
/// evaluation — one Touch ID tap authorizes the widen AND opens its scope.
///
/// Constructing a `WideningGesture` is the caller's explicit assertion that the
/// signature and the unwrap belong to the SAME operator intent (e.g.
/// `create_persona` + opening the persona-scope `KEK_s` to seal the new
/// persona's secret). The role separation between the two SE keys is carried in
/// the TYPES, not here: the sign half takes a [`SignKeyHandle`] (reachable only
/// via [`SignKeyLabel`]) and the unwrap half takes an [`EciesKeyLabel`] (AC-3,
/// compile-enforced), so the §1 signing key can never be used as the §4 ECIES
/// recipient or vice versa.
pub struct WideningGesture<'a> {
    /// The §1 intent bytes the presence Device signs (the daemon-computed
    /// `canonical_presence_intent_bytes` for this exact widening op).
    pub intent_bytes: &'a [u8],
    /// The §4 wrapped scope KEK (`wrap(ecies_pub, KEK_s)`) for the op's scope.
    pub wrapped_kek: &'a [u8],
}

impl<'a> WideningGesture<'a> {
    /// Declare a §1 signature over `intent_bytes` and a §4 unwrap of
    /// `wrapped_kek` as belonging to a single widening operator intent.
    pub fn new(intent_bytes: &'a [u8], wrapped_kek: &'a [u8]) -> Self {
        Self {
            intent_bytes,
            wrapped_kek,
        }
    }
}

/// ADR 206 §1 + §4 — the **unified widening gesture**: under a SINGLE Secure
/// Enclave presence evaluation (one Touch ID tap), produce BOTH the §1
/// authorization signature over `gesture.intent_bytes` (on the sign-only
/// `sign_key`) AND the §4 unwrapped scope `KEK_s` from `gesture.wrapped_kek` (on
/// the ECIES-recipient `ecies_key`). Returns `(signature_der, Zeroizing(kek))`.
///
/// ## How one tap covers two keys
///
/// A `.userPresence` SE key honors an `LAContext`'s
/// `touchIDAuthenticationAllowableReuseDuration`: a presence-gated key operation
/// performed against an already-evaluated context rides the first tap instead of
/// re-prompting. This call creates **one** such context, performs the sign and
/// the unwrap against the SAME context, and drops it on return — so the reuse
/// window is structurally incapable of outliving this single call and can never
/// span two operator intents. This is the cross-key generalization of
/// [`se_sign_batch`]'s one-tap boundary (which rides one tap across N signatures
/// on one key); here it rides one tap across a sign (sign key) and a decrypt
/// (ECIES key). `security-framework`'s `authentication_context` ADOPTS the +1
/// reference it is given (Create Rule — it does not add its own retain) and
/// releases it when the query drops, so the context is `retain`'d once more to
/// hand the unwrap query its own owned reference — both queries reference the
/// same underlying `LAContext`, sharing its one biometric evaluation, and the
/// two references balance to zero on return.
///
/// ## Hardware-validated (real Apple SE, 2026-06-04)
///
/// A shared, explicit-reuse-window `LAContext` collapses a SIGN (sign key)
/// followed by an ECDH-DECRYPT (ECIES key) to ONE prompt — confirmed on real
/// Secure Enclave hardware (one Touch ID tap covers both ops). If a future OS
/// regressed this to two prompts it would be a safe, fail-closed two-tap, not a
/// security hole — each op still requires a live presence gesture. The
/// `#[ignore]`d `se_sign_and_unwrap_*` hardware test (run via
/// `scripts/dev-sign-se.sh`) remains the regression vehicle.
///
/// ## Fail-closed
///
/// A declined tap (or a decrypt failure on a tampered `wrapped_kek`) returns
/// `Err` — the caller MUST propagate it and never proceed. The signature is
/// produced first; if it succeeds but the unwrap fails, the partial signature is
/// dropped with the `Err` and the caller acquires nothing usable.
pub fn se_sign_and_unwrap(
    sign_key: &SignKeyHandle,
    ecies_key: &EciesKeyLabel,
    gesture: WideningGesture<'_>,
    reason: &str,
) -> Result<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>), SeError> {
    match &sign_key.0.inner {
        #[cfg(feature = "se-real")]
        SeKeyInner::Real(sec_key) => {
            use security_framework::item::{
                ItemClass, ItemSearchOptions, KeyClass, Reference, SearchResult,
            };
            use security_framework::key::Algorithm;

            // ONE pre-authenticated LAContext with a per-intent reuse window.
            // `authentication_context` ADOPTS the +1 we hold (Create Rule) and
            // releases it when the query drops. The unwrap query needs its OWN
            // owned reference to the SAME context, so we `retain` once more —
            // but only AFTER the sign succeeds (below), so a declined tap /
            // sign failure leaks nothing. Both refs are released on return, so
            // the reuse window cannot outlive this call (cannot span intents).
            let ctx = create_la_context(reason, Some(BATCH_PRESENCE_REUSE_WINDOW_SECS))
                .map_err(SeError::SignFailed)?;

            // --- §1: sign on the sign-only key (presents the Touch ID sheet) ---
            let mut sign_query = ItemSearchOptions::new();
            sign_query
                .class(ItemClass::key())
                .key_class(KeyClass::private())
                .label(&sign_key.0.label)
                .load_refs(true);
            #[allow(deprecated)]
            unsafe {
                sign_query.authentication_context(ctx);
            }
            // Fail-safe fallback (mirrors se_sign_batch): if the windowed lookup
            // fails, sign with the already-held handle (NO window) — costs an
            // extra prompt, never skips one. The unwrap below still rides its
            // own retained context.
            let signing_key = match sign_query.search() {
                Ok(results) => results.into_iter().find_map(|r| match r {
                    SearchResult::Ref(Reference::Key(k)) => Some(k),
                    _ => None,
                }),
                Err(_) => None,
            }
            .unwrap_or_else(|| sec_key.clone());
            let sig = signing_key
                .create_signature(
                    Algorithm::ECDSASignatureMessageX962SHA256,
                    gesture.intent_bytes,
                )
                .map_err(|e| SeError::SignFailed(e.to_string()))?;

            // The sign succeeded (its presence evaluation is now cached on the
            // context). Hand the unwrap query its own owned +1 reference to the
            // SAME context so the ECDH-decrypt rides that cached evaluation. The
            // context object is still alive here — `sign_query` holds its ref
            // until it drops at the end of this arm. (`ctx` is a Copy raw
            // pointer; the move into `sign_query` did not invalidate it.)
            let ctx_for_unwrap = objc_retain(ctx);

            // --- §4: unwrap KEK_s on the ECIES recipient key (rides the tap) ---
            let mut unwrap_query = ItemSearchOptions::new();
            unwrap_query
                .class(ItemClass::key())
                .key_class(KeyClass::private())
                .label(ecies_key.as_str())
                .load_refs(true);
            #[allow(deprecated)]
            unsafe {
                unwrap_query.authentication_context(ctx_for_unwrap);
            }
            let unwrap_key = unwrap_query
                .search()
                .map_err(|e| {
                    SeError::UnwrapFailed(format!(
                        "ECIES key lookup for '{}': {e}",
                        ecies_key.as_str()
                    ))
                })?
                .into_iter()
                .find_map(|r| match r {
                    SearchResult::Ref(Reference::Key(k)) => Some(k),
                    _ => None,
                })
                .ok_or_else(|| {
                    SeError::UnwrapFailed(format!(
                        "no SE key for ECIES label '{}'",
                        ecies_key.as_str()
                    ))
                })?;
            let kek = unwrap_key
                .decrypt_data(
                    Algorithm::ECIESEncryptionStandardVariableIVX963SHA256AESGCM,
                    gesture.wrapped_kek,
                )
                .map_err(|e| SeError::UnwrapFailed(format!("se_sign_and_unwrap decrypt: {e}")))?;

            Ok((sig, zeroize::Zeroizing::new(kek)))
        }

        // Stub path (tests / unsigned builds): no biometric prompt, so the
        // gesture is just the two single ops. Byte-for-byte parity with the
        // separate-call path so daemon-side verification + KEK-install tests
        // observe identical outputs whether or not they batch.
        SeKeyInner::Stub { .. } => {
            let sig = se_sign_with_touch_id_reason(sign_key, gesture.intent_bytes, reason)?;
            let kek = se_unwrap(ecies_key, gesture.wrapped_kek)?;
            Ok((sig, zeroize::Zeroizing::new(kek)))
        }
    }
}

/// Extract the uncompressed P-256 public key bytes (65 bytes: 0x04 || X || Y).
///
/// On the real SE path: derives the public half via `SecKeyCopyPublicKey`,
/// then exports that public key via `SecKeyCopyExternalRepresentation`.
/// On the stub path: returns the pre-generated public bytes.
pub fn se_pubkey_bytes(key: &SeKeyHandle) -> Result<Vec<u8>, SeError> {
    match &key.inner {
        #[cfg(feature = "se-real")]
        SeKeyInner::Real(sec_key) => {
            let public_key = sec_key.public_key().ok_or_else(|| {
                SeError::PubkeyExportFailed("SecKeyCopyPublicKey returned None".to_string())
            })?;
            public_key
                .external_representation()
                .map(|d| d.to_vec())
                .ok_or_else(|| {
                    SeError::PubkeyExportFailed(
                        "SecKeyCopyExternalRepresentation returned None for the public key"
                            .to_string(),
                    )
                })
        }

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
    find_se_key_by_label_with_reason(label, "Authenticate to continue")
}

#[cfg(feature = "se-real")]
fn find_se_key_by_label_with_reason(
    label: &str,
    reason: &str,
) -> Result<security_framework::key::SecKey, String> {
    find_se_key_inner(label, reason, None)
}

/// Per-intent presence reuse window (seconds) used ONLY by [`se_sign_batch`].
///
/// A single operator intent (e.g. the 3 ceremony events of one device
/// enrollment) signs its N blobs under ONE pre-authenticated `LAContext`; this
/// window lets the N rapid `SecKeyCreateSignature` calls ride the single Touch
/// ID tap instead of re-prompting per signature. It is short on purpose — N SE
/// signatures complete in milliseconds — and is only reachable through the
/// batch helper, whose context is created fresh and dropped on return, so the
/// window can never outlive a single call (and thus never span two intents).
/// `.userPresence` keys honor this window; `.biometryCurrentSet` keys do not —
/// which is why the dev0 presence floor is `.userPresence`.
#[cfg(feature = "se-real")]
const BATCH_PRESENCE_REUSE_WINDOW_SECS: f64 = 10.0;

/// Look up the SE key under a context carrying a short presence-reuse window so
/// that the N signatures of ONE operator intent ride a single Touch ID tap.
/// See [`se_sign_batch`] for the load-bearing per-intent security boundary.
#[cfg(feature = "se-real")]
fn find_se_key_by_label_batched(
    label: &str,
    reason: &str,
) -> Result<security_framework::key::SecKey, String> {
    find_se_key_inner(label, reason, Some(BATCH_PRESENCE_REUSE_WINDOW_SECS))
}

#[cfg(feature = "se-real")]
fn find_se_key_inner(
    label: &str,
    reason: &str,
    reuse_window_secs: Option<f64>,
) -> Result<security_framework::key::SecKey, String> {
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
    let mut query = ItemSearchOptions::new();
    query
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(label)
        .load_refs(true);
    #[allow(deprecated)]
    unsafe {
        query.authentication_context(create_la_context(reason, reuse_window_secs)?);
    }
    let results = query
        .search()
        .map_err(|e| format!("SE key lookup for label '{label}': {e}"))?;

    for result in results {
        if let SearchResult::Ref(Reference::Key(key)) = result {
            return Ok(key);
        }
    }
    Err(format!(
        "no SE key found for label '{label}' — run `sudo ember daemon install` to provision"
    ))
}

/// Build an `LAContext` carrying `reason` (the Touch ID sheet copy) and, when
/// `reuse_window_secs` is `Some`, a `touchIDAuthenticationAllowableReuseDuration`
/// so multiple presence-gated key operations performed against THIS context ride
/// a single biometric prompt. Only [`se_sign_batch`] passes `Some`; every other
/// caller passes `None` (one prompt per operation). The returned context is a
/// retained ObjC object owned by the caller (matched to the existing leak-on-use
/// pattern — it is consumed by a keychain query and never re-exposed).
/// ObjC `-retain` on a raw `id`: returns the same object with refcount +1.
/// Used by [`se_sign_and_unwrap`] to hand a second owned reference of one
/// `LAContext` to the unwrap query, since `authentication_context` consumes
/// the pointer it is given (Create Rule). Returns the same pointer.
#[cfg(feature = "se-real")]
fn objc_retain(obj: *mut std::os::raw::c_void) -> *mut std::os::raw::c_void {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_void};
    type Id = *mut c_void;
    type Sel = *const c_void;
    unsafe extern "C" {
        fn sel_registerName(name: *const c_char) -> Sel;
        #[link_name = "objc_msgSend"]
        fn msg_send_id(receiver: Id, sel: Sel) -> Id;
    }
    let name = CString::new("retain").expect("static selector name");
    unsafe { msg_send_id(obj, sel_registerName(name.as_ptr())) }
}

#[cfg(feature = "se-real")]
#[allow(clashing_extern_declarations)]
fn create_la_context(
    reason: &str,
    reuse_window_secs: Option<f64>,
) -> Result<*mut std::os::raw::c_void, String> {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_void};

    type Id = *mut c_void;
    type Sel = *const c_void;

    #[link(name = "LocalAuthentication", kind = "framework")]
    unsafe extern "C" {}

    #[link(name = "Foundation", kind = "framework")]
    unsafe extern "C" {}

    unsafe extern "C" {
        fn objc_getClass(name: *const c_char) -> Id;
        fn sel_registerName(name: *const c_char) -> Sel;
    }
    unsafe extern "C" {
        #[link_name = "objc_msgSend"]
        fn msg_send_id(receiver: Id, sel: Sel) -> Id;
    }
    unsafe extern "C" {
        #[link_name = "objc_msgSend"]
        fn msg_send_void_id(receiver: Id, sel: Sel, arg0: Id);
    }
    unsafe extern "C" {
        #[link_name = "objc_msgSend"]
        fn msg_send_void_double(receiver: Id, sel: Sel, arg0: std::os::raw::c_double);
    }
    unsafe extern "C" {
        #[link_name = "objc_msgSend"]
        fn msg_send_id_cstr(receiver: Id, sel: Sel, arg0: *const c_char) -> Id;
    }

    unsafe fn nsstring_from_str(s: &str) -> Result<Id, String> {
        let cls_name =
            CString::new("NSString").map_err(|e| format!("NSString class CString: {e}"))?;
        let cls = unsafe { objc_getClass(cls_name.as_ptr()) };
        if cls.is_null() {
            return Err("NSString class lookup returned nil".to_string());
        }
        let sel_name = CString::new("stringWithUTF8String:")
            .map_err(|e| format!("NSString selector CString: {e}"))?;
        let sel = unsafe { sel_registerName(sel_name.as_ptr()) };
        let cstr = CString::new(s).map_err(|e| format!("localized reason CString: {e}"))?;
        Ok(unsafe { msg_send_id_cstr(cls, sel, cstr.as_ptr()) })
    }

    unsafe {
        let cls_name =
            CString::new("LAContext").map_err(|e| format!("LAContext class CString: {e}"))?;
        let cls = objc_getClass(cls_name.as_ptr());
        if cls.is_null() {
            return Err("LAContext class lookup returned nil".to_string());
        }
        let alloc_sel = sel_registerName(
            CString::new("alloc")
                .map_err(|e| format!("alloc selector CString: {e}"))?
                .as_ptr(),
        );
        let init_sel = sel_registerName(
            CString::new("init")
                .map_err(|e| format!("init selector CString: {e}"))?
                .as_ptr(),
        );
        let set_reason_sel = sel_registerName(
            CString::new("setLocalizedReason:")
                .map_err(|e| format!("setLocalizedReason selector CString: {e}"))?
                .as_ptr(),
        );
        let allocated = msg_send_id(cls, alloc_sel);
        if allocated.is_null() {
            return Err("LAContext alloc returned nil".to_string());
        }
        let context = msg_send_id(allocated, init_sel);
        if context.is_null() {
            return Err("LAContext init returned nil".to_string());
        }
        let reason_ns = nsstring_from_str(reason)?;
        msg_send_void_id(context, set_reason_sel, reason_ns);

        // Optional presence reuse window: lets N presence-gated operations on
        // this one context ride a single Touch ID tap. Used ONLY by
        // se_sign_batch to collapse one operator intent's N signatures to one
        // tap; the context is dropped on return so the window cannot span
        // intents. setTouchIDAuthenticationAllowableReuseDuration: takes an
        // NSTimeInterval (double, seconds).
        if let Some(secs) = reuse_window_secs {
            let set_reuse_sel = sel_registerName(
                CString::new("setTouchIDAuthenticationAllowableReuseDuration:")
                    .map_err(|e| format!("setReuseDuration selector CString: {e}"))?
                    .as_ptr(),
            );
            msg_send_void_double(context, set_reuse_sel, secs);
        }
        Ok(context)
    }
}

#[cfg(feature = "se-real")]
// SE public-key lookup retained for SE/crypto completeness; not currently called.
#[allow(dead_code)]
fn find_se_public_key_by_label(label: &str) -> Result<security_framework::key::SecKey, SeError> {
    use security_framework::item::{
        ItemClass, ItemSearchOptions, KeyClass, Reference, SearchResult,
    };

    let results = ItemSearchOptions::new()
        .class(ItemClass::key())
        .key_class(KeyClass::public())
        .label(label)
        .load_refs(true)
        .search()
        .map_err(|e| {
            SeError::PubkeyExportFailed(format!("public-key lookup for label '{label}': {e}"))
        })?;

    for result in results {
        if let SearchResult::Ref(Reference::Key(key)) = result {
            return Ok(key);
        }
    }

    Err(SeError::PubkeyExportFailed(format!(
        "no public-key item found for label '{label}'"
    )))
}
/// Re-open a previously-created Secure Enclave key by label.
pub fn find_secure_enclave_key(label: &str) -> Result<SeKeyHandle, SeError> {
    #[cfg(feature = "se-real")]
    {
        let key = find_se_key_by_label(label).map_err(SeError::KeyGenFailed)?;
        Ok(SeKeyHandle {
            label: label.to_string(),
            inner: SeKeyInner::Real(key),
        })
    }

    #[cfg(not(feature = "se-real"))]
    let maybe_stub = STUB_KEY_STORE.with(|store| store.borrow().get(label).cloned());
    #[cfg(not(feature = "se-real"))]
    if let Some(material) = maybe_stub {
        return Ok(SeKeyHandle {
            label: label.to_string(),
            inner: SeKeyInner::Stub {
                private_bytes: material.private_bytes,
                public_bytes: material.public_bytes,
            },
        });
    }

    #[cfg(not(feature = "se-real"))]
    Err(SeError::NotSupported)
}

/// Delete a Secure Enclave key from the keychain by label (best-effort cleanup).
///
/// Used by the `emberd se-probe` diagnostic to clean up its provisioned
/// `.userPresence` SE keys after the probe run so repeat invocations on the
/// same host don't accumulate DPK entries. NOT a general production primitive
/// — provisioned interactive / sealing keys have lifecycle owners (ADR 206 §4
/// scopes, ADR 200 device-set roots) that must not be deleted out from under
/// the higher-level state. Treat callers of this function as a closed set
/// (probe-only, today) and route any new caller through an explicit lifecycle
/// review.
///
/// Looks the key up via a no-auth-context query (deletion does not need a
/// presence evaluation) and calls `SecKey::delete()` (which in turn calls
/// `SecItemDelete`). The deletion is silent on `errSecItemNotFound`-style
/// misses so a partial-failure probe run can still attempt cleanup.
///
/// On non-`se-real` builds this returns `SeError::NotSupported` rather than
/// touching any stub-store state.
#[cfg(feature = "se-real")]
pub fn delete_secure_enclave_key(label: &str) -> Result<(), SeError> {
    use security_framework::item::{
        ItemClass, ItemSearchOptions, KeyClass, Reference, SearchResult,
    };

    let mut query = ItemSearchOptions::new();
    query
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(label)
        .load_refs(true);
    let results = query
        .search()
        .map_err(|e| SeError::KeyGenFailed(format!("delete: lookup for '{label}': {e}")))?;
    for result in results {
        if let SearchResult::Ref(Reference::Key(key)) = result {
            key.delete()
                .map_err(|e| SeError::KeyGenFailed(format!("delete: '{label}': {e}")))?;
            return Ok(());
        }
    }
    Err(SeError::KeyGenFailed(format!(
        "delete: no SE key found for label '{label}'"
    )))
}

#[cfg(not(feature = "se-real"))]
pub fn delete_secure_enclave_key(_label: &str) -> Result<(), SeError> {
    Err(SeError::NotSupported)
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
/// auth tag is `SHA-256(0xFF || nonce || key || ciphertext)` (encrypt-then-MAC,
/// per adversarial-review item P1-B) and the stream key is
/// `SHA-256(counter || nonce || key)` per 32-byte block.
///
/// # Errors
///
/// Returns [`SeError::WrapFailed`] if no key is registered for `label` or if
/// the underlying cryptographic operation fails.
pub fn se_wrap(label: &EciesKeyLabel, plaintext: &[u8]) -> Result<Vec<u8>, SeError> {
    let label = label.as_str();
    // Look up the thread-local stub key registry first (test path).
    let maybe_key = STUB_KEY_STORE.with(|store| store.borrow().get(label).cloned());

    match maybe_key {
        Some(material) => stub_wrap(&material.private_bytes, label, plaintext),
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
/// Inverse of [`se_wrap`]. On the stub path, **verifies the auth tag
/// constant-time first, then XOR-decrypts** (encrypt-then-MAC + verify-
/// then-decrypt; see [`stub_unwrap`] for the per-byte invariant and the
/// adversarial-review item P1-B rationale).
///
/// # Errors
///
/// Returns [`SeError::UnwrapFailed`] if authentication fails, if no key is
/// registered for `label`, or if the ciphertext is malformed.
pub fn se_unwrap(label: &EciesKeyLabel, ciphertext: &[u8]) -> Result<Vec<u8>, SeError> {
    let label = label.as_str();
    let maybe_key = STUB_KEY_STORE.with(|store| store.borrow().get(label).cloned());

    match maybe_key {
        Some(material) => stub_unwrap(&material.private_bytes, label, ciphertext),
        None => {
            // Real ECIES path. SecKey::decrypt_data routes through the SE for
            // the ECDH-derive step; any SAC attached to the key (e.g. the
            // BiometryCurrentSet protection set by `generate_secure_enclave_key`)
            // triggers a biometric prompt here. For the daemon's separate-uid
            // posture (ADR 131) the install-side P2 followup
            // pins the key to
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

#[derive(Clone)]
struct StubKeyMaterial {
    private_bytes: Vec<u8>,
    #[allow(dead_code)]
    public_bytes: Vec<u8>,
}

thread_local! {
    static STUB_KEY_STORE: RefCell<HashMap<String, StubKeyMaterial>> = RefCell::new(HashMap::new());
}

/// Register a stub key for `label` so [`se_wrap`] / [`se_unwrap`] can operate
/// without a real SE key handle. Only available in test and stub builds.
#[cfg(any(test, feature = "se-stub"))]
/// Return the registered stub key handle for `label`, if one exists in the
/// thread-local stub store. DEV-ONLY (`se-stub`): lets callers re-derive a
/// previously-registered stub key's pubkey / unwrap with it even on builds where
/// `se-real` is also active (under which `find_secure_enclave_key` takes the
/// real keychain path and ignores the stub store). Used by the §4 implicit-
/// unlock test affordance in emberlink-cli.
#[cfg(feature = "se-stub")]
pub fn stub_key_handle(label: &str) -> Option<SeKeyHandle> {
    STUB_KEY_STORE.with(|store| {
        store.borrow().get(label).map(|material| SeKeyHandle {
            label: label.to_string(),
            inner: SeKeyInner::Stub {
                private_bytes: material.private_bytes.clone(),
                public_bytes: material.public_bytes.clone(),
            },
        })
    })
}

pub fn se_register_stub_key(label: &str, handle: &SeKeyHandle) {
    let private_bytes = match &handle.inner {
        SeKeyInner::Stub { private_bytes, .. } => private_bytes,
        #[cfg(feature = "se-real")]
        SeKeyInner::Real(_) => return,
    };
    STUB_KEY_STORE.with(|store| {
        let public_bytes = se_pubkey_bytes(handle).expect("stub pubkey bytes");
        store.borrow_mut().insert(
            label.to_string(),
            StubKeyMaterial {
                private_bytes: private_bytes.clone(),
                public_bytes,
            },
        );
    });
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

/// Compute encrypt-then-MAC auth tag: `SHA-256(0xFF || nonce || key || ciphertext)`.
///
/// Adversarial-review item P1-B — the tag MUST be
/// computed over the CIPHERTEXT (encrypt-then-MAC), not the plaintext.
/// Tag-over-plaintext requires decryption before verification, which
/// turned `stub_unwrap` into a padding/timing oracle on a malformed
/// blob (the XOR stream is decrypted unconditionally, then the tag
/// compares against attacker-influenced bytes). Tag-over-ciphertext
/// lets `stub_unwrap` verify-then-decrypt: an attacker who tampers
/// with `nonce || ciphertext` triggers the tag-mismatch return BEFORE
/// any decryption happens.
fn auth_tag(nonce: &[u8; 16], key: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update([0xFFu8]);
    h.update(nonce);
    h.update(key);
    h.update(ciphertext);
    h.finalize().into()
}

/// Internal: XOR-encrypt/decrypt `input` against the keystream derived
/// from `(counter, nonce, key)`. Symmetric — same function on the wrap
/// (plaintext → ciphertext) and unwrap (ciphertext → plaintext) sides.
fn xor_keystream(nonce: &[u8; 16], key: &[u8; 32], input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut counter: u8 = 0;
    let mut block = keystream_block(counter, nonce, key);
    let mut block_pos = 0usize;
    for &b in input {
        if block_pos == 32 {
            counter = counter.wrapping_add(1);
            block = keystream_block(counter, nonce, key);
            block_pos = 0;
        }
        out.push(b ^ block[block_pos]);
        block_pos += 1;
    }
    out
}

/// Stub wrap: `nonce(16) || tag(32) || xor_encrypt(plaintext)`.
///
/// Encrypt-then-MAC: encrypt the plaintext to ciphertext via the
/// SHA-256-keystream XOR, then MAC `(nonce, key, ciphertext)`. The
/// inverse path (`stub_unwrap`) can verify-then-decrypt without ever
/// exposing tampered plaintext.
fn stub_wrap(private_bytes: &[u8], label: &str, plaintext: &[u8]) -> Result<Vec<u8>, SeError> {
    let key = derive_stub_key(label, private_bytes);

    // Random nonce via getrandom.
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|e| SeError::WrapFailed(e.to_string()))?;

    // Encrypt first (encrypt-then-MAC).
    let ciphertext = xor_keystream(&nonce, &key, plaintext);

    // MAC over the ciphertext, not the plaintext.
    let tag = auth_tag(&nonce, &key, &ciphertext);

    let mut out = Vec::with_capacity(16 + 32 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Stub unwrap: verify tag (constant-time, against ciphertext) **then**
/// XOR-decrypt.
///
/// Adversarial-review item P1-B — the prior
/// implementation decrypted before verifying, which:
///   1. Did work the attacker controlled (touched every ciphertext byte
///      before the tag check), and
///   2. Verified the tag against the freshly-decrypted plaintext
///      (tag-over-plaintext format), which means a malicious blob with
///      a matching plaintext-MAC would still decrypt despite arbitrary
///      ciphertext tampering.
///
/// The fix is two paired changes:
///   - Wrap-side now MACs over ciphertext (encrypt-then-MAC; see
///     [`auth_tag`] and [`stub_wrap`]).
///   - Unwrap-side recomputes the expected tag from the *received*
///     ciphertext, compares constant-time via `subtle::ConstantTimeEq`,
///     and only on success runs the XOR decryption pass.
///
/// `subtle::ConstantTimeEq` is the canonical Rust primitive for
/// constant-time byte-slice comparison; it is audited by the crypto
/// community and replaces the prior `core::hint::black_box` /
/// XOR-accumulate hand-rolled barrier (whose constant-time guarantee
/// depended on LLVM honoring the black_box hint at every optimization
/// level — best-effort, not guaranteed).
fn stub_unwrap(private_bytes: &[u8], label: &str, ciphertext: &[u8]) -> Result<Vec<u8>, SeError> {
    use subtle::ConstantTimeEq;

    if ciphertext.len() < 16 + 32 {
        return Err(SeError::UnwrapFailed("ciphertext too short".to_string()));
    }

    let key = derive_stub_key(label, private_bytes);

    let nonce: [u8; 16] = ciphertext[..16].try_into().unwrap();
    let stored_tag: [u8; 32] = ciphertext[16..48].try_into().unwrap();
    let body = &ciphertext[48..];

    // Verify-then-decrypt: compute expected tag from the received
    // ciphertext (encrypt-then-MAC format), constant-time-compare
    // against the stored tag, and reject BEFORE any decryption work.
    let expected_tag = auth_tag(&nonce, &key, body);
    if expected_tag.ct_eq(&stored_tag).unwrap_u8() != 1 {
        return Err(SeError::UnwrapFailed(
            "authentication tag mismatch".to_string(),
        ));
    }

    // Tag verified — safe to run the XOR decryption pass. Mirrors the
    // wrap-side `xor_keystream` (symmetric).
    Ok(xor_keystream(&nonce, &key, body))
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
    use p256::SecretKey;
    use p256::ecdsa::SigningKey;

    let secret = loop {
        let mut candidate = [0u8; 32];
        getrandom::fill(&mut candidate).expect("getrandom for SE stub key");
        if let Ok(secret) = SecretKey::from_slice(&candidate) {
            break secret;
        }
    };
    let signing_key = SigningKey::from(secret);
    let verifying_key = signing_key.verifying_key();
    let public_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
    let private_bytes = signing_key.to_bytes().to_vec();

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

    /// Test helper: a software stub key tagged as a signing-role handle.
    fn stub_sign(label: &str) -> SignKeyHandle {
        SignKeyHandle::from_provisioned(new_stub_key(label))
    }

    /// Test helper: an ECIES-role label (stub key registered separately).
    fn ecies(label: &str) -> EciesKeyLabel {
        EciesKeyLabel::from_provisioned(label)
    }

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
        let handle = stub_sign("test-sign");
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
        let handle = stub_sign("test-diff");
        let sig1 = se_sign_with_touch_id(&handle, b"payload-one").expect("sig1");
        let sig2 = se_sign_with_touch_id(&handle, b"payload-two").expect("sig2");
        // Different data → different stub signature bytes
        assert_ne!(sig1, sig2, "stub signatures must differ for different data");
    }

    /// T1 — `se_sign_batch` must produce exactly one signature per input, in
    /// order, each byte-for-byte identical to the single-sign path. This is the
    /// interop floor the daemon's append-time verifier depends on: batching only
    /// changes the *presence ceremony* (N signatures, one tap), never the signed
    /// bytes. The real-SE one-tap collapse is the operator's live hardware gate;
    /// here we lock the signature-equivalence on the deterministic stub.
    #[test]
    fn batch_sign_matches_single_sign_per_message() {
        let handle = stub_sign("batch-parity");
        let messages: Vec<&[u8]> = vec![b"root-created", b"persona-created", b"device-enrolled"];

        let batched = se_sign_batch(&handle, SingleIntent::new(&messages), "enroll this device")
            .expect("batch sign");
        assert_eq!(
            batched.len(),
            messages.len(),
            "one signature per ceremony blob"
        );

        for (i, msg) in messages.iter().enumerate() {
            let single = se_sign_with_touch_id(&handle, msg).expect("single sign");
            assert_eq!(
                batched[i], single,
                "batched signature {i} must equal the single-sign output for the same message"
            );
            assert!(!batched[i].is_empty(), "signature {i} must be non-empty");
        }
        // Distinct messages → distinct signatures (no accidental reuse of one
        // signature across the batch).
        assert_ne!(batched[0], batched[1]);
        assert_ne!(batched[1], batched[2]);
    }

    /// T1 — the per-op widening contract: calling `se_sign_batch` with a single
    /// message is the canonical one-blob-per-op shape (ADR 200 AC-3, no
    /// cross-op window). It must return exactly one signature.
    #[test]
    fn batch_sign_single_message_is_one_signature() {
        let handle = stub_sign("batch-single");
        let messages: Vec<&[u8]> = vec![b"one-widening-op"];
        let out = se_sign_batch(&handle, SingleIntent::new(&messages), "widen for this op")
            .expect("batch sign");
        assert_eq!(out.len(), 1, "one message in → one signature out");
        let single = se_sign_with_touch_id(&handle, messages[0]).expect("single sign");
        assert_eq!(out[0], single);
    }

    /// T1 — empty input is a no-op (zero signatures), not an error.
    #[test]
    fn batch_sign_empty_is_empty() {
        let handle = stub_sign("batch-empty");
        let out = se_sign_batch(&handle, SingleIntent::new(&[]), "nothing to sign")
            .expect("batch sign empty");
        assert!(out.is_empty(), "no messages → no signatures");
    }

    /// T1 — `se_sign_and_unwrap` stub parity: the unified gesture's §1 signature
    /// is byte-for-byte the single-sign output, and its §4 unwrap recovers the
    /// wrapped KEK. Proves the batched primitive is a faithful composition of the
    /// two single ops (the real-SE path only changes the *presence ceremony* —
    /// one tap instead of two — never the produced bytes), so daemon-side
    /// signature verification + KEK-install see identical inputs either way.
    #[test]
    fn se_sign_and_unwrap_stub_parity() {
        let sign_key = stub_sign("gesture-sign");
        let ecies_handle = new_stub_key("gesture-ecies");
        se_register_stub_key("gesture-ecies", &ecies_handle);

        let intent = b"create_persona|op-1|nonce-abc";
        let canary_kek = [0x7Au8; 32];
        let wrapped = se_wrap(&ecies("gesture-ecies"), &canary_kek).expect("wrap canary KEK");

        let (sig, kek) = se_sign_and_unwrap(
            &sign_key,
            &ecies("gesture-ecies"),
            WideningGesture::new(intent, &wrapped),
            "widen: create_persona",
        )
        .expect("unified gesture");

        let single = se_sign_with_touch_id_reason(&sign_key, intent, "widen: create_persona")
            .expect("single sign");
        assert_eq!(
            sig, single,
            "batched §1 sig must equal the single-sign output"
        );
        assert_eq!(
            &kek[..],
            &canary_kek,
            "§4 unwrap must recover the wrapped KEK"
        );
    }

    /// T1 — fail-closed: a tampered `wrapped_kek` makes the §4 unwrap fail, so
    /// the whole gesture returns `Err` (the caller acquires nothing usable even
    /// though the §1 sign succeeded).
    #[test]
    fn se_sign_and_unwrap_fails_closed_on_tampered_kek() {
        let sign_key = stub_sign("gesture-sign-2");
        let ecies_handle = new_stub_key("gesture-ecies-2");
        se_register_stub_key("gesture-ecies-2", &ecies_handle);

        let mut wrapped =
            se_wrap(&ecies("gesture-ecies-2"), &[0x11u8; 32]).expect("wrap canary KEK");
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0x01; // corrupt the ciphertext

        let result = se_sign_and_unwrap(
            &sign_key,
            &ecies("gesture-ecies-2"),
            WideningGesture::new(b"intent", &wrapped),
            "widen: tampered",
        );
        assert!(
            matches!(result, Err(SeError::UnwrapFailed(_))),
            "tampered wrapped_kek must fail the gesture closed; got {result:?}"
        );
    }

    /// HARDWARE — run on a real Secure Enclave (signed binary) via:
    ///   scripts/dev-sign-se.sh <test-bin> --run -- \
    ///       --ignored se_sign_and_unwrap_one_tap_on_real_se --nocapture --test-threads=1
    ///
    /// Validates the LOAD-BEARING one-tap assumption in [`se_sign_and_unwrap`]:
    /// provisions a `.userPresence` sign key + ECIES key, wraps a canary KEK to
    /// the ECIES public half (no prompt), then runs the unified gesture.
    /// **Count the Touch ID prompts:** ONE → the unified gesture is one tap
    /// (delete the doc's hardware-assumption note + wire Phases 2-3); TWO → the
    /// cold-start floor on Apple SE is two taps (sign + decrypt), and true
    /// one-tap-cold needs YubiKey 9c/9d. The test asserts only the cryptographic
    /// result (a non-empty sig + the recovered canary); the tap COUNT is the
    /// human observation this probe exists to surface.
    #[test]
    #[ignore]
    #[cfg(feature = "se-real")]
    fn se_sign_and_unwrap_one_tap_on_real_se() {
        const SIGN_LABEL: &str = "sh.emberlink.test.gesture-sign";
        const ECIES_LABEL: &str = "sh.emberlink.test.gesture-ecies";

        // Best-effort idempotent provision: on a re-run the label already exists,
        // keygen errors, and we reuse the existing key via the by-label lookup.
        let _ = generate_secure_enclave_key_with_policy(
            SIGN_LABEL,
            SeKeychainTarget::SystemKeychain,
            SeAccessPolicy::UserPresence,
        );
        let _ = generate_secure_enclave_key_with_policy(
            ECIES_LABEL,
            SeKeychainTarget::SystemKeychain,
            SeAccessPolicy::UserPresence,
        );

        let sign_key = SignKeyHandle::from_provisioned(
            find_secure_enclave_key(SIGN_LABEL).expect("sign key must provision/exist"),
        );
        let ecies_label = EciesKeyLabel::from_provisioned(ECIES_LABEL);

        // Wrap a canary KEK to the ECIES public half — public-key op, no prompt.
        let canary = [0x7Au8; 32];
        let wrapped = se_wrap(&ecies_label, &canary).expect("wrap canary KEK to ECIES pubkey");

        eprintln!(">>> se_sign_and_unwrap: EXPECT EXACTLY ONE Touch ID prompt now <<<");
        let intent = b"create_persona|test-op|test-nonce";
        let (sig, kek) = se_sign_and_unwrap(
            &sign_key,
            &ecies_label,
            WideningGesture::new(intent, &wrapped),
            "Emberlink: authorize + open scope (one tap)",
        )
        .expect("unified gesture on real SE");

        assert!(!sig.is_empty(), "§1 signature must be non-empty");
        assert_eq!(&kek[..], &canary, "§4 unwrap must recover the canary KEK");
        eprintln!(
            ">>> PASS: gesture returned a sig + the canary KEK. How many taps did you count?"
        );
    }

    #[test]
    #[ignore]
    fn se_wrap_unwrap_round_trip() {
        let handle = new_stub_key("test");
        se_register_stub_key("test", &handle);
        let ct = se_wrap(&ecies("test"), b"hello").expect("wrap");
        let pt = se_unwrap(&ecies("test"), &ct).expect("unwrap");
        assert_eq!(pt, b"hello");
    }

    /// T1 — adversarial-review item P1-B: stub_unwrap
    /// must reject tampered ciphertext via the auth tag before producing
    /// any plaintext. Exercises the encrypt-then-MAC + verify-then-decrypt
    /// invariant on the stub path (deterministic, no SE hardware needed).
    #[test]
    fn stub_unwrap_rejects_ciphertext_tamper_before_decrypt() {
        let handle = new_stub_key("tamper-reject");
        se_register_stub_key("tamper-reject", &handle);

        // Round-trip baseline so we know the wrap output format is stable.
        let mut ct = se_wrap(&ecies("tamper-reject"), b"sensitive-payload").expect("wrap");
        let baseline = se_unwrap(&ecies("tamper-reject"), &ct).expect("baseline unwrap");
        assert_eq!(baseline, b"sensitive-payload");

        // Flip a bit in the ciphertext body (past the 16-byte nonce +
        // 32-byte tag prefix). Any single-bit flip in the encrypted bytes
        // must cause the tag verification to fail.
        let body_idx = 48usize;
        assert!(ct.len() > body_idx, "ciphertext must include body bytes");
        ct[body_idx] ^= 0x01;

        let result = se_unwrap(&ecies("tamper-reject"), &ct);
        match result {
            Err(SeError::UnwrapFailed(msg)) => {
                assert!(
                    msg.contains("authentication tag mismatch"),
                    "expected tag-mismatch diagnostic, got: {msg}"
                );
            }
            Ok(pt) => {
                panic!("expected UnwrapFailed for tampered ciphertext, got plaintext: {pt:?}")
            }
            Err(other) => panic!("expected UnwrapFailed for tampered ciphertext, got: {other:?}"),
        }
    }

    /// T1 — adversarial-review item P1-B: tampering
    /// with the stored auth-tag region (offset 16..48) must also be
    /// rejected. Complement to the body-tamper test — both attacker-
    /// reachable regions of the blob are covered.
    #[test]
    fn stub_unwrap_rejects_tag_tamper() {
        let handle = new_stub_key("tag-tamper");
        se_register_stub_key("tag-tamper", &handle);

        let mut ct = se_wrap(&ecies("tag-tamper"), b"tag-tamper-payload").expect("wrap");
        // Flip a bit in the auth-tag region.
        ct[20] ^= 0x80;

        let result = se_unwrap(&ecies("tag-tamper"), &ct);
        assert!(
            matches!(result, Err(SeError::UnwrapFailed(_))),
            "tampering with the tag region must produce UnwrapFailed, got: {result:?}"
        );
    }
}
