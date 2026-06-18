//! ADR 206 §4 — presence-as-decryption sealing engine.
//!
//! Authority-bearing secret VALUES are sealed so that opening them requires a
//! **live hardware presence gesture** — an `se_unwrap` of a presence-device
//! SE-ECIES key the daemon does not hold. The autonomous System.keychain MEK
//! is **NEVER** a recipient of anything on this path. That is the cryptographic
//! `can't` that replaces today's policy `won't` (the daemon holds the MEK, so
//! the old presence gate was a software check in front of an available key).
//!
//! ## Two-level key hierarchy (ADR 206 §4 topology)
//!
//! ```text
//! payload  <- CK_x   (per-secret content key; fresh per seal)
//! CK_x     <- KEK_s  (per-scope key-encryption key; AEAD-wrapped, AAD-bound)
//! KEK_s    <- presence-device SE-ECIES pubkey   (se_wrap / se_unwrap)
//! ```
//!
//! One presence gesture (`se_unwrap` of the scope's wrapped KEK_s) yields the
//! cleartext `KEK_s`, which then unwraps every `CK_x` in that scope for the
//! operation; the [`ScopeKek`] is `Zeroizing` + non-`Clone` and is dropped
//! (evicted) after the op. The decrypt path uses NO LAContext reuse window —
//! each scope-open is its own SE evaluation (S1: SE decrypt has no native reuse
//! window). Cross-scope exposure is impossible: a `KEK_s` cannot unwrap another
//! scope's `CK_x` (different key + AAD), so reaching another scope needs a
//! separate gesture.
//!
//! ## What this module deliberately does NOT do (yet)
//!
//! It does not re-point live persona/credential custody off the MEK — that
//! flip needs the enrolled ECIES recipient key (enrollment slice) and is where
//! [`Vault::seal`] gains its `AuthorityBearing` refusal. This module is the
//! tested mechanism those slices wire in. See ADR 206 §4 and
//! `project_adr206_presence_fullmodel_cut`.
//!
//! CLASSIFICATION: PUBLIC

// The §4 recipient path composes the macOS Secure Enclave (`se_wrap` /
// `se_unwrap`), which only exists on macOS. The sealing-engine abstraction
// generalizes the recipient to "ECDH pubkey + curve" (P-256 hardware /
// X25519 software) in a later slice; until then this module is macOS-scoped,
// matching `ember_broker::secure_enclave`.
#![cfg(target_os = "macos")]

use chacha20poly1305::aead::Payload;
use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::Aead, aead::KeyInit};
use core_principals::KeyAlgorithm;
use core_state::MaterializedState;
use ember_broker::secure_enclave::{
    EciesKeyLabel, se_backend_is_real, se_stub_is_active, se_unwrap, se_wrap,
};
use zeroize::{Zeroize, Zeroizing};

// ADR 206 §4 — the value-class vocabulary now lives cross-platform on the vault
// (it routes `Vault::seal`/`open` to the §4 interactive key vs the autonomous
// headless key). Re-export it here so this engine and the vault speak one type.
pub use crate::infra::vault::ValueClass;

/// Domain-separated AAD prefix for the `CK_x`-under-`KEK_s` wrap. Changing this
/// is a wire-format break.
const CK_WRAP_AAD_PREFIX: &[u8] = b"emberlink/adr206/v1/ck-wrap";
/// Domain-separated AAD prefix for the payload-under-`CK_x` seal.
const PAYLOAD_AAD_PREFIX: &[u8] = b"emberlink/adr206/v1/payload";

/// Errors from the §4 presence-sealing engine.
#[derive(Debug)]
pub enum PresenceSealError {
    /// The SE backend is the in-memory software stub, not a real Secure
    /// Enclave, in a non-test build. Refusing to seal/serve authority-bearing
    /// material under a stub is the ADR 206 §4 fail-closed guard (closes the
    /// "XOR stub is a shipped-buildable daemon profile" gap): a software key is
    /// exportable and not hardware-presence-gated, so it must never stand in
    /// for a presence factor.
    StubBackendRefused,
    /// The hardware unwrap (`se_unwrap` — the presence gesture) failed: gesture
    /// declined, key absent, or tampered ciphertext. There is NO MEK fallback;
    /// this fails closed.
    PresenceUnwrapFailed(String),
    /// An AEAD operation (wrap/unwrap `CK_x`, or seal/open payload) failed —
    /// wrong `KEK_s`, wrong `aad_id`, tampered blob, or a malformed input.
    Crypto(String),
}

impl std::fmt::Display for PresenceSealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PresenceSealError::StubBackendRefused => write!(
                f,
                "refusing to seal/open authority-bearing material under the software SE stub \
                 (ADR 206 §4: a stub is not a hardware presence factor)"
            ),
            PresenceSealError::PresenceUnwrapFailed(m) => {
                write!(
                    f,
                    "presence unwrap (se_unwrap) failed, no MEK fallback: {m}"
                )
            }
            PresenceSealError::Crypto(m) => write!(f, "presence-seal AEAD failure: {m}"),
        }
    }
}

impl std::error::Error for PresenceSealError {}

/// A per-scope key-encryption key (`KEK_s`) in cleartext. Non-`Clone` and
/// zeroized on drop so an opened scope key cannot linger or be copied; callers
/// drop it (evict) immediately after the operation it authorized.
pub struct ScopeKek(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for ScopeKek {
    /// Redacts the key bytes — never print scope-KEK material (a derive on
    /// `Zeroizing<[u8; 32]>` would leak it).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScopeKek(<redacted 32 bytes>)")
    }
}

impl ScopeKek {
    /// Take ownership of an already-`Zeroizing` 32-byte buffer. Callers stage
    /// the key in a `Zeroizing` buffer so no cleartext-KEK copy is left on the
    /// stack by a `[u8; 32]: Copy` move.
    fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
        ScopeKek(bytes)
    }

    /// Build a `ScopeKek` from a raw slice (e.g. the output of an `se_unwrap`).
    /// The staging buffer is `Zeroizing`, and the caller is responsible for
    /// scrubbing the source slice it passed in.
    fn try_from_slice(bytes: &[u8]) -> Result<Self, PresenceSealError> {
        if bytes.len() != 32 {
            return Err(PresenceSealError::Crypto(format!(
                "scope KEK must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = Zeroizing::new([0u8; 32]);
        arr.copy_from_slice(bytes);
        Ok(ScopeKek::from_zeroizing(arr))
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A per-secret authority blob: the payload sealed under a fresh `CK_x`, plus
/// `CK_x` AEAD-wrapped under the scope's `KEK_s`. The `KEK_s` itself is sealed
/// to the presence device separately (see [`wrap_scope_kek_to_presence`]) and
/// is NOT part of this blob — so this blob is undecryptable without a presence
/// gesture, and contains no MEK-reachable path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoritySealedBlob {
    /// 24-byte XChaCha20 nonce for the payload seal (under `CK_x`).
    pub payload_nonce: Vec<u8>,
    /// Payload ciphertext-with-tag, sealed under `CK_x`.
    pub ciphertext: Vec<u8>,
    /// 24-byte XChaCha20 nonce for the `CK_x` wrap (under `KEK_s`).
    pub ck_nonce: Vec<u8>,
    /// `CK_x`, AEAD-wrapped under `KEK_s` with the §4 wrap AAD.
    pub wrapped_ck: Vec<u8>,
}

fn ck_wrap_aad(aad_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CK_WRAP_AAD_PREFIX.len() + 4 + aad_id.len());
    aad.extend_from_slice(CK_WRAP_AAD_PREFIX);
    aad.extend_from_slice(&(aad_id.len() as u32).to_le_bytes());
    aad.extend_from_slice(aad_id);
    aad
}

fn payload_aad(aad_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PAYLOAD_AAD_PREFIX.len() + 4 + aad_id.len());
    aad.extend_from_slice(PAYLOAD_AAD_PREFIX);
    aad.extend_from_slice(&(aad_id.len() as u32).to_le_bytes());
    aad.extend_from_slice(aad_id);
    aad
}

/// Fail closed unless this is a **real hardware-enclave build with NO software
/// stub compiled in**. The in-process unit tests deliberately drive the stub
/// (and run `cfg(test)`), so tests are exempt; ANY non-test build that is not
/// `se_backend_is_real() && !se_stub_is_active()` is refused.
///
/// The `!se_stub_is_active()` clause is load-bearing: `se_wrap`/`se_unwrap`
/// consult the stub's `STUB_KEY_STORE` *before* the real ECIES path, so a build
/// that merely has `se-real` on is NOT enough — if `se-stub` is also compiled
/// in (e.g. it leaked back into regular `[dependencies]`), an exportable
/// software key could stand in for the hardware presence factor. `se-stub` is
/// dev-only (declared in `[dev-dependencies]`, kept out of production builds by
/// resolver 2), so production passes this gate and a stub-leak fails closed.
/// ADR 206 §4 (closure-pass finding #9).
fn require_real_backend() -> Result<(), PresenceSealError> {
    #[cfg(test)]
    {
        Ok(())
    }
    #[cfg(not(test))]
    {
        if se_backend_is_real() && !se_stub_is_active() {
            Ok(())
        } else {
            Err(PresenceSealError::StubBackendRefused)
        }
    }
}

/// Generate a fresh per-scope `KEK_s` from OS entropy.
pub fn generate_scope_kek() -> ScopeKek {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut_slice()).expect("OS entropy failure on scope KEK generation");
    ScopeKek::from_zeroizing(bytes)
}

/// Seal `KEK_s` to the presence device's SE-ECIES recipient (`se_wrap`), so the
/// only way back to cleartext `KEK_s` is a live presence gesture. Returns the
/// opaque wrapped blob to store at rest per scope. Refuses the software stub in
/// non-test builds.
///
/// NOTE: `se_wrap` (encryption) uses the recipient's PUBLIC key and does NOT
/// prompt for presence — only [`unwrap_scope_kek_from_presence`] (decryption)
/// triggers the gesture. So sealing new secrets to an established scope does
/// not require a tap; opening them does.
/// Private wrap MECHANISM for a P-256 SE presence recipient. Not public: the only
/// way to wrap a `KEK_s` is via [`AuthorizedKekRecipient::wrap`], which proves the
/// recipient came from the operator's event-sourced custody set (AC-7 is a type
/// invariant, not a call-site check).
fn wrap_scope_kek_to_presence(
    recipient: &EciesKeyLabel,
    kek: &ScopeKek,
) -> Result<Vec<u8>, PresenceSealError> {
    require_real_backend()?;
    se_wrap(recipient, kek.as_bytes())
        .map_err(|e| PresenceSealError::PresenceUnwrapFailed(e.to_string()))
}

/// Recover cleartext `KEK_s` from its presence-sealed blob via `se_unwrap` —
/// **this is the presence gesture** (one tap per scope-open). Fails closed on
/// any error; there is deliberately NO MEK fallback. Refuses the software stub
/// in non-test builds.
///
/// LOAD-BEARING PRECONDITION (enforced by the enrollment slice, not here): the
/// `recipient` ECIES key MUST have been provisioned with
/// `SeAccessPolicy::UserPresence`. `se_unwrap` (ECDH-decrypt) only triggers a
/// hardware gesture if the key's own SAC requires presence — a key provisioned
/// `Headless` would `se_unwrap` with NO tap, silently defeating §4. This module
/// takes an opaque [`EciesKeyLabel`] and cannot inspect the policy; the §4
/// enrollment path is responsible for provisioning the recipient key under
/// `UserPresence` (and is where that invariant is asserted). See ADR 206 §4 /
/// AC-4 and closure-pass finding on key-policy dependency.
pub fn unwrap_scope_kek_from_presence(
    recipient: &EciesKeyLabel,
    wrapped_kek: &[u8],
) -> Result<ScopeKek, PresenceSealError> {
    require_real_backend()?;
    let mut raw = se_unwrap(recipient, wrapped_kek)
        .map_err(|e| PresenceSealError::PresenceUnwrapFailed(e.to_string()))?;
    let kek = ScopeKek::try_from_slice(&raw);
    // se_unwrap returns a plain Vec; scrub it once copied into the Zeroizing
    // ScopeKek (slice-1 follow-up: make se_unwrap return Zeroizing directly).
    raw.zeroize();
    kek
}

// ---------------------------------------------------------------------------
// ADR 206 §6 — off-host cold-recovery recipient (printed / exported recovery
// code; the ranked recovery model's software tier).
//
// The ranked recovery model's lowest tier — and the only-one-device floor — is
// an off-host **age X25519** recipient: a single `AGE-SECRET-KEY-…` secret the
// operator prints/exports ONCE and stores wherever they choose (the industry-
// standard 2FA "recovery code" posture). `KEK_s` is wrapped to that recipient
// so device loss never becomes identity loss.
//
// The daemon holds ONLY the `age1…` RECIPIENT public key (in the event-sourced
// recovery set) and the wrapped `KEK_s` blob — NEVER the secret half (ADR 206
// §6 finding C3: the recovery secret must be provably off-host, never daemon-
// reachable software). Wrapping is public-key encryption, so the daemon can do
// it with `KEK_s` (held momentarily at provision) + the stored recipient pubkey;
// **unwrapping requires the printed secret and therefore runs in the operator/
// recovery session, never the daemon** — so there is no daemon code path that
// recovers `KEK_s` from this blob (§4 AC-4 holds: the recovery recipient is not
// an autonomous-MEK recipient).
//
// This is a deliberate SOFTWARE recipient and is therefore NOT subject to
// `require_real_backend()` — that guard stops a software SE *stub* from
// masquerading as a *hardware presence factor* (a daily-driver concern). The
// recovery recipient is not a presence factor and never serves a normal op; it
// is used only in an explicit, operator-initiated recovery after device loss.

/// Private wrap MECHANISM for an off-host **age X25519 recovery recipient** (the
/// printed/exported recovery code's PUBLIC half, `age1…`). Pure software — no
/// presence gesture, no Secure Enclave: the recipient is a cold-recovery target,
/// not a daily presence factor. The returned opaque blob is stored at rest
/// alongside the per-Device SE wraps; only the holder of the matching
/// `AGE-SECRET-KEY-…` secret (off-host) can recover `KEK_s` from it — and that
/// recovery runs CLI-side, never in the daemon (ADR 206 §6 finding C3).
///
/// NOT public: the only way to wrap a `KEK_s` is via
/// [`AuthorizedKekRecipient::wrap`], whose recipient is resolved from the
/// operator's event-sourced custody set. Exposing a raw-`&str` wrap here would be
/// a skeleton-key factory (a caller could seal `KEK_s` to an arbitrary off-host
/// identity), defeating §4/§6 AC-7. So this stays an internal mechanism.
#[cfg(feature = "age")]
fn wrap_kek_to_age_recipient(
    recipient_age_pubkey: &str,
    kek: &ScopeKek,
) -> Result<Vec<u8>, PresenceSealError> {
    use std::io::Write as _;
    let recipient = recipient_age_pubkey
        .parse::<age::x25519::Recipient>()
        .map_err(|e| {
            PresenceSealError::Crypto(format!("invalid age recovery recipient pubkey: {e}"))
        })?;
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|e| PresenceSealError::Crypto(format!("age recovery encryptor: {e}")))?;
    let mut out = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut out)
        .map_err(|e| PresenceSealError::Crypto(format!("age recovery wrap open: {e}")))?;
    writer
        .write_all(kek.as_bytes())
        .map_err(|e| PresenceSealError::Crypto(format!("age recovery wrap write: {e}")))?;
    writer
        .finish()
        .map_err(|e| PresenceSealError::Crypto(format!("age recovery wrap finish: {e}")))?;
    Ok(out)
}

/// `age`-feature-off fallback: the printed/exported recovery tier is unavailable
/// without the `age` dependency. Fails closed (loud) rather than silently
/// dropping a recovery recipient, mirroring the `sops.rs` feature-gate posture.
#[cfg(not(feature = "age"))]
fn wrap_kek_to_age_recipient(
    _recipient_age_pubkey: &str,
    _kek: &ScopeKek,
) -> Result<Vec<u8>, PresenceSealError> {
    Err(PresenceSealError::Crypto(
        "age feature disabled: printed/exported recovery recipient unavailable".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// ADR 206 §4/§6 — the TYPE-GATED `KEK_s` wrap (structural AC-7).
//
// A `KEK_s` may be wrapped ONLY to a recipient in the operator's event-sourced
// custody set (enrolled presence Devices ∪ off-host Recovery recipients), and
// NEVER to an arbitrary pubkey or the autonomous MEK (AC-4 + AC-7 / §6 finding
// M3). We make that a TYPE invariant rather than a call-site check: the wrap
// mechanisms above are private, and the only public wrap entry point —
// [`AuthorizedKekRecipient::wrap`] — consumes a recipient that can be minted ONLY
// by [`resolve_authorized_kek_recipients`] (which reads `devices_current`). A
// caller therefore cannot even *name* an off-allowlist recipient, so there is no
// skeleton-key re-seal path to guard at every site.
// ---------------------------------------------------------------------------

/// Private dispatch over the recipient's wrap mechanism. Kept private so the only
/// way to obtain one is the resolver below.
enum RecipientInner {
    /// P-256 SE-ECIES presence Device — wrap via `se_wrap` (label-local: this arm
    /// only succeeds where the recipient's SE key is in the local keychain, i.e.
    /// the operator-session that holds that Device).
    SecureEnclave(EciesKeyLabel),
    /// Off-host `age` X25519 recovery recipient — wrapped in software (the daemon
    /// can do this with the stored public half; the private half is the printed
    /// recovery code, off-host).
    AgeRecovery(String),
}

/// A `KEK_s` wrap recipient PROVEN to belong to the operator's event-sourced
/// custody set (ADR 206 §4/§6 AC-7). Its inner key material is private and there
/// is no public constructor from a raw pubkey/label — the sole way to obtain one
/// is [`resolve_authorized_kek_recipients`]. So "may a `KEK_s` be wrapped to this
/// recipient?" is answered by the type system: every value in existence passed
/// the allowlist resolution.
pub struct AuthorizedKekRecipient {
    device_id: String,
    key_id: String,
    inner: RecipientInner,
}

impl AuthorizedKekRecipient {
    /// The recipient Device id (a presence Device or a `Recovery` Device).
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// The §4 ECIES recipient `key_id` stored alongside the wrap.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// True for an off-host `age` recovery recipient the DAEMON can wrap to in
    /// software (no presence, no local SE key). A presence (SE) recipient's wrap
    /// is label-local and is produced in that Device's own session instead.
    pub fn is_software_recovery(&self) -> bool {
        matches!(self.inner, RecipientInner::AgeRecovery(_))
    }

    /// Wrap `kek` to this authorized recipient, dispatching by recipient kind.
    /// The ONLY public `KEK_s`-wrap entry point — there is no raw pubkey/label
    /// variant, so AC-7 cannot be bypassed by a forgetful caller.
    pub fn wrap(&self, kek: &ScopeKek) -> Result<Vec<u8>, PresenceSealError> {
        match &self.inner {
            RecipientInner::SecureEnclave(label) => wrap_scope_kek_to_presence(label, kek),
            RecipientInner::AgeRecovery(pubkey) => wrap_kek_to_age_recipient(pubkey, kek),
        }
    }
}

/// Resolve EVERY authorized `KEK_s` recipient from the operator's **event-sourced**
/// custody set: enrolled presence Devices (`se_wrap`) ∪ off-host Recovery
/// recipients (`age`). This is the SOLE constructor of [`AuthorizedKekRecipient`],
/// so AC-7 ("re-seal recipients ∈ enrolled ∪ recovery, refuse any other") holds by
/// construction. A recipient whose curve is neither P-256 nor age-X25519 is
/// dropped fail-closed (no guessed wrap mechanism). Empty ⇒ no recipient ⇒ §4
/// sealing fails closed (never the MEK; AC-4). Read-only.
pub fn resolve_authorized_kek_recipients(state: &MaterializedState) -> Vec<AuthorizedKekRecipient> {
    crate::infra::operator_identity::active_kek_recipients_under_operator_root(state)
        .into_iter()
        .filter_map(|r| {
            let inner = match r.algorithm {
                KeyAlgorithm::EcdsaP256 => {
                    RecipientInner::SecureEnclave(EciesKeyLabel::from_provisioned(r.key_id.clone()))
                }
                KeyAlgorithm::AgeX25519 => RecipientInner::AgeRecovery(r.public_key.clone()),
                _ => return None,
            };
            Some(AuthorizedKekRecipient {
                device_id: r.device_id,
                key_id: r.key_id,
                inner,
            })
        })
        .collect()
}

/// Seal `plaintext` (an authority-bearing value) under the scope's `KEK_s`:
/// fresh `CK_x` encrypts the payload, then `CK_x` is AEAD-wrapped under
/// `KEK_s`. Both AADs bind `aad_id` (a stable purpose-bound identifier, e.g.
/// `persona-secret:<id>`) so a blob cannot be spliced across purposes/owners.
/// The MEK is never touched.
pub fn seal_authority(
    kek: &ScopeKek,
    aad_id: &[u8],
    plaintext: &[u8],
) -> Result<AuthoritySealedBlob, PresenceSealError> {
    // Fresh per-secret content key; payload sealed under CK_x (not KEK_s).
    let mut ck = Zeroizing::new([0u8; 32]);
    getrandom::fill(ck.as_mut_slice()).expect("OS entropy failure on CK_x generation");

    let payload_cipher = XChaCha20Poly1305::new_from_slice(ck.as_slice())
        .map_err(|e| PresenceSealError::Crypto(format!("payload cipher init: {e}")))?;
    let mut payload_nonce = [0u8; 24];
    getrandom::fill(&mut payload_nonce).expect("OS entropy failure on payload nonce");
    let p_aad = payload_aad(aad_id);
    let ciphertext = payload_cipher
        .encrypt(
            XNonce::from_slice(&payload_nonce),
            Payload {
                msg: plaintext,
                aad: &p_aad,
            },
        )
        .map_err(|e| PresenceSealError::Crypto(format!("payload seal: {e}")))?;

    // Wrap CK_x under KEK_s with the §4 wrap AAD.
    let ck_cipher = XChaCha20Poly1305::new_from_slice(kek.as_bytes())
        .map_err(|e| PresenceSealError::Crypto(format!("ck wrap cipher init: {e}")))?;
    let mut ck_nonce = [0u8; 24];
    getrandom::fill(&mut ck_nonce).expect("OS entropy failure on ck nonce");
    let c_aad = ck_wrap_aad(aad_id);
    let wrapped_ck = ck_cipher
        .encrypt(
            XNonce::from_slice(&ck_nonce),
            Payload {
                msg: ck.as_slice(),
                aad: &c_aad,
            },
        )
        .map_err(|e| PresenceSealError::Crypto(format!("ck wrap: {e}")))?;

    Ok(AuthoritySealedBlob {
        payload_nonce: payload_nonce.to_vec(),
        ciphertext,
        ck_nonce: ck_nonce.to_vec(),
        wrapped_ck,
    })
}

/// Open an [`AuthoritySealedBlob`] under the SAME scope `KEK_s` and `aad_id`:
/// unwrap `CK_x` under `KEK_s`, then decrypt the payload under `CK_x`. Any
/// mismatch (wrong `KEK_s`, wrong `aad_id`, spliced/tampered blob) fails the
/// AEAD tag. Returns plaintext as `Zeroizing`. NO MEK fallback.
pub fn open_authority(
    kek: &ScopeKek,
    aad_id: &[u8],
    blob: &AuthoritySealedBlob,
) -> Result<Zeroizing<Vec<u8>>, PresenceSealError> {
    if blob.ck_nonce.len() != 24 || blob.payload_nonce.len() != 24 {
        return Err(PresenceSealError::Crypto(format!(
            "invalid nonce length (ck={}, payload={}; expected 24)",
            blob.ck_nonce.len(),
            blob.payload_nonce.len()
        )));
    }

    // Unwrap CK_x under KEK_s.
    let ck_cipher = XChaCha20Poly1305::new_from_slice(kek.as_bytes())
        .map_err(|e| PresenceSealError::Crypto(format!("ck unwrap cipher init: {e}")))?;
    let c_aad = ck_wrap_aad(aad_id);
    let ck = Zeroizing::new(
        ck_cipher
            .decrypt(
                XNonce::from_slice(&blob.ck_nonce),
                Payload {
                    msg: blob.wrapped_ck.as_slice(),
                    aad: &c_aad,
                },
            )
            .map_err(|e| PresenceSealError::Crypto(format!("ck unwrap: {e}")))?,
    );
    if ck.len() != 32 {
        return Err(PresenceSealError::Crypto(format!(
            "unwrapped CK_x is {} bytes (expected 32)",
            ck.len()
        )));
    }

    // Decrypt payload under CK_x.
    let payload_cipher = XChaCha20Poly1305::new_from_slice(&ck)
        .map_err(|e| PresenceSealError::Crypto(format!("payload cipher init: {e}")))?;
    let p_aad = payload_aad(aad_id);
    let plaintext = payload_cipher
        .decrypt(
            XNonce::from_slice(&blob.payload_nonce),
            Payload {
                msg: blob.ciphertext.as_slice(),
                aad: &p_aad,
            },
        )
        .map_err(|e| PresenceSealError::Crypto(format!("payload open: {e}")))?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ember_broker::secure_enclave::{new_stub_key, se_register_stub_key};

    /// Register a software stub SE key under `label` and return its
    /// ECIES-role label so the §4 path can wrap/unwrap against it without
    /// real hardware. (se_wrap/se_unwrap consult the stub registry first, so
    /// this works regardless of the `se-real` feature.)
    fn stub_ecies(label: &str) -> EciesKeyLabel {
        let handle = new_stub_key(label);
        se_register_stub_key(label, &handle);
        EciesKeyLabel::from_provisioned(label)
    }

    #[test]
    fn round_trip_through_presence_kek() {
        let recipient = stub_ecies("test-ecies-roundtrip");
        let kek = generate_scope_kek();
        let wrapped_kek = wrap_scope_kek_to_presence(&recipient, &kek).expect("wrap kek");

        let aad = b"persona-secret:claude-code-default";
        let blob = seal_authority(&kek, aad, b"ed25519-secret:deadbeef").expect("seal");

        // Open path: recover KEK_s via the (stubbed) presence gesture, then open.
        let reopened =
            unwrap_scope_kek_from_presence(&recipient, &wrapped_kek).expect("unwrap kek");
        let pt = open_authority(&reopened, aad, &blob).expect("open");
        assert_eq!(&pt[..], b"ed25519-secret:deadbeef");
    }

    #[test]
    fn ac4_fail_closed_without_the_scope_kek() {
        // AC-4: a blob is undecryptable without the presence-derived KEK_s.
        // Sealing with one KEK and opening with an unrelated KEK must fail the
        // AEAD tag — there is no MEK or other fallback that recovers it.
        let kek = generate_scope_kek();
        let aad = b"persona-secret:p1";
        let blob = seal_authority(&kek, aad, b"top-secret").expect("seal");

        let wrong_kek = generate_scope_kek();
        let err = open_authority(&wrong_kek, aad, &blob).unwrap_err();
        assert!(
            matches!(err, PresenceSealError::Crypto(_)),
            "opening with the wrong KEK_s must fail the AEAD tag, got {err:?}"
        );
    }

    #[test]
    fn ac4_fail_closed_when_presence_unwrap_unavailable() {
        // AC-4: if the presence device / SE-ECIES key is absent, recovering
        // KEK_s fails closed (no MEK fallback) — so the blob cannot be opened.
        let recipient = stub_ecies("test-ecies-present");
        let kek = generate_scope_kek();
        let _wrapped = wrap_scope_kek_to_presence(&recipient, &kek).expect("wrap");

        // A recipient label with no registered key (stands in for "no enrolled
        // presence device"): se_unwrap finds nothing and we fail closed.
        let absent = EciesKeyLabel::from_provisioned("test-ecies-absent");
        let err = unwrap_scope_kek_from_presence(&absent, &[0u8; 80]).unwrap_err();
        assert!(
            matches!(err, PresenceSealError::PresenceUnwrapFailed(_)),
            "absent presence key must fail closed, got {err:?}"
        );
    }

    #[test]
    fn aad_binding_defeats_cross_purpose_splice() {
        // A blob sealed under one purpose id must not open under another, even
        // with the correct KEK_s — the AAD binds the purpose.
        let kek = generate_scope_kek();
        let blob = seal_authority(&kek, b"persona-secret:a", b"v").expect("seal");
        let err = open_authority(&kek, b"persona-secret:b", &blob).unwrap_err();
        assert!(matches!(err, PresenceSealError::Crypto(_)));
    }

    #[test]
    fn ciphertext_tamper_is_rejected() {
        let kek = generate_scope_kek();
        let aad = b"persona-secret:tamper";
        let mut blob = seal_authority(&kek, aad, b"payload").expect("seal");
        blob.ciphertext[0] ^= 0x01;
        assert!(open_authority(&kek, aad, &blob).is_err());
    }

    #[test]
    fn wrapped_ck_tamper_is_rejected() {
        let kek = generate_scope_kek();
        let aad = b"persona-secret:tamper2";
        let mut blob = seal_authority(&kek, aad, b"payload").expect("seal");
        blob.wrapped_ck[0] ^= 0x01;
        assert!(open_authority(&kek, aad, &blob).is_err());
    }

    #[cfg(feature = "age")]
    #[test]
    fn recovery_recipient_age_round_trips_and_wrong_secret_fails_closed() {
        // ADR 206 §6 cold-recovery recipient: KEK_s wrapped to the printed
        // age X25519 recipient is recoverable ONLY with the off-host secret.
        use age::secrecy::ExposeSecret as _;
        use std::io::Read as _;

        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public().to_string(); // age1… (daemon stores this)
        let secret = identity.to_string().expose_secret().to_string(); // printed once

        let kek = generate_scope_kek();
        let kek_bytes = *kek.as_bytes();
        let wrapped = wrap_kek_to_age_recipient(&recipient, &kek).expect("wrap to recovery");
        // The wrap is not the plaintext KEK_s (it is an age blob).
        assert_ne!(&wrapped[..], &kek_bytes[..]);

        // Recover KEK_s from the PRINTED secret string (the off-host code),
        // mirroring the CLI recovery path. The daemon never runs this.
        let id: age::x25519::Identity = secret.parse().expect("parse printed recovery secret");
        let decryptor = age::Decryptor::new(wrapped.as_slice()).expect("decryptor");
        let mut reader = decryptor
            .decrypt(std::iter::once(&id as &dyn age::Identity))
            .expect("decrypt with recovery secret");
        let mut recovered = Vec::new();
        reader
            .read_to_end(&mut recovered)
            .expect("read recovered KEK_s");
        assert_eq!(
            recovered, kek_bytes,
            "recovered KEK_s must match the sealed one"
        );

        // A different (wrong) recovery secret fails closed — no fallback.
        let wrong = age::x25519::Identity::generate();
        let decryptor = age::Decryptor::new(wrapped.as_slice()).expect("decryptor2");
        assert!(
            decryptor
                .decrypt(std::iter::once(&wrong as &dyn age::Identity))
                .is_err(),
            "an unrelated recovery secret must fail closed"
        );
    }

    #[test]
    fn one_scope_kek_serves_many_secrets() {
        // The per-scope-open property: one KEK_s (one gesture) seals/opens
        // every secret in the scope.
        let kek = generate_scope_kek();
        let b1 = seal_authority(&kek, b"scope:s/secret:1", b"one").expect("seal1");
        let b2 = seal_authority(&kek, b"scope:s/secret:2", b"two").expect("seal2");
        assert_eq!(
            &open_authority(&kek, b"scope:s/secret:1", &b1).unwrap()[..],
            b"one"
        );
        assert_eq!(
            &open_authority(&kek, b"scope:s/secret:2", &b2).unwrap()[..],
            b"two"
        );
    }
}
