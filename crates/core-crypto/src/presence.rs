//! Presence attestation trait.
//! .B: Tier 1/2 approvals consult an attester before flipping
//! approved state. Real macOS SE wiring deferred to .B-SE-WIRE.
//!
//! implementation-note-36 (design note D2):
//! [`bind_presence_challenge`] (a.k.a. `presence_challenge_bind`) computes the
//! per-request challenge that the browser presence prompter signs. The challenge
//! is `SHA-256` over the length-prefixed canonical encoding of
//! `(workflow_id, action_key, spiffe_uri, nonce)` — every component is per-request
//! unique, so replay across requests is structurally impossible. Length-prefixing
//! defends against component-collision attacks where rearranging the field
//! boundaries would otherwise produce identical concatenated bytes.

use ed25519_dalek::{
    Signature as DalekSignature, Signer as DalekSigner, SigningKey, Verifier as DalekVerifier,
    VerifyingKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresenceProof {
    /// Bytes the attester signed/proved (typically grant_id || statement_hash || now).
    pub challenge: Vec<u8>,
    /// Timestamp when proof was produced (millis since epoch).
    pub produced_at_ms: u64,
    /// Implementation name, for audit (e.g. "null", "se-macos-v1").
    pub attester_name: String,
    /// Optional implementation-specific attestation bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum PresenceError {
    #[error("presence attestation unavailable: {0}")]
    Unavailable(String),
    #[error("presence attestation refused by user")]
    Refused,
    #[error("presence proof too stale (age_ms={age_ms})")]
    Stale { age_ms: u64 },
}

pub trait PresenceAttester: Send + Sync {
    fn name(&self) -> &str;
    fn attest(&self, challenge: &[u8]) -> Result<PresenceProof, PresenceError>;
}

#[derive(Debug, Default)]
pub struct NullAttester;

impl PresenceAttester for NullAttester {
    fn name(&self) -> &str {
        "null"
    }
    fn attest(&self, _challenge: &[u8]) -> Result<PresenceProof, PresenceError> {
        Err(PresenceError::Unavailable(
            "NullAttester always refuses; configure SecureEnclaveAttester or alternative".into(),
        ))
    }
}

#[cfg(target_os = "macos")]
pub struct SecureEnclaveAttester;

#[cfg(target_os = "macos")]
impl PresenceAttester for SecureEnclaveAttester {
    fn name(&self) -> &str {
        "se-macos-v1-stub"
    }
    fn attest(&self, _challenge: &[u8]) -> Result<PresenceProof, PresenceError> {
        Err(PresenceError::Unavailable(
            "SecureEnclaveAttester wire-up deferred to .B-SE-WIRE".into(),
        ))
    }
}

/// `presence_challenge_bind`: SHA-256 over the length-prefixed canonical
/// encoding of `(workflow_id, action_key, spiffe_uri, nonce)` — defense
/// against component-collision attacks.
///
/// Per design note D2, the presence challenge the
/// browser prompter signs is bound to the exact tuple that authorizes the
/// action. Every component is per-request unique, so a valid challenge cannot
/// be replayed across requests:
///
/// - `workflow_id` — the daemon-issued unique identifier for this workflow
/// - `action_key`  — the action being authorized inside that workflow
/// - `spiffe_uri`  — the SPIFFE URI of the bridge/agent making the request
/// - `nonce`       — fresh server-supplied per-request entropy
///
/// # Canonical encoding
///
/// `SHA-256(LEN(workflow_id) || workflow_id ||`
/// `         LEN(action_key)  || action_key  ||`
/// `         LEN(spiffe_uri)  || spiffe_uri  ||`
/// `         LEN(nonce)       || nonce)`
///
/// where `LEN` is an 8-byte big-endian `u64`. Length-prefixing prevents
/// component-collision attacks: without it, `("foobar", "")` and
/// `("foo", "bar")` would hash to the same value because the concatenated
/// raw bytes are identical.
pub fn bind_presence_challenge(
    workflow_id: &str,
    action_key: &str,
    spiffe_uri: &str,
    nonce: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    write_length_prefixed(&mut hasher, workflow_id.as_bytes());
    write_length_prefixed(&mut hasher, action_key.as_bytes());
    write_length_prefixed(&mut hasher, spiffe_uri.as_bytes());
    write_length_prefixed(&mut hasher, nonce);
    hasher.finalize().into()
}

/// Feed `bytes` into `hasher` prefixed by its length as an 8-byte big-endian
/// `u64`. Internal helper for [`bind_presence_challenge`].
fn write_length_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = bytes.len() as u64;
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
}

// ---------------------------------------------------------------------------
// implementation-note-37
// ---------------------------------------------------------------------------
//
// Per design note D2: after the daemon verifies the
// browser's WebAuthn assertion, it mints a `DaemonSignedHandle` — a short-lived
// Ed25519-signed envelope over `(challenge_hash, persona_id, issued_at, ttl)`.
// Downstream RPCs verify against the daemon's pinned public key and never see
// the raw WebAuthn assertion bytes. This keeps the audit log clean (just a
// handle status + the inputs that bind it) and frees clients from grappling
// with the WebAuthn spec: the daemon does it once, hands back a tiny envelope.
//
// Wire shape mirrors `bind_presence_challenge` — all variable fields are
// length-prefixed (8-byte big-endian u64) so the signed bytes cannot collide
// under component rearrangement. The fixed-width `[u8; 32]` challenge_hash
// and `u64` ttl/issued_at fields encode directly without a length prefix
// (their length is structural, not data-dependent).

/// Default lifetime for a daemon-signed presence handle.
///
/// Per the brief — no codebase-wide spawn-handle TTL constant exists yet, so
/// 30s is the default. Short enough that a stolen handle's blast radius is
/// bounded; long enough to cover an RPC round-trip plus the downstream verb.
pub const DEFAULT_PRESENCE_HANDLE_TTL_MS: u64 = 30_000;

/// Domain-separation tag for `DaemonSignedHandle` signing. Prevents the
/// signature from being replayable in any other Emberlink signing context
/// (event signatures, grant offers, etc.).
const DOMAIN_PRESENCE_HANDLE: &[u8] = b"emberlink/v1/presence-handle";

/// Daemon-signed envelope returned after the WebAuthn assertion is verified.
///
/// Downstream RPC handlers verify the `signature` field against the daemon's
/// pinned Ed25519 public key — they never see the raw WebAuthn assertion.
/// The envelope binds:
///
/// - `challenge_hash`    — output of [`bind_presence_challenge`] for the
///   authorizing request; ties the handle to the exact
///   `(workflow_id, action_key, spiffe_uri, nonce)`
///   tuple the user attested to.
/// - `persona_id`        — the persona on whose behalf the handle was issued.
/// - `issued_at_unix_ms` — daemon clock at mint time.
/// - `ttl_ms`            — handle lifetime; verify rejects when
///   `now > issued_at + ttl_ms`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonSignedHandle {
    pub challenge_hash: [u8; 32],
    pub persona_id: String,
    pub issued_at_unix_ms: u64,
    pub ttl_ms: u64,
    /// Ed25519 signature over the canonical encoding of the fields above.
    pub signature: Vec<u8>,
}

/// Errors that can be returned by [`verify_presence_handle`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PresenceHandleError {
    /// The Ed25519 signature did not verify under the daemon's pinned key.
    #[error("daemon-signed handle signature did not verify")]
    SignatureInvalid,
    /// The handle's `issued_at + ttl` is in the past relative to `now`.
    #[error(
        "daemon-signed handle expired (issued_at_ms={issued_at_ms}, ttl_ms={ttl_ms}, now_ms={now_ms})"
    )]
    Expired {
        issued_at_ms: u64,
        ttl_ms: u64,
        now_ms: u64,
    },
    /// `issued_at > now` — implies the caller's clock is behind the daemon's
    /// by more than the verifier tolerates (no skew allowance in v1).
    #[error(
        "daemon-signed handle issued_at is in the future (issued_at_ms={issued_at_ms}, now_ms={now_ms})"
    )]
    NotYetValid { issued_at_ms: u64, now_ms: u64 },
    /// `persona_id` field on the handle does not match the caller's expected
    /// persona. Caller-supplied check (the signature itself does not bind a
    /// "right" persona — the persona id IS the bound value).
    #[error("daemon-signed handle persona mismatch (expected={expected}, got={got})")]
    PersonaMismatch { expected: String, got: String },
    /// Caller's expected challenge hash does not match the handle's
    /// `challenge_hash` field. Surfaces when the downstream RPC binds the
    /// handle to a fresh `(workflow_id, action_key, spiffe_uri, nonce)`
    /// tuple and the recomputed hash diverges from what the daemon signed.
    #[error("daemon-signed handle challenge mismatch")]
    ChallengeMismatch,
}

/// Mint a [`DaemonSignedHandle`] over `(challenge_hash, persona_id,
/// issued_at, ttl)` using the daemon's Ed25519 `signing_key`.
///
/// `issued_at_unix_ms` is passed by the caller (no internal clock dependency
/// — keeps the function testable with synthetic time).
pub fn sign_presence_handle(
    challenge_hash: [u8; 32],
    persona_id: &str,
    issued_at_unix_ms: u64,
    ttl_ms: u64,
    signing_key: &SigningKey,
) -> DaemonSignedHandle {
    let signing_input =
        canonical_handle_signing_input(&challenge_hash, persona_id, issued_at_unix_ms, ttl_ms);
    let signature = signing_key.sign(&signing_input);
    DaemonSignedHandle {
        challenge_hash,
        persona_id: persona_id.to_string(),
        issued_at_unix_ms,
        ttl_ms,
        signature: signature.to_bytes().to_vec(),
    }
}

/// Verify a [`DaemonSignedHandle`] against the daemon's pinned Ed25519
/// `verifying_key`.
///
/// `now_unix_ms` is supplied by the caller — the verifier has no internal
/// clock dependency, which keeps both signing and verification trivially
/// testable with synthetic time.
///
/// Returns `Ok(())` when the signature is valid AND the handle is within its
/// TTL window. The four error variants surface the distinct failure modes
/// callers most need to distinguish in audit logs.
pub fn verify_presence_handle(
    handle: &DaemonSignedHandle,
    verifying_key: &VerifyingKey,
    now_unix_ms: u64,
) -> Result<(), PresenceHandleError> {
    // Clock-skew check first: a handle from the future is structurally
    // broken (either bad daemon clock or the verifier's clock is behind).
    // Reject before doing the signature check so we don't waste a curve op
    // on definitely-rejected handles.
    if handle.issued_at_unix_ms > now_unix_ms {
        return Err(PresenceHandleError::NotYetValid {
            issued_at_ms: handle.issued_at_unix_ms,
            now_ms: now_unix_ms,
        });
    }

    // Expiry check: `issued_at + ttl` is the deadline. Saturating add
    // matches the intent that a u64 overflow is treated as never-expiring
    // rather than wrapping to a past timestamp (defense against caller
    // passing `ttl_ms = u64::MAX` to bypass expiry — the caller's RPC
    // should also cap ttl at issuance time).
    let deadline_ms = handle.issued_at_unix_ms.saturating_add(handle.ttl_ms);
    if now_unix_ms > deadline_ms {
        return Err(PresenceHandleError::Expired {
            issued_at_ms: handle.issued_at_unix_ms,
            ttl_ms: handle.ttl_ms,
            now_ms: now_unix_ms,
        });
    }

    // Signature check.
    let signature_bytes: [u8; 64] = handle
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| PresenceHandleError::SignatureInvalid)?;
    let signature = DalekSignature::from_bytes(&signature_bytes);
    let signing_input = canonical_handle_signing_input(
        &handle.challenge_hash,
        &handle.persona_id,
        handle.issued_at_unix_ms,
        handle.ttl_ms,
    );
    verifying_key
        .verify(&signing_input, &signature)
        .map_err(|_| PresenceHandleError::SignatureInvalid)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// implementation-note-38
// (design note D2)
// ---------------------------------------------------------------------------
//
// Checkpoint marker: `presence_bridge_proto`.
//
// Canonical wire-format types for the presence-bridge JSON-RPC surface.
// Lifted out of `ember-daemon::broker::handler` so client crates (CLI,
// dashboard, future SDK bindings) can consume them without taking a
// daemon-internal dependency. The handler in `ember-daemon` re-exports
// these as `pub use core_crypto::presence::{PresenceProofRequest,
// PresenceProofResponse, ChallengeBinding}` so existing call sites keep
// compiling unchanged.
//
// Shape derivation rationale:
//
// - `PresenceProofRequest` carries the full challenge-tuple
//   `(workflow_id, action_key, spiffe_uri, nonce_hex)` so the daemon can
//   reconstruct the bound challenge via [`bind_presence_challenge`] and
//   bind the resulting `DaemonSignedHandle`'s `challenge_hash` to the
//   exact tuple the browser presence prompter signed. The
//   `nonce_hex`-as-hex-string encoding (rather than raw bytes) keeps the
//   JSON shape portable across language clients (JS dashboard, future
//   Python SDK) — every JSON parser handles strings, but base64/binary
//   blob handling varies.
//
// - `PresenceProofResponse` carries ONLY the `DaemonSignedHandle` — the
//   raw WebAuthn assertion stays inside the daemon's trust boundary so
//   downstream RPCs never need to know the WebAuthn spec.
//
// - `ChallengeBinding` is a thin newtype around the 32-byte SHA-256
//   output of [`bind_presence_challenge`]. It exists to make the
//   challenge-binding type appear at the public API surface (callers can
//   accept `&ChallengeBinding` rather than `&[u8; 32]` for stronger
//   intent signalling at the type system level) without changing the
//   underlying hash. Existing code that calls `bind_presence_challenge`
//   directly continues to work — `ChallengeBinding::compute` is a
//   convenience constructor.

/// Wire-format request for the `presence/request_proof` JSON-RPC method.
///
/// All four challenge-tuple fields are forwarded unchanged to the browser
/// presence prompter; they recombine into the
/// [`bind_presence_challenge`] hash the WebAuthn assertion binds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceProofRequest {
    /// Daemon-issued unique identifier for this workflow.
    pub workflow_id: String,
    /// The action being authorized inside that workflow.
    pub action_key: String,
    /// SPIFFE URI of the bridge/agent making the request.
    pub spiffe_uri: String,
    /// Server-supplied per-request entropy. Encoded as a hex string on
    /// the wire so the JSON shape is portable across language clients.
    pub nonce_hex: String,
    /// Persona on whose behalf the proof is requested. Used to (a)
    /// consult the freeze gate and (b) bind the resulting
    /// `DaemonSignedHandle`'s `persona_id` field.
    pub persona_id: String,
    /// Optional stable prompt identifier chosen by the caller. When
    /// present, runtime-local prompt transports may use it so the caller
    /// can deterministically route the operator to the matching approval
    /// surface while the proof RPC is in flight.
    #[serde(default)]
    pub prompt_id: Option<String>,
    /// Optional operator-facing reason string for the prompt transport.
    /// When absent, the verifier transport derives a generic reason from
    /// `action_key` and `spiffe_uri`.
    #[serde(default)]
    pub reason: Option<String>,
    /// Optional caller_persona for peercred binding checks, mirrors the
    /// shape of sibling broker RPCs. When absent, no peercred check is
    /// performed on this surface.
    #[serde(default)]
    pub caller_persona: Option<String>,
    /// Optional handle TTL in milliseconds. When omitted the daemon
    /// applies [`DEFAULT_PRESENCE_HANDLE_TTL_MS`].
    #[serde(default)]
    pub ttl_ms: Option<u64>,
}

/// Wire-format response for `presence/request_proof`. The
/// `daemon_signed_handle` is the ONLY artifact returned — the raw WebAuthn
/// assertion stays inside the daemon's trust boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceProofResponse {
    pub daemon_signed_handle: DaemonSignedHandle,
}

/// Canonical bound-challenge value — the 32-byte SHA-256 output of
/// [`bind_presence_challenge`] over the
/// `(workflow_id, action_key, spiffe_uri, nonce)` tuple.
///
/// Thin newtype that exists for intent signalling at API boundaries:
/// downstream functions that accept `&ChallengeBinding` are explicit
/// about the fact that they want a canonically-bound challenge, not just
/// any 32 bytes. Equivalent to `[u8; 32]` at the byte level; conversions
/// are zero-cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeBinding {
    /// `SHA-256(LEN(workflow_id) || workflow_id || …)` per
    /// [`bind_presence_challenge`].
    pub canonical_bytes: [u8; 32],
}

impl ChallengeBinding {
    /// Compute the canonical challenge binding for the supplied tuple by
    /// delegating to [`bind_presence_challenge`]. Returns a
    /// [`ChallengeBinding`] wrapping the 32-byte SHA-256 output.
    pub fn compute(workflow_id: &str, action_key: &str, spiffe_uri: &str, nonce: &[u8]) -> Self {
        Self {
            canonical_bytes: bind_presence_challenge(workflow_id, action_key, spiffe_uri, nonce),
        }
    }

    /// View the canonical hash as a fixed-size byte array — useful for
    /// passing into [`sign_presence_handle`] / [`verify_presence_handle`]
    /// which take `[u8; 32]` directly.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.canonical_bytes
    }
}

impl From<[u8; 32]> for ChallengeBinding {
    fn from(canonical_bytes: [u8; 32]) -> Self {
        Self { canonical_bytes }
    }
}

impl From<ChallengeBinding> for [u8; 32] {
    fn from(binding: ChallengeBinding) -> [u8; 32] {
        binding.canonical_bytes
    }
}

/// Canonical signing input for [`DaemonSignedHandle`].
///
/// Layout:
///
/// `DOMAIN_PRESENCE_HANDLE                                 ` (fixed tag) `||`
/// `challenge_hash                                          ` (fixed 32 bytes) `||`
/// `issued_at_unix_ms.to_be_bytes()                         ` (fixed 8 bytes) `||`
/// `ttl_ms.to_be_bytes()                                    ` (fixed 8 bytes) `||`
/// `LEN(persona_id) || persona_id                           ` (length-prefixed)
///
/// The fixed-width fields (`challenge_hash`, the two u64 timestamps) do not
/// need length prefixes because their length is structural — a verifier
/// always reads exactly 32 / 8 / 8 bytes there. The variable-length
/// `persona_id` is length-prefixed with an 8-byte big-endian u64, matching
/// the convention from [`bind_presence_challenge`] and defending against
/// component-collision attacks.
fn canonical_handle_signing_input(
    challenge_hash: &[u8; 32],
    persona_id: &str,
    issued_at_unix_ms: u64,
    ttl_ms: u64,
) -> Vec<u8> {
    let persona_bytes = persona_id.as_bytes();
    let mut out =
        Vec::with_capacity(DOMAIN_PRESENCE_HANDLE.len() + 32 + 8 + 8 + 8 + persona_bytes.len());
    out.extend_from_slice(DOMAIN_PRESENCE_HANDLE);
    out.extend_from_slice(challenge_hash);
    out.extend_from_slice(&issued_at_unix_ms.to_be_bytes());
    out.extend_from_slice(&ttl_ms.to_be_bytes());
    out.extend_from_slice(&(persona_bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(persona_bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_attester_always_refuses() {
        let a = NullAttester;
        let r = a.attest(b"test-challenge");
        assert!(matches!(r, Err(PresenceError::Unavailable(_))));
        assert_eq!(a.name(), "null");
    }

    #[test]
    fn presence_proof_round_trips_through_serde() {
        let p = PresenceProof {
            challenge: vec![0xde, 0xad],
            produced_at_ms: 42,
            attester_name: "test".to_string(),
            attestation: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: PresenceProof = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    /// `presence_challenge_bind` known-vector: hand-computed SHA-256 over the
    /// length-prefixed canonical encoding of a fixed `(workflow_id, action_key,
    /// spiffe_uri, nonce)` tuple. Regression guard for accidental encoding
    /// changes that would break wire compatibility with the browser prompter.
    #[test]
    fn bind_presence_challenge_known_vector() {
        let workflow_id = "wf-123";
        let action_key = "approve-grant";
        let spiffe_uri = "spiffe://emberlink.dev/agent/foo";
        let nonce: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let got = bind_presence_challenge(workflow_id, action_key, spiffe_uri, &nonce);
        // Hand-computed via Python:
        //   def lp(b): return struct.pack('>Q', len(b)) + b
        //   sha256(lp(b'wf-123') + lp(b'approve-grant')
        //          + lp(b'spiffe://emberlink.dev/agent/foo')
        //          + lp(bytes.fromhex('0102030405060708090a0b0c0d0e0f10')))
        let expected_hex = "24e07761051a0a14057509d11fb5595b387ef28efe5f4bf49eec6ddd74a2d906";
        assert_eq!(core_types::bytes_to_hex(&got), expected_hex);
    }

    /// Injectivity: flipping any single tuple component (workflow_id,
    /// action_key, spiffe_uri, nonce) must produce a different challenge.
    /// Parametric over all four components.
    #[test]
    fn bind_presence_challenge_injective_per_component() {
        let base = bind_presence_challenge(
            "wf-1",
            "approve",
            "spiffe://emberlink.dev/agent/a",
            &[0xaa, 0xbb],
        );

        // Vary workflow_id.
        let v_workflow = bind_presence_challenge(
            "wf-2",
            "approve",
            "spiffe://emberlink.dev/agent/a",
            &[0xaa, 0xbb],
        );
        assert_ne!(base, v_workflow, "workflow_id change must alter challenge");

        // Vary action_key.
        let v_action = bind_presence_challenge(
            "wf-1",
            "revoke",
            "spiffe://emberlink.dev/agent/a",
            &[0xaa, 0xbb],
        );
        assert_ne!(base, v_action, "action_key change must alter challenge");

        // Vary spiffe_uri.
        let v_spiffe = bind_presence_challenge(
            "wf-1",
            "approve",
            "spiffe://emberlink.dev/agent/b",
            &[0xaa, 0xbb],
        );
        assert_ne!(base, v_spiffe, "spiffe_uri change must alter challenge");

        // Vary nonce.
        let v_nonce = bind_presence_challenge(
            "wf-1",
            "approve",
            "spiffe://emberlink.dev/agent/a",
            &[0xaa, 0xbc],
        );
        assert_ne!(base, v_nonce, "nonce change must alter challenge");
    }

    /// Length-prefixing matters: `("foobar", "")` and `("foo", "bar")`
    /// share identical concatenated raw bytes for the (workflow_id,
    /// action_key) pair. Without 8-byte big-endian length prefixes the
    /// challenge would collide; with them, the two tuples produce
    /// distinct SHA-256 digests. This is the defense against
    /// component-collision attacks.
    #[test]
    fn bind_presence_challenge_length_prefix_disambiguates_components() {
        let spiffe_uri = "spiffe://e/a";
        let nonce = [0x00_u8];

        let a = bind_presence_challenge("foobar", "", spiffe_uri, &nonce);
        let b = bind_presence_challenge("foo", "bar", spiffe_uri, &nonce);

        assert_ne!(
            a, b,
            "length-prefixing must disambiguate ('foobar','') from ('foo','bar')"
        );
    }

    // -----------------------------------------------------------------
    // implementation-note-37 tests
    // -----------------------------------------------------------------

    /// Deterministic Ed25519 keypair for handle-signing tests. Derived
    /// the same way as `derive_fixture_signing_key` in `lib.rs` so the
    /// test does not pull in OS entropy.
    fn fixture_handle_keypair(seed_label: &str) -> SigningKey {
        let digest = Sha256::digest(format!("presence-handle-fixture:{seed_label}").as_bytes());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest[..32]);
        SigningKey::from_bytes(&seed)
    }

    /// Round-trip: a freshly minted handle, verified at `now == issued_at`,
    /// passes signature verification AND falls inside its TTL window.
    #[test]
    fn sign_presence_handle_round_trip() {
        let signing_key = fixture_handle_keypair("round-trip");
        let verifying_key = signing_key.verifying_key();
        let challenge_hash = bind_presence_challenge(
            "wf-rt",
            "approve",
            "spiffe://emberlink.dev/agent/rt",
            &[0x01, 0x02, 0x03],
        );
        let issued_at = 1_000_000_000_000u64;
        let handle = sign_presence_handle(
            challenge_hash,
            "persona-rt",
            issued_at,
            DEFAULT_PRESENCE_HANDLE_TTL_MS,
            &signing_key,
        );

        // Verify immediately at issuance time → Ok.
        verify_presence_handle(&handle, &verifying_key, issued_at)
            .expect("freshly minted handle must verify at issued_at");

        // Verify just before deadline → still Ok.
        let deadline = issued_at + DEFAULT_PRESENCE_HANDLE_TTL_MS;
        verify_presence_handle(&handle, &verifying_key, deadline)
            .expect("handle must verify at deadline (now == issued_at + ttl)");

        // Sanity: round-trips through serde (Receipt audit serialisation).
        let json = serde_json::to_string(&handle).unwrap();
        let back: DaemonSignedHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(handle, back);
    }

    /// Expired handle: TTL of 10ms, verified 1000ms after issuance, returns
    /// `PresenceHandleError::Expired`.
    #[test]
    fn verify_presence_handle_rejects_expired() {
        let signing_key = fixture_handle_keypair("expired");
        let verifying_key = signing_key.verifying_key();
        let issued_at = 2_000_000_000_000u64;
        let ttl_ms = 10u64;
        let handle = sign_presence_handle(
            bind_presence_challenge("wf-e", "act-e", "spiffe://e/a", &[]),
            "persona-e",
            issued_at,
            ttl_ms,
            &signing_key,
        );

        let now = issued_at + 1000;
        let err =
            verify_presence_handle(&handle, &verifying_key, now).expect_err("must reject expired");
        match err {
            PresenceHandleError::Expired {
                issued_at_ms,
                ttl_ms: ttl,
                now_ms,
            } => {
                assert_eq!(issued_at_ms, issued_at);
                assert_eq!(ttl, ttl_ms);
                assert_eq!(now_ms, now);
            }
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    /// Tampered signature: flip a single bit in the signature byte vector
    /// and verification returns `PresenceHandleError::SignatureInvalid`.
    /// This also covers tampering with any of the signed fields: any
    /// post-mint modification produces a signature that no longer verifies
    /// against the recomputed canonical signing input.
    #[test]
    fn verify_presence_handle_rejects_tampered_signature() {
        let signing_key = fixture_handle_keypair("tampered");
        let verifying_key = signing_key.verifying_key();
        let issued_at = 3_000_000_000_000u64;
        let mut handle = sign_presence_handle(
            bind_presence_challenge("wf-t", "act-t", "spiffe://e/t", &[0xff]),
            "persona-t",
            issued_at,
            DEFAULT_PRESENCE_HANDLE_TTL_MS,
            &signing_key,
        );

        // Round-trip baseline: untampered → Ok.
        verify_presence_handle(&handle, &verifying_key, issued_at)
            .expect("baseline (untampered) handle must verify");

        // Flip the high bit of the first signature byte. Ed25519 sig
        // verification will reject — no chance of accidental forgery.
        handle.signature[0] ^= 0x80;
        let err = verify_presence_handle(&handle, &verifying_key, issued_at)
            .expect_err("tampered signature must be rejected");
        assert_eq!(err, PresenceHandleError::SignatureInvalid);
    }

    /// Persona mismatch (between two distinct handles): a handle minted
    /// for persona A must NOT verify if the verifier (or downstream RPC)
    /// supplied a handle whose `persona_id` field has been replaced with
    /// persona B. The persona id is part of the signed envelope, so
    /// replacing it invalidates the signature.
    #[test]
    fn verify_presence_handle_rejects_persona_substitution() {
        let signing_key = fixture_handle_keypair("persona-sub");
        let verifying_key = signing_key.verifying_key();
        let issued_at = 4_000_000_000_000u64;
        let challenge_hash = bind_presence_challenge("wf-p", "act-p", "spiffe://e/p", &[0x00]);

        // Mint a handle for persona-A.
        let handle_a = sign_presence_handle(
            challenge_hash,
            "persona-a",
            issued_at,
            DEFAULT_PRESENCE_HANDLE_TTL_MS,
            &signing_key,
        );

        // Forge a copy that swaps persona_id to persona-b — signature
        // was over persona-a, so it no longer verifies under persona-b.
        let mut forged = handle_a.clone();
        forged.persona_id = "persona-b".to_string();
        let err = verify_presence_handle(&forged, &verifying_key, issued_at)
            .expect_err("persona substitution must invalidate signature");
        assert_eq!(err, PresenceHandleError::SignatureInvalid);
    }

    /// Future-dated handle: `issued_at > now` returns
    /// `PresenceHandleError::NotYetValid` (no clock skew tolerated in v1).
    #[test]
    fn verify_presence_handle_rejects_future_issued_at() {
        let signing_key = fixture_handle_keypair("not-yet");
        let verifying_key = signing_key.verifying_key();
        let issued_at = 5_000_000_000_000u64;
        let handle = sign_presence_handle(
            bind_presence_challenge("wf-f", "act-f", "spiffe://e/f", &[]),
            "persona-f",
            issued_at,
            DEFAULT_PRESENCE_HANDLE_TTL_MS,
            &signing_key,
        );

        // Verifier's clock is 1 second behind the daemon's.
        let now = issued_at - 1_000;
        let err = verify_presence_handle(&handle, &verifying_key, now)
            .expect_err("future-dated handle must be rejected");
        match err {
            PresenceHandleError::NotYetValid {
                issued_at_ms,
                now_ms,
            } => {
                assert_eq!(issued_at_ms, issued_at);
                assert_eq!(now_ms, now);
            }
            other => panic!("expected NotYetValid, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // implementation-note-38 tests — wire-format
    // round-trip + ChallengeBinding determinism.
    // -----------------------------------------------------------------

    /// `PresenceProofRequest` must round-trip through JSON with every
    /// field preserved (Debug-equal). Defends the wire shape: any
    /// accidental rename, default value drift, or serde-flavor regression
    /// shows up as a string-equality failure here.
    #[test]
    fn presence_proof_request_round_trips_through_serde() {
        let req = PresenceProofRequest {
            workflow_id: "wf-rt-1".to_string(),
            action_key: "approve-grant".to_string(),
            spiffe_uri: "spiffe://emberlink.dev/agent/rt".to_string(),
            nonce_hex: "deadbeef".to_string(),
            persona_id: "persona-rt".to_string(),
            prompt_id: Some("prompt-rt-1".to_string()),
            reason: Some("Approve grant proof.".to_string()),
            caller_persona: Some("persona-caller".to_string()),
            ttl_ms: Some(15_000),
        };
        let json = serde_json::to_string(&req).expect("request serializes");
        let back: PresenceProofRequest = serde_json::from_str(&json).expect("request deserializes");
        // Round-trip equality via field-by-field comparison (the struct
        // does not derive PartialEq because `Option<String>` semantics
        // are intentionally not part of the public contract).
        assert_eq!(req.workflow_id, back.workflow_id);
        assert_eq!(req.action_key, back.action_key);
        assert_eq!(req.spiffe_uri, back.spiffe_uri);
        assert_eq!(req.nonce_hex, back.nonce_hex);
        assert_eq!(req.persona_id, back.persona_id);
        assert_eq!(req.prompt_id, back.prompt_id);
        assert_eq!(req.reason, back.reason);
        assert_eq!(req.caller_persona, back.caller_persona);
        assert_eq!(req.ttl_ms, back.ttl_ms);
    }

    /// `caller_persona` and `ttl_ms` are `#[serde(default)]` — both
    /// must accept omission in the JSON payload. Defends against an
    /// accidental drop of the `default` attribute that would break
    /// clients that don't supply the optional fields.
    #[test]
    fn presence_proof_request_accepts_omitted_optional_fields() {
        let json = r#"{
            "workflow_id":"wf-omit",
            "action_key":"approve",
            "spiffe_uri":"spiffe://e/o",
            "nonce_hex":"00",
            "persona_id":"persona-o"
        }"#;
        let back: PresenceProofRequest =
            serde_json::from_str(json).expect("optional fields must accept omission");
        assert_eq!(back.workflow_id, "wf-omit");
        assert_eq!(back.prompt_id, None);
        assert_eq!(back.reason, None);
        assert_eq!(back.caller_persona, None);
        assert_eq!(back.ttl_ms, None);
    }

    /// `PresenceProofResponse` round-trips through JSON. The handle
    /// field carries the full `DaemonSignedHandle` envelope, whose own
    /// round-trip is covered separately in
    /// `sign_presence_handle_round_trip`.
    #[test]
    fn presence_proof_response_round_trips_through_serde() {
        let signing_key = fixture_handle_keypair("response-rt");
        let challenge_hash =
            bind_presence_challenge("wf-resp", "act-resp", "spiffe://e/resp", &[0x42]);
        let handle = sign_presence_handle(
            challenge_hash,
            "persona-resp",
            6_000_000_000_000u64,
            DEFAULT_PRESENCE_HANDLE_TTL_MS,
            &signing_key,
        );
        let response = PresenceProofResponse {
            daemon_signed_handle: handle.clone(),
        };
        let json = serde_json::to_string(&response).expect("response serializes");
        let back: PresenceProofResponse =
            serde_json::from_str(&json).expect("response deserializes");
        assert_eq!(handle, back.daemon_signed_handle);
    }

    /// `ChallengeBinding::compute` must be deterministic (the same
    /// tuple must always produce the same 32-byte hash) AND its output
    /// length must be exactly 32 bytes. Regression guard for any future
    /// accidental change to the hash algorithm or output width.
    #[test]
    fn challenge_binding_compute_is_deterministic_and_32_bytes() {
        let a = ChallengeBinding::compute(
            "wf-cb",
            "approve",
            "spiffe://emberlink.dev/agent/cb",
            &[0xab, 0xcd],
        );
        let b = ChallengeBinding::compute(
            "wf-cb",
            "approve",
            "spiffe://emberlink.dev/agent/cb",
            &[0xab, 0xcd],
        );
        assert_eq!(a, b, "same tuple must produce same binding");
        assert_eq!(a.as_bytes().len(), 32, "binding hash must be 32 bytes");

        // Changing any one component changes the binding (delegates to
        // the existing `bind_presence_challenge` injectivity test for
        // the full coverage; this is a smoke check at the wrapper).
        let c = ChallengeBinding::compute(
            "wf-cb-other",
            "approve",
            "spiffe://emberlink.dev/agent/cb",
            &[0xab, 0xcd],
        );
        assert_ne!(a, c, "different workflow_id must change binding");
    }

    /// `ChallengeBinding` must round-trip through serde (used in audit
    /// records and downstream RPC payloads).
    #[test]
    fn challenge_binding_round_trips_through_serde() {
        let binding = ChallengeBinding::compute(
            "wf-cb-rt",
            "approve",
            "spiffe://emberlink.dev/agent/cb-rt",
            &[0x01],
        );
        let json = serde_json::to_string(&binding).expect("binding serializes");
        let back: ChallengeBinding = serde_json::from_str(&json).expect("binding deserializes");
        assert_eq!(binding, back);
    }

    /// `ChallengeBinding` must be byte-equivalent to the raw
    /// [`bind_presence_challenge`] output — confirms the newtype is a
    /// zero-cost convenience, not a divergent code path.
    #[test]
    fn challenge_binding_matches_bind_presence_challenge_bytes() {
        let raw = bind_presence_challenge("wf-eq", "act-eq", "spiffe://e/eq", &[0xff, 0xee]);
        let wrapped = ChallengeBinding::compute("wf-eq", "act-eq", "spiffe://e/eq", &[0xff, 0xee]);
        assert_eq!(&raw, wrapped.as_bytes());
        // And `From`/`Into` round-trips.
        let round: [u8; 32] = wrapped.into();
        assert_eq!(raw, round);
        let back: ChallengeBinding = raw.into();
        assert_eq!(back, wrapped);
    }
}
