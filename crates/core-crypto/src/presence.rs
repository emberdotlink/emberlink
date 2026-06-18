//! Presence attestation trait.
//! P63.B: Tier 1/2 approvals consult an attester before flipping
//! approved state. Real macOS SE wiring deferred to P63.B-SE-WIRE.
//!
//! META-AP-PRESENCE-BRIDGE-CHALLENGE-BINDING (ADR-DRAFT-BROWSER-AS-TOUCH-ID-PROMPTER D2):
//! [`bind_presence_challenge`] (a.k.a. `presence_challenge_bind`) computes the
//! per-request challenge that the browser presence prompter signs. The challenge
//! is `SHA-256` over the length-prefixed canonical encoding of
//! `(delegation_id, action_ref.plugin_address, action_ref.action_key,
//! action_ref.action_version, spiffe_uri, nonce)` — every component is
//! per-request unique, so replay across requests is structurally impossible.
//! Length-prefixing defends against component-collision attacks where
//! rearranging the field boundaries would otherwise produce identical
//! concatenated bytes.

use core_event_types::ActionRef;
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

/// Operator-facing prompt policy for a presence request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PresencePromptPolicy {
    /// Apple-native / platform-native fallback is allowed when the platform
    /// supports it (for example Touch ID -> Apple Watch / password on macOS).
    Recoverable,
    /// Biometric-only posture. If biometry is unavailable or locked out, the
    /// prompt fails closed instead of falling back to a password lane.
    StrictBiometric,
}

/// High-level class of operator prompt. Used for coalescing and for
/// generating terse native prompt copy from a richer daemon-owned intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PresencePromptClass {
    SessionOpen,
    LaunchTool,
    Approval,
    VaultAdmin,
    Generic,
}

fn default_pending_prompt_count() -> u32 {
    1
}

/// Daemon-owned prompt intent shared across attester adapters.
///
/// The attester surface (native macOS, browser/WebAuthn, future mobile) does
/// not invent its own wording or coalescing shape. The daemon owns the
/// operator intent once, then adapters render it according to their UX
/// constraints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresencePromptIntent {
    pub policy: PresencePromptPolicy,
    pub prompt_class: PresencePromptClass,
    /// Singular operator-facing summary for this action. Example:
    /// `"Start Claude Code with Ember"`.
    pub summary: String,
    /// Additional rich detail lines for Ember-owned UI surfaces (browser,
    /// mobile, terminal preambles). Native OS prompts typically cannot fit
    /// these details.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detail_lines: Vec<String>,
    /// Number of semantically-identical pending actions currently coalesced
    /// onto this prompt.
    #[serde(default = "default_pending_prompt_count")]
    pub pending_count: u32,
    /// Stable coalescing key chosen by the daemon. Equal keys may share one
    /// active prompt workflow.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub coalescing_key: String,
}

impl PresencePromptIntent {
    pub fn new(
        policy: PresencePromptPolicy,
        prompt_class: PresencePromptClass,
        summary: impl Into<String>,
        detail_lines: Vec<String>,
    ) -> Self {
        let summary = summary.into();
        let class_key = match prompt_class {
            PresencePromptClass::SessionOpen => "session-open",
            PresencePromptClass::LaunchTool => "launch-tool",
            PresencePromptClass::Approval => "approval",
            PresencePromptClass::VaultAdmin => "vault-admin",
            PresencePromptClass::Generic => "generic",
        };
        let policy_key = match policy {
            PresencePromptPolicy::Recoverable => "recoverable",
            PresencePromptPolicy::StrictBiometric => "strict-biometric",
        };
        let coalescing_key = format!("{policy_key}:{class_key}:{summary}");
        Self {
            policy,
            prompt_class,
            summary,
            detail_lines,
            pending_count: default_pending_prompt_count(),
            coalescing_key,
        }
    }

    pub fn generic_recoverable(summary: impl Into<String>) -> Self {
        Self::new(
            PresencePromptPolicy::Recoverable,
            PresencePromptClass::Generic,
            summary,
            Vec::new(),
        )
    }

    pub fn increment_pending_count(&mut self) {
        self.pending_count = self.pending_count.saturating_add(1);
    }

    /// Terse native prompt copy suitable for LocalAuthentication's
    /// `localizedReason`.
    pub fn native_os_reason(&self) -> String {
        let total = self.pending_count.max(1);
        if total == 1 {
            return self.summary.clone();
        }

        let pluralize = |count: u32| if count == 1 { "" } else { "s" };
        let additional = total.saturating_sub(1);
        match (&self.policy, &self.prompt_class) {
            (
                PresencePromptPolicy::Recoverable,
                PresencePromptClass::LaunchTool | PresencePromptClass::SessionOpen,
            ) => format!(
                "{} and continue {} pending Ember action{}",
                self.summary,
                additional,
                pluralize(additional)
            ),
            (PresencePromptPolicy::StrictBiometric, _) => {
                format!("Approve {} pending Ember action{}", total, pluralize(total))
            }
            _ => format!(
                "Continue {} pending Ember action{}",
                total,
                pluralize(total)
            ),
        }
    }
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
            "SecureEnclaveAttester wire-up deferred to P63.B-SE-WIRE".into(),
        ))
    }
}

/// `presence_challenge_bind`: SHA-256 over the length-prefixed canonical
/// encoding of `(delegation_id, action_ref, spiffe_uri, nonce)` — defense
/// against component-collision attacks.
///
/// Per ADR-DRAFT-BROWSER-AS-TOUCH-ID-PROMPTER D2, the presence challenge the
/// browser prompter signs is bound to the exact tuple that authorizes the
/// action. Every component is per-request unique, so a valid challenge cannot
/// be replayed across requests:
///
/// - `delegation_id` — the daemon-issued unique identifier for this workflow
/// - `action_ref`  — the canonical structured action identity being authorized
/// - `spiffe_uri`  — the SPIFFE URI of the bridge/agent making the request
/// - `nonce`       — fresh server-supplied per-request entropy
///
/// # Canonical encoding
///
/// `SHA-256(LEN(delegation_id) || delegation_id ||`
/// `         LEN(plugin_address) || plugin_address ||`
/// `         LEN(action_key)     || action_key     ||`
/// `         LEN(action_version) || action_version ||`
/// `         LEN(spiffe_uri)  || spiffe_uri  ||`
/// `         LEN(nonce)       || nonce)`
///
/// where `LEN` is an 8-byte big-endian `u64`. Length-prefixing prevents
/// component-collision attacks: without it, `("foobar", "")` and
/// `("foo", "bar")` would hash to the same value because the concatenated
/// raw bytes are identical.
pub fn bind_presence_challenge(
    delegation_id: &str,
    action_ref: &ActionRef,
    spiffe_uri: &str,
    nonce: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    write_length_prefixed(&mut hasher, delegation_id.as_bytes());
    write_length_prefixed(&mut hasher, action_ref.plugin_address.as_bytes());
    write_length_prefixed(&mut hasher, action_ref.action_key.as_bytes());
    write_length_prefixed(&mut hasher, action_ref.action_version.as_bytes());
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
// ADR 206 slice 4 C — retired `DaemonSignedHandle` + the daemon-handle signing
// surface (`sign_presence_handle` / `verify_presence_handle` /
// `canonical_handle_signing_input` / `DOMAIN_PRESENCE_HANDLE` /
// `DEFAULT_PRESENCE_HANDLE_TTL_MS` / `PresenceProofResponse`).
//
// The handle was a forgeable, daemon-rooted presence attestation: a daemon
// holding its own Ed25519 identity key could mint a "presence verified" envelope
// with no real operator gesture behind it. Operator presence is now sourced from
// the §4 presence-as-decryption unlock (the operator's `.userPresence` SE key
// is the only thing that can unwrap the scope KEK), so a daemon cannot fabricate
// it. Widening continues to verify a REAL enrolled-device signature via
// `presence_gate::verify_presence_signature` (unchanged).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// META-AP-PRESENCE-BRIDGE-PROTO-DEFINE
// (ADR-DRAFT-BROWSER-AS-TOUCH-ID-PROMPTER D2)
// ---------------------------------------------------------------------------
//
// Checkpoint marker: `presence_bridge_proto`.
//
// Canonical wire-format types for the presence-bridge JSON-RPC surface.
// Lifted out of `ember-daemon::broker::handler` so client crates (CLI,
// dashboard, future SDK bindings) can consume them without taking a
// daemon-internal dependency.
//
// Shape derivation rationale:
//
// - `PresenceProofRequest` carries the full challenge-tuple
//   `(delegation_id, action_ref, spiffe_uri, nonce_hex)` so the daemon can
//   reconstruct the bound challenge via [`bind_presence_challenge`] and bind a
//   presence proof to the exact tuple the operator attested to. The
//   `nonce_hex`-as-hex-string encoding (rather than raw bytes) keeps the
//   JSON shape portable across language clients (JS dashboard, future
//   Python SDK) — every JSON parser handles strings, but base64/binary
//   blob handling varies.
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
/// All four challenge-tuple fields are forwarded unchanged to the presence
/// prompter; they recombine into the [`bind_presence_challenge`] hash the
/// operator's presence signature binds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceProofRequest {
    /// Daemon-issued unique identifier for this workflow.
    pub delegation_id: String,
    /// The canonical structured action identity being authorized.
    pub action_ref: ActionRef,
    /// SPIFFE URI of the bridge/agent making the request.
    pub spiffe_uri: String,
    /// Server-supplied per-request entropy. Encoded as a hex string on
    /// the wire so the JSON shape is portable across language clients.
    pub nonce_hex: String,
    /// Persona on whose behalf the proof is requested. Used to consult the
    /// freeze gate and bind the presence proof to the persona.
    pub persona_id: String,
    /// Optional stable prompt identifier chosen by the caller. When
    /// present, runtime-local prompt transports may use it so the caller
    /// can deterministically route the operator to the matching approval
    /// surface while the proof RPC is in flight.
    #[serde(default)]
    pub prompt_id: Option<String>,
    /// Optional operator-facing reason string for the prompt transport.
    /// When absent, the verifier transport derives a generic reason from
    /// `action_ref` and `spiffe_uri`.
    #[serde(default)]
    pub reason: Option<String>,
    /// Optional structured operator intent shared across attester adapters.
    #[serde(default)]
    pub prompt_intent: Option<PresencePromptIntent>,
    /// Optional caller_persona for peercred binding checks, mirrors the
    /// shape of sibling broker RPCs. When absent, no peercred check is
    /// performed on this surface.
    #[serde(default)]
    pub caller_persona: Option<String>,
    /// Optional proof TTL in milliseconds.
    #[serde(default)]
    pub ttl_ms: Option<u64>,
}

/// Canonical bound-challenge value — the 32-byte SHA-256 output of
/// [`bind_presence_challenge`] over the
/// `(delegation_id, action_ref, spiffe_uri, nonce)` tuple.
///
/// Thin newtype that exists for intent signalling at API boundaries:
/// downstream functions that accept `&ChallengeBinding` are explicit
/// about the fact that they want a canonically-bound challenge, not just
/// any 32 bytes. Equivalent to `[u8; 32]` at the byte level; conversions
/// are zero-cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeBinding {
    /// `SHA-256(LEN(delegation_id) || delegation_id || …)` per
    /// [`bind_presence_challenge`].
    pub canonical_bytes: [u8; 32],
}

impl ChallengeBinding {
    /// Compute the canonical challenge binding for the supplied tuple by
    /// delegating to [`bind_presence_challenge`]. Returns a
    /// [`ChallengeBinding`] wrapping the 32-byte SHA-256 output.
    pub fn compute(
        delegation_id: &str,
        action_ref: &ActionRef,
        spiffe_uri: &str,
        nonce: &[u8],
    ) -> Self {
        Self {
            canonical_bytes: bind_presence_challenge(delegation_id, action_ref, spiffe_uri, nonce),
        }
    }

    /// View the canonical hash as a fixed-size byte array — useful for
    /// passing into byte-oriented APIs that take `[u8; 32]` directly.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_action_ref(action_key: &str) -> ActionRef {
        ActionRef::new(
            "registry.ember.systems/ember-systems/ember-presence",
            action_key,
            "v1",
        )
    }

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
    /// length-prefixed canonical encoding of a fixed `(delegation_id, action_ref,
    /// spiffe_uri, nonce)` tuple. Regression guard for accidental encoding
    /// changes that would break wire compatibility with the browser prompter.
    #[test]
    fn bind_presence_challenge_known_vector() {
        let delegation_id = "wf-123";
        let action_ref = fixture_action_ref("approve-grant");
        let spiffe_uri = "spiffe://emberlink.dev/agent/foo";
        let nonce: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let got = bind_presence_challenge(delegation_id, &action_ref, spiffe_uri, &nonce);
        // Hand-computed via Python:
        //   def lp(b): return struct.pack('>Q', len(b)) + b
        //   sha256(lp(b'wf-123')
        //          + lp(b'registry.ember.systems/ember-systems/ember-presence')
        //          + lp(b'approve-grant')
        //          + lp(b'v1')
        //          + lp(b'spiffe://emberlink.dev/agent/foo')
        //          + lp(bytes.fromhex('0102030405060708090a0b0c0d0e0f10')))
        let expected_hex = "bdf608969d5fb8bfc4047019744f2481f22a11e40239916901e22d7b185f2eea";
        assert_eq!(core_types::bytes_to_hex(&got), expected_hex);
    }

    /// Injectivity: flipping any single tuple component (delegation_id,
    /// action_ref, spiffe_uri, nonce) must produce a different challenge.
    /// Parametric over all six encoded components.
    #[test]
    fn bind_presence_challenge_injective_per_component() {
        let base_action = fixture_action_ref("approve");
        let base = bind_presence_challenge(
            "wf-1",
            &base_action,
            "spiffe://emberlink.dev/agent/a",
            &[0xaa, 0xbb],
        );

        // Vary delegation_id.
        let v_workflow = bind_presence_challenge(
            "wf-2",
            &base_action,
            "spiffe://emberlink.dev/agent/a",
            &[0xaa, 0xbb],
        );
        assert_ne!(
            base, v_workflow,
            "delegation_id change must alter challenge"
        );

        // Vary action_key.
        let v_action = bind_presence_challenge(
            "wf-1",
            &fixture_action_ref("revoke"),
            "spiffe://emberlink.dev/agent/a",
            &[0xaa, 0xbb],
        );
        assert_ne!(base, v_action, "action_key change must alter challenge");

        // Vary plugin_address.
        let v_plugin = bind_presence_challenge(
            "wf-1",
            &ActionRef::new(
                "registry.ember.systems/ember-systems/ember-other",
                "approve",
                "v1",
            ),
            "spiffe://emberlink.dev/agent/a",
            &[0xaa, 0xbb],
        );
        assert_ne!(base, v_plugin, "plugin_address change must alter challenge");

        // Vary action_version.
        let v_version = bind_presence_challenge(
            "wf-1",
            &ActionRef::new(
                "registry.ember.systems/ember-systems/ember-presence",
                "approve",
                "v2",
            ),
            "spiffe://emberlink.dev/agent/a",
            &[0xaa, 0xbb],
        );
        assert_ne!(
            base, v_version,
            "action_version change must alter challenge"
        );

        // Vary spiffe_uri.
        let v_spiffe = bind_presence_challenge(
            "wf-1",
            &base_action,
            "spiffe://emberlink.dev/agent/b",
            &[0xaa, 0xbb],
        );
        assert_ne!(base, v_spiffe, "spiffe_uri change must alter challenge");

        // Vary nonce.
        let v_nonce = bind_presence_challenge(
            "wf-1",
            &base_action,
            "spiffe://emberlink.dev/agent/a",
            &[0xaa, 0xbc],
        );
        assert_ne!(base, v_nonce, "nonce change must alter challenge");
    }

    /// Length-prefixing matters: `(plugin_address="foobar", action_key="")`
    /// and `(plugin_address="foo", action_key="bar")` share identical
    /// concatenated raw bytes for the adjacent action-ref components.
    /// Without 8-byte big-endian length prefixes the challenge would
    /// collide; with them, the two tuples produce distinct SHA-256
    /// digests. This is the defense against component-collision attacks.
    #[test]
    fn bind_presence_challenge_length_prefix_disambiguates_components() {
        let spiffe_uri = "spiffe://e/a";
        let nonce = [0x00_u8];

        let a = bind_presence_challenge(
            "wf-prefix",
            &ActionRef::new("foobar", "", "v1"),
            spiffe_uri,
            &nonce,
        );
        let b = bind_presence_challenge(
            "wf-prefix",
            &ActionRef::new("foo", "bar", "v1"),
            spiffe_uri,
            &nonce,
        );

        assert_ne!(
            a, b,
            "length-prefixing must disambiguate adjacent action_ref components"
        );
    }

    // -----------------------------------------------------------------
    // META-AP-PRESENCE-BRIDGE-PROTO-DEFINE tests — wire-format
    // round-trip + ChallengeBinding determinism.
    // -----------------------------------------------------------------

    /// `PresenceProofRequest` must round-trip through JSON with every
    /// field preserved (Debug-equal). Defends the wire shape: any
    /// accidental rename, default value drift, or serde-flavor regression
    /// shows up as a string-equality failure here.
    #[test]
    fn presence_proof_request_round_trips_through_serde() {
        let req = PresenceProofRequest {
            delegation_id: "wf-rt-1".to_string(),
            action_ref: fixture_action_ref("approve-grant"),
            spiffe_uri: "spiffe://emberlink.dev/agent/rt".to_string(),
            nonce_hex: "deadbeef".to_string(),
            persona_id: "persona-rt".to_string(),
            prompt_id: Some("prompt-rt-1".to_string()),
            reason: Some("Approve grant proof.".to_string()),
            prompt_intent: Some(PresencePromptIntent::new(
                PresencePromptPolicy::Recoverable,
                PresencePromptClass::LaunchTool,
                "Start Claude Code with Ember",
                vec!["Persona: claude-code-default".to_string()],
            )),
            caller_persona: Some("persona-caller".to_string()),
            ttl_ms: Some(15_000),
        };
        let json = serde_json::to_string(&req).expect("request serializes");
        let back: PresenceProofRequest = serde_json::from_str(&json).expect("request deserializes");
        // Round-trip equality via field-by-field comparison (the struct
        // does not derive PartialEq because `Option<String>` semantics
        // are intentionally not part of the public contract).
        assert_eq!(req.delegation_id, back.delegation_id);
        assert_eq!(req.action_ref, back.action_ref);
        assert_eq!(req.spiffe_uri, back.spiffe_uri);
        assert_eq!(req.nonce_hex, back.nonce_hex);
        assert_eq!(req.persona_id, back.persona_id);
        assert_eq!(req.prompt_id, back.prompt_id);
        assert_eq!(req.reason, back.reason);
        assert_eq!(req.prompt_intent, back.prompt_intent);
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
            "delegation_id":"wf-omit",
            "action_ref":{
                "plugin_address":"registry.ember.systems/ember-systems/ember-presence",
                "action_key":"approve",
                "action_version":"v1"
            },
            "spiffe_uri":"spiffe://e/o",
            "nonce_hex":"00",
            "persona_id":"persona-o"
        }"#;
        let back: PresenceProofRequest =
            serde_json::from_str(json).expect("optional fields must accept omission");
        assert_eq!(back.delegation_id, "wf-omit");
        assert_eq!(back.prompt_id, None);
        assert_eq!(back.reason, None);
        assert_eq!(back.prompt_intent, None);
        assert_eq!(back.caller_persona, None);
        assert_eq!(back.ttl_ms, None);
    }

    #[test]
    fn presence_prompt_intent_native_reason_summarizes_coalesced_actions() {
        let mut intent = PresencePromptIntent::new(
            PresencePromptPolicy::Recoverable,
            PresencePromptClass::LaunchTool,
            "Start Claude Code with Ember",
            vec![],
        );
        assert_eq!(intent.native_os_reason(), "Start Claude Code with Ember");
        intent.increment_pending_count();
        assert_eq!(
            intent.native_os_reason(),
            "Start Claude Code with Ember and continue 1 pending Ember action"
        );

        let mut strict = PresencePromptIntent::new(
            PresencePromptPolicy::StrictBiometric,
            PresencePromptClass::Approval,
            "Approve this Ember grant",
            vec![],
        );
        strict.increment_pending_count();
        strict.increment_pending_count();
        assert_eq!(strict.native_os_reason(), "Approve 3 pending Ember actions");
    }

    /// `ChallengeBinding::compute` must be deterministic (the same
    /// tuple must always produce the same 32-byte hash) AND its output
    /// length must be exactly 32 bytes. Regression guard for any future
    /// accidental change to the hash algorithm or output width.
    #[test]
    fn challenge_binding_compute_is_deterministic_and_32_bytes() {
        let action_ref = fixture_action_ref("approve");
        let a = ChallengeBinding::compute(
            "wf-cb",
            &action_ref,
            "spiffe://emberlink.dev/agent/cb",
            &[0xab, 0xcd],
        );
        let b = ChallengeBinding::compute(
            "wf-cb",
            &action_ref,
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
            &action_ref,
            "spiffe://emberlink.dev/agent/cb",
            &[0xab, 0xcd],
        );
        assert_ne!(a, c, "different delegation_id must change binding");
    }

    /// `ChallengeBinding` must round-trip through serde (used in audit
    /// records and downstream RPC payloads).
    #[test]
    fn challenge_binding_round_trips_through_serde() {
        let binding = ChallengeBinding::compute(
            "wf-cb-rt",
            &fixture_action_ref("approve"),
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
        let action_ref = fixture_action_ref("act-eq");
        let raw = bind_presence_challenge("wf-eq", &action_ref, "spiffe://e/eq", &[0xff, 0xee]);
        let wrapped =
            ChallengeBinding::compute("wf-eq", &action_ref, "spiffe://e/eq", &[0xff, 0xee]);
        assert_eq!(&raw, wrapped.as_bytes());
        // And `From`/`Into` round-trips.
        let round: [u8; 32] = wrapped.into();
        assert_eq!(raw, round);
        let back: ChallengeBinding = raw.into();
        assert_eq!(back, wrapped);
    }
}
