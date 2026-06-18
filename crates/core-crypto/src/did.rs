//! CLASSIFICATION: PUBLIC
//!
//! DID resolver primitives for `did:emberlink:<root-pubkey>` — ADR 146 Phase 2.
//!
//! Provides parsing of the `did:emberlink:<root-pubkey>` identifier shape and
//! JWKS emission for the parsed identity. `<root-pubkey>` is a base64url
//! (unpadded) encoding of a 32-byte Ed25519 public key (the same encoding the
//! JWKS `x` field uses, so the DID and the JWKS share one alphabet).
//!
//! No filesystem I/O, no `SystemTime::now()` — WASM-safe. The resolver is the
//! transport-side primitive; the emberlink-relay HTTP handler calls
//! [`resolve_did_jwks`] to serve `/.well-known/jwks.json` per ADR 146 §2.b.
//!
//! Anchor: `did_emberlink_resolver_phase2` — ADR-141-PHASE2-RELAY-RESOLVER-IMPL.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_NO_PAD};
use ed25519_dalek::VerifyingKey;
use serde_json::{Value, json};
use thiserror::Error;

/// Prefix every `did:emberlink` identifier carries.
///
/// Used both as a parse anchor in [`parse_did`] and as the canonical render in
/// [`DidEmberlink::as_str`]. Lowercase per W3C DID Core §3.1 — DIDs are
/// case-insensitive at the `did:method:` level but the canonical render is
/// lowercase.
pub const DID_EMBERLINK_PREFIX: &str = "did:emberlink:";

/// Errors produced by DID parsing and resolution.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DidError {
    /// The input string did not start with `did:emberlink:`. Covers the
    /// case of an entirely different DID method (`did:web:…`, `did:key:…`)
    /// as well as completely malformed inputs.
    #[error("DID must start with `did:emberlink:`")]
    MissingPrefix,
    /// The portion after the `did:emberlink:` prefix failed base64url decode.
    /// Either non-alphabet characters or padding (padded base64 is rejected —
    /// the canonical form is unpadded per RFC 7515 §2).
    #[error("root pubkey is not valid base64url (unpadded): {0}")]
    InvalidBase64Url(String),
    /// The decoded root pubkey was not exactly 32 bytes. Ed25519 public keys
    /// are always 32 bytes; anything else is structurally invalid.
    #[error("root pubkey must decode to 32 bytes, got {0}")]
    WrongPubkeyLength(usize),
    /// The 32 decoded bytes did not parse as a valid Ed25519 verifying key
    /// (e.g., not a valid curve point).
    #[error("root pubkey is not a valid Ed25519 public key: {0}")]
    InvalidEd25519Key(String),
}

/// A parsed `did:emberlink:<root-pubkey>` identifier.
///
/// The root pubkey is the Ed25519 public key of the device that initially
/// registered the identity (ADR 146 §1). The DID is stable across device
/// additions/removals — the root pubkey is the durable identifier; new devices
/// join via the DID-document's verification-methods list.
///
/// This struct holds the parsed `VerifyingKey` plus its canonical render so
/// callers do not have to re-encode for logging or JWKS emission.
#[derive(Debug, Clone)]
pub struct DidEmberlink {
    /// The Ed25519 verifying key extracted from the DID's `<root-pubkey>`
    /// segment. Used for JWKS emission and (in future Phase 2.x work) for
    /// verifying signed assertions on DID-document updates.
    pub root_pubkey: VerifyingKey,
    /// Base64url-unpadded encoding of `root_pubkey.to_bytes()`. Cached on the
    /// parsed struct so JWKS emission and canonical-render paths avoid
    /// re-encoding.
    pub root_pubkey_b64url: String,
}

impl DidEmberlink {
    /// Render the DID in its canonical `did:emberlink:<root-pubkey>` form.
    ///
    /// The result round-trips with [`parse_did`].
    pub fn as_str(&self) -> String {
        format!("{DID_EMBERLINK_PREFIX}{}", self.root_pubkey_b64url)
    }

    /// Raw 32-byte Ed25519 public key bytes — convenience for callers that
    /// want the raw key without going through [`VerifyingKey::to_bytes`].
    pub fn root_pubkey_bytes(&self) -> [u8; 32] {
        self.root_pubkey.to_bytes()
    }
}

impl PartialEq for DidEmberlink {
    fn eq(&self, other: &Self) -> bool {
        self.root_pubkey.to_bytes() == other.root_pubkey.to_bytes()
    }
}

impl Eq for DidEmberlink {}

/// Parse a `did:emberlink:<root-pubkey>` identifier.
///
/// The `<root-pubkey>` segment is decoded as base64url-unpadded (RFC 7515 §2)
/// and validated as a 32-byte Ed25519 public key.
///
/// Returns [`DidError::MissingPrefix`] for inputs that do not start with
/// `did:emberlink:`, [`DidError::InvalidBase64Url`] for decode failures,
/// [`DidError::WrongPubkeyLength`] when the decoded segment is not 32 bytes,
/// and [`DidError::InvalidEd25519Key`] when the bytes do not parse as a valid
/// Ed25519 curve point.
pub fn parse_did(s: &str) -> Result<DidEmberlink, DidError> {
    let pubkey_segment = s
        .strip_prefix(DID_EMBERLINK_PREFIX)
        .ok_or(DidError::MissingPrefix)?;

    let decoded = BASE64_URL_NO_PAD
        .decode(pubkey_segment.as_bytes())
        .map_err(|e| DidError::InvalidBase64Url(e.to_string()))?;

    if decoded.len() != 32 {
        return Err(DidError::WrongPubkeyLength(decoded.len()));
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    let root_pubkey =
        VerifyingKey::from_bytes(&bytes).map_err(|e| DidError::InvalidEd25519Key(e.to_string()))?;

    Ok(DidEmberlink {
        root_pubkey,
        root_pubkey_b64url: pubkey_segment.to_owned(),
    })
}

/// Build a DID from a raw 32-byte Ed25519 public key.
///
/// The inverse of [`parse_did`] for callers that hold an Ed25519 key and want
/// the corresponding DID identifier. Used by the relay's DID-registration
/// path and by tests that round-trip `parse_did` → `did_from_root_pubkey`.
pub fn did_from_root_pubkey(root_pubkey: &VerifyingKey) -> DidEmberlink {
    let root_pubkey_b64url = BASE64_URL_NO_PAD.encode(root_pubkey.to_bytes());
    DidEmberlink {
        root_pubkey: *root_pubkey,
        root_pubkey_b64url,
    }
}

/// Resolve a parsed DID to a JWKS containing the root device's Ed25519 public
/// key in OKP form (ADR 146 §2.b).
///
/// The returned JSON Value is shaped as:
///
/// ```json
/// {
///   "keys": [
///     {
///       "kty": "OKP",
///       "crv": "Ed25519",
///       "x": "<base64url-pubkey>",
///       "kid": "<base64url-pubkey>",
///       "use": "sig",
///       "alg": "EdDSA"
///     }
///   ]
/// }
/// ```
///
/// At Phase 2 the JWKS only contains the root device's public key. Multi-
/// device JWKS emission (one key per participating device, per ADR 146 §2.b
/// and §4) is forward-compatible — additional devices' keys are appended to
/// the `keys` array by callers that resolve the full DID document. This
/// function is the single-key primitive that produces the JWKS shape; the
/// multi-device aggregation lives at the relay-state layer.
///
/// **Invariants** (ADR 146 §2.b):
/// - Contains only public material — no private keys ever transit the JWKS.
/// - `kid` matches the JWK's `x` field; future multi-device JWKS may use
///   per-device kids drawn from the DID-document verification-method list.
/// - The JSON shape matches RFC 7517 §4 (JWK) and RFC 8037 §2 (OKP Ed25519).
///
/// **WASM-safe**: no `SystemTime::now()`, no filesystem I/O — pure JSON
/// emission.
pub fn resolve_did_jwks(did: &DidEmberlink) -> Value {
    let key_b64url = &did.root_pubkey_b64url;
    json!({
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": key_b64url,
                "kid": key_b64url,
                "use": "sig",
                "alg": "EdDSA",
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn fixture_verifying_key(seed_byte: u8) -> VerifyingKey {
        let seed = [seed_byte; 32];
        SigningKey::from_bytes(&seed).verifying_key()
    }

    #[test]
    fn parse_did_accepts_valid_did_emberlink_round_trip() {
        let vk = fixture_verifying_key(0x42);
        let did = did_from_root_pubkey(&vk);
        let s = did.as_str();
        assert!(s.starts_with("did:emberlink:"));

        let parsed = parse_did(&s).expect("round-trip parse must succeed");
        assert_eq!(parsed, did);
        assert_eq!(parsed.root_pubkey_bytes(), vk.to_bytes());
    }

    #[test]
    fn parse_did_rejects_missing_prefix() {
        // Wrong DID method.
        assert_eq!(
            parse_did("did:web:example.com").unwrap_err(),
            DidError::MissingPrefix
        );
        // No `did:` at all.
        assert_eq!(
            parse_did("emberlink:abcdef").unwrap_err(),
            DidError::MissingPrefix
        );
        // Empty string.
        assert_eq!(parse_did("").unwrap_err(), DidError::MissingPrefix);
    }

    #[test]
    fn parse_did_rejects_invalid_base64url() {
        // `!` is outside the base64url alphabet.
        let err = parse_did("did:emberlink:not!valid").unwrap_err();
        assert!(
            matches!(err, DidError::InvalidBase64Url(_)),
            "expected InvalidBase64Url, got {err:?}"
        );

        // Padded base64 — the canonical form is unpadded, so `=` padding
        // is treated as out-of-alphabet by URL_SAFE_NO_PAD.
        let vk = fixture_verifying_key(0x01);
        let padded = format!("did:emberlink:{}=", BASE64_URL_NO_PAD.encode(vk.to_bytes()));
        let err = parse_did(&padded).unwrap_err();
        assert!(
            matches!(err, DidError::InvalidBase64Url(_)),
            "expected padded form to be rejected, got {err:?}"
        );
    }

    #[test]
    fn parse_did_rejects_wrong_pubkey_length() {
        // Decodes to 3 bytes, not 32.
        let err = parse_did("did:emberlink:AAAA").unwrap_err();
        assert_eq!(err, DidError::WrongPubkeyLength(3));

        // Decodes to 31 bytes.
        let short = BASE64_URL_NO_PAD.encode([0u8; 31]);
        let err = parse_did(&format!("did:emberlink:{short}")).unwrap_err();
        assert_eq!(err, DidError::WrongPubkeyLength(31));

        // Decodes to 33 bytes.
        let long = BASE64_URL_NO_PAD.encode([0u8; 33]);
        let err = parse_did(&format!("did:emberlink:{long}")).unwrap_err();
        assert_eq!(err, DidError::WrongPubkeyLength(33));
    }

    #[test]
    fn parse_did_rejects_non_curve_point() {
        // 32 bytes that are not a valid Ed25519 verifying key. We probe a
        // small set of candidate y-coordinates and assert that at least one
        // is rejected — the exact off-curve candidate depends on the
        // ed25519-dalek implementation's canonicalization gate (which has
        // historically tightened across releases), so the test is written
        // against the rejection-surface invariant rather than a single
        // implementation-fingerprint vector.
        //
        // Candidates (each is a 32-byte y-coordinate, little-endian):
        // - y = 2, sign-bit=0   → 0x02, 0, …, 0
        // - y = 3, sign-bit=0   → 0x03, 0, …, 0
        // - y = p+19 non-canon. → 0xee, 0xff, …, 0xff, 0x7f
        // The candidates are deliberately small / structured so a future
        // dalek release that accepts one of them still leaves the test green
        // as long as at least one remains rejected.
        let candidates: [[u8; 32]; 3] = [
            {
                let mut b = [0u8; 32];
                b[0] = 0x02;
                b
            },
            {
                let mut b = [0u8; 32];
                b[0] = 0x03;
                b
            },
            {
                let mut b = [0xff; 32];
                b[0] = 0xee;
                b[31] = 0x7f;
                b
            },
        ];

        let mut saw_rejection = false;
        for bad_bytes in &candidates {
            let bad_did = format!("did:emberlink:{}", BASE64_URL_NO_PAD.encode(bad_bytes));
            match parse_did(&bad_did) {
                Err(DidError::InvalidEd25519Key(_)) => {
                    saw_rejection = true;
                    break;
                }
                Ok(_) => continue,
                Err(other) => panic!("unexpected error variant: {other:?}"),
            }
        }
        assert!(
            saw_rejection,
            "no candidate triggered DidError::InvalidEd25519Key — the dalek key parser \
             must reject at least one structurally invalid 32-byte sequence for this \
             rejection surface to be exercised"
        );
    }

    #[test]
    fn resolve_did_jwks_emits_valid_okp_shape() {
        let vk = fixture_verifying_key(0x33);
        let did = did_from_root_pubkey(&vk);
        let jwks = resolve_did_jwks(&did);

        // Top-level shape: `{ "keys": [...] }`.
        let keys = jwks
            .get("keys")
            .and_then(Value::as_array)
            .expect("JWKS must contain a `keys` array");
        assert_eq!(keys.len(), 1, "Phase 2 JWKS holds one root-device key");

        let key = &keys[0];
        assert_eq!(key.get("kty").and_then(Value::as_str), Some("OKP"));
        assert_eq!(key.get("crv").and_then(Value::as_str), Some("Ed25519"));
        assert_eq!(key.get("use").and_then(Value::as_str), Some("sig"));
        assert_eq!(key.get("alg").and_then(Value::as_str), Some("EdDSA"));

        let x = key
            .get("x")
            .and_then(Value::as_str)
            .expect("JWK must carry an `x` field");
        let kid = key
            .get("kid")
            .and_then(Value::as_str)
            .expect("JWK must carry a `kid` field");

        // `x` and `kid` are both base64url-unpadded forms of the same key at
        // Phase 2 (per ADR 146 §2.b illustrative shape, single root device).
        assert_eq!(x, kid);
        // `x` must decode to the same 32-byte key the DID parsed.
        let decoded = BASE64_URL_NO_PAD
            .decode(x.as_bytes())
            .expect("`x` must be valid base64url");
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded.as_slice(), &vk.to_bytes()[..]);
    }

    /// End-to-end DID resolver workflow: build a DID from a fresh Ed25519 key,
    /// stringify, re-parse, and emit JWKS — exercising the full
    /// `parse_did → resolve_did_jwks → JWKS shape` pipeline named in the
    /// task's acceptance criteria.
    #[test]
    fn parse_did_then_resolve_jwks_round_trip() {
        let vk = fixture_verifying_key(0x77);
        let did_str = did_from_root_pubkey(&vk).as_str();

        let parsed = parse_did(&did_str).expect("parse_did must succeed");
        let jwks = resolve_did_jwks(&parsed);

        // The JWKS's only key matches the DID's root pubkey.
        let key = &jwks["keys"][0];
        let x = key["x"].as_str().expect("`x` must be a string");
        let decoded = BASE64_URL_NO_PAD.decode(x.as_bytes()).expect("base64url");
        assert_eq!(decoded.as_slice(), &vk.to_bytes()[..]);
    }
}
