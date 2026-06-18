//! Daemon-side Construct signature verifier per
//! `docs/construct-signing-pipeline.md` §Verification flow steps 1-5.
//!
//! Entry point: [`verify_construct_signature`].

use base64::Engine as _;
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

static GLOBAL_CACHE: Lazy<VerifierCache> = Lazy::new(VerifierCache::new);

/// Global binary-hash cache shared across all `verify_construct_sidecar` calls.
pub fn verifier_cache() -> &'static VerifierCache {
    &GLOBAL_CACHE
}

/// The verifier's interface for reading trust-graph state from the store.
/// Implemented by `DaemonStore`; defined here so the verifier file imports
/// zero backend-specific types, preserving ADR 137 backend portability.
pub trait TrustStore {
    /// Read active (non-revoked) publisher trust delegations.
    fn list_active_publisher_trusts(
        &self,
    ) -> Result<Vec<crate::trust_graph::PublisherTrustDelegation>, TrustStoreError>;

    /// Opaque revision counter — must change on any mutation to the trust
    /// delegation table visible through this store.
    fn trust_graph_revision(&self) -> u64;
}

#[derive(Debug, thiserror::Error)]
#[error("trust store: {0}")]
pub struct TrustStoreError(pub String);

/// Deserialized sidecar JSON envelope. Schema matches what
/// emberlink-cli's `ember construct sign` writes (see
/// `crates/emberlink-cli/src/construct/sign.rs`).
#[derive(Debug, Clone, Deserialize)]
pub struct SidecarEnvelope {
    pub schema_version: u32,
    pub publisher_did: String,
    pub name: String,
    pub version: String,
    /// "blake3:hex..." — strip prefix before compare.
    pub blake3: String,
    /// RFC3339 build timestamp.
    pub build_ts: String,
    /// "ed25519:base64..." — strip prefix before decode.
    pub signature: String,
    /// Must equal "ed25519".
    pub signature_alg: String,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("binary_pin_mismatch: sidecar blake3 {sidecar} != computed {computed}")]
    BinaryPinMismatch { sidecar: String, computed: String },
    #[error("signature_invalid: {reason}")]
    SignatureInvalid { reason: String },
    #[error("publisher_not_trusted: {0}")]
    PublisherNotTrusted(String),
    #[error("schema_unsupported: schema_version={0} (expected 1)")]
    SchemaUnsupported(u32),
    #[error("signature_alg_unsupported: alg={0} (expected ed25519)")]
    SignatureAlgUnsupported(String),
    #[error("trust_graph error: {0}")]
    TrustGraph(#[from] crate::trust_graph::TrustGraphError),
    #[error("trust_store: {0}")]
    TrustStoreRead(#[from] TrustStoreError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("base64: {0}")]
    Base64(String),
    #[error("hex: {0}")]
    Hex(String),
    /// Pre-release security review M7: refuse to verify any sidecar
    /// against a trust anchor that is still the dev0 placeholder
    /// (derived from the committed `keys/dev0-construct-signing.seed`).
    /// The placeholder seed in the public mirror lets anyone forge
    /// signatures that validate against this anchor, so verification
    /// MUST fail-closed until the operator cutover (production key
    /// installed + seed file deleted) lands. See
    /// `trust_graph::is_placeholder_trust_anchor`.
    #[error(
        "placeholder_trust_anchor: anchor pubkey {anchor_hex} still traces to \
         the dev0 placeholder seed; AC-7 enforcement must not be enabled until \
         the production publisher-trust key replaces it"
    )]
    PlaceholderTrustAnchor { anchor_hex: String },
}

/// Binary-hash cache. Keys on file identity `(path, mtime_secs, file_size)`;
/// values are `blake3_hex` of `binary_bytes || construct_toml_bytes`. The cache
/// memoizes only the expensive file-hash recomputation; trust-graph state is
/// never cached here — delegations are read fresh from the store on every
/// `verify_construct_signature` call, so a revoked delegation immediately
/// stops verifying with zero explicit cache invalidation.
type BinaryCacheKey = (PathBuf, i64, u64);

pub struct VerifierCache {
    inner: RwLock<HashMap<BinaryCacheKey, String>>,
}

impl Default for VerifierCache {
    fn default() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }
}

// len() is a cache-size metric, not a collection emptiness check; adding is_empty() is out of scope for the lint-clear.
#[allow(clippy::len_without_is_empty)]
impl VerifierCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, path: &std::path::Path, mtime: i64, file_size: u64) -> Option<String> {
        let key = (path.to_path_buf(), mtime, file_size);
        self.inner.read().ok()?.get(&key).cloned()
    }

    pub fn insert(&self, path: PathBuf, mtime: i64, file_size: u64, blake3_hex: String) {
        if let Ok(mut g) = self.inner.write() {
            g.insert((path, mtime, file_size), blake3_hex);
        }
    }

    pub fn flush(&self) {
        if let Ok(mut g) = self.inner.write() {
            g.clear();
        }
    }

    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

/// Top-level verifier entry point.
///
/// Steps (per docs/construct-signing-pipeline.md §Verification flow):
/// 1. Validate schema_version and signature_alg.
/// 2. Compare the caller-supplied `computed_blake3_hex` (which the caller
///    MUST have computed from the actual `binary_bytes || construct_toml_bytes`)
///    with the sidecar's `blake3` claim.
/// 3. Read active publisher delegations from `trust_store` (**fresh on
///    every call** — no trust-state caching).
/// 4. Resolve publisher's pubkey via `trust_graph::resolve_publisher_pubkey`.
/// 5. Build canonical payload (JCS), Ed25519-verify against the resolved
///    pubkey.
pub fn verify_construct_signature(
    sidecar: &SidecarEnvelope,
    computed_blake3_hex: &str,
    trust_store: &dyn TrustStore,
) -> Result<(), VerifyError> {
    // Step 1 — schema + alg gate.
    if sidecar.schema_version != 1 {
        return Err(VerifyError::SchemaUnsupported(sidecar.schema_version));
    }
    if sidecar.signature_alg != "ed25519" {
        return Err(VerifyError::SignatureAlgUnsupported(
            sidecar.signature_alg.clone(),
        ));
    }

    // Step 2 — binary pin: compare the CALLER-COMPUTED hash with the
    // sidecar's self-asserted claim.
    let sidecar_blake3 = sidecar
        .blake3
        .strip_prefix("blake3:")
        .unwrap_or(&sidecar.blake3);
    if computed_blake3_hex != sidecar_blake3 {
        return Err(VerifyError::BinaryPinMismatch {
            sidecar: sidecar_blake3.to_string(),
            computed: computed_blake3_hex.to_string(),
        });
    }

    // Step 3 — read delegations fresh from the store on every call.
    let delegations = trust_store.list_active_publisher_trusts()?;

    // Step 4 — resolve publisher key.
    let build_ts_epoch = chrono::DateTime::parse_from_rfc3339(&sidecar.build_ts)
        .map_err(|e| VerifyError::SignatureInvalid {
            reason: format!("build_ts parse: {e}"),
        })?
        .timestamp();
    let publisher_key = crate::trust_graph::resolve_publisher_pubkey(
        &sidecar.publisher_did,
        build_ts_epoch,
        &delegations,
    )?;

    // M7 (pre-release security review): refuse to verify against the
    // dev0 placeholder anchor. `keys/dev0-construct-signing.seed` is
    // committed to git and derives `EMBER_SYSTEMS_PUBKEY_BYTES`; a public
    // mirror would ship the seed, letting anyone forge signatures that
    // validate against this key. The check is byte-comparison and
    // applies to BOTH the pinned `did:emberlink` path and any installed
    // delegation whose pubkey happens to equal the placeholder — either
    // would be equally forgeable. The operator cutover (replace
    // `EMBER_SYSTEMS_PUBKEY_BYTES` + delete the seed file) turns this
    // back into a no-op without any verifier-side code change.
    let anchor_bytes = publisher_key.pubkey.to_bytes();
    if crate::trust_graph::is_placeholder_trust_anchor(&anchor_bytes) {
        return Err(VerifyError::PlaceholderTrustAnchor {
            anchor_hex: hex::encode(anchor_bytes),
        });
    }

    // Step 5 — JCS canonical payload + Ed25519 verify.
    let canonical_payload_value = serde_json::json!({
        "blake3": sidecar.blake3,
        "build_ts": sidecar.build_ts,
        "name": sidecar.name,
        "publisher_did": sidecar.publisher_did,
        "version": sidecar.version,
    });
    let canonical_bytes = core_crypto::canonicalize_jcs(&canonical_payload_value).map_err(|e| {
        VerifyError::SignatureInvalid {
            reason: format!("jcs: {e}"),
        }
    })?;

    let sig_b64 = sidecar
        .signature
        .strip_prefix("ed25519:")
        .unwrap_or(&sidecar.signature);
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|e| VerifyError::Base64(e.to_string()))?;
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).map_err(|e| {
        VerifyError::SignatureInvalid {
            reason: format!("sig parse: {e}"),
        }
    })?;

    publisher_key
        .pubkey
        .verify_strict(&canonical_bytes, &sig)
        .map_err(|e| VerifyError::SignatureInvalid {
            reason: format!("ed25519 verify: {e}"),
        })?;

    Ok(())
}

/// Compute blake3 over `binary_bytes || construct_toml_bytes`.
pub fn compute_blake3_hex(binary_bytes: &[u8], construct_toml_bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(binary_bytes);
    hasher.update(construct_toml_bytes);
    hex::encode(hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestTrustStore {
        delegations: Vec<crate::trust_graph::PublisherTrustDelegation>,
    }

    impl TrustStore for TestTrustStore {
        fn list_active_publisher_trusts(
            &self,
        ) -> Result<Vec<crate::trust_graph::PublisherTrustDelegation>, TrustStoreError> {
            Ok(self
                .delegations
                .iter()
                .filter(|d| d.revoked_at.is_none())
                .cloned()
                .collect())
        }

        fn trust_graph_revision(&self) -> u64 {
            1
        }
    }

    fn make_valid_sidecar(
        signing_key: &ed25519_dalek::SigningKey,
    ) -> (SidecarEnvelope, Vec<u8>, Vec<u8>) {
        use ed25519_dalek::Signer as _;

        let binary_bytes = b"fake-binary-content".to_vec();
        let toml_bytes = b"[meta]\npublisher = \"did:test\"\nname = \"test-construct\"\n".to_vec();

        let blake3_hex = compute_blake3_hex(&binary_bytes, &toml_bytes);
        let blake3_field = format!("blake3:{blake3_hex}");

        let build_ts = "2026-05-05T13:42:08Z".to_string();
        let payload_value = serde_json::json!({
            "blake3": blake3_field,
            "build_ts": build_ts,
            "name": "test-construct",
            "publisher_did": "did:test",
            "version": "1.0.0",
        });
        let canonical_bytes = core_crypto::canonicalize_jcs(&payload_value).unwrap();
        let signature = signing_key.sign(&canonical_bytes);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        let signature_field = format!("ed25519:{sig_b64}");

        let sidecar = SidecarEnvelope {
            schema_version: 1,
            publisher_did: "did:test".to_string(),
            name: "test-construct".to_string(),
            version: "1.0.0".to_string(),
            blake3: blake3_field,
            build_ts,
            signature: signature_field,
            signature_alg: "ed25519".to_string(),
        };

        (sidecar, binary_bytes, toml_bytes)
    }

    /// Signing key derived from the committed dev0 seed (raw `[1..=32]`).
    /// Its verifying key equals `EMBER_SYSTEMS_PUBKEY_BYTES` and is
    /// therefore recognized as the placeholder anchor. Use this ONLY in
    /// tests that exercise the M7 placeholder-refusal path; everything
    /// else uses `non_placeholder_signing_key()`.
    fn test_signing_key() -> ed25519_dalek::SigningKey {
        let seed: [u8; 32] = {
            let mut s = [0u8; 32];
            for (i, b) in s.iter_mut().enumerate() {
                *b = (i + 1) as u8;
            }
            s
        };
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    /// Signing key whose verifying key is distinct from
    /// `EMBER_SYSTEMS_PUBKEY_BYTES`. Used by every test that expects
    /// `verify_construct_signature` to make it past the M7 placeholder
    /// guard.
    fn non_placeholder_signing_key() -> ed25519_dalek::SigningKey {
        let mut seed = [0u8; 32];
        seed[0] = 0xa5;
        seed[31] = 0x5a;
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        debug_assert_ne!(
            sk.verifying_key().to_bytes(),
            crate::trust_graph::EMBER_SYSTEMS_PUBKEY_BYTES,
            "non_placeholder_signing_key must not collide with the placeholder anchor"
        );
        sk
    }

    fn make_delegation_for_did(
        did: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> crate::trust_graph::PublisherTrustDelegation {
        crate::trust_graph::PublisherTrustDelegation {
            id: "test-deleg".to_string(),
            publisher_did: did.to_string(),
            pubkey_bytes: signing_key.verifying_key().to_bytes(),
            valid_from: 0,
            valid_until: None,
            installed_at: 1000,
            revoked_at: None,
        }
    }

    #[test]
    fn happy_path_with_delegation_verifies_cleanly() {
        // Uses non_placeholder_signing_key so the M7 placeholder guard
        // doesn't refuse — the goal of this test is to confirm the
        // delegation-backed verify path works end-to-end with a real
        // (non-placeholder) trust anchor.
        let signing_key = non_placeholder_signing_key();
        let (sidecar, binary_bytes, toml_bytes) = make_valid_sidecar(&signing_key);
        let deleg = make_delegation_for_did("did:test", &signing_key);
        let store = TestTrustStore {
            delegations: vec![deleg],
        };
        let blake3_hex = compute_blake3_hex(&binary_bytes, &toml_bytes);

        let result = verify_construct_signature(&sidecar, &blake3_hex, &store);
        assert!(
            result.is_ok(),
            "delegation-backed verify must succeed: {result:?}"
        );
    }

    #[test]
    fn no_delegation_for_publisher_fails_closed() {
        let signing_key = test_signing_key();
        let (sidecar, binary_bytes, toml_bytes) = make_valid_sidecar(&signing_key);
        let store = TestTrustStore {
            delegations: vec![],
        };
        let blake3_hex = compute_blake3_hex(&binary_bytes, &toml_bytes);

        let result = verify_construct_signature(&sidecar, &blake3_hex, &store);
        assert!(
            matches!(result, Err(VerifyError::TrustGraph(_))),
            "no delegation must fail closed: {result:?}"
        );
    }

    #[test]
    fn schema_unsupported_returns_error() {
        let signing_key = test_signing_key();
        let (mut sidecar, binary_bytes, toml_bytes) = make_valid_sidecar(&signing_key);
        sidecar.schema_version = 99;
        let store = TestTrustStore {
            delegations: vec![],
        };
        let blake3_hex = compute_blake3_hex(&binary_bytes, &toml_bytes);

        let result = verify_construct_signature(&sidecar, &blake3_hex, &store);
        match result {
            Err(VerifyError::SchemaUnsupported(99)) => {}
            other => panic!("expected SchemaUnsupported(99), got {other:?}"),
        }
    }

    #[test]
    fn sig_alg_unsupported_returns_error() {
        let signing_key = test_signing_key();
        let (mut sidecar, binary_bytes, toml_bytes) = make_valid_sidecar(&signing_key);
        sidecar.signature_alg = "rsa".to_string();
        let store = TestTrustStore {
            delegations: vec![],
        };
        let blake3_hex = compute_blake3_hex(&binary_bytes, &toml_bytes);

        let result = verify_construct_signature(&sidecar, &blake3_hex, &store);
        match result {
            Err(VerifyError::SignatureAlgUnsupported(ref alg)) if alg == "rsa" => {}
            other => panic!("expected SignatureAlgUnsupported(rsa), got {other:?}"),
        }
    }

    #[test]
    fn blake3_mismatch_returns_binary_pin_mismatch() {
        let signing_key = test_signing_key();
        let (sidecar, _binary_bytes, toml_bytes) = make_valid_sidecar(&signing_key);
        let store = TestTrustStore {
            delegations: vec![],
        };
        let wrong_hash = compute_blake3_hex(b"tampered-binary-content", &toml_bytes);

        let result = verify_construct_signature(&sidecar, &wrong_hash, &store);
        match result {
            Err(VerifyError::BinaryPinMismatch { .. }) => {}
            other => panic!("expected BinaryPinMismatch, got {other:?}"),
        }
    }

    #[test]
    fn revoked_delegation_fails_signature_verification() {
        let signing_key = test_signing_key();
        let (sidecar, binary_bytes, toml_bytes) = make_valid_sidecar(&signing_key);
        let mut deleg = make_delegation_for_did("did:test", &signing_key);
        deleg.revoked_at = Some(1735000000);
        let store = TestTrustStore {
            delegations: vec![deleg],
        };
        let blake3_hex = compute_blake3_hex(&binary_bytes, &toml_bytes);

        let result = verify_construct_signature(&sidecar, &blake3_hex, &store);
        assert!(
            matches!(result, Err(VerifyError::TrustGraph(_))),
            "revoked delegation must fail: {result:?}"
        );
    }

    fn make_did_emberlink_sidecar(
        signing_key: &ed25519_dalek::SigningKey,
        binary_bytes: &[u8],
        toml_bytes: &[u8],
    ) -> SidecarEnvelope {
        use ed25519_dalek::Signer as _;

        let blake3_hex = compute_blake3_hex(binary_bytes, toml_bytes);
        let blake3_field = format!("blake3:{blake3_hex}");
        let build_ts = "2026-06-09T12:00:00Z".to_string();

        let payload_value = serde_json::json!({
            "blake3": blake3_field,
            "build_ts": build_ts,
            "name": "gh",
            "publisher_did": "did:emberlink",
            "version": "0.3.0",
        });
        let canonical_bytes = core_crypto::canonicalize_jcs(&payload_value).unwrap();
        let signature = signing_key.sign(&canonical_bytes);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        SidecarEnvelope {
            schema_version: 1,
            publisher_did: "did:emberlink".to_string(),
            name: "gh".to_string(),
            version: "0.3.0".to_string(),
            blake3: blake3_field,
            build_ts,
            signature: format!("ed25519:{sig_b64}"),
            signature_alg: "ed25519".to_string(),
        }
    }

    /// M7: a sidecar signed by the placeholder dev0 key and verified
    /// through the pinned `did:emberlink` path MUST be refused. The
    /// signature itself would be valid (the daemon could decode it and
    /// `verify_strict` would succeed), but the verifier refuses earlier
    /// — the trust anchor is the placeholder whose seed is committed to
    /// git, so any verification through this path is forgeable.
    #[test]
    fn verify_construct_signature_refuses_when_trust_anchor_is_placeholder() {
        let signing_key = test_signing_key(); // placeholder dev0 key
        let binary_bytes = b"bundled-construct-binary";
        let toml_bytes = b"[meta]\npublisher = \"did:emberlink\"\nname = \"gh\"\n";
        let sidecar = make_did_emberlink_sidecar(&signing_key, binary_bytes, toml_bytes);
        let store = TestTrustStore {
            delegations: vec![],
        };
        let blake3_hex = compute_blake3_hex(binary_bytes, toml_bytes);

        let result = verify_construct_signature(&sidecar, &blake3_hex, &store);
        match result {
            Err(VerifyError::PlaceholderTrustAnchor { ref anchor_hex }) => {
                assert_eq!(
                    anchor_hex,
                    &hex::encode(crate::trust_graph::EMBER_SYSTEMS_PUBKEY_BYTES),
                    "anchor_hex must report the resolved (placeholder) trust anchor"
                );
            }
            other => panic!(
                "expected PlaceholderTrustAnchor refusal for did:emberlink with \
                 placeholder anchor, got {other:?}"
            ),
        }
    }

    /// M7: when the trust anchor is NOT the placeholder (a freshly
    /// generated test key installed via a delegation), the placeholder
    /// guard does NOT blanket-refuse — verification proceeds and either
    /// passes or fails on its own merits. This test asserts the guard
    /// only triggers on the placeholder byte-pattern.
    #[test]
    fn verify_construct_signature_proceeds_when_trust_anchor_is_not_placeholder() {
        let signing_key = non_placeholder_signing_key();
        let (sidecar, binary_bytes, toml_bytes) = make_valid_sidecar(&signing_key);
        let deleg = make_delegation_for_did("did:test", &signing_key);
        let store = TestTrustStore {
            delegations: vec![deleg],
        };
        let blake3_hex = compute_blake3_hex(&binary_bytes, &toml_bytes);

        let result = verify_construct_signature(&sidecar, &blake3_hex, &store);
        // Either Ok (full verify passes) or some non-placeholder error —
        // the load-bearing assertion is that we do NOT get the
        // PlaceholderTrustAnchor refusal.
        assert!(
            !matches!(result, Err(VerifyError::PlaceholderTrustAnchor { .. })),
            "non-placeholder anchor must not be refused by the M7 guard: {result:?}"
        );
        assert!(
            result.is_ok(),
            "valid signature with non-placeholder anchor must verify cleanly: {result:?}"
        );
    }

    #[test]
    fn tampered_binary_fails_did_emberlink() {
        let signing_key = test_signing_key();
        let binary_bytes = b"bundled-construct-binary";
        let toml_bytes = b"[meta]\npublisher = \"did:emberlink\"\nname = \"gh\"\n";
        let sidecar = make_did_emberlink_sidecar(&signing_key, binary_bytes, toml_bytes);
        let store = TestTrustStore {
            delegations: vec![],
        };
        let tampered_hash = compute_blake3_hex(b"tampered-binary", toml_bytes);

        let result = verify_construct_signature(&sidecar, &tampered_hash, &store);
        assert!(
            matches!(result, Err(VerifyError::BinaryPinMismatch { .. })),
            "tampered binary must fail: {result:?}"
        );
    }

    #[test]
    fn cache_key_shape_is_path_mtime_size() {
        let cache = VerifierCache::new();
        let path = PathBuf::from("/some/binary");
        cache.insert(path.clone(), 1234, 5678, "abc123".to_string());
        assert_eq!(cache.get(&path, 1234, 5678), Some("abc123".to_string()));
        assert_eq!(
            cache.get(&path, 1234, 9999),
            None,
            "different size must miss"
        );
        assert_eq!(
            cache.get(&path, 9999, 5678),
            None,
            "different mtime must miss"
        );
        assert_eq!(
            cache.get(&PathBuf::from("/other/binary"), 1234, 5678),
            None,
            "different path must miss"
        );
    }
}
