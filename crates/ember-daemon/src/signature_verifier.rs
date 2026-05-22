//! Daemon-side Construct signature verifier per
//! `docs/construct-signing-pipeline.md` §Verification flow steps 1-5.
//!
//! Entry point: [`verify_construct_signature`].

use base64::Engine as _;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::RwLock;

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
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("base64: {0}")]
    Base64(String),
    #[error("hex: {0}")]
    Hex(String),
}

/// Cache key: (blake3_hex, trust_graph_version). Cache flush happens on
/// trust-graph mutation by bumping the trust_graph_version.
type CacheKey = (String, u64);

/// In-process cache for verified sidecars. Fail-closed: an unknown key
/// requires a full re-verification.
pub struct VerifierCache {
    inner: RwLock<HashMap<CacheKey, ()>>,
}

impl Default for VerifierCache {
    fn default() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }
}

impl VerifierCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn flush(&self) {
        if let Ok(mut g) = self.inner.write() {
            g.clear();
        }
    }
}

/// Top-level verifier entry point.
///
/// Steps (per docs/construct-signing-pipeline.md §Verification flow):
/// 1. Validate schema_version and signature_alg, then check cache.
/// 2. Re-compute blake3 over `binary_bytes || construct_toml_bytes`
///    and compare with `sidecar.blake3` (strip "blake3:" prefix).
/// 3. Resolve publisher's pubkey via `trust_graph::resolve_publisher_pubkey`.
/// 4. Build canonical payload (JCS) over
///    {publisher_did, name, version, blake3, build_ts}
///    and Ed25519-verify the signature against the resolved pubkey.
/// 5. On success, insert into cache keyed by (blake3, trust_graph_version).
pub fn verify_construct_signature(
    sidecar: &SidecarEnvelope,
    binary_bytes: &[u8],
    construct_toml_bytes: &[u8],
    cache: &VerifierCache,
    trust_graph_version: u64,
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

    // Step 2 — cache lookup before any crypto.
    let blake3_hex_only = sidecar
        .blake3
        .strip_prefix("blake3:")
        .unwrap_or(&sidecar.blake3)
        .to_string();
    let cache_key: CacheKey = (blake3_hex_only.clone(), trust_graph_version);
    if let Ok(g) = cache.inner.read()
        && g.contains_key(&cache_key)
    {
        return Ok(());
    }

    // Step 3 — re-compute blake3.
    let mut hasher = blake3::Hasher::new();
    hasher.update(binary_bytes);
    hasher.update(construct_toml_bytes);
    let computed = hex::encode(hasher.finalize().as_bytes());
    if computed != blake3_hex_only {
        return Err(VerifyError::BinaryPinMismatch {
            sidecar: blake3_hex_only,
            computed,
        });
    }

    // Step 4 — resolve publisher key.
    let build_ts_epoch = chrono::DateTime::parse_from_rfc3339(&sidecar.build_ts)
        .map_err(|e| VerifyError::SignatureInvalid {
            reason: format!("build_ts parse: {e}"),
        })?
        .timestamp();
    let publisher_key =
        crate::trust_graph::resolve_publisher_pubkey(&sidecar.publisher_did, build_ts_epoch)?;

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

    // Cache the successful verification.
    if let Ok(mut g) = cache.inner.write() {
        g.insert(cache_key, ());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a sidecar + matching binary/toml bytes using a fresh Ed25519 key.
    /// Returns (sidecar, binary_bytes, toml_bytes, signing_key).
    fn make_valid_sidecar(
        signing_key: &ed25519_dalek::SigningKey,
    ) -> (SidecarEnvelope, Vec<u8>, Vec<u8>) {
        use ed25519_dalek::Signer as _;

        let binary_bytes = b"fake-binary-content".to_vec();
        let toml_bytes = b"[meta]\npublisher = \"did:test\"\nname = \"test-construct\"\n".to_vec();

        let mut hasher = blake3::Hasher::new();
        hasher.update(&binary_bytes);
        hasher.update(&toml_bytes);
        let blake3_hex = hex::encode(hasher.finalize().as_bytes());
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

    /// Stub trust graph lookup using a caller-supplied pubkey — bypasses
    /// resolve_publisher_pubkey's DID-based lookup so tests exercise the
    /// crypto path with a real key pair.
    fn verify_with_stub_pubkey(
        sidecar: &SidecarEnvelope,
        binary_bytes: &[u8],
        construct_toml_bytes: &[u8],
        pubkey: ed25519_dalek::VerifyingKey,
        cache: &VerifierCache,
        trust_graph_version: u64,
    ) -> Result<(), VerifyError> {
        if sidecar.schema_version != 1 {
            return Err(VerifyError::SchemaUnsupported(sidecar.schema_version));
        }
        if sidecar.signature_alg != "ed25519" {
            return Err(VerifyError::SignatureAlgUnsupported(
                sidecar.signature_alg.clone(),
            ));
        }

        let blake3_hex_only = sidecar
            .blake3
            .strip_prefix("blake3:")
            .unwrap_or(&sidecar.blake3)
            .to_string();
        let cache_key: CacheKey = (blake3_hex_only.clone(), trust_graph_version);
        if let Ok(g) = cache.inner.read() {
            if g.contains_key(&cache_key) {
                return Ok(());
            }
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(binary_bytes);
        hasher.update(construct_toml_bytes);
        let computed = hex::encode(hasher.finalize().as_bytes());
        if computed != blake3_hex_only {
            return Err(VerifyError::BinaryPinMismatch {
                sidecar: blake3_hex_only,
                computed,
            });
        }

        let canonical_payload_value = serde_json::json!({
            "blake3": sidecar.blake3,
            "build_ts": sidecar.build_ts,
            "name": sidecar.name,
            "publisher_did": sidecar.publisher_did,
            "version": sidecar.version,
        });
        let canonical_bytes =
            core_crypto::canonicalize_jcs(&canonical_payload_value).map_err(|e| {
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

        pubkey.verify_strict(&canonical_bytes, &sig).map_err(|e| {
            VerifyError::SignatureInvalid {
                reason: format!("ed25519 verify: {e}"),
            }
        })?;

        if let Ok(mut g) = cache.inner.write() {
            g.insert(cache_key, ());
        }
        Ok(())
    }

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

    #[test]
    fn happy_path_verifies_cleanly() {
        let signing_key = test_signing_key();
        let verifying_key = signing_key.verifying_key();
        let cache = VerifierCache::new();
        let (sidecar, binary_bytes, toml_bytes) = make_valid_sidecar(&signing_key);

        let result = verify_with_stub_pubkey(
            &sidecar,
            &binary_bytes,
            &toml_bytes,
            verifying_key,
            &cache,
            1,
        );
        assert!(result.is_ok(), "happy path must succeed: {result:?}");
    }

    #[test]
    fn schema_unsupported_returns_error() {
        let signing_key = test_signing_key();
        let (mut sidecar, binary_bytes, toml_bytes) = make_valid_sidecar(&signing_key);
        sidecar.schema_version = 99;

        let cache = VerifierCache::new();
        let result = verify_construct_signature(&sidecar, &binary_bytes, &toml_bytes, &cache, 1);
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

        let cache = VerifierCache::new();
        let result = verify_construct_signature(&sidecar, &binary_bytes, &toml_bytes, &cache, 1);
        match result {
            Err(VerifyError::SignatureAlgUnsupported(ref alg)) if alg == "rsa" => {}
            other => panic!("expected SignatureAlgUnsupported(rsa), got {other:?}"),
        }
    }

    #[test]
    fn blake3_mismatch_returns_binary_pin_mismatch() {
        let signing_key = test_signing_key();
        let (sidecar, _binary_bytes, toml_bytes) = make_valid_sidecar(&signing_key);

        // Pass different binary bytes — the blake3 won't match.
        let tampered_binary = b"tampered-binary-content";
        let cache = VerifierCache::new();
        let result = verify_construct_signature(&sidecar, tampered_binary, &toml_bytes, &cache, 1);
        match result {
            Err(VerifyError::BinaryPinMismatch { .. }) => {}
            other => panic!("expected BinaryPinMismatch, got {other:?}"),
        }
    }

    #[test]
    fn cache_hit_skips_crypto_on_second_call() {
        let signing_key = test_signing_key();
        let verifying_key = signing_key.verifying_key();
        let cache = VerifierCache::new();
        let (sidecar, binary_bytes, toml_bytes) = make_valid_sidecar(&signing_key);

        // First call — populates cache.
        verify_with_stub_pubkey(
            &sidecar,
            &binary_bytes,
            &toml_bytes,
            verifying_key,
            &cache,
            1,
        )
        .expect("first call must succeed");

        // Second call with tampered binary — would normally fail blake3, but
        // cache hit returns Ok before reaching the crypto path.
        let tampered_binary = b"completely-different-bytes";
        let result = verify_with_stub_pubkey(
            &sidecar,
            tampered_binary,
            &toml_bytes,
            verifying_key,
            &cache,
            1,
        );
        assert!(result.is_ok(), "cache hit must short-circuit: {result:?}");
    }
}
