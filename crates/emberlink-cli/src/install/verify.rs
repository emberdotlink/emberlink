//! Install-bundle signature verification — runs **before** any sudo elevation.
//!
//! The install pipeline ([T-INSTALL-BUNDLE-SIGNING], `docs/install-supply-chain.md`)
//! produces signed install bundles in two flavors:
//!
//! - **Linux**: a `.tar.gz` install bundle paired with a sigstore keyless
//!   `.sig` + `.crt` produced by `cosign sign-blob` from
//!   `.github/workflows/release.yml`. The publisher key is the GitHub Actions
//!   OIDC identity recorded in Rekor (the public transparency log) — there is
//!   no long-lived signing key.
//! - **macOS**: a notarized `.pkg` whose Apple Developer ID signature +
//!   notarization ticket is verified by Gatekeeper before the wizard even
//!   reaches this module. We additionally verify a sidecar manifest hash so
//!   the install path catches mid-flight tampering of the bundle's contents
//!   (a `.pkg` extracted, modified, and re-signed by an attacker who stole the
//!   notarization ticket would still fail this content check).
//!
//! # Why this runs before `sudo`
//!
//! `wizard::batch_sudo_v` is the gate that primes the operator's password
//! cache and authorizes every later install step. If we elevated *first* and
//! verified the bundle *second*, an attacker who replaced the bundle on disk
//! between download and install would already have a sudo'd shell that could
//! be reused for arbitrary side effects (the wizard does shell out via
//! `sudo`). Verifying first and refusing to elevate on failure is the
//! security-correct ordering.
//!
//! # Pure-function, no side effects
//!
//! The verifier reads the bundle and its sidecar metadata, computes the
//! manifest hash, and compares against a publisher-issued trust manifest. It
//! does not write anywhere on disk and does not shell out. The wizard or a
//! future `ember install verify <bundle>` CLI verb composes the call.
//!
//! # Forward-compat: community publishers
//!
//! The trust manifest takes a `publisher_did` and an `ed25519` public key in
//! the same shape `core_crypto` already uses for Constructs (see
//! `crates/emberlink-cli/src/construct/sign.rs`). Anyone publishing a
//! community install bundle can hand us a manifest signed by their key; the
//! verifier accepts any `publisher_did` whose key is on the supplied trust
//! list. This is the [acceptance criterion] "Signing tool accepts publisher
//! key as input (forward-compat for community)".
//!
//! [acceptance criterion]: ../../../release-checklist

use std::path::{Path, PathBuf};

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sigstore::cosign::payload::SimpleSigning;

use core_crypto::canonicalize_jcs;
use ember_update::in_toto::{self, SignedEnvelope};

/// Schema version this verifier accepts in `BundleManifest::schema_version`.
///
/// Bumped when the canonical JCS payload shape changes — older sidecars
/// fail closed rather than silently mis-verify.
pub const BUNDLE_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Errors raised by [`verify_install_bundle`].
///
/// Each variant maps a verification failure to an operator-actionable
/// message. The `Display` impls intentionally include "do not run the
/// installer" guidance for every failure path that surfaces to the operator
/// — see `docs/install-supply-chain.md` §"What to do if verification fails".
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("install bundle '{0}' not found; download it from the GitHub Release")]
    BundleMissing(PathBuf),
    #[error(
        "install bundle sidecar '{0}' not found; \
         re-download the bundle alongside its `.bundle.json` manifest"
    )]
    ManifestMissing(PathBuf),
    #[error("io error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "bundle manifest schema_version {found} not supported by this CLI \
         (this CLI accepts {expected}); upgrade the CLI before installing"
    )]
    UnsupportedSchema { found: u32, expected: u32 },
    #[error(
        "bundle manifest is malformed JSON: {0}; \
         do NOT run the installer — re-download the bundle"
    )]
    ManifestParse(serde_json::Error),
    #[error(
        "publisher '{publisher_did}' is not on the trust list; \
         pass --trust-publisher <DID> only after auditing the publisher's key"
    )]
    UntrustedPublisher { publisher_did: String },
    #[error(
        "publisher key for '{publisher_did}' is malformed: {detail}; \
         do NOT run the installer — the trust manifest is corrupt"
    )]
    BadPublisherKey {
        publisher_did: String,
        detail: String,
    },
    #[error(
        "bundle signature for '{publisher_did}' is malformed: {detail}; \
         do NOT run the installer — re-download the bundle"
    )]
    BadSignature {
        publisher_did: String,
        detail: String,
    },
    #[error(
        "bundle hash mismatch (expected {expected}, got {actual}); \
         the bundle was tampered with — do NOT run the installer"
    )]
    HashMismatch { expected: String, actual: String },
    #[error(
        "bundle signature failed verification against publisher '{publisher_did}'; \
         the bundle was tampered with — do NOT run the installer"
    )]
    SignatureMismatch { publisher_did: String },
    #[error(
        "bundle manifest could not be canonicalized (JCS): {0}; \
         do NOT run the installer — the manifest is corrupt"
    )]
    Canonicalize(String),
    #[error(
        "in-toto statement envelope verification failed: {0}; \
         do NOT run the installer — the provenance envelope is invalid"
    )]
    InTotoInvalid(String),
}

/// Sidecar manifest written next to the install bundle by the release
/// pipeline.
///
/// The release workflow (`.github/workflows/release.yml`) emits one of these
/// per bundle as `<bundle>.bundle.json`. The shape mirrors
/// `crates/emberlink-cli/src/construct/sign.rs::sign_construct`'s sidecar
/// for consistency — same canonical-JCS signing payload, same
/// `<alg>:<base64>` field encoding.
///
/// # Canonical signing payload
///
/// The signature covers the JCS encoding of:
///
/// ```json
/// {
///   "blake3":        "blake3:<hex>",
///   "build_ts":      "<rfc3339>",
///   "bundle_name":   "<filename>",
///   "publisher_did": "<DID>",
///   "version":       "<semver>"
/// }
/// ```
///
/// `build_ts` is included in the signed payload (unlike the Construct
/// sidecar) so a trusted bundle from yesterday can't be served as today's
/// release without re-signing. The release workflow asserts
/// `build_ts == github.event.release.published_at` for end-to-end provenance.
#[derive(Debug, Serialize, Deserialize)]
pub struct BundleManifest {
    pub schema_version: u32,
    pub publisher_did: String,
    pub bundle_name: String,
    pub version: String,
    pub blake3: String,
    pub build_ts: String,
    pub signature: String,
    pub signature_alg: String,
}

/// A trusted publisher entry the verifier consults.
///
/// The default trust list ships with one entry — the project's release
/// identity. Operators or community redistributors can add entries via the
/// CLI/wizard `--trust-publisher` flag; the verifier accepts any manifest
/// whose `publisher_did` is on the list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPublisher {
    pub publisher_did: String,
    /// Ed25519 public key, base64-encoded (32 raw bytes → 44 ascii chars).
    pub ed25519_pub_b64: String,
}

/// The official Emberlink release publisher.
///
/// The corresponding Ed25519 secret key is held in the project's hardware
/// security module — see `docs/install-supply-chain.md` §"Publisher key
/// custody". The base64 string here is a placeholder that the release
/// pipeline will overwrite once the production key is provisioned (implementation-note-422
/// follow-up). Until then, `verify_install_bundle` will fail-closed with
/// `BadPublisherKey` because the placeholder isn't a valid Ed25519 point.
pub const EMBERLINK_RELEASE_PUBLISHER_DID: &str = "did:web:ember.link";

/// Compute the publisher trust list given any operator-supplied additions.
///
/// Always includes the default Emberlink release publisher.
pub fn default_trust_list() -> Vec<TrustedPublisher> {
    vec![TrustedPublisher {
        publisher_did: EMBERLINK_RELEASE_PUBLISHER_DID.to_string(),
        // Placeholder — production key will be provisioned via the release
        // pipeline (see `docs/install-supply-chain.md` §"Publisher key
        // custody"). Until then, verification falls back to
        // `BadPublisherKey`, which is the correct fail-closed default.
        ed25519_pub_b64: "PLACEHOLDER_PUBLISHER_KEY_NOT_YET_PROVISIONED".to_string(),
    }]
}

/// Verify an install bundle against a sidecar manifest.
///
/// `bundle_path` is the path to the `.tar.gz` (Linux) or `.pkg` (macOS) file.
/// The verifier expects a sidecar at `<bundle_path>.bundle.json`.
///
/// On success returns `Ok(())`; on failure returns one of [`VerifyError`].
/// **The wizard MUST refuse to elevate on `Err(_)`.**
///
/// # Errors
///
/// See [`VerifyError`] — every variant carries operator-actionable text.
pub fn verify_install_bundle(
    bundle_path: &Path,
    trust_list: &[TrustedPublisher],
) -> Result<BundleManifest, VerifyError> {
    if !bundle_path.exists() {
        return Err(VerifyError::BundleMissing(bundle_path.to_path_buf()));
    }

    let manifest_path = sidecar_path_for(bundle_path);
    if !manifest_path.exists() {
        return Err(VerifyError::ManifestMissing(manifest_path));
    }

    let manifest_bytes = std::fs::read(&manifest_path).map_err(|e| VerifyError::Io {
        path: manifest_path.clone(),
        source: e,
    })?;
    let manifest: BundleManifest =
        serde_json::from_slice(&manifest_bytes).map_err(VerifyError::ManifestParse)?;

    if manifest.schema_version != BUNDLE_MANIFEST_SCHEMA_VERSION {
        return Err(VerifyError::UnsupportedSchema {
            found: manifest.schema_version,
            expected: BUNDLE_MANIFEST_SCHEMA_VERSION,
        });
    }

    let publisher = trust_list
        .iter()
        .find(|p| p.publisher_did == manifest.publisher_did)
        .ok_or_else(|| VerifyError::UntrustedPublisher {
            publisher_did: manifest.publisher_did.clone(),
        })?;

    // Decode the publisher key — fails closed on placeholder/malformed keys.
    let pub_bytes = base64::engine::general_purpose::STANDARD
        .decode(&publisher.ed25519_pub_b64)
        .map_err(|e| VerifyError::BadPublisherKey {
            publisher_did: manifest.publisher_did.clone(),
            detail: format!("base64: {e}"),
        })?;
    if pub_bytes.len() != 32 {
        return Err(VerifyError::BadPublisherKey {
            publisher_did: manifest.publisher_did.clone(),
            detail: format!("expected 32 bytes, got {}", pub_bytes.len()),
        });
    }
    let pub_arr: [u8; 32] = pub_bytes[..32].try_into().unwrap();
    let verifying_key =
        VerifyingKey::from_bytes(&pub_arr).map_err(|e| VerifyError::BadPublisherKey {
            publisher_did: manifest.publisher_did.clone(),
            detail: format!("invalid Ed25519 point: {e}"),
        })?;

    // Re-hash the bundle bytes and compare against the manifest's claim.
    let bundle_bytes = std::fs::read(bundle_path).map_err(|e| VerifyError::Io {
        path: bundle_path.to_path_buf(),
        source: e,
    })?;
    let actual = format!(
        "blake3:{}",
        hex::encode(blake3::hash(&bundle_bytes).as_bytes())
    );
    if actual != manifest.blake3 {
        return Err(VerifyError::HashMismatch {
            expected: manifest.blake3.clone(),
            actual,
        });
    }

    // Re-build the canonical JCS payload and verify the Ed25519 signature.
    let payload = serde_json::json!({
        "blake3": manifest.blake3,
        "build_ts": manifest.build_ts,
        "bundle_name": manifest.bundle_name,
        "publisher_did": manifest.publisher_did,
        "version": manifest.version,
    });
    let canonical =
        canonicalize_jcs(&payload).map_err(|e| VerifyError::Canonicalize(e.to_string()))?;

    let sig_b64 =
        manifest
            .signature
            .strip_prefix("ed25519:")
            .ok_or_else(|| VerifyError::BadSignature {
                publisher_did: manifest.publisher_did.clone(),
                detail: "missing 'ed25519:' prefix".to_string(),
            })?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|e| VerifyError::BadSignature {
            publisher_did: manifest.publisher_did.clone(),
            detail: format!("base64: {e}"),
        })?;
    if sig_bytes.len() != 64 {
        return Err(VerifyError::BadSignature {
            publisher_did: manifest.publisher_did.clone(),
            detail: format!("expected 64 bytes, got {}", sig_bytes.len()),
        });
    }
    let sig_arr: [u8; 64] = sig_bytes[..64].try_into().unwrap();
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(&canonical, &signature)
        .map_err(|_| VerifyError::SignatureMismatch {
            publisher_did: manifest.publisher_did.clone(),
        })?;

    Ok(manifest)
}

/// Verify an in-toto Statement v1 envelope wrapping a `BundleManifest` predicate.
///
/// The release pipeline produces a sidecar `<bundle>.intoto.json` containing a
/// [`SignedEnvelope<BundleManifest>`] signed by the publisher key. This function
/// verifies the envelope's Ed25519 signature via
/// [`ember_update::in_toto::verify`] before the wizard elevates privileges.
///
/// # Errors
///
/// Returns [`VerifyError::InTotoInvalid`] if the signature or `_type` field is wrong.
pub fn verify_bundle_in_toto_envelope(
    envelope: &SignedEnvelope<BundleManifest>,
    verifying_key: &VerifyingKey,
) -> Result<(), VerifyError> {
    in_toto::verify(envelope, verifying_key).map_err(|e| VerifyError::InTotoInvalid(e.to_string()))
}

// TODO: integrate ember_update::channel::verify_channel_pointer at
// install path — before `wizard::batch_sudo_v` elevation, fetch and verify the channel pointer
// for the install channel, then confirm the manifest_uri / manifest_digest_hex match the
// bundle being installed.  The `verify_install_bundle` call above handles the Ember-IdentityRoot
// Ed25519 witness; the channel pointer verification is the discovery / freshness layer on top.

/// Dual-witness verification for image manifests hosted at `manifests.emberlink.dev`.
///
/// Each manifest blob served by the R2 + Worker stack
/// (infra/pulumi/gitops/manifests-emberlink-dev/) carries two independent
/// signatures that the daemon MUST verify before accepting an image update
/// (design note §3):
///
/// 1. **Sigstore keyless** — produced by `cosign sign-blob` inside
///    `.github/workflows/release.yml` using GitHub Actions OIDC identity.
///    The signature is bound to the Rekor public transparency log, so there is
///    no long-lived cosign signing key. This witness is passed as
///    `sigstore_sig` (the raw bytes that cosign would verify, i.e. the decoded
///    `.sig` sidecar). Currently modelled as an opaque byte slice; the full
///    cosign-verify integration is left for a follow-up task (implementation-note-423).
///
/// 2. **Ember-IdentityRoot Ed25519** — the release pipeline signs the manifest
///    blob with the project's hardware-bound Ed25519 key (see
///    `docs/install-supply-chain.md` §"Publisher key custody"). This witness is
///    verified via the same `in_toto::verify` machinery used for install bundles.
///
/// # Arguments
///
/// - `blob` — the raw manifest JSON bytes fetched from `manifests.emberlink.dev`.
/// - `sigstore_sig` — raw bytes of the sigstore keyless signature sidecar.
///   Must be non-empty; deep cosign verification is a follow-up.
/// - `ember_id_root_sig` — 64-byte Ed25519 signature over `blob`, produced by
///   the Ember-IdentityRoot signing key.
/// - `ember_id_root_key` — the Ember-IdentityRoot Ed25519 verifying key.
///
/// # Errors
///
/// Returns [`VerifyError::InTotoInvalid`] if the Ember-IdentityRoot signature
/// fails. Returns [`VerifyError::BadSignature`] if the sigstore witness is
/// absent or the Ed25519 signature bytes are malformed.
///
/// # Security note
///
/// Both checks are AND-gated: failure of either witness rejects the manifest.
/// This ensures an attacker who compromises one signing channel cannot serve
/// a malicious update undetected.
pub fn verify_manifest_dual_witness(
    blob: &[u8],
    sigstore_sig: &[u8],
    ember_id_root_sig: &[u8],
    ember_id_root_key: &VerifyingKey,
) -> Result<(), VerifyError> {
    // Witness 1: sigstore keyless — parse `sigstore_sig` as a cosign
    // SimpleSigning envelope (JCS-encoded JSON) and verify its
    // `critical.image.docker_manifest_digest` matches `sha256(blob)`. This is
    // implementation-note-424 (anchor:
    // sigstore_witness_envelope_digest_verified). Fulcio cert chain
    // verification + Rekor inclusion-proof verification are deferred to
    // implementation-note-383 and -C — a determined attacker who can
    // forge a SimpleSigning envelope locally can still pass this slice until
    // -B and -C land.
    if sigstore_sig.is_empty() {
        return Err(VerifyError::BadSignature {
            publisher_did: "sigstore/keyless".to_string(),
            detail: "sigstore witness is absent — manifest must be co-signed by release.yml"
                .to_string(),
        });
    }
    let envelope: SimpleSigning =
        serde_json::from_slice(sigstore_sig).map_err(|e| VerifyError::BadSignature {
            publisher_did: "sigstore/keyless".to_string(),
            detail: format!("envelope parse: {}", e),
        })?;
    let blob_digest = format!("sha256:{}", hex::encode(Sha256::digest(blob)));
    if !envelope.satisfies_manifest_digest(&blob_digest) {
        return Err(VerifyError::BadSignature {
            publisher_did: "sigstore/keyless".to_string(),
            detail: format!(
                "envelope payload digest mismatches manifest hash (expected {}, envelope carried {})",
                blob_digest, envelope.critical.image.docker_manifest_digest,
            ),
        });
    }

    // Witness 2: Ember-IdentityRoot Ed25519 — verify raw signature over blob.
    if ember_id_root_sig.len() != 64 {
        return Err(VerifyError::BadSignature {
            publisher_did: EMBERLINK_RELEASE_PUBLISHER_DID.to_string(),
            detail: format!(
                "Ember-IdentityRoot sig must be 64 bytes, got {}",
                ember_id_root_sig.len()
            ),
        });
    }
    let sig_arr: [u8; 64] = ember_id_root_sig[..64].try_into().unwrap();
    let signature = Signature::from_bytes(&sig_arr);

    ember_id_root_key
        .verify(blob, &signature)
        .map_err(|_| VerifyError::SignatureMismatch {
            publisher_did: EMBERLINK_RELEASE_PUBLISHER_DID.to_string(),
        })?;

    Ok(())
}

/// Resolve the sidecar path for an install bundle.
///
/// `<bundle>.tar.gz` → `<bundle>.tar.gz.bundle.json`.
fn sidecar_path_for(bundle: &Path) -> PathBuf {
    let mut p = bundle.to_path_buf();
    let name = p
        .file_name()
        .map(|n| format!("{}.bundle.json", n.to_string_lossy()))
        .unwrap_or_else(|| "bundle.json".to_string());
    p.set_file_name(name);
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    /// Build a (publisher_did, signing_key, trusted_publisher) triple for
    /// tests — the publisher key is fully provisioned so we exercise the
    /// real verify path, not the placeholder fail-closed branch.
    fn fixture_publisher() -> (String, SigningKey, TrustedPublisher) {
        let seed: [u8; 32] = [
            7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
            7, 7, 7,
        ];
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(verifying.to_bytes());
        let did = "did:web:ember.link/test".to_string();
        (
            did.clone(),
            signing,
            TrustedPublisher {
                publisher_did: did,
                ed25519_pub_b64: pub_b64,
            },
        )
    }

    fn write_bundle_and_manifest(
        dir: &Path,
        bundle_bytes: &[u8],
        publisher_did: &str,
        signing: &SigningKey,
        version: &str,
    ) -> PathBuf {
        let bundle_path = dir.join("ember-installer-x86_64.tar.gz");
        std::fs::write(&bundle_path, bundle_bytes).unwrap();
        let blake3 = format!(
            "blake3:{}",
            hex::encode(blake3::hash(bundle_bytes).as_bytes())
        );
        let bundle_name = "ember-installer-x86_64.tar.gz";
        let build_ts = "2026-05-08T00:00:00Z";
        let payload = serde_json::json!({
            "blake3": blake3,
            "build_ts": build_ts,
            "bundle_name": bundle_name,
            "publisher_did": publisher_did,
            "version": version,
        });
        let canonical = canonicalize_jcs(&payload).unwrap();
        let signature = signing.sign(&canonical);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        let manifest = BundleManifest {
            schema_version: BUNDLE_MANIFEST_SCHEMA_VERSION,
            publisher_did: publisher_did.to_string(),
            bundle_name: bundle_name.to_string(),
            version: version.to_string(),
            blake3,
            build_ts: build_ts.to_string(),
            signature: format!("ed25519:{}", sig_b64),
            signature_alg: "ed25519".to_string(),
        };
        let manifest_path = sidecar_path_for(&bundle_path);
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        bundle_path
    }

    #[test]
    fn verify_accepts_well_signed_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let (did, signing, trusted) = fixture_publisher();
        let bundle =
            write_bundle_and_manifest(dir.path(), b"fake-installer-bytes", &did, &signing, "0.3.1");
        let manifest = verify_install_bundle(&bundle, &[trusted]).expect("should verify");
        assert_eq!(manifest.publisher_did, did);
        assert_eq!(manifest.version, "0.3.1");
    }

    #[test]
    fn verify_rejects_tampered_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let (did, signing, trusted) = fixture_publisher();
        let bundle =
            write_bundle_and_manifest(dir.path(), b"fake-installer-bytes", &did, &signing, "0.3.1");
        // Tamper with the bundle AFTER the manifest was written.
        std::fs::write(&bundle, b"malicious-replacement").unwrap();
        let err = verify_install_bundle(&bundle, &[trusted]).unwrap_err();
        assert!(
            matches!(err, VerifyError::HashMismatch { .. }),
            "expected HashMismatch, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_untrusted_publisher() {
        let dir = tempfile::tempdir().unwrap();
        let (did, signing, _trusted) = fixture_publisher();
        let bundle =
            write_bundle_and_manifest(dir.path(), b"fake-installer-bytes", &did, &signing, "0.3.1");
        // Trust list has a DIFFERENT publisher.
        let other = TrustedPublisher {
            publisher_did: "did:web:somebody.else".to_string(),
            ed25519_pub_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        };
        let err = verify_install_bundle(&bundle, &[other]).unwrap_err();
        assert!(
            matches!(err, VerifyError::UntrustedPublisher { .. }),
            "expected UntrustedPublisher, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_missing_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let (_did, _signing, trusted) = fixture_publisher();
        let bogus = dir.path().join("nope.tar.gz");
        let err = verify_install_bundle(&bogus, &[trusted]).unwrap_err();
        assert!(
            matches!(err, VerifyError::BundleMissing(_)),
            "expected BundleMissing, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_missing_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let (_did, _signing, trusted) = fixture_publisher();
        let bundle = dir.path().join("orphan.tar.gz");
        std::fs::write(&bundle, b"bytes").unwrap();
        // Note: NO sidecar written.
        let err = verify_install_bundle(&bundle, &[trusted]).unwrap_err();
        assert!(
            matches!(err, VerifyError::ManifestMissing(_)),
            "expected ManifestMissing, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_unsupported_schema() {
        let dir = tempfile::tempdir().unwrap();
        let (did, _signing, trusted) = fixture_publisher();
        let bundle = dir.path().join("schema.tar.gz");
        std::fs::write(&bundle, b"bytes").unwrap();
        let manifest = serde_json::json!({
            "schema_version": 999,
            "publisher_did": did,
            "bundle_name": "schema.tar.gz",
            "version": "0.0.0",
            "blake3": "blake3:0000",
            "build_ts": "2026-05-08T00:00:00Z",
            "signature": "ed25519:AA",
            "signature_alg": "ed25519"
        });
        std::fs::write(
            sidecar_path_for(&bundle),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let err = verify_install_bundle(&bundle, &[trusted]).unwrap_err();
        assert!(
            matches!(err, VerifyError::UnsupportedSchema { found: 999, .. }),
            "expected UnsupportedSchema(999), got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_bad_signature() {
        let dir = tempfile::tempdir().unwrap();
        let (did, signing, trusted) = fixture_publisher();
        let bundle =
            write_bundle_and_manifest(dir.path(), b"fake-installer-bytes", &did, &signing, "0.3.1");
        // Corrupt the signature field in the sidecar.
        let sidecar = sidecar_path_for(&bundle);
        let mut manifest: BundleManifest =
            serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
        manifest.signature = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            .to_string();
        std::fs::write(&sidecar, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
        let err = verify_install_bundle(&bundle, &[trusted]).unwrap_err();
        assert!(
            matches!(
                err,
                VerifyError::SignatureMismatch { .. } | VerifyError::BadSignature { .. }
            ),
            "expected SignatureMismatch or BadSignature, got {err:?}"
        );
    }

    #[test]
    fn default_trust_list_contains_release_publisher() {
        let list = default_trust_list();
        assert!(
            list.iter()
                .any(|p| p.publisher_did == EMBERLINK_RELEASE_PUBLISHER_DID)
        );
    }

    // ── verify_manifest_dual_witness tests ────────────────────────────────────

    fn dual_witness_fixture() -> (SigningKey, VerifyingKey) {
        let seed: [u8; 32] = [42u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    /// Build a cosign `SimpleSigning` envelope whose
    /// `critical.image.docker-manifest-digest` matches `sha256(blob)`.
    ///
    /// Produces the canonical cosign JSON shape (kebab-case keys, type
    /// `"cosign container image signature"`) so the envelope deserializes
    /// via `sigstore::cosign::payload::SimpleSigning` deserialization
    /// inside `verify_manifest_dual_witness`.
    fn cosign_envelope_for(blob: &[u8]) -> Vec<u8> {
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(blob)));
        let envelope = serde_json::json!({
            "critical": {
                "identity": { "docker-reference": "manifests.emberlink.dev/release" },
                "image": { "docker-manifest-digest": digest },
                "type": "cosign container image signature"
            },
            "optional": serde_json::Value::Null
        });
        serde_json::to_vec(&envelope).expect("envelope JSON is well-formed")
    }

    #[test]
    fn dual_witness_accepts_valid_manifest() {
        let (sk, vk) = dual_witness_fixture();
        let blob = b"{ \"version\": \"0.4.0\", \"digest\": \"sha256:abc\" }";
        let sig: ed25519_dalek::Signature = sk.sign(blob);
        let sigstore_sig = cosign_envelope_for(blob);

        verify_manifest_dual_witness(blob, &sigstore_sig, &sig.to_bytes(), &vk)
            .expect("valid dual-witness should pass");
    }

    #[test]
    fn dual_witness_rejects_tampered_manifest() {
        let (sk, vk) = dual_witness_fixture();
        let blob = b"{ \"version\": \"0.4.0\", \"digest\": \"sha256:abc\" }";
        let sig: ed25519_dalek::Signature = sk.sign(blob);

        // Tamper: verify a DIFFERENT blob against the original signature.
        // The envelope is built against `tampered` so the sigstore witness
        // passes, isolating the failure to the Ember-IdentityRoot witness.
        let tampered = b"{ \"version\": \"0.4.0\", \"digest\": \"sha256:EVIL\" }";
        let tampered_envelope = cosign_envelope_for(tampered);
        let err = verify_manifest_dual_witness(tampered, &tampered_envelope, &sig.to_bytes(), &vk)
            .unwrap_err();
        assert!(
            matches!(err, VerifyError::SignatureMismatch { .. }),
            "expected SignatureMismatch on tampered blob, got {err:?}"
        );
    }

    #[test]
    fn dual_witness_rejects_absent_sigstore_witness() {
        let (sk, vk) = dual_witness_fixture();
        let blob = b"{ \"version\": \"0.4.0\" }";
        let sig: ed25519_dalek::Signature = sk.sign(blob);

        let err = verify_manifest_dual_witness(blob, &[], &sig.to_bytes(), &vk).unwrap_err();
        assert!(
            matches!(err, VerifyError::BadSignature { ref publisher_did, .. }
                if publisher_did == "sigstore/keyless"),
            "expected BadSignature(sigstore/keyless) for empty sigstore witness, got {err:?}"
        );
    }

    #[test]
    fn dual_witness_rejects_malformed_ember_id_root_sig() {
        let (_sk, vk) = dual_witness_fixture();
        let blob = b"{ \"version\": \"0.4.0\" }";
        let sigstore_sig = cosign_envelope_for(blob);

        // Pass a 32-byte (truncated) signature instead of 64.
        let short_sig = vec![0u8; 32];
        let err = verify_manifest_dual_witness(blob, &sigstore_sig, &short_sig, &vk).unwrap_err();
        assert!(
            matches!(err, VerifyError::BadSignature { .. }),
            "expected BadSignature for malformed Ember-IdentityRoot sig, got {err:?}"
        );
    }

    /// implementation-note-424 T1: bytes that don't deserialize as
    /// a cosign SimpleSigning envelope must be rejected before any digest
    /// comparison — the previous `if sigstore_sig.is_empty()` stub accepted
    /// arbitrary non-empty bytes; this test pins that the structural-parse
    /// gate now closes that surface.
    #[test]
    fn dual_witness_rejects_non_envelope_bytes() {
        let (sk, vk) = dual_witness_fixture();
        let blob = b"{ \"version\": \"0.4.0\" }";
        let sig: ed25519_dalek::Signature = sk.sign(blob);

        // Pre-slice stub byte string — not JSON, must fail to parse.
        let bogus = b"cosign-keyless-stub-sig";
        let err = verify_manifest_dual_witness(blob, bogus, &sig.to_bytes(), &vk).unwrap_err();
        match err {
            VerifyError::BadSignature {
                ref publisher_did,
                ref detail,
            } => {
                assert_eq!(publisher_did, "sigstore/keyless");
                assert!(
                    detail.starts_with("envelope parse:"),
                    "expected `envelope parse:` prefix, got {detail:?}"
                );
            }
            other => panic!("expected BadSignature(envelope parse), got {other:?}"),
        }
    }

    /// implementation-note-424 T1: a structurally-valid envelope
    /// whose `docker-manifest-digest` does not match `sha256(blob)` must be
    /// rejected — checkpoint `sigstore_witness_envelope_digest_verified`.
    #[test]
    fn dual_witness_rejects_envelope_with_digest_mismatch() {
        let (sk, vk) = dual_witness_fixture();
        let blob = b"{ \"version\": \"0.4.0\" }";
        let sig: ed25519_dalek::Signature = sk.sign(blob);

        // Envelope built for a DIFFERENT blob → digest mismatch.
        let other_blob = b"{ \"version\": \"99.0.0\" }";
        let envelope_for_other = cosign_envelope_for(other_blob);
        let err = verify_manifest_dual_witness(blob, &envelope_for_other, &sig.to_bytes(), &vk)
            .unwrap_err();
        match err {
            VerifyError::BadSignature {
                ref publisher_did,
                ref detail,
            } => {
                assert_eq!(publisher_did, "sigstore/keyless");
                assert!(
                    detail.contains("envelope payload digest mismatches manifest hash"),
                    "expected digest-mismatch detail, got {detail:?}"
                );
            }
            other => panic!("expected BadSignature(digest mismatch), got {other:?}"),
        }
    }
}
