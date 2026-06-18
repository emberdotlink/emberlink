//! T2 integration tests for ADR 157 §Component 1 — trust-root SET
//! parameterization of the daemon manifest signature verifier.
//!
//! These tests exercise the public API surface
//! (`binary_manifest::verify_manifest_signature_with_trust_roots` +
//! `binary_manifest::parse_trust_roots`) as an external consumer
//! would. The internal unit tests in `src/binary_manifest.rs` cover
//! the property axis (release-only / release+1-dev / release+N); this
//! file pins the integration contract:
//!
//! - T2: manifest signed by dev root verifies when
//!       `EMBER_TRUST_ROOTS=<dev-fpr>` is parsed and unioned with the
//!       release root.
//! - T2: manifest signed by dev root FAILS when `EMBER_TRUST_ROOTS` is
//!       unset and the trust set is release-only.
//!
//! Per ADR 157: dev/prod daemons run the SAME code path; only the
//! input trust-set varies. These tests pin that invariant.
//!
//! CLASSIFICATION: PUBLIC

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use ember_daemon::binary_manifest::{
    VerifyError, parse_trust_roots, verify_manifest_signature_with_trust_roots,
};
use tempfile::tempdir;

/// Build a signed manifest at `path` using `signing_key` over `bytes`.
fn fixture_signed_manifest(path: &std::path::Path, signing_key: &SigningKey, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write manifest");
    let sig = signing_key.sign(bytes);
    let sidecar = serde_json::json!({
        "schema_version": 1,
        "signature": format!(
            "ed25519:{}",
            base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
        ),
        "signature_alg": "ed25519",
    });
    let sidecar_path = path.with_extension("toml.sig");
    std::fs::write(&sidecar_path, sidecar.to_string()).expect("write sidecar");
}

#[test]
fn dev_signed_manifest_verifies_when_dev_trust_root_parsed() {
    // T2 acceptance: manifest signed by dev root verifies when
    // `EMBER_TRUST_ROOTS=<dev-fpr>` set.
    let dir = tempdir().expect("tempdir");
    let manifest_path = dir.path().join("manifest.toml");
    let release_sk = SigningKey::from_bytes(&[1u8; 32]);
    let dev_sk = SigningKey::from_bytes(&[2u8; 32]);
    fixture_signed_manifest(&manifest_path, &dev_sk, b"[some] = \"manifest\"");

    // Simulate the runtime.rs trust-set composition:
    //   release-bundled UNION parse_trust_roots(operator-supplied)
    let dev_fpr_hex = hex::encode(dev_sk.verifying_key().to_bytes());
    let mut trust_roots = vec![release_sk.verifying_key()];
    trust_roots.extend(parse_trust_roots(&dev_fpr_hex).expect("parse dev fpr"));

    verify_manifest_signature_with_trust_roots(&manifest_path, &trust_roots)
        .expect("dev-signed manifest verifies under release + dev trust set");
}

#[test]
fn dev_signed_manifest_rejected_when_trust_roots_release_only() {
    // T2 acceptance: manifest signed by dev root FAILS when
    // `EMBER_TRUST_ROOTS` unset (release-only).
    let dir = tempdir().expect("tempdir");
    let manifest_path = dir.path().join("manifest.toml");
    let release_sk = SigningKey::from_bytes(&[1u8; 32]);
    let dev_sk = SigningKey::from_bytes(&[2u8; 32]);
    fixture_signed_manifest(&manifest_path, &dev_sk, b"[some] = \"manifest\"");

    // Simulate the prod-daemon trust-set composition: release-only.
    let release_only = vec![release_sk.verifying_key()];

    let result = verify_manifest_signature_with_trust_roots(&manifest_path, &release_only);
    assert!(
        matches!(result, Err(VerifyError::SignatureMismatch)),
        "dev-signed manifest must NOT verify under release-only trust set; got {result:?}"
    );
}

#[test]
fn did_key_prefix_round_trip_under_signed_manifest() {
    // T2 acceptance: the operator-facing input shape from ADR 157
    // (`EMBER_TRUST_ROOTS=did:key:<hex>`) flows through parse →
    // verify cleanly.
    let dir = tempdir().expect("tempdir");
    let manifest_path = dir.path().join("manifest.toml");
    let release_sk = SigningKey::from_bytes(&[3u8; 32]);
    let dev_sk = SigningKey::from_bytes(&[4u8; 32]);
    fixture_signed_manifest(&manifest_path, &dev_sk, b"[manifest] = \"v1\"");

    let did_key_input = format!("did:key:{}", hex::encode(dev_sk.verifying_key().to_bytes()));
    let mut trust_roots = vec![release_sk.verifying_key()];
    trust_roots.extend(parse_trust_roots(&did_key_input).expect("parse did:key"));

    verify_manifest_signature_with_trust_roots(&manifest_path, &trust_roots)
        .expect("did:key-prefixed dev fingerprint verifies the manifest");
}

#[test]
fn multi_root_trust_set_walks_all_keys() {
    // T2 acceptance: the trust-set walks every key (matches ADR 157
    // `EMBER_TRUST_ROOTS=<dev>,<org-internal>` shape).
    let dir = tempdir().expect("tempdir");
    let manifest_path = dir.path().join("manifest.toml");
    let release_sk = SigningKey::from_bytes(&[5u8; 32]);
    let dev_sk = SigningKey::from_bytes(&[6u8; 32]);
    let org_sk = SigningKey::from_bytes(&[7u8; 32]);
    // Manifest signed by org root (the LAST in the trust set after
    // release + dev) — exercises the walk-all-keys path rather than
    // short-circuiting on the first match.
    fixture_signed_manifest(&manifest_path, &org_sk, b"[manifest] = \"v2\"");

    let multi = format!(
        "{},{}",
        hex::encode(dev_sk.verifying_key().to_bytes()),
        hex::encode(org_sk.verifying_key().to_bytes()),
    );
    let mut trust_roots = vec![release_sk.verifying_key()];
    trust_roots.extend(parse_trust_roots(&multi).expect("parse multi-root list"));
    assert_eq!(trust_roots.len(), 3, "trust set has release + dev + org");

    verify_manifest_signature_with_trust_roots(&manifest_path, &trust_roots)
        .expect("org-signed manifest verifies under release + dev + org trust set");
}
