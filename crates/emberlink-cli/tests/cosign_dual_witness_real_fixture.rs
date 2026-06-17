use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use emberlink_cli::install::verify::{VerifyError, verify_manifest_dual_witness};

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cosign");

fn fixture_bytes(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(FIXTURE_DIR).join(name)).expect("fixture should be readable")
}

fn identity_root_fixture() -> (SigningKey, VerifyingKey) {
    let seed = [91u8; 32];
    let signing = SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

#[test]
fn cosign_dual_witness_real_fixture_integration_accepts_fixture() {
    // Anchor: cosign_dual_witness_real_fixture_integration.
    let manifest = fixture_bytes("real-rekor-artifact.txt");
    let cosign_bundle = fixture_bytes("real-rekor.cosign-bundle.json");
    let (identity_signing, identity_key) = identity_root_fixture();
    let identity_sig = identity_signing.sign(&manifest);

    verify_manifest_dual_witness(
        &manifest,
        &cosign_bundle,
        &identity_sig.to_bytes(),
        &identity_key,
    )
    .expect("real cosign bundle + IdentityRoot fixture should verify");
}

#[test]
fn cosign_dual_witness_real_fixture_integration_rejects_tampered_manifest() {
    let mut manifest = fixture_bytes("real-rekor-artifact.txt");
    manifest[0] = b'S';
    let cosign_bundle = fixture_bytes("real-rekor.cosign-bundle.json");
    let (identity_signing, identity_key) = identity_root_fixture();
    let identity_sig = identity_signing.sign(&manifest);

    let err = verify_manifest_dual_witness(
        &manifest,
        &cosign_bundle,
        &identity_sig.to_bytes(),
        &identity_key,
    )
    .expect_err("tampered manifest should fail before acceptance");
    assert!(
        matches!(
            err,
            VerifyError::BadSignature {
                ref publisher_did,
                ..
            } if publisher_did == "sigstore/keyless"
        ),
        "expected BadSignature(sigstore/keyless), got {err:?}"
    );
}

#[test]
fn cosign_dual_witness_real_fixture_integration_rejects_no_rekor_bundle() {
    let manifest = fixture_bytes("manifest.json");
    let cosign_bundle = fixture_bytes("manifest.cosign-bundle.json");
    let (identity_signing, identity_key) = identity_root_fixture();
    let identity_sig = identity_signing.sign(&manifest);

    let err = verify_manifest_dual_witness(
        &manifest,
        &cosign_bundle,
        &identity_sig.to_bytes(),
        &identity_key,
    )
    .expect_err("no-Rekor bundle should fail closed");
    assert!(
        matches!(
            err,
            VerifyError::BadSignature {
                ref publisher_did,
                ..
            } if publisher_did == "sigstore/keyless"
        ),
        "expected BadSignature(sigstore/keyless), got {err:?}"
    );
}
