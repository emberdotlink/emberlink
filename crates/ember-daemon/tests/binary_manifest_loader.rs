//! T2 integration tests for the binary-manifest loader, signer, and verifier
//! surface (`crates/ember-daemon/src/binary_manifest.rs`).
//!
//! These tests were previously in-tree `#[cfg(test)] mod tests { ... }` blocks
//! that imported `tempfile::NamedTempFile` / `tempfile::tempdir`. The T1 lint
//! (`lint-t1-tier.sh`) catches that as a T1→T2 drift; the right home for tests
//! that legitimately need filesystem I/O against the signed-manifest reader is
//! a T2 integration file like this one.
//!
//! Refiled per `AUDIT-V030-T1-BASELINE-DRAIN`. Tests cover:
//! - TOML round-trip via `load_manifest`
//! - sidecar-signature verifier happy / tampered / missing-sidecar paths
//! - trust-root SET parameterization (release-only / release+dev / release+N /
//!   empty-set fail-loud)
//! - `write_signed_manifest` round-trip + tamper detection
//! - `channel` serde default for legacy manifests written before the field
//!   existed
//!
//! Internal-only T1 tests (parser unit tests for `parse_trust_roots`,
//! `parse_tracer_pid`, lookup helpers, etc.) remain in-tree under
//! `src/binary_manifest.rs`. This file is only for tests that needed I/O.
//!
//! Anchor: t1_tier_baseline_drained
//!
//! CLASSIFICATION: PUBLIC

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ember_daemon::binary_manifest::{
    BinaryDistributionChannel, BinaryManifest, BinaryManifestEntry, VerifyError, load_manifest,
    verify_manifest_signature, verify_manifest_signature_with_trust_roots, write_signed_manifest,
};
use std::io::Write;
use std::path::PathBuf;
use tempfile::{NamedTempFile, tempdir};

/// Build a signed manifest at `path` using `signing_key`. Returns nothing; the
/// caller can read back the file (and tamper with it) to test verifier
/// behaviour.
fn fixture_signed_manifest(
    path: &std::path::Path,
    signing_key: &SigningKey,
    manifest_bytes: &[u8],
) {
    std::fs::write(path, manifest_bytes).expect("write manifest");
    let sig = signing_key.sign(manifest_bytes);
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
fn load_manifest_parses_toml() {
    let mut f = NamedTempFile::new().expect("temp");
    write!(
        f,
        r#"
[[entries]]
tool_name = "ember-gh"
version = "1.0.0"
content_hash = "blake3:abc123"
absolute_path = "/usr/local/bin/ember-gh"
installed_at = 1735689600
publisher = "did:emberlink"
"#
    )
    .expect("write");
    let m = load_manifest(f.path()).expect("parse");
    assert_eq!(m.entries.len(), 1);
    assert_eq!(m.entries[0].tool_name, "ember-gh");
}

#[test]
fn verify_manifest_signature_missing_sidecar_returns_err() {
    let mut f = NamedTempFile::new().expect("temp");
    f.write_all(b"[some] = \"manifest\"").expect("write");

    let sk = SigningKey::from_bytes(&[1u8; 32]);
    let pk = sk.verifying_key();

    let result = verify_manifest_signature(f.path(), &pk);
    assert!(matches!(result, Err(VerifyError::MissingSidecar(_))));
}

#[test]
fn verify_manifest_signature_happy_path() {
    let dir = tempdir().expect("temp");
    let manifest_path = dir.path().join("manifest.toml");
    let manifest_bytes = b"[some] = \"manifest\"";
    std::fs::write(&manifest_path, manifest_bytes).expect("write manifest");

    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let pk = sk.verifying_key();
    let sig = sk.sign(manifest_bytes);

    let sidecar = serde_json::json!({
        "schema_version": 1,
        "signature": format!("ed25519:{}", base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())),
        "signature_alg": "ed25519",
    });
    let sidecar_path = manifest_path.with_extension("toml.sig");
    std::fs::write(&sidecar_path, sidecar.to_string()).expect("write sidecar");

    verify_manifest_signature(&manifest_path, &pk).expect("should verify");
}

#[test]
fn verify_manifest_signature_tampered_returns_err() {
    let dir = tempdir().expect("temp");
    let manifest_path = dir.path().join("manifest.toml");
    let original_bytes = b"[orig] = \"v1\"";
    std::fs::write(&manifest_path, original_bytes).expect("write manifest");

    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let pk = sk.verifying_key();
    let sig = sk.sign(original_bytes);

    let sidecar = serde_json::json!({
        "schema_version": 1,
        "signature": format!("ed25519:{}", base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())),
        "signature_alg": "ed25519",
    });
    let sidecar_path = manifest_path.with_extension("toml.sig");
    std::fs::write(&sidecar_path, sidecar.to_string()).expect("write sidecar");

    // Tamper the manifest after signing.
    std::fs::write(&manifest_path, b"[orig] = \"v2-tampered\"").expect("rewrite");

    let result = verify_manifest_signature(&manifest_path, &pk);
    assert!(matches!(result, Err(VerifyError::SignatureMismatch)));
}

// -----------------------------------------------------------------
// ADR 157 §Component 1 — trust-root SET parameterization tests.
// Refiled to T2 because the verifier reads the sidecar from disk.
// Property axis: release-only / release+dev / release+N / empty.
// -----------------------------------------------------------------

#[test]
fn verify_with_trust_roots_release_only_accepts_release_signed() {
    // Prod-shape trust set (length 1) — release-signed manifest verifies.
    let dir = tempdir().expect("temp");
    let manifest_path = dir.path().join("manifest.toml");
    let release_sk = SigningKey::from_bytes(&[1u8; 32]);
    fixture_signed_manifest(&manifest_path, &release_sk, b"[some] = \"manifest\"");

    let trust_roots = vec![release_sk.verifying_key()];
    verify_manifest_signature_with_trust_roots(&manifest_path, &trust_roots)
        .expect("release-signed verifies under release-only trust set");
}

#[test]
fn verify_with_trust_roots_release_only_rejects_dev_signed() {
    // Prod-shape trust set (length 1) — dev-signed manifest rejected.
    // This is the load-bearing invariant for ADR 157 §Component 1:
    // when `EMBER_TRUST_ROOTS` is unset the daemon trusts ONLY the
    // compiled-in release root.
    let dir = tempdir().expect("temp");
    let manifest_path = dir.path().join("manifest.toml");
    let release_sk = SigningKey::from_bytes(&[1u8; 32]);
    let dev_sk = SigningKey::from_bytes(&[2u8; 32]);
    fixture_signed_manifest(&manifest_path, &dev_sk, b"[some] = \"manifest\"");

    let trust_roots = vec![release_sk.verifying_key()];
    let result = verify_manifest_signature_with_trust_roots(&manifest_path, &trust_roots);
    assert!(
        matches!(result, Err(VerifyError::SignatureMismatch)),
        "dev-signed manifest must NOT verify under release-only trust set; got {result:?}"
    );
}

#[test]
fn verify_with_trust_roots_release_plus_dev_accepts_dev_signed() {
    // Dev-shape trust set (length 2) — dev-signed manifest verifies
    // when the dev root is added alongside the release root.
    let dir = tempdir().expect("temp");
    let manifest_path = dir.path().join("manifest.toml");
    let release_sk = SigningKey::from_bytes(&[1u8; 32]);
    let dev_sk = SigningKey::from_bytes(&[2u8; 32]);
    fixture_signed_manifest(&manifest_path, &dev_sk, b"[some] = \"manifest\"");

    let trust_roots = vec![release_sk.verifying_key(), dev_sk.verifying_key()];
    verify_manifest_signature_with_trust_roots(&manifest_path, &trust_roots)
        .expect("dev-signed verifies when dev root added to trust set");
}

#[test]
fn verify_with_trust_roots_release_plus_n_accepts_internal_signed() {
    // Org-policy-shape trust set (length 3) — internal-endorsement
    // root added without removing release. Reflects ADR 157's
    // `EMBER_TRUST_ROOTS=<dev>,<org-internal>` example.
    let dir = tempdir().expect("temp");
    let manifest_path = dir.path().join("manifest.toml");
    let release_sk = SigningKey::from_bytes(&[1u8; 32]);
    let dev_sk = SigningKey::from_bytes(&[2u8; 32]);
    let org_sk = SigningKey::from_bytes(&[3u8; 32]);
    fixture_signed_manifest(&manifest_path, &org_sk, b"[some] = \"manifest\"");

    let trust_roots = vec![
        release_sk.verifying_key(),
        dev_sk.verifying_key(),
        org_sk.verifying_key(),
    ];
    verify_manifest_signature_with_trust_roots(&manifest_path, &trust_roots)
        .expect("org-internal-signed verifies under release+dev+org trust set");
}

#[test]
fn verify_with_trust_roots_empty_set_fails_loud() {
    // Defense — empty trust set is rejected at the API boundary
    // rather than short-circuiting to Ok via the for-loop's zero
    // iterations.
    let dir = tempdir().expect("temp");
    let manifest_path = dir.path().join("manifest.toml");
    let release_sk = SigningKey::from_bytes(&[1u8; 32]);
    fixture_signed_manifest(&manifest_path, &release_sk, b"[some] = \"manifest\"");

    let trust_roots: Vec<VerifyingKey> = vec![];
    let result = verify_manifest_signature_with_trust_roots(&manifest_path, &trust_roots);
    assert!(
        matches!(result, Err(VerifyError::TrustRootsEmpty)),
        "empty trust set must surface TrustRootsEmpty; got {result:?}"
    );
}

#[test]
fn write_signed_manifest_round_trips_through_verifier() {
    // The writer must produce exactly what the verifier expects: a TOML
    // body whose bytes the signature covers, plus a JSON sidecar in the
    // ManifestSidecar shape (schema_version=1, ed25519:base64 prefix,
    // signature_alg=ed25519). Round-trip through
    // verify_manifest_signature_with_trust_roots is the canonical test.
    let dir = tempdir().expect("temp");
    let manifest_path = dir.path().join("subdir").join("manifest.toml");

    let manifest = BinaryManifest {
        entries: vec![BinaryManifestEntry {
            tool_name: "ember-gh".to_string(),
            version: "0.3.0".to_string(),
            content_hash: "blake3:deadbeef".to_string(),
            absolute_path: PathBuf::from("/usr/local/lib/ember/binaries/ember-gh"),
            installed_at: 1735689600,
            publisher: "did:emberlink".to_string(),
            channel: BinaryDistributionChannel::Bundled,
        }],
    };

    let sk = SigningKey::from_bytes(&[9u8; 32]);
    write_signed_manifest(&manifest, &sk, &manifest_path).expect("write must succeed");

    assert!(manifest_path.exists(), "manifest.toml must exist");
    let sidecar_path = manifest_path.with_extension("toml.sig");
    assert!(sidecar_path.exists(), "manifest.toml.sig must exist");

    verify_manifest_signature_with_trust_roots(&manifest_path, &[sk.verifying_key()])
        .expect("verifier must accept the just-written manifest");

    // Re-load and confirm the entries survive the TOML round-trip.
    let loaded = load_manifest(&manifest_path).expect("parse");
    assert_eq!(loaded.entries.len(), 1);
    assert_eq!(loaded.entries[0].tool_name, "ember-gh");
    assert_eq!(
        loaded.entries[0].channel,
        BinaryDistributionChannel::Bundled
    );
}

#[test]
fn write_signed_manifest_rejects_tampered_body() {
    // Defense-in-depth: if anything modifies the manifest bytes after the
    // write step, the sidecar must fail verification. This protects
    // against a future call site accidentally writing both files but
    // mutating the TOML between sign and write.
    let dir = tempdir().expect("temp");
    let manifest_path = dir.path().join("manifest.toml");
    let manifest = BinaryManifest::default();
    let sk = SigningKey::from_bytes(&[10u8; 32]);
    write_signed_manifest(&manifest, &sk, &manifest_path).expect("write");

    std::fs::write(&manifest_path, b"# tampered\n").expect("rewrite");
    let result = verify_manifest_signature_with_trust_roots(&manifest_path, &[sk.verifying_key()]);
    assert!(
        matches!(result, Err(VerifyError::SignatureMismatch)),
        "tampered body must surface SignatureMismatch; got {result:?}"
    );
}

#[test]
fn channel_defaults_to_bundled_for_legacy_manifests() {
    // Pre-channel manifests written by older daemons omit the
    // `channel` field; serde default must materialize Bundled so
    // the v0.3.0 daemon can keep reading them.
    let mut f = NamedTempFile::new().expect("temp");
    write!(
        f,
        r#"
[[entries]]
tool_name = "ember-gh"
version = "1.0.0"
content_hash = "blake3:abc123"
absolute_path = "/usr/local/lib/ember/binaries/ember-gh"
installed_at = 1735689600
publisher = "did:emberlink"
"#
    )
    .expect("write");
    let m = load_manifest(f.path()).expect("parse");
    assert_eq!(m.entries[0].channel, BinaryDistributionChannel::Bundled);
}
