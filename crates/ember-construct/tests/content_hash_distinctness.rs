//! Integration test: each of the 15 [[bin]] targets must hash to a distinct
//! blake3 content_hash. This is the load-bearing trust invariant per ADR 125 §2
//! and ADR 124 §1 — if two binaries share a content_hash, per-vendor WoT trust
//! delegation collapses to all-or-nothing.
//!
//! The test builds all 15 bins in release mode, reads the output bytes, and
//! asserts `HashSet<hash>` cardinality equals 15.

use std::collections::HashSet;
use std::process::Command;

/// Vendor names matching the 15 [[bin]] targets.
const VENDORS: &[&str] = &[
    "aws",
    "az",
    "gcloud",
    "vercel",
    "wrangler",
    "gh",
    "git",
    "docker",
    "kubectl",
    "pulumi",
    "terraform",
    "tofu",
    "flyctl",
    "npm",
    "okta",
];

#[test]
fn content_hash_distinctness() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root");

    let status = Command::new("cargo")
        .args(["build", "--release", "--bins", "-p", "ember-construct"])
        .current_dir(workspace_root)
        .status()
        .expect("cargo build --release --bins -p ember-construct");
    assert!(status.success(), "cargo build --release --bins failed");

    let release_dir = workspace_root.join("target").join("release");

    let mut hashes: HashSet<String> = HashSet::new();
    for vendor in VENDORS {
        let bin_path = release_dir.join(format!("ember-{vendor}"));
        assert!(
            bin_path.exists(),
            "binary not found: {} — expected at {}",
            vendor,
            bin_path.display()
        );
        let bytes = std::fs::read(&bin_path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", bin_path.display()));
        let hash = blake3::hash(&bytes);
        let hex = format!("blake3:{}", hash.to_hex());
        hashes.insert(hex);
    }

    assert_eq!(
        hashes.len(),
        VENDORS.len(),
        "content_hash cardinality {} != {} — some binaries are identical (per-vendor trust scoping broken)",
        hashes.len(),
        VENDORS.len()
    );
}
