//! `ember binary remove <tool>@<version>`
//!
//! Removes a manifest entry by (tool_name, version). Does not check for
//! construct.toml pins (deferred follow-up).

use std::path::PathBuf;

use clap::Parser;
use ember_daemon::binary_manifest::load_manifest;

#[derive(Debug, Parser)]
pub struct BinaryRemoveArgs {
    /// Tool name and version in `<name>@<version>` format (e.g. `ember-gh@1.0.0`).
    pub tool_at_version: String,
}

fn manifest_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join(".ember")
            .join("binaries")
            .join("manifest.toml")
    } else {
        PathBuf::from("/usr/local/lib/ember/binaries/manifest.toml")
    }
}

pub fn binary_remove(args: &BinaryRemoveArgs) -> Result<(), Box<dyn std::error::Error>> {
    binary_remove_at(args, &manifest_path())
}

/// Variant of [`binary_remove`] that takes the manifest path explicitly
/// rather than deriving it from `$HOME`. Production code uses
/// [`binary_remove`]; tests use this entry point with a tempdir-rooted
/// path so they don't have to mutate the process-global `HOME` env var
/// (which races with every test that reads HOME-derived state under the
/// cargo parallel runner).
pub fn binary_remove_at(
    args: &BinaryRemoveArgs,
    path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let (tool_name, version) = args
        .tool_at_version
        .split_once('@')
        .ok_or_else(|| format!("expected <tool>@<version>, got '{}'", args.tool_at_version))?;

    let mut manifest = load_manifest(path)?;

    let before = manifest.entries.len();
    manifest
        .entries
        .retain(|e| !(e.tool_name == tool_name && e.version == version));
    let after = manifest.entries.len();

    if before == after {
        return Err(format!("no entry found for {}@{}", tool_name, version).into());
    }

    // WARN: did not check for construct.toml pins
    println!("# WARN: did not check for construct.toml pins");

    let toml_out = toml::to_string_pretty(&manifest)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, toml_out)?;

    println!(
        "[binary remove] OK — {}@{} removed from {}",
        tool_name,
        version,
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ember_daemon::binary_manifest::{
        BinaryDistributionChannel, BinaryManifest, BinaryManifestEntry,
    };
    use std::path::PathBuf;

    #[test]
    fn remove_drops_entry_from_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_dir = dir.path().join(".ember").join("binaries");
        std::fs::create_dir_all(&manifest_dir).unwrap();
        let manifest_toml = manifest_dir.join("manifest.toml");

        let manifest = BinaryManifest {
            entries: vec![BinaryManifestEntry {
                tool_name: "ember-gh".to_string(),
                version: "1.0.0".to_string(),
                content_hash: "blake3:abc123".to_string(),
                absolute_path: PathBuf::from("/usr/local/bin/ember-gh"),
                installed_at: 1735689600,
                publisher: "did:emberlink".to_string(),
                channel: BinaryDistributionChannel::Bundled,
            }],
        };
        std::fs::write(&manifest_toml, toml::to_string_pretty(&manifest).unwrap()).unwrap();

        let args = BinaryRemoveArgs {
            tool_at_version: "ember-gh@1.0.0".to_string(),
        };

        // Use the path-explicit variant so the test doesn't mutate
        // the process-global HOME env var. Mutating HOME would race
        // every test that reads HOME-derived state under the cargo
        // parallel runner (the previous version of this test
        // intermittently failed in workspace test sweeps).
        binary_remove_at(&args, &manifest_toml).expect("remove should succeed");

        let updated = load_manifest(&manifest_toml).expect("manifest must parse after remove");
        assert!(
            updated.entries.is_empty(),
            "manifest must be empty after removing the only entry"
        );
    }
}
