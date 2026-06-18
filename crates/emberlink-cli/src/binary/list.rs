//! `ember binary list`
//!
//! Reads the bundled system manifest, or an explicit `--manifest-path`, and
//! prints a table of registered binaries.

use std::path::{Path, PathBuf};

use ember_daemon::binary_manifest::load_manifest;

fn default_manifest_path() -> PathBuf {
    ember_daemon::binary_manifest::bundled_install_dir().join("manifest.toml")
}

pub fn binary_list(manifest_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let manifest_path = manifest_path.unwrap_or_else(default_manifest_path);
    binary_list_at(&manifest_path)
}

pub fn binary_list_at(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = load_manifest(path)?;

    if manifest.entries.is_empty() {
        println!("No binaries registered. Use 'ember binary install' to add one.");
        return Ok(());
    }

    println!(
        "{:<20} {:<12} {:<26} PATH",
        "TOOL_NAME", "VERSION", "CONTENT_HASH"
    );
    println!("{}", "-".repeat(80));

    for entry in &manifest.entries {
        let hash_short = if entry.content_hash.len() > 25 {
            format!("{}...", &entry.content_hash[..25])
        } else {
            entry.content_hash.clone()
        };
        println!(
            "{:<20} {:<12} {:<26} {}",
            entry.tool_name,
            entry.version,
            hash_short,
            entry.absolute_path.display()
        );
    }

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
    fn list_prints_table_header() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_dir = dir.path().join(".ember").join("binaries");
        std::fs::create_dir_all(&manifest_dir).unwrap();
        let manifest_path = manifest_dir.join("manifest.toml");

        let manifest = BinaryManifest {
            entries: vec![BinaryManifestEntry {
                tool_name: "ember-gh".to_string(),
                version: "1.0.0".to_string(),
                content_hash: "blake3:7c2a9f1234567890abcdef".to_string(),
                absolute_path: PathBuf::from("/usr/local/bin/ember-gh"),
                installed_at: 1735689600,
                publisher: "did:emberlink".to_string(),
                channel: BinaryDistributionChannel::Bundled,
            }],
        };
        let toml_out = toml::to_string_pretty(&manifest).unwrap();
        std::fs::write(&manifest_path, toml_out).unwrap();

        // binary_list_at writes to stdout; verify it doesn't error.
        binary_list_at(&manifest_path).expect("list should succeed");
    }

    #[test]
    fn default_manifest_path_lands_in_bundled_system_dir() {
        assert_eq!(
            default_manifest_path(),
            PathBuf::from("/usr/local/lib/ember/binaries/manifest.toml")
        );
    }
}
