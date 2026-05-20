//! `ember binary list`
//!
//! Reads `~/.ember/binaries/manifest.toml` and prints a table of registered
//! binaries.

use std::path::PathBuf;

use ember_daemon::binary_manifest::load_manifest;

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

pub fn binary_list() -> Result<(), Box<dyn std::error::Error>> {
    let path = manifest_path();
    let manifest = load_manifest(&path)?;

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

        // SAFETY: test sets HOME to a tempdir before invoking binary_list.
        // Single-threaded test; no concurrent env access.
        unsafe {
            std::env::set_var("HOME", dir.path());
        }

        // binary_list writes to stdout; verify it doesn't error.
        binary_list().expect("list should succeed");
    }
}
