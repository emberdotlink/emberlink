//! `ember binary install <tool>@<version> --from-path <path> [--publisher <DID>]`
//!
//! For v1: reads the binary at `--from-path`, computes blake3, writes a new
//! manifest entry to `~/.ember/binaries/manifest.toml`.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use ember_daemon::binary_manifest::{
    BinaryDistributionChannel, BinaryManifestEntry, load_manifest,
};

#[derive(Debug, Parser)]
pub struct BinaryInstallArgs {
    /// Tool name and version in `<name>@<version>` format (e.g. `ember-gh@1.0.0`).
    pub tool_at_version: String,

    /// Path to the binary to register.
    #[arg(long)]
    pub from_path: PathBuf,

    /// Publisher DID (defaults to "did:unknown").
    #[arg(long, default_value = "did:unknown")]
    pub publisher: String,
}

fn manifest_path(home_dir: &std::path::Path) -> PathBuf {
    home_dir.join(".ember").join("binaries").join("manifest.toml")
}

pub fn binary_install(args: &BinaryInstallArgs, home_dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let (tool_name, version) = args
        .tool_at_version
        .split_once('@')
        .ok_or_else(|| format!("expected <tool>@<version>, got '{}'", args.tool_at_version))?;

    let binary_bytes = std::fs::read(&args.from_path)
        .map_err(|e| format!("cannot read {}: {e}", args.from_path.display()))?;

    let hash = blake3::hash(&binary_bytes);
    let content_hash = format!("blake3:{}", hex::encode(hash.as_bytes()));

    let absolute_path = args.from_path.canonicalize().unwrap_or_else(|_| args.from_path.clone());

    let installed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let path = manifest_path(home_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut manifest = load_manifest(&path)?;

    manifest.entries.push(BinaryManifestEntry {
        tool_name: tool_name.to_string(),
        version: version.to_string(),
        content_hash: content_hash.clone(),
        absolute_path,
        installed_at,
        publisher: args.publisher.clone(),
        // v0.3.0: `ember binary install --from-path` is the local
        // bundled-install path used by the release pipeline + tests.
        // The dynamic-install (`InstallOnDemand`) channel is the v0.4
        // surface and is gated separately.
        channel: BinaryDistributionChannel::Bundled,
    });

    let toml_out = toml::to_string_pretty(&manifest)?;
    std::fs::write(&path, toml_out)?;

    println!(
        "[binary install] OK — {}@{} content_hash={} written to {}",
        tool_name,
        version,
        &content_hash[..std::cmp::min(content_hash.len(), 20)],
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_writes_manifest_entry() {
        let dir = tempfile::tempdir().unwrap();

        // Write a fake binary.
        let bin_path = dir.path().join("ember-gh");
        std::fs::write(&bin_path, b"fake-binary").unwrap();

        // Use a dedicated tempdir as the home directory; no global env mutation needed.
        let home_dir = tempfile::tempdir().unwrap();

        let args = BinaryInstallArgs {
            tool_at_version: "ember-gh@1.0.0".to_string(),
            from_path: bin_path.clone(),
            publisher: "did:emberlink".to_string(),
        };

        binary_install(&args, home_dir.path()).expect("install should succeed");

        let manifest_path = home_dir.path().join(".ember").join("binaries").join("manifest.toml");
        assert!(manifest_path.exists(), "manifest.toml must be created");

        let manifest = load_manifest(&manifest_path).expect("manifest must parse");
        assert_eq!(manifest.entries.len(), 1);
        let entry = &manifest.entries[0];
        assert_eq!(entry.tool_name, "ember-gh");
        assert_eq!(entry.version, "1.0.0");
        assert!(entry.content_hash.starts_with("blake3:"), "content_hash must have blake3: prefix");

        // Verify the hash matches blake3 of the binary.
        let expected = format!("blake3:{}", hex::encode(blake3::hash(b"fake-binary").as_bytes()));
        assert_eq!(entry.content_hash, expected);
    }
}
