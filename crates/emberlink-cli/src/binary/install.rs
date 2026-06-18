//! `ember binary install <tool>@<version> --from-path <path> [--publisher <DID>]`
//!
//! For v1: reads the binary at `--from-path`, computes blake3, writes a new
//! manifest entry to the bundled system manifest unless `--manifest-path` is
//! provided explicitly.

use std::path::{Path, PathBuf};
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

    /// Destination TOML path. Defaults to `/usr/local/lib/ember/binaries/manifest.toml`.
    #[arg(long)]
    pub manifest_path: Option<PathBuf>,
}

fn default_manifest_path() -> PathBuf {
    ember_daemon::binary_manifest::bundled_install_dir().join("manifest.toml")
}

pub fn binary_install(args: &BinaryInstallArgs) -> Result<(), Box<dyn std::error::Error>> {
    let manifest_path = args
        .manifest_path
        .clone()
        .unwrap_or_else(default_manifest_path);
    binary_install_at(args, &manifest_path)
}

pub fn binary_install_at(
    args: &BinaryInstallArgs,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let (tool_name, version) = args
        .tool_at_version
        .split_once('@')
        .ok_or_else(|| format!("expected <tool>@<version>, got '{}'", args.tool_at_version))?;

    let binary_bytes = std::fs::read(&args.from_path)
        .map_err(|e| format!("cannot read {}: {e}", args.from_path.display()))?;

    let hash = blake3::hash(&binary_bytes);
    let content_hash = format!("blake3:{}", hex::encode(hash.as_bytes()));

    let absolute_path = args
        .from_path
        .canonicalize()
        .unwrap_or_else(|_| args.from_path.clone());

    let installed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

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
            manifest_path: None,
        };

        let manifest_path = home_dir
            .path()
            .join(".ember")
            .join("binaries")
            .join("manifest.toml");
        binary_install_at(&args, &manifest_path).expect("install should succeed");
        assert!(manifest_path.exists(), "manifest.toml must be created");

        let manifest = load_manifest(&manifest_path).expect("manifest must parse");
        assert_eq!(manifest.entries.len(), 1);
        let entry = &manifest.entries[0];
        assert_eq!(entry.tool_name, "ember-gh");
        assert_eq!(entry.version, "1.0.0");
        assert!(
            entry.content_hash.starts_with("blake3:"),
            "content_hash must have blake3: prefix"
        );

        // Verify the hash matches blake3 of the binary.
        let expected = format!(
            "blake3:{}",
            hex::encode(blake3::hash(b"fake-binary").as_bytes())
        );
        assert_eq!(entry.content_hash, expected);
    }

    #[test]
    fn default_manifest_path_lands_in_bundled_system_dir() {
        assert_eq!(
            default_manifest_path(),
            PathBuf::from("/usr/local/lib/ember/binaries/manifest.toml")
        );
    }
}
