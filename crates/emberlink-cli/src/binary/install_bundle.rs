//! `ember binary install-bundle` — batch-register all cohort-A Construct
//! binaries from a directory into a single signed manifest.
//!
//! Companion to `ember binary install <tool>@<version> --from-path <path>`:
//! the per-binary verb writes one entry at a time without a signature, while
//! `install-bundle` scans a directory for every Cohort-A Construct and, on the
//! canonical host install path, the platform `emberd-rpc-*` sibling required by
//! the bridge provenance gate. It builds the canonical [`BinaryManifest`],
//! signs it with the dev IdentityRoot key from Keychain, and writes both the
//! TOML and its `.toml.sig` sidecar — exactly the shape the daemon's
//! startup-verify gate expects (see
//! `ember_daemon::binary_manifest::verify_manifest_signature_with_trust_roots`).
//!
//! Intended caller: `scripts/dev-refresh-macos-host-install.sh` (after the
//! binary install loop, before the daemon kickstart) and the prod release
//! pipeline in `scripts/release-macos.sh`. Re-running is idempotent — each
//! run rewrites the manifest from disk.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use ed25519_dalek::SigningKey;
use ember_daemon::binary_manifest::{
    BinaryDistributionChannel, BinaryManifest, BinaryManifestEntry, COHORT_A_CONSTRUCTS,
    bundled_install_dir, bundled_runtime_manifest_candidates, write_signed_manifest,
};

use crate::dev::identity_root;

#[derive(Debug, Parser)]
pub struct BinaryInstallBundleArgs {
    /// Directory holding the cohort-A Construct binaries. Defaults to the
    /// canonical bundled-install dir (`/usr/local/lib/ember/binaries`).
    #[arg(long, default_value_os_t = bundled_install_dir())]
    pub from_dir: PathBuf,

    /// Destination TOML path for the signed manifest. The companion `.sig`
    /// sidecar is written alongside (`<manifest_path>.with_extension("toml.sig")`).
    /// Defaults to the bundled system manifest path
    /// (`/usr/local/lib/ember/binaries/manifest.toml`). Noncanonical
    /// manifests require an explicit `--manifest-path`.
    #[arg(long)]
    pub manifest_path: Option<PathBuf>,

    /// Publisher DID stamped onto every entry. Defaults to `did:emberlink`,
    /// the value used for the Ember Systems–signed bundled drop.
    #[arg(long, default_value = "did:emberlink")]
    pub publisher: String,

    /// Version string stamped onto every entry. Bundled Constructs ship as a
    /// set, so one version covers the whole batch.
    #[arg(long, default_value = "0.3.0")]
    pub version: String,

    /// Release/pkgbuild mode: read binaries from this staged filesystem root
    /// while writing manifest absolute paths for the installed host paths
    /// (`/usr/local/...`). This keeps packaged manifests from pinning
    /// temporary pkgroot paths.
    #[arg(long)]
    pub staged_root: Option<PathBuf>,

    /// Sign with a raw 32-byte Ed25519 seed file instead of the operator
    /// Keychain dev IdentityRoot. Intended for release/pkgbuild signing.
    #[arg(long)]
    pub identity_root_keypath: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryInstallBundleOutput {
    pub entries_written: usize,
    pub manifest_path: PathBuf,
    pub trust_root_hex: String,
}

fn default_manifest_path(_home_dir: &Path) -> PathBuf {
    bundled_install_dir().join("manifest.toml")
}

/// Hash `path`'s bytes with blake3 and return the canonical
/// `"blake3:<hex>"` form used in [`BinaryManifestEntry::content_hash`].
fn blake3_of(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let hash = blake3::hash(&bytes);
    Ok(format!("blake3:{}", hex::encode(hash.as_bytes())))
}

struct ManifestCandidate {
    tool_name: &'static str,
    source_path: PathBuf,
    absolute_path: PathBuf,
}

fn staged_source_path(staged_root: &Path, installed_path: &Path) -> Result<PathBuf, String> {
    let relative = installed_path.strip_prefix("/").map_err(|_| {
        format!(
            "staged manifest candidate path must be absolute: {}",
            installed_path.display()
        )
    })?;
    Ok(staged_root.join(relative))
}

fn manifest_candidates(args: &BinaryInstallBundleArgs) -> Result<Vec<ManifestCandidate>, String> {
    let mut candidates = Vec::new();
    if let Some(staged_root) = args.staged_root.as_ref() {
        let installed_dir = bundled_install_dir();
        for (tool, installed_path) in bundled_runtime_manifest_candidates(&installed_dir) {
            candidates.push(ManifestCandidate {
                tool_name: tool,
                source_path: staged_source_path(staged_root, &installed_path)?,
                absolute_path: installed_path,
            });
        }
    } else {
        for (tool, source_path) in bundled_runtime_manifest_candidates(&args.from_dir) {
            let absolute_path = source_path.canonicalize().unwrap_or(source_path.clone());
            candidates.push(ManifestCandidate {
                tool_name: tool,
                source_path,
                absolute_path,
            });
        }
    }
    Ok(candidates)
}

/// Build a [`BinaryManifest`] by scanning `from_dir` for every Cohort-A
/// Construct binary that's present and readable. Tools absent from disk are
/// silently skipped — the daemon's broker only vends tools it finds in the
/// manifest, so a partial install yields a partial manifest, not a hard
/// failure.
fn build_manifest(
    args: &BinaryInstallBundleArgs,
    publisher: &str,
    version: &str,
) -> Result<BinaryManifest, String> {
    let installed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut entries = Vec::new();
    for candidate in manifest_candidates(args)? {
        if !candidate.source_path.exists() {
            continue;
        }
        let content_hash = blake3_of(&candidate.source_path)?;
        entries.push(BinaryManifestEntry {
            tool_name: candidate.tool_name.to_string(),
            version: version.to_string(),
            content_hash,
            absolute_path: candidate.absolute_path,
            installed_at,
            publisher: publisher.to_string(),
            channel: BinaryDistributionChannel::Bundled,
        });
    }
    Ok(BinaryManifest { entries })
}

fn signing_key_from_raw_seed(path: &Path) -> Result<SigningKey, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if bytes.len() < 32 {
        return Err(format!(
            "identity-root-keypath file is too short: {} bytes (need at least 32)",
            bytes.len()
        ));
    }
    let seed: [u8; 32] = bytes[..32]
        .try_into()
        .map_err(|_| "identity-root-keypath seed slice had wrong length".to_string())?;
    Ok(SigningKey::from_bytes(&seed))
}

fn signing_key(args: &BinaryInstallBundleArgs) -> Result<SigningKey, String> {
    if let Some(path) = args.identity_root_keypath.as_ref() {
        return signing_key_from_raw_seed(path);
    }
    identity_root::ensure_dev_identity_root_signing_key()
}

pub fn binary_install_bundle(
    args: &BinaryInstallBundleArgs,
    home_dir: &Path,
) -> Result<BinaryInstallBundleOutput, String> {
    let manifest_path = args
        .manifest_path
        .clone()
        .unwrap_or_else(|| default_manifest_path(home_dir));

    let manifest = build_manifest(args, &args.publisher, &args.version)?;
    if manifest.entries.is_empty() {
        return Err(format!(
            "no cohort-A binaries found under {} — expected at least one of {:?}",
            args.from_dir.display(),
            COHORT_A_CONSTRUCTS,
        ));
    }

    let signing_key = signing_key(args)?;

    write_signed_manifest(&manifest, &signing_key, &manifest_path)
        .map_err(|e| format!("write_signed_manifest({}): {e}", manifest_path.display()))?;

    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
    println!(
        "[binary install-bundle] OK — {} entr{} written to {}",
        manifest.entries.len(),
        if manifest.entries.len() == 1 {
            "y"
        } else {
            "ies"
        },
        manifest_path.display(),
    );
    for entry in &manifest.entries {
        let hash_short = &entry.content_hash[..entry.content_hash.len().min(27)];
        println!(
            "  - {}@{} {} {}",
            entry.tool_name,
            entry.version,
            hash_short,
            entry.absolute_path.display()
        );
    }
    println!("dev IdentityRoot pubkey (use as EMBER_TRUST_ROOTS): {pubkey_hex}");
    Ok(BinaryInstallBundleOutput {
        entries_written: manifest.entries.len(),
        manifest_path,
        trust_root_hex: pubkey_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ember_daemon::binary_manifest::{
        load_manifest, verify_manifest_signature_with_trust_roots,
    };

    fn args_for_from_dir(from_dir: PathBuf) -> BinaryInstallBundleArgs {
        BinaryInstallBundleArgs {
            from_dir,
            manifest_path: None,
            publisher: "did:emberlink".to_string(),
            version: "0.3.0".to_string(),
            staged_root: None,
            identity_root_keypath: None,
        }
    }

    /// Stand up a `from_dir` with three fake Construct binaries, build the
    /// manifest from it, sign with a known key, then re-verify and re-parse
    /// to confirm the on-disk artifact round-trips through the daemon's
    /// verifier.
    #[test]
    fn install_bundle_writes_signed_manifest_for_cohort_a() {
        let dir = tempfile::tempdir().expect("temp");
        let from_dir = dir.path().join("binaries");
        std::fs::create_dir_all(&from_dir).expect("mkdir");
        for tool in COHORT_A_CONSTRUCTS {
            std::fs::write(from_dir.join(tool), format!("fake-{tool}")).expect("fake binary");
        }

        let manifest_path = dir
            .path()
            .join("home")
            .join(".ember")
            .join("binaries")
            .join("manifest.toml");
        let args = args_for_from_dir(from_dir.clone());
        let manifest = build_manifest(&args, "did:emberlink", "0.3.0").expect("manifest");
        assert_eq!(manifest.entries.len(), COHORT_A_CONSTRUCTS.len());

        let sk = SigningKey::from_bytes(&[3u8; 32]);
        write_signed_manifest(&manifest, &sk, &manifest_path).expect("write");

        verify_manifest_signature_with_trust_roots(&manifest_path, &[sk.verifying_key()])
            .expect("verifier must accept");
        let loaded = load_manifest(&manifest_path).expect("parse");
        assert_eq!(loaded.entries.len(), COHORT_A_CONSTRUCTS.len());
        for (expected, got) in COHORT_A_CONSTRUCTS.iter().zip(&loaded.entries) {
            assert_eq!(*expected, got.tool_name);
            assert!(got.content_hash.starts_with("blake3:"));
            assert_eq!(got.channel, BinaryDistributionChannel::Bundled);
            assert_eq!(got.publisher, "did:emberlink");
        }
    }

    #[test]
    fn install_bundle_skips_missing_binaries() {
        let dir = tempfile::tempdir().expect("temp");
        let from_dir = dir.path().join("binaries");
        std::fs::create_dir_all(&from_dir).expect("mkdir");
        // Only one of the three cohort-A tools is present on disk.
        std::fs::write(from_dir.join("ember-gh"), b"fake").expect("fake binary");

        let args = args_for_from_dir(from_dir);
        let manifest = build_manifest(&args, "did:emberlink", "0.3.0").expect("manifest");
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.entries[0].tool_name, "ember-gh");
    }

    #[test]
    fn staged_root_manifest_hashes_pkgroot_but_records_installed_paths() {
        let dir = tempfile::tempdir().expect("temp");
        let staged_root = dir.path().join("pkgroot");
        let source_dir = staged_root.join("usr/local/lib/ember/binaries");
        std::fs::create_dir_all(&source_dir).expect("mkdir");
        std::fs::write(source_dir.join("ember-gh"), b"pkgroot-gh").expect("fake binary");

        let args = BinaryInstallBundleArgs {
            from_dir: PathBuf::from("/ignored/by/staged/root"),
            manifest_path: None,
            publisher: "did:emberlink".to_string(),
            version: "0.3.0-test".to_string(),
            staged_root: Some(staged_root),
            identity_root_keypath: None,
        };

        let manifest = build_manifest(&args, "did:emberlink", "0.3.0-test").expect("manifest");
        assert_eq!(manifest.entries.len(), 1);
        let entry = &manifest.entries[0];
        assert_eq!(entry.tool_name, "ember-gh");
        assert_eq!(
            entry.absolute_path,
            PathBuf::from("/usr/local/lib/ember/binaries/ember-gh")
        );
        assert_eq!(
            entry.content_hash,
            "blake3:".to_string() + &hex::encode(blake3::hash(b"pkgroot-gh").as_bytes())
        );
    }

    #[test]
    fn default_manifest_path_lands_in_bundled_system_dir() {
        let home = PathBuf::from("/home/test-operator");
        let path = default_manifest_path(&home);
        assert_eq!(
            path,
            PathBuf::from("/usr/local/lib/ember/binaries/manifest.toml")
        );
    }
}
