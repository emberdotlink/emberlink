//! Binary manifest types — content-hash-pinned binary discovery per design §7.
//!
//! The daemon's `~/.ember/binaries/manifest.toml` (per-user) or
//! `/usr/local/lib/ember/binaries/manifest.toml` (system) binds
//! (tool_name, version) → (absolute_path, blake3 content_hash).
//! `verify_binary_pin` (in `broker_handler.rs`) consumes this on every
//! `broker_exec` call and refuses execution on hash mismatch.
//!
//! ## Binary distribution channel (design §7 v0.3.0)
//!
//! v0.3.0 ships **Option A — bundled-with-daemon**: the cohort-A
//! Constructs ([`COHORT_A_CONSTRUCTS`]) ride inside the `emberd` release
//! artifact and land at the canonical bundled-install dir
//! ([`bundled_install_dir`]). Pre-vetted; signed by Ember Systems'
//! IdentityRoot — same trust boundary as the daemon itself. The
//! [`BinaryDistributionChannel`] enum names the choice; the manifest
//! tags each entry with the channel that produced it. Option B
//! (`InstallOnDemand`, `ember binary install <tool>@<version>` from a
//! per-publisher mirror) is deferred to v0.4 — see design §7
//! "Binary distribution channel" amendment.
//!
//! Sibling tasks (decomposed under T-CONSTRUCT-PATH-PINNING parent):
//! - T-CONSTRUCT-PATH-PINNING-CLI: `ember binary install/list/update/remove`
//! - T-CONSTRUCT-PATH-PINNING-STARTUP-VERIFY: manifest signature gate at daemon startup
//! - T-CONSTRUCT-BINARY-DISTRIBUTION-CHANNEL: the v0.3.0 channel decision (this file)

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Cohort-A Construct artifact names per design §"Cohort-A bundled
/// Constructs". These are the binaries the v0.3.0 release pipeline
/// pre-bundles inside `emberd`'s artifact and the daemon discovers
/// from [`bundled_install_dir`] at startup. Order is stable for
/// release-tooling determinism.
pub const COHORT_A_CONSTRUCTS: &[&str] = &[
    "ember-git",
    "ember-gh",
    "ember-kubectl",
    "ember-npm",
    "ember-docker",
    "ember-wrangler",
    "ember-pulumi",
];

/// Where the v0.3.0 release pipeline lays down bundled Construct
/// binaries on disk. The daemon scans this directory at startup +
/// records the entries it finds into the runtime manifest with
/// [`BinaryDistributionChannel::Bundled`].
///
/// Matches design §7 manifest-shape `absolute_path` examples
/// (`/usr/local/lib/ember/binaries/<tool>-<version>`).
pub fn bundled_install_dir() -> PathBuf {
    PathBuf::from("/usr/local/lib/ember/binaries")
}

/// Binary distribution channel — names *where* a pinned binary came
/// from, per design §7 "binary distribution channel" amendment.
///
/// Recorded per-entry on the manifest so the daemon's audit chain can
/// surface "this `gh` binary shipped inside `emberd` v0.3.0" vs
/// "this `kubectl` was fetched on demand by `ember binary install`".
/// v0.3.0 only emits [`Bundled`](Self::Bundled); [`InstallOnDemand`](Self::InstallOnDemand)
/// is the v0.4 follow-up surface and is parsed-but-rejected at startup
/// for v0.3.0 (defensive — refuses to vend creds against a binary that
/// arrived through a channel the current daemon doesn't yet trust).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryDistributionChannel {
    /// Cohort-A: shipped inside the `emberd` release artifact. Signed
    /// by Ember Systems' IdentityRoot. Discovered from
    /// [`bundled_install_dir`] at daemon startup.
    Bundled,
    /// v0.4: `ember binary install <tool>@<version>` fetches from a
    /// per-publisher GitHub release or an ember-managed mirror. Each
    /// entry carries its own publisher DID; the daemon validates the
    /// publisher's signature against a per-publisher trust delegation
    /// recorded in the daemon's WoT graph (per design).
    InstallOnDemand,
}

impl Default for BinaryDistributionChannel {
    fn default() -> Self {
        Self::Bundled
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryManifestEntry {
    pub tool_name: String,
    pub version: String,
    /// blake3 hex-encoded with "blake3:" prefix.
    pub content_hash: String,
    pub absolute_path: PathBuf,
    /// Unix epoch seconds.
    pub installed_at: i64,
    /// Publisher DID (e.g. "did:ember-systems").
    pub publisher: String,
    /// Distribution channel that landed this entry on disk. Per ADR
    /// 124 §7 "binary distribution channel" amendment. Defaults to
    /// [`BinaryDistributionChannel::Bundled`] for back-compat with
    /// pre-channel manifests written by older daemons.
    #[serde(default)]
    pub channel: BinaryDistributionChannel,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BinaryManifest {
    #[serde(default)]
    pub entries: Vec<BinaryManifestEntry>,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml parse: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("missing required field: {0}")]
    MissingField(String),
}

/// Load a manifest from a TOML file path. Returns an empty manifest if
/// the file doesn't exist (caller decides whether absence is fatal).
pub fn load_manifest(path: &Path) -> Result<BinaryManifest, ManifestError> {
    if !path.exists() {
        return Ok(BinaryManifest::default());
    }
    let bytes = std::fs::read(path)?;
    let s = std::str::from_utf8(&bytes)
        .map_err(|e| ManifestError::MissingField(format!("not utf8: {e}")))?;
    let manifest: BinaryManifest = toml::from_str(s)?;
    Ok(manifest)
}

/// Lookup error surfaced by [`lookup_construct`].
#[derive(Debug, thiserror::Error)]
pub enum LookupError {
    /// No manifest entry matched the given construct name.
    #[error("construct '{0}' not found in manifest")]
    NotFound(String),
    /// v0.3.0 ships only [`BinaryDistributionChannel::Bundled`]; an
    /// entry with [`BinaryDistributionChannel::InstallOnDemand`] is
    /// rejected defensively until v0.4 lands the dynamic-install
    /// signing pipeline.
    #[error("construct '{name}' uses unsupported channel {channel:?} in v0.3.0")]
    UnsupportedChannel {
        name: String,
        channel: BinaryDistributionChannel,
    },
}

/// Public lookup entry point — bind a Construct artifact name (e.g.
/// `"ember-gh"`) to its manifest entry. Per design §7 "binary
/// distribution channel" v0.3.0: only [`BinaryDistributionChannel::Bundled`]
/// entries are vendable. The companion verify step is
/// [`crate::broker::handler::verify_binary_pin`] which re-hashes the
/// on-disk bytes immediately before `execve` (TOCTOU window
/// minimization).
///
/// Callers compose:
///   1. `lookup_construct(&manifest, "ember-gh")` — manifest binding
///   2. `verify_binary_pin(&manifest, &entry.tool_name)` — content-hash check
///   3. daemon spawns the resolved path as supervisor (design §1 step 4)
pub fn lookup_construct<'a>(
    manifest: &'a BinaryManifest,
    name: &str,
) -> Result<&'a BinaryManifestEntry, LookupError> {
    let entry = manifest
        .entries
        .iter()
        .find(|e| e.tool_name == name)
        .ok_or_else(|| LookupError::NotFound(name.to_string()))?;

    match entry.channel {
        BinaryDistributionChannel::Bundled => Ok(entry),
        ch @ BinaryDistributionChannel::InstallOnDemand => Err(LookupError::UnsupportedChannel {
            name: name.to_string(),
            channel: ch,
        }),
    }
}

/// Returns true iff `name` is one of [`COHORT_A_CONSTRUCTS`]. Used by
/// the bundled-install discovery path to filter the install-dir scan
/// to known artifacts (defense against a stray binary in
/// [`bundled_install_dir`] being treated as a Construct).
pub fn is_cohort_a_construct(name: &str) -> bool {
    COHORT_A_CONSTRUCTS.iter().any(|c| *c == name)
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("missing sidecar at {0}")]
    MissingSidecar(String),
    #[error("sidecar parse: {0}")]
    SidecarParse(String),
    #[error("manifest signature mismatch")]
    SignatureMismatch,
    #[error("invalid pubkey: {0}")]
    InvalidPubkey(String),
    #[error("invalid signature bytes: {0}")]
    InvalidSignature(String),
    #[error("io: {0}")]
    Io(String),
    #[error("base64: {0}")]
    Base64(String),
}

/// Sidecar JSON envelope for the binary manifest. Mirrors the Construct
/// sidecar shape (#1819): schema_version + ed25519 signature over the
/// canonical TOML bytes of the manifest file. The signature is computed
/// at install time by `ember binary install` (sibling task) using the
/// daemon's IdentityRoot.
#[derive(Debug, serde::Deserialize)]
pub struct ManifestSidecar {
    pub schema_version: u32,
    pub signature: String,     // "ed25519:base64..." — strip prefix before decode
    pub signature_alg: String, // must be "ed25519"
}

/// Verify that the manifest at `manifest_path` is signed by the daemon's
/// IdentityRoot. Reads `<manifest_path>.sig` for the sidecar JSON,
/// Ed25519-verifies the signature against `root_pubkey` over the raw
/// bytes of the manifest TOML.
pub fn verify_manifest_signature(
    manifest_path: &Path,
    root_pubkey: &VerifyingKey,
) -> Result<(), VerifyError> {
    let sidecar_path = manifest_path.with_extension("toml.sig");
    if !sidecar_path.exists() {
        return Err(VerifyError::MissingSidecar(
            sidecar_path.display().to_string(),
        ));
    }

    let sidecar_bytes = std::fs::read(&sidecar_path).map_err(|e| VerifyError::Io(e.to_string()))?;
    let sidecar: ManifestSidecar = serde_json::from_slice(&sidecar_bytes)
        .map_err(|e| VerifyError::SidecarParse(e.to_string()))?;

    if sidecar.schema_version != 1 {
        return Err(VerifyError::SidecarParse(format!(
            "unsupported schema_version: {}",
            sidecar.schema_version
        )));
    }
    if sidecar.signature_alg != "ed25519" {
        return Err(VerifyError::SidecarParse(format!(
            "unsupported signature_alg: {}",
            sidecar.signature_alg
        )));
    }

    let manifest_bytes =
        std::fs::read(manifest_path).map_err(|e| VerifyError::Io(e.to_string()))?;

    let sig_b64 = sidecar
        .signature
        .strip_prefix("ed25519:")
        .unwrap_or(&sidecar.signature);
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|e| VerifyError::Base64(e.to_string()))?;
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|e| VerifyError::InvalidSignature(e.to_string()))?;

    root_pubkey
        .verify(&manifest_bytes, &sig)
        .map_err(|_| VerifyError::SignatureMismatch)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn load_manifest_returns_empty_when_missing() {
        let path = std::path::PathBuf::from("/nonexistent/manifest.toml");
        let m = load_manifest(&path).expect("ok on missing");
        assert!(m.entries.is_empty());
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
publisher = "did:ember-systems"
"#
        )
        .expect("write");
        let m = load_manifest(f.path()).expect("parse");
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].tool_name, "ember-gh");
    }

    #[test]
    fn verify_manifest_signature_missing_sidecar_returns_err() {
        use ed25519_dalek::SigningKey;

        let mut f = NamedTempFile::new().expect("temp");
        f.write_all(b"[some] = \"manifest\"").expect("write");

        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let pk = sk.verifying_key();

        let result = verify_manifest_signature(f.path(), &pk);
        assert!(matches!(result, Err(VerifyError::MissingSidecar(_))));
    }

    #[test]
    fn verify_manifest_signature_happy_path() {
        use ed25519_dalek::{Signer, SigningKey};
        use tempfile::tempdir;

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
        use ed25519_dalek::{Signer, SigningKey};
        use tempfile::tempdir;

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
    // T-CONSTRUCT-BINARY-DISTRIBUTION-CHANNEL: lookup + channel tests
    // -----------------------------------------------------------------

    fn fixture_bundled_entry(tool: &str) -> BinaryManifestEntry {
        BinaryManifestEntry {
            tool_name: tool.to_string(),
            version: "1.0.0".to_string(),
            content_hash: "blake3:abc123".to_string(),
            absolute_path: bundled_install_dir().join(tool),
            installed_at: 1735689600,
            publisher: "did:ember-systems".to_string(),
            channel: BinaryDistributionChannel::Bundled,
        }
    }

    #[test]
    fn cohort_a_constructs_covers_seven_tools() {
        // Acceptance per task brief: cohort A is gh, git, kubectl, npm,
        // docker, wrangler, pulumi (7 tools).
        assert_eq!(COHORT_A_CONSTRUCTS.len(), 7);
        assert!(is_cohort_a_construct("ember-gh"));
        assert!(is_cohort_a_construct("ember-git"));
        assert!(is_cohort_a_construct("ember-kubectl"));
        assert!(is_cohort_a_construct("ember-npm"));
        assert!(is_cohort_a_construct("ember-docker"));
        assert!(is_cohort_a_construct("ember-wrangler"));
        assert!(is_cohort_a_construct("ember-pulumi"));
        assert!(!is_cohort_a_construct("ember-rogue"));
    }

    #[test]
    fn lookup_construct_returns_bundled_entry() {
        let manifest = BinaryManifest {
            entries: vec![fixture_bundled_entry("ember-gh")],
        };
        let entry = lookup_construct(&manifest, "ember-gh").expect("found");
        assert_eq!(entry.tool_name, "ember-gh");
        assert_eq!(entry.channel, BinaryDistributionChannel::Bundled);
        assert_eq!(entry.publisher, "did:ember-systems");
    }

    #[test]
    fn lookup_construct_not_found_errors() {
        let manifest = BinaryManifest::default();
        let err = lookup_construct(&manifest, "ember-ghost").expect_err("absent");
        assert!(matches!(err, LookupError::NotFound(_)));
    }

    #[test]
    fn lookup_construct_rejects_install_on_demand_in_v030() {
        // v0.3.0 ships only the Bundled channel; defensively refuse
        // InstallOnDemand entries so a forged manifest cannot vend
        // creds against an unsigned third-party binary before v0.4
        // delivers the dynamic-install signing pipeline.
        let mut entry = fixture_bundled_entry("ember-gh");
        entry.channel = BinaryDistributionChannel::InstallOnDemand;
        let manifest = BinaryManifest { entries: vec![entry] };
        let err = lookup_construct(&manifest, "ember-gh").expect_err("rejected");
        assert!(matches!(err, LookupError::UnsupportedChannel { .. }));
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
publisher = "did:ember-systems"
"#
        )
        .expect("write");
        let m = load_manifest(f.path()).expect("parse");
        assert_eq!(m.entries[0].channel, BinaryDistributionChannel::Bundled);
    }

    #[test]
    fn bundled_install_dir_is_canonical_path() {
        // Stable contract — the v0.3.0 release pipeline writes binaries
        // into this directory; changing it requires a coordinated
        // pipeline + design §7 amendment.
        assert_eq!(
            bundled_install_dir(),
            PathBuf::from("/usr/local/lib/ember/binaries")
        );
    }
}
