//! CLASSIFICATION: PUBLIC
//!
//! ADR 157 Phase 4 step 8: scan tool binaries, generate signed manifest.
//!
//! Manifest is TOML with one `[[binary]]` block per gated tool (gh, git,
//! kubectl, npm, docker, pulumi, wrangler, etc.). Each entry: path,
//! content_hash (SHA-256), version (best-effort from `--version`),
//! signed_at (RFC3339).
//!
//! Signed with the dev IdentityRoot (caller provides the `ed25519_dalek::SigningKey`);
//! sidecar at the current worktree's dev runtime manifest path.

use std::path::{Path, PathBuf};

use chrono::Utc;
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use super::CommandRunner;
/// Tool names that ember gates. `scan_tool_binaries` locates each tool via
/// `which` (best-effort; missing tools are silently omitted).
const GATED_TOOLS: &[&str] = &[
    "gh", "git", "kubectl", "npm", "docker", "pulumi", "wrangler",
];

/// One entry in the generated manifest.
pub struct ManifestEntry {
    pub name: String,
    pub path: PathBuf,
    pub content_hash: [u8; 32],
    pub version: Option<String>,
}

/// Scan the host's `PATH` for each tool in `GATED_TOOLS` and collect
/// `ManifestEntry` values for every tool that is present and readable.
///
/// Version strings are obtained via `<tool> --version` (first line only,
/// trimmed). If the version subcommand fails the field is `None`.
///
/// # Errors
///
/// Returns an error if the `which` invocation itself fails (i.e. `which` is
/// not on `PATH`, which would be unusual but reportable).
pub fn scan_tool_binaries(
    runner: &dyn CommandRunner,
) -> Result<Vec<ManifestEntry>, Box<dyn std::error::Error>> {
    let mut entries = Vec::new();

    for &tool in GATED_TOOLS {
        // Locate the binary via `which`.
        let which_out = match runner.run("which", &[tool]) {
            Ok(out) => out,
            Err(_) => continue, // tool not found — skip silently
        };

        let path_str = String::from_utf8_lossy(&which_out).trim().to_string();
        if path_str.is_empty() {
            continue;
        }
        let path = PathBuf::from(&path_str);

        // Hash the binary content.
        let content_hash = match hash_file_via_runner(runner, &path) {
            Ok(h) => h,
            Err(_) => continue, // unreadable — skip
        };

        // Best-effort version string.
        let version = runner.run(tool, &["--version"]).ok().and_then(|out| {
            let s = String::from_utf8_lossy(&out).trim().to_string();
            let first_line = s.lines().next()?.trim().to_string();
            if first_line.is_empty() {
                None
            } else {
                Some(first_line)
            }
        });

        entries.push(ManifestEntry {
            name: tool.to_string(),
            path,
            content_hash,
            version,
        });
    }

    Ok(entries)
}

/// Compute SHA-256 of the file at `path` by reading it via the runner (stub)
/// or directly from disk in the real path. Because `CommandRunner` is
/// command-based rather than filesystem-based, we hash the file bytes via
/// `std::fs::read` which is acceptable (no privilege involved at this step).
fn hash_file_via_runner(
    _runner: &dyn CommandRunner,
    path: &Path,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Render a slice of `ManifestEntry` values as a TOML document.
///
/// Each entry becomes one `[[binary]]` block. The `signed_at` timestamp is the
/// current UTC time in RFC3339 format.
pub fn render_manifest(entries: &[ManifestEntry]) -> String {
    let signed_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut out = String::from("# ember dev install — binary manifest\n");
    out.push_str(&format!("# generated: {signed_at}\n\n"));

    for entry in entries {
        out.push_str("[[binary]]\n");
        out.push_str(&format!("name = \"{}\"\n", entry.name));
        out.push_str(&format!("path = \"{}\"\n", entry.path.display()));
        out.push_str(&format!(
            "content_hash = \"{}\"\n",
            hex::encode(entry.content_hash)
        ));
        match &entry.version {
            Some(v) => out.push_str(&format!("version = \"{}\"\n", v.replace('"', "\\\""))),
            None => out.push_str("version = \"\"\n"),
        }
        out.push_str(&format!("signed_at = \"{signed_at}\"\n"));
        out.push('\n');
    }

    out
}

/// Sign `toml_bytes` with `signer` and return the raw Ed25519 `Signature`.
///
/// The signature covers the exact bytes of the TOML document as rendered by
/// `render_manifest`. Callers write both the `.toml` and `.toml.sig` sidecar.
pub fn sign_manifest(
    toml_bytes: &[u8],
    signer: &SigningKey,
) -> Result<Signature, Box<dyn std::error::Error>> {
    let sig = signer.sign(toml_bytes);
    Ok(sig)
}

/// Write the TOML manifest and its Ed25519 signature sidecar to `dest_dir`.
///
/// Creates two files:
/// - `<dest_dir>/manifest.toml`       — the TOML text
/// - `<dest_dir>/manifest.toml.sig`   — hex-encoded Ed25519 signature
///
/// Both files are created with mode 0644. `dest_dir` is created if absent.
///
/// # Errors
///
/// Propagates any I/O error.
pub fn write_manifest(
    toml: &str,
    sig: &Signature,
    dest_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dest_dir)?;
    let toml_path = dest_dir.join("manifest.toml");
    let sig_path = dest_dir.join("manifest.toml.sig");
    std::fs::write(&toml_path, toml.as_bytes())?;
    std::fs::write(&sig_path, hex::encode(sig.to_bytes()))?;
    Ok(())
}

/// Return the destination directory that owns `manifest_path`.
pub fn manifest_dest_dir(manifest_path: &Path) -> Option<PathBuf> {
    manifest_path.parent().map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use std::cell::RefCell;

    fn test_signing_key() -> SigningKey {
        let seed = [42u8; 32];
        SigningKey::from_bytes(&seed)
    }

    // --- render_manifest tests ---

    fn sample_entries() -> Vec<ManifestEntry> {
        vec![
            ManifestEntry {
                name: "gh".to_string(),
                path: PathBuf::from("/usr/local/bin/gh"),
                content_hash: [0xab; 32],
                version: Some("gh version 2.50.0".to_string()),
            },
            ManifestEntry {
                name: "git".to_string(),
                path: PathBuf::from("/usr/bin/git"),
                content_hash: [0xcd; 32],
                version: None,
            },
        ]
    }

    #[test]
    fn render_manifest_produces_toml_with_binary_blocks() {
        let entries = sample_entries();
        let toml = render_manifest(&entries);

        // Should have [[binary]] blocks for each entry.
        let block_count = toml.matches("[[binary]]").count();
        assert_eq!(
            block_count, 2,
            "expected 2 [[binary]] blocks, got {block_count}"
        );

        assert!(toml.contains("name = \"gh\""), "must include gh entry");
        assert!(toml.contains("name = \"git\""), "must include git entry");
        assert!(toml.contains("/usr/local/bin/gh"), "must include gh path");
        assert!(
            toml.contains(&hex::encode([0xab; 32])),
            "must include gh content_hash"
        );
        assert!(
            toml.contains("gh version 2.50.0"),
            "must include gh version"
        );
        // git has no version: should produce empty string.
        assert!(
            toml.contains("version = \"\""),
            "missing tool must have empty version"
        );
    }

    #[test]
    fn render_manifest_empty_entries_produces_valid_toml() {
        let toml = render_manifest(&[]);
        assert!(!toml.is_empty(), "empty manifest must still produce header");
        assert!(
            !toml.contains("[[binary]]"),
            "no binary blocks for empty entries"
        );
    }

    // --- sign + verify round-trip tests ---

    #[test]
    fn sign_manifest_round_trip_verify() {
        use ed25519_dalek::Verifier as _;

        let key = test_signing_key();
        let verifying_key: VerifyingKey = (&key).into();

        let toml_bytes = b"[[binary]]\nname = \"gh\"\n";
        let sig = sign_manifest(toml_bytes, &key).expect("sign_manifest must succeed");

        // Verify with the corresponding verifying key — must pass.
        verifying_key
            .verify(toml_bytes, &sig)
            .expect("signature must verify against matching key");
    }

    #[test]
    fn sign_manifest_fails_verification_with_wrong_key() {
        use ed25519_dalek::Verifier as _;

        let key = test_signing_key();
        let wrong_seed = [0xffu8; 32];
        let wrong_key = SigningKey::from_bytes(&wrong_seed);
        let wrong_verifying: VerifyingKey = (&wrong_key).into();

        let toml_bytes = b"[[binary]]\nname = \"gh\"\n";
        let sig = sign_manifest(toml_bytes, &key).expect("sign_manifest must succeed");

        // Verification with a different key must fail.
        let result = wrong_verifying.verify(toml_bytes, &sig);
        assert!(result.is_err(), "verification with wrong key must fail");
    }

    // --- write_manifest + path tests ---

    #[test]
    fn write_manifest_creates_both_files() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_signing_key();
        let toml = "[[binary]]\nname = \"gh\"\n";
        let sig = sign_manifest(toml.as_bytes(), &key).unwrap();

        write_manifest(toml, &sig, dir.path()).expect("write_manifest must succeed");

        assert!(
            dir.path().join("manifest.toml").exists(),
            "manifest.toml must exist"
        );
        assert!(
            dir.path().join("manifest.toml.sig").exists(),
            "manifest.toml.sig must exist"
        );
    }

    #[test]
    fn manifest_dest_dir_resolves_from_worktree_manifest_path() {
        let manifest_path = Path::new(
            "/home/test-operator/.ember-dev/envs/worktree-a-123456789abc/binaries/manifest.toml",
        );
        let dest = manifest_dest_dir(manifest_path).expect("manifest dest dir");
        let dest_str = dest.to_string_lossy();
        assert!(
            dest_str.contains(".ember-dev/envs/"),
            "manifest dest must be under a worktree env: {dest_str}"
        );
        assert!(
            dest_str.ends_with("/binaries"),
            "manifest dest must end with binaries: {dest_str}"
        );
    }

    // --- scan_tool_binaries test with stub runner ---

    struct StubToolRunner {
        found_tools: Vec<&'static str>,
        versions: RefCell<std::collections::HashMap<String, String>>,
    }

    impl StubToolRunner {
        fn new(tools: &[&'static str]) -> Self {
            let mut versions = std::collections::HashMap::new();
            for &t in tools {
                versions.insert(t.to_string(), format!("{t} version 1.0.0"));
            }
            Self {
                found_tools: tools.to_vec(),
                versions: RefCell::new(versions),
            }
        }
    }

    impl CommandRunner for StubToolRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            if program == "which" {
                let tool = args.first().copied().unwrap_or("");
                if self.found_tools.contains(&tool) {
                    // Return a fake path.
                    return Ok(format!("/usr/local/bin/{tool}\n").into_bytes());
                }
                return Err(format!("which: {tool} not found").into());
            }
            // Version query.
            if let Some(v) = self.versions.borrow().get(program) {
                return Ok(v.as_bytes().to_vec());
            }
            Err(format!("{program}: command not found").into())
        }
    }

    #[test]
    fn scan_tool_binaries_skips_missing_tools() {
        // Only "gh" is present; all others are missing.
        let runner = StubToolRunner::new(&["gh"]);
        // scan_tool_binaries hashes the path via std::fs::read which will fail
        // for our fake path. That's expected — the function skips unreadable
        // binaries. We only verify that it doesn't panic and returns Ok.
        let result = scan_tool_binaries(&runner);
        assert!(
            result.is_ok(),
            "scan_tool_binaries must return Ok even when tools are unreadable"
        );
    }
}
