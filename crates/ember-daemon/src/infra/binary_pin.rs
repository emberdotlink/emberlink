//! Binary-pin manifest for content-hash peer binding.
//!
//! Implements the full content-hash binding for `local_state_key_*`
//! dispatch methods per KEYCHAIN-CONSOLIDATE-CLI adversarial-review
//! HIGH-1. Replaces the basename/path matching that the design
//! conversation rejected as a half-measure.
//!
//! # Trust model (v0.3 — Path 1: TOFU at install + operator re-attestation)
//!
//! The daemon self-signs the manifest at install time using its persona
//! signing key (per ADR 116). Verification at runtime uses the daemon's
//! own cached pubkey. Trust assumption: **the moment the operator runs
//! `ember binary-pin generate` is the trust root.**
//!
//! This is honest TOFU (trust-on-first-use) with cryptographic
//! enforcement after enrollment:
//! - First generate hashes whatever binaries are at the configured
//!   paths; the operator's intent at that moment establishes which
//!   binaries are legitimate.
//! - Subsequent generates require user-presence (`Touch ID` per
//!   `HighRiskOp::BinaryPinGenerate`) — an attacker who replaces a
//!   binary cannot silently re-pin it.
//! - All `local_state_key_*` dispatches verify the calling peer's
//!   binary blake3 against the manifest. Mismatch → fail-closed.
//! - Missing manifest → fail-closed with directive to run generate.
//!
//! Path 2 (filed as `ARCH-IDENTITY-ROOT-PIPELINE`) replaces the
//! daemon-self-signing model with Ember Systems IdentityRoot pre-signing
//! in the release pipeline. Until then, this module's TOFU is the
//! strongest v0.3-shippable check.
//!
//! # Storage
//!
//! Manifest is serialized to JSON and stored as a credential in the
//! daemon's vault under name `binary-pins/manifest`. Vault grammar is
//! enforced (lowercase + hyphens + single slash). The vault encrypts at
//! rest with the daemon's MEK (per ADR 131 separate-uid posture, only
//! `ember` user can decrypt). Manifest signature defeats tampering even
//! if filesystem permissions are bypassed.

use std::path::Path;

use core_crypto::{
    Ed25519Verifier, PublicKey, Signature, Signer, sign_with_context, verify_with_context,
};
use serde::{Deserialize, Serialize};

use crate::infra::store::DaemonStore;
use crate::infra::vault::{Vault, VaultError, VaultScope};

/// Vault namespace for the signed manifest. Matches ADR 099 path grammar
/// (lowercase + hyphens + single slash).
pub const MANIFEST_VAULT_NAMESPACE: &str = "binary-pins/manifest";

/// Domain context for `sign_with_context` / `verify_with_context` over
/// the manifest's canonical bytes.
pub const MANIFEST_SIGNING_CONTEXT: &[u8] = b"ember-binary-pin-manifest-v1";

#[derive(Debug, thiserror::Error)]
pub enum BinaryPinError {
    #[error("io error reading peer binary: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("manifest signature verification failed")]
    InvalidSignature,
    #[error("manifest signed by wrong identity: expected {expected}, got {actual}")]
    SignerMismatch { expected: String, actual: String },
    #[error("manifest is not yet signed")]
    Unsigned,
    #[error("no pin entry for caller {caller:?}")]
    NoPinForCaller { caller: String },
    #[error("peer binary hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("peer pid unavailable — cannot resolve binary identity")]
    PeerPidUnavailable,
    #[error("peer binary path unavailable for pid {pid}")]
    PeerBinaryPathUnavailable { pid: i32 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BinaryPin {
    /// One of `cli`, `gui`, `native-host` — the wire-claimed caller this
    /// pin authorizes.
    pub caller: String,
    /// Hex-encoded blake3 of the binary file bytes at pin time.
    pub blake3_hex: String,
    /// Path where the binary was found at pin time (audit only; not
    /// enforced — content-hash is the real check).
    pub binary_path: String,
    /// Basename of the binary at pin time (audit only).
    pub basename: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BinaryPinManifest {
    pub pins: Vec<BinaryPin>,
    /// RFC3339 timestamp the manifest was signed.
    pub signed_at: String,
    /// `ed25519:<hex>` form of the signer's pubkey. The verifier checks
    /// this matches the expected daemon-persona pubkey.
    pub signer_pubkey: String,
    /// `ed25519sig:<hex>` form of the signature over `canonical_bytes`.
    /// `None` for unsigned drafts (only used briefly during construction).
    pub signature: Option<String>,
}

impl BinaryPinManifest {
    pub fn new(pins: Vec<BinaryPin>, signer_pubkey: &str) -> Self {
        Self {
            pins,
            signed_at: chrono::Utc::now().to_rfc3339(),
            signer_pubkey: signer_pubkey.to_string(),
            signature: None,
        }
    }

    /// JCS-canonical bytes of the manifest WITHOUT the `signature` field
    /// — what gets signed.
    fn canonical_bytes(&self) -> Result<Vec<u8>, BinaryPinError> {
        let mut v = serde_json::to_value(self)?;
        if let serde_json::Value::Object(map) = &mut v {
            map.remove("signature");
        }
        Ok(serde_json::to_vec(&v)?)
    }

    /// Sign the manifest with `signer`. Populates `signature` field in
    /// place. The signer is expected to be the daemon's persona key
    /// (ADR 116); the signature is verified at startup against the
    /// stored `signer_pubkey`.
    pub fn sign(&mut self, signer: &dyn Signer) -> Result<(), BinaryPinError> {
        self.signature = None; // ensure stable canonical form before signing
        let bytes = self.canonical_bytes()?;
        let sig = sign_with_context(MANIFEST_SIGNING_CONTEXT, signer, &bytes);
        self.signature = Some(sig.0);
        Ok(())
    }

    /// Verify the manifest signature against `expected_pubkey` (the
    /// daemon's persona pubkey at startup). Returns `Ok(())` on valid
    /// signature + matching signer; structured error otherwise.
    pub fn verify(&self, expected_pubkey: &str) -> Result<(), BinaryPinError> {
        if self.signer_pubkey != expected_pubkey {
            return Err(BinaryPinError::SignerMismatch {
                expected: expected_pubkey.to_string(),
                actual: self.signer_pubkey.clone(),
            });
        }
        let sig_str = self.signature.as_ref().ok_or(BinaryPinError::Unsigned)?;
        let bytes = self.canonical_bytes()?;

        let pubkey = PublicKey(self.signer_pubkey.clone());
        let signature = Signature(sig_str.clone());

        // Verify via the ed25519-dalek-backed verifier.
        let verifier = Ed25519Verifier;
        let ok = verify_with_context(
            MANIFEST_SIGNING_CONTEXT,
            &verifier,
            &pubkey,
            &bytes,
            &signature,
        );
        if !ok {
            return Err(BinaryPinError::InvalidSignature);
        }
        Ok(())
    }

    pub fn find_pin(&self, caller: &str) -> Option<&BinaryPin> {
        self.pins.iter().find(|p| p.caller == caller)
    }
}

/// Resolve the peer process's executable PATH, cross-platform.
///
/// - **macOS:** `proc_pidpath(pid, buf, buf_len)`.
/// - **Linux:** `readlink("/proc/<pid>/exe")`.
/// - **Other:** returns `None`.
///
/// TOCTOU acknowledgment: this resolves a PATH STRING (`readlink` / `proc_pidpath`)
/// which [`peer_binary_blake3`] then opens BY PATH — so the file at the returned
/// path can be replaced between resolve and open+hash (a same-uid attacker
/// renaming a signed binary onto the path). This is NOT inode-pinned: an earlier
/// version of this comment falsely claimed Linux "opens via the symlink"; the
/// code opens the resolved path, not the `/proc/<pid>/exe` fd. Callers that need
/// inode pinning (the ADR 155 bridge provenance gate) open `/proc/<pid>/exe`
/// directly instead (see `infra::rpc_listener::hash_peer_exe`). pidfd/csops-grade
/// hardening of THIS helper lands in a follow-up.
#[cfg(target_os = "macos")]
fn peer_binary_path(pid: i32) -> Option<std::path::PathBuf> {
    use std::os::raw::{c_char, c_int};
    const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
    unsafe extern "C" {
        fn proc_pidpath(pid: c_int, buffer: *mut c_char, buffersize: u32) -> c_int;
    }
    let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
    let n = unsafe { proc_pidpath(pid, buf.as_mut_ptr() as *mut c_char, buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    let path = String::from_utf8(buf).ok()?;
    Some(std::path::PathBuf::from(path))
}

#[cfg(target_os = "linux")]
fn peer_binary_path(pid: i32) -> Option<std::path::PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn peer_binary_path(_pid: i32) -> Option<std::path::PathBuf> {
    None
}

/// Compute blake3 of the peer's executable file. Returns hex-encoded
/// 64-char hash on success, structured error otherwise.
pub fn peer_binary_blake3(pid: i32) -> Result<String, BinaryPinError> {
    let path = peer_binary_path(pid).ok_or(BinaryPinError::PeerBinaryPathUnavailable { pid })?;
    hash_file_blake3(&path)
}

/// blake3 hash of a file's bytes, hex-encoded.
pub fn hash_file_blake3(path: &Path) -> Result<String, BinaryPinError> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Build a manifest by hashing each `(caller, path)` pair. Used by the
/// daemon's `binary_pin_generate` socket method. Paths that fail to
/// open (missing binary) are reported via `missing`; the manifest is
/// built from the successful hashes only.
pub struct GenerateOutcome {
    pub manifest: BinaryPinManifest,
    pub missing: Vec<(String, String)>, // (caller, path)
}

pub fn build_manifest_from_paths(
    targets: &[(String, std::path::PathBuf)],
    signer_pubkey: &str,
) -> Result<GenerateOutcome, BinaryPinError> {
    let mut pins = Vec::new();
    let mut missing = Vec::new();
    for (caller, path) in targets {
        match hash_file_blake3(path) {
            Ok(blake3_hex) => {
                let basename = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();
                pins.push(BinaryPin {
                    caller: caller.clone(),
                    blake3_hex,
                    binary_path: path.display().to_string(),
                    basename,
                });
            }
            Err(_) => missing.push((caller.clone(), path.display().to_string())),
        }
    }
    Ok(GenerateOutcome {
        manifest: BinaryPinManifest::new(pins, signer_pubkey),
        missing,
    })
}

/// Persist a signed manifest into the daemon vault under
/// `MANIFEST_VAULT_NAMESPACE`. Uses `Vault::replace` so re-generation
/// atomically swaps the entry.
pub fn store_manifest(
    vault: &Vault,
    store: &DaemonStore,
    manifest: &BinaryPinManifest,
) -> Result<(), BinaryPinError> {
    let bytes = serde_json::to_vec(manifest)?;
    vault.replace(
        VaultScope::Interactive,
        store,
        MANIFEST_VAULT_NAMESPACE,
        &bytes,
        None,
    )?;
    Ok(())
}

/// Load + verify a signed manifest from the daemon vault. Returns
/// `Ok(None)` if no manifest is stored. `Ok(Some(m))` only on valid
/// signature + matching signer pubkey.
pub fn load_manifest(
    vault: &Vault,
    store: &DaemonStore,
    expected_signer_pubkey: &str,
) -> Result<Option<BinaryPinManifest>, BinaryPinError> {
    let bytes = match vault.get(VaultScope::Interactive, store, MANIFEST_VAULT_NAMESPACE) {
        Ok(b) => b,
        Err(VaultError::NotFound) => return Ok(None),
        Err(e) => return Err(BinaryPinError::Vault(e)),
    };
    let manifest: BinaryPinManifest = serde_json::from_slice(&bytes)?;
    manifest.verify(expected_signer_pubkey)?;
    Ok(Some(manifest))
}

/// Verify the calling peer's binary against the manifest entry for the
/// claimed `caller`. The load-bearing security check for
/// `local_state_key_*` dispatch arms.
pub fn verify_peer_against_manifest(
    pid: Option<i32>,
    caller: &str,
    manifest: &BinaryPinManifest,
) -> Result<(), BinaryPinError> {
    let pid = pid.ok_or(BinaryPinError::PeerPidUnavailable)?;
    let pin = manifest
        .find_pin(caller)
        .ok_or_else(|| BinaryPinError::NoPinForCaller {
            caller: caller.to_string(),
        })?;
    let actual = peer_binary_blake3(pid)?;
    if actual != pin.blake3_hex {
        return Err(BinaryPinError::HashMismatch {
            expected: pin.blake3_hex.clone(),
            actual,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::FixtureSigner;

    fn fixture_signer() -> FixtureSigner {
        FixtureSigner::new("binary-pin-manifest-test")
    }

    fn fixture_pubkey_str(s: &FixtureSigner) -> String {
        use core_crypto::Signer;
        s.public_key().0.clone()
    }

    #[test]
    fn manifest_round_trips_through_json() {
        let manifest = BinaryPinManifest::new(
            vec![BinaryPin {
                caller: "cli".into(),
                blake3_hex: "abcd".repeat(16),
                binary_path: "/usr/local/bin/ember".into(),
                basename: "ember".into(),
            }],
            "ed25519:1234abcd",
        );
        let json = serde_json::to_string(&manifest).unwrap();
        let back: BinaryPinManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    #[test]
    fn manifest_sign_then_verify_succeeds() {
        let signer = fixture_signer();
        let pubkey_str = fixture_pubkey_str(&signer);
        let mut manifest = BinaryPinManifest::new(
            vec![BinaryPin {
                caller: "cli".into(),
                blake3_hex: "a".repeat(64),
                binary_path: "/usr/local/bin/ember".into(),
                basename: "ember".into(),
            }],
            &pubkey_str,
        );
        manifest.sign(&signer).expect("sign manifest");
        assert!(manifest.signature.is_some());
        manifest.verify(&pubkey_str).expect("verify manifest");
    }

    #[test]
    fn verify_rejects_signer_mismatch() {
        let signer = fixture_signer();
        let pubkey_str = fixture_pubkey_str(&signer);
        let mut manifest = BinaryPinManifest::new(vec![], &pubkey_str);
        manifest.sign(&signer).expect("sign");
        let err = manifest
            .verify("ed25519:wrong-pubkey-hex-string")
            .unwrap_err();
        assert!(matches!(err, BinaryPinError::SignerMismatch { .. }));
    }

    #[test]
    fn verify_rejects_tampered_manifest() {
        let signer = fixture_signer();
        let pubkey_str = fixture_pubkey_str(&signer);
        let mut manifest = BinaryPinManifest::new(
            vec![BinaryPin {
                caller: "cli".into(),
                blake3_hex: "a".repeat(64),
                binary_path: "/usr/local/bin/ember".into(),
                basename: "ember".into(),
            }],
            &pubkey_str,
        );
        manifest.sign(&signer).expect("sign");
        // Tamper: swap the pinned hash post-signature.
        manifest.pins[0].blake3_hex = "b".repeat(64);
        let err = manifest.verify(&pubkey_str).unwrap_err();
        assert!(matches!(err, BinaryPinError::InvalidSignature));
    }

    #[test]
    fn find_pin_returns_match() {
        let manifest = BinaryPinManifest::new(
            vec![
                BinaryPin {
                    caller: "cli".into(),
                    blake3_hex: "a".repeat(64),
                    binary_path: "/usr/local/bin/ember".into(),
                    basename: "ember".into(),
                },
                BinaryPin {
                    caller: "gui".into(),
                    blake3_hex: "b".repeat(64),
                    binary_path: "/Applications/Emberlink.app".into(),
                    basename: "emberlink-gui".into(),
                },
            ],
            "ed25519:fake",
        );
        assert!(manifest.find_pin("cli").is_some());
        assert!(manifest.find_pin("gui").is_some());
        assert!(manifest.find_pin("unknown").is_none());
    }

    #[test]
    fn hash_file_blake3_matches_well_known_value() {
        use std::io::Write;
        let tmp = std::env::temp_dir().join("binary-pin-test-input.bin");
        let mut f = std::fs::File::create(&tmp).unwrap();
        f.write_all(b"hello world").unwrap();
        drop(f);
        let h = hash_file_blake3(&tmp).expect("hash file");
        // Well-known blake3 of "hello world".
        assert_eq!(
            h,
            "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn verify_peer_against_manifest_rejects_no_pin() {
        let manifest = BinaryPinManifest::new(vec![], "ed25519:fake");
        let err = verify_peer_against_manifest(Some(std::process::id() as i32), "cli", &manifest)
            .unwrap_err();
        assert!(matches!(err, BinaryPinError::NoPinForCaller { .. }));
    }

    #[test]
    fn verify_peer_against_manifest_rejects_missing_pid() {
        let manifest = BinaryPinManifest::new(
            vec![BinaryPin {
                caller: "cli".into(),
                blake3_hex: "a".repeat(64),
                binary_path: "/whatever".into(),
                basename: "ember".into(),
            }],
            "ed25519:fake",
        );
        let err = verify_peer_against_manifest(None, "cli", &manifest).unwrap_err();
        assert!(matches!(err, BinaryPinError::PeerPidUnavailable));
    }

    #[test]
    fn build_manifest_from_paths_reports_missing() {
        let targets = vec![(
            "cli".to_string(),
            std::path::PathBuf::from("/totally/nonexistent/binary"),
        )];
        let outcome = build_manifest_from_paths(&targets, "ed25519:fake").unwrap();
        assert!(outcome.manifest.pins.is_empty());
        assert_eq!(outcome.missing.len(), 1);
        assert_eq!(outcome.missing[0].0, "cli");
    }
}
