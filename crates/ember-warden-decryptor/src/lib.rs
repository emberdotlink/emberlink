//! TZ-SOPS-3 — cluster-side SOPS decryptor.
//!
//! ArgoCD on the team-zero cluster needs to apply manifests that contain
//! SOPS-encrypted secrets. This crate exposes the primitive used by the
//! `ember-warden-decryptor` init container / sidecar: take a SOPS-
//! encrypted file plus an age identity (the private key emberd holds for
//! the cluster), and emit plaintext bytes to a tmpfs path that the main
//! container reads.
//!
//! Per ADR 084 / ADR 086 SOPS+emberd direction. The age recipient is the
//! cluster's age public key; the matching age **identity** (private key)
//! is what this function takes in. In production the identity comes from
//! emberd over the tailnet; in tests the caller supplies a fixture key.
//!
//! The decrypted plaintext is wrapped in [`DecryptedSecret`], which
//! zeroizes its buffer on drop. Callers should write the bytes to tmpfs
//! and drop the value as quickly as possible.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SOPS file format on disk. We only read the fields we need to drive
/// decryption — the rest (`mac`, `version`, etc.) is ignored.
///
/// Files we accept have one of two shapes:
///   - YAML SOPS files where each leaf value is a `ENC[...]` blob and a
///     `sops:` metadata block at the bottom carries the age recipients.
///   - Raw age-armored binary (a single `BEGIN AGE ENCRYPTED FILE` block).
///
/// For the v1 scaffold we accept the raw-age form (what `sops -e
/// --output-type binary` produces, and what `helm-secrets` happily
/// applies). The full SOPS-YAML walker is a follow-on stage — see the
/// operator README.
#[derive(Debug, Deserialize)]
struct SopsYamlEnvelope {
    /// SOPS metadata block. We use it only to detect that the file *is*
    /// SOPS-formatted and to surface a clearer error if someone hands us
    /// a plain-YAML file by mistake.
    #[serde(default)]
    sops: Option<SopsMetadata>,
}

#[derive(Debug, Deserialize)]
struct SopsMetadata {
    #[serde(default)]
    age: Vec<SopsAgeRecipient>,
}

#[derive(Debug, Deserialize)]
struct SopsAgeRecipient {
    /// The recipient's age public key (`age1...`).
    #[serde(default)]
    recipient: String,
}

/// A buffer of decrypted plaintext that zeroizes itself on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecryptedSecret {
    bytes: Vec<u8>,
}

impl DecryptedSecret {
    /// Borrow the plaintext bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length of the plaintext buffer.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the plaintext buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for DecryptedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedSecret")
            .field("len", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("read sops file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid age identity: {0}")]
    InvalidIdentity(String),
    #[error("malformed sops yaml at {path}: {source}")]
    MalformedYaml {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error(
        "sops envelope at {path} declares no age recipients matching the supplied identity \
         ({recipient}); file recipients: {found:?}"
    )]
    RecipientMismatch {
        path: PathBuf,
        recipient: String,
        found: Vec<String>,
    },
    #[error("age decrypt failed for {path}: {source}")]
    AgeDecrypt {
        path: PathBuf,
        #[source]
        source: age::DecryptError,
    },
    #[error("age decrypt setup failed: {0}")]
    AgeSetup(String),
}

/// Decrypt a SOPS-encrypted file using the supplied age identity (private
/// key string, `AGE-SECRET-KEY-1...`).
///
/// `age_recipient` is the **identity** (private key) — kept as a string so
/// the caller can hand off whatever emberd's `lease_age_identity` returns
/// without re-parsing. The name `age_recipient` is per the task spec; in
/// age terminology it is the matching identity for the recipient that
/// SOPS-encrypted the file.
///
/// The function:
///   1. Reads the file contents into memory.
///   2. If the bytes parse as YAML with a `sops:` block, performs a
///      sanity check that one of the listed recipients matches the
///      supplied identity (so the error is "you handed us the wrong key"
///      rather than a low-level age decrypt failure).
///   3. Hands the bytes to `age::Decryptor` and reads the plaintext into
///      a self-zeroizing [`DecryptedSecret`].
///
/// For the v1 scaffold the function operates on age-armored *binary*
/// SOPS files (`sops -e --output-type binary`). Walking the per-leaf
/// `ENC[...]` form is a follow-on stage tracked in the operator README.
pub fn decrypt_sops_file(
    path: &Path,
    age_recipient: &str,
) -> Result<DecryptedSecret, DecryptError> {
    let raw = std::fs::read(path).map_err(|source| DecryptError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    let identity = age_recipient
        .parse::<age::x25519::Identity>()
        .map_err(|err| DecryptError::InvalidIdentity(err.to_string()))?;

    // Best-effort YAML sanity check. We do *not* require the file to be
    // YAML — raw age-armored payloads are accepted directly. We only run
    // the check when the bytes happen to parse as YAML, so we can fail
    // early with a useful "wrong recipient" message before hitting age.
    if let Ok(envelope) = serde_yaml::from_slice::<SopsYamlEnvelope>(&raw)
        && let Some(sops) = envelope.sops
    {
        let supplied = identity.to_public().to_string();
        let recipients: Vec<String> = sops.age.iter().map(|r| r.recipient.clone()).collect();
        if !recipients.iter().any(|r| r == &supplied) {
            return Err(DecryptError::RecipientMismatch {
                path: path.to_path_buf(),
                recipient: supplied,
                found: recipients,
            });
        }
    }

    let decryptor = age::Decryptor::new(raw.as_slice())
        .map_err(|err| DecryptError::AgeSetup(err.to_string()))?;

    let mut plaintext: Vec<u8> = Vec::new();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|source| DecryptError::AgeDecrypt {
            path: path.to_path_buf(),
            source,
        })?;
    reader.read_to_end(&mut plaintext).map_err(|err| {
        // Treat read-after-setup failures as decrypt failures — the
        // reader has already consumed the header, so a downstream IO
        // error here is almost always a corrupt body.
        DecryptError::AgeSetup(format!("read plaintext: {err}"))
    })?;

    Ok(DecryptedSecret { bytes: plaintext })
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use std::io::Write;

    /// Encrypt `plaintext` to `recipient_pub` and return the age-armored
    /// bytes. Used to produce fixtures inside tests; never called from
    /// production code.
    fn age_encrypt_to(recipient_pub: &str, plaintext: &[u8]) -> Vec<u8> {
        let recipient = recipient_pub
            .parse::<age::x25519::Recipient>()
            .expect("valid age recipient");
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .expect("encryptor");
        let mut out = Vec::new();
        let mut writer = encryptor.wrap_output(&mut out).expect("wrap output");
        writer.write_all(plaintext).expect("write plaintext");
        writer.finish().expect("finish");
        out
    }

    #[test]
    fn positive_decrypt_roundtrip() {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        let id_str = identity.to_string().expose_secret().to_string();

        let plaintext = b"sops:\n  age: redacted\nsecret: hunter2\n";
        let ciphertext = age_encrypt_to(&recipient, plaintext);

        let dir = tempdir();
        let path = dir.join("secret.enc.yaml");
        std::fs::write(&path, &ciphertext).expect("write fixture");

        let out = decrypt_sops_file(&path, &id_str).expect("decrypt ok");
        assert_eq!(out.as_bytes(), plaintext);
        assert_eq!(out.len(), plaintext.len());
        assert!(!out.is_empty());

        // Debug repr must not leak plaintext bytes.
        let debug = format!("{out:?}");
        assert!(
            !debug.contains("hunter2"),
            "debug leaked plaintext: {debug}"
        );
    }

    #[test]
    fn malformed_yaml_with_sops_block_rejects_wrong_recipient() {
        // A plausible-looking SOPS YAML envelope whose declared
        // recipient does NOT match the identity we supply.
        let other = age::x25519::Identity::generate();
        let other_pub = other.to_public().to_string();

        let envelope = format!(
            "data: ENC[AES256_GCM,data:fake,iv:fake,tag:fake,type:str]\nsops:\n  age:\n    - recipient: {other_pub}\n      enc: fake\n  version: 3.7.3\n"
        );

        let dir = tempdir();
        let path = dir.join("mismatch.enc.yaml");
        std::fs::write(&path, envelope.as_bytes()).expect("write fixture");

        let mine = age::x25519::Identity::generate();
        let mine_str = mine.to_string().expose_secret().to_string();

        let err =
            decrypt_sops_file(&path, &mine_str).expect_err("must fail — recipient does not match");
        match err {
            DecryptError::RecipientMismatch { found, .. } => {
                assert_eq!(found, vec![other_pub]);
            }
            other => panic!("expected RecipientMismatch, got {other:?}"),
        }
    }

    #[test]
    fn wrong_identity_fails_age_decrypt() {
        // Encrypt to recipient A, then attempt to decrypt with identity
        // B's private key. This bypasses the YAML sanity check (the
        // payload is raw age, not a SOPS-YAML envelope) so the failure
        // path is age's own decrypt error.
        let alice = age::x25519::Identity::generate();
        let alice_pub = alice.to_public().to_string();

        let bob = age::x25519::Identity::generate();
        let bob_str = bob.to_string().expose_secret().to_string();

        let ciphertext = age_encrypt_to(&alice_pub, b"top secret");

        let dir = tempdir();
        let path = dir.join("wrong-key.enc");
        std::fs::write(&path, &ciphertext).expect("write fixture");

        let err = decrypt_sops_file(&path, &bob_str).expect_err("must fail");
        match err {
            DecryptError::AgeDecrypt { .. } => {}
            other => panic!("expected AgeDecrypt, got {other:?}"),
        }
    }

    #[test]
    fn invalid_identity_string_rejected() {
        let dir = tempdir();
        let path = dir.join("anything.enc");
        std::fs::write(&path, b"placeholder").expect("write");
        let err =
            decrypt_sops_file(&path, "not-an-age-identity").expect_err("must reject identity");
        assert!(matches!(err, DecryptError::InvalidIdentity(_)));
    }

    #[test]
    fn missing_file_surfaces_read_error() {
        let identity = age::x25519::Identity::generate();
        let id_str = identity.to_string().expose_secret().to_string();
        let path = std::path::Path::new("/tmp/ember-warden-decryptor-does-not-exist.enc.yaml");
        let err = decrypt_sops_file(path, &id_str).expect_err("must fail to read");
        assert!(matches!(err, DecryptError::Read { .. }));
    }

    /// Per-test scratch dir that survives until process exit. Tests run
    /// in parallel, so we use a unique nanosecond-based suffix instead
    /// of pulling in the `tempfile` crate just for this.
    fn tempdir() -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("ember-warden-decryptor-{pid}-{nanos}"));
        std::fs::create_dir_all(&path).expect("create tempdir");
        path
    }
}
