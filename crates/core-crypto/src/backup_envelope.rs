//! Encrypted IR backup envelope — passphrase-sealed Ed25519 private key
//! material for cross-workstation operator portability + F-AUTHORITY-3/4
//! recovery.
//!
//! Per ADR 162 §Component 4 and META-TRUST-BACKUP-RESTORE. The substrate
//! is intentionally pure: `seal_backup` / `open_backup` consume only the
//! envelope payload + a passphrase and return the sealed-blob bytes (or
//! a recovered envelope). All operator UX (Touch ID prompts, Keychain
//! reads/writes, Receipt emission) lives one layer up in
//! `emberlink-cli::trust::{backup,restore}` so this module is callable
//! from non-CLI contexts (tests, future GUI surfaces) without dragging
//! in macOS Keychain plumbing.
//!
//! ## Wire format
//!
//! Mirrors the MEK-C-1 sealed-blob shape from
//! `crates/ember-daemon/src/infra/vault.rs` — magic bytes + version +
//! KDF id + AEAD id + length-prefixed salt + length-prefixed nonce +
//! ciphertext. Magic is `b"EMBK"` ("ember backup") to distinguish from
//! the daemon's `EMBV` MEK blobs at parse time.
//!
//! ```text
//!   offset  field                  bytes
//!   ------  ---------------------  --------------------------------
//!   0..4    magic                  b"EMBK"
//!   4       format version         1u8 (= 1)
//!   5       KDF id                 1u8 (1 = Argon2id v0x13)
//!   6       AEAD id                1u8 (1 = XChaCha20-Poly1305)
//!   7       reserved               1u8 (= 0)
//!   8..10   salt length            u16 LE
//!   N..M    salt                   <salt_len> bytes
//!   M..M+2  nonce length           u16 LE
//!   M+2..M+2+nonce_len  nonce      <nonce_len> bytes
//!   …       ciphertext + tag       remainder of file
//! ```
//!
//! ## Argon2id cost
//!
//! Defaults match the OWASP-recommended profile + the `ember-daemon`
//! vault MEK derivation: `m_cost = 65536 KiB`, `t_cost = 3`,
//! `p_cost = 1`. The cost parameters are *not* embedded in the wire
//! form; they are pinned at compile time so a sealed blob that survives
//! the cost-rotation campaign must be re-sealed by the operator. The
//! KDF id byte (`0x01`) gates future param-rotation: bumping to `0x02`
//! lets older blobs continue to open under the old cost while new
//! seals use the higher profile.
//!
//! Checkpoint covered up the call stack: `trust_backup_restore_landed`
//! in `crates/emberlink-cli/src/trust/backup.rs`.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use getrandom::fill as os_fill;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Magic bytes prefixing every backup blob — `b"EMBK"` ("ember
/// backup"). Distinguishes the blob from the daemon's vault MEK
/// sealed-credential bytes at parse time.
pub const BACKUP_MAGIC: &[u8; 4] = b"EMBK";
/// Wire-format version. Bumped only on incompatible layout changes
/// (adding optional fields uses CBOR's tolerant schema for the inner
/// payload instead).
pub const BACKUP_VERSION: u8 = 1;
/// KDF id byte. `0x01` = Argon2id v0x13 with the OWASP-recommended
/// cost profile pinned below.
pub const KDF_ARGON2ID_V1: u8 = 0x01;
/// AEAD id byte. `0x01` = XChaCha20-Poly1305 (24-byte nonce, 16-byte
/// authentication tag).
pub const AEAD_XCHACHA20_POLY1305: u8 = 0x01;
/// Reserved byte — must be zero in v1 blobs. Carrying it through now
/// keeps room for future field additions without a version bump.
pub const RESERVED_BYTE: u8 = 0x00;

/// Argon2id memory cost in KiB (= 64 MiB). Matches OWASP guidance for
/// interactive passphrase-protected blobs.
pub const ARGON2_M_COST_KIB: u32 = 65536;
/// Argon2id time cost (iterations).
pub const ARGON2_T_COST: u32 = 3;
/// Argon2id parallelism factor.
pub const ARGON2_P_COST: u32 = 1;
/// Argon2id output length in bytes. 32 bytes = XChaCha20-Poly1305 key
/// size.
pub const ARGON2_OUTPUT_LEN: usize = 32;

/// Salt length in bytes. 16 bytes is the canonical RFC 9106 recommended
/// minimum.
pub const SALT_LEN: usize = 16;
/// XChaCha20 nonce length in bytes (24 bytes / 192 bits).
pub const NONCE_LEN: usize = 24;

/// Minimum passphrase length (chars) the substrate enforces.
/// CLI surfaces may impose stricter rules; the floor is here so a
/// programmatic caller cannot bypass passphrase strength entirely.
pub const MIN_PASSPHRASE_LEN: usize = 16;

/// Errors returned by [`seal_backup`] / [`open_backup`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BackupError {
    /// Passphrase shorter than [`MIN_PASSPHRASE_LEN`] characters.
    /// Surfaced by `seal_backup` only — `open_backup` cannot detect
    /// passphrase length, only correctness.
    #[error("passphrase must be at least {min} characters (got {got})")]
    PassphraseTooWeak { min: usize, got: usize },
    /// Blob is shorter than the fixed header or its length-prefixed
    /// fields do not fit.
    #[error("malformed backup blob: {0}")]
    Malformed(&'static str),
    /// Magic bytes do not match [`BACKUP_MAGIC`]. The blob is not an
    /// ember backup envelope.
    #[error("not an ember backup blob (bad magic)")]
    BadMagic,
    /// Wire-format version unsupported by this build.
    #[error("unsupported backup version: {0}")]
    UnsupportedVersion(u8),
    /// KDF identifier byte unknown.
    #[error("unsupported KDF id: {0}")]
    UnsupportedKdf(u8),
    /// AEAD identifier byte unknown.
    #[error("unsupported AEAD id: {0}")]
    UnsupportedAead(u8),
    /// Argon2id KDF rejected the parameter combination. Should be
    /// unreachable with the compile-time-pinned constants but surfaced
    /// rather than panicked for fail-loud diagnostics.
    #[error("Argon2id KDF failed: {0}")]
    Kdf(String),
    /// AEAD decryption failed — wrong passphrase, tampered ciphertext,
    /// or truncated blob. The error is intentionally non-descriptive
    /// so a malicious caller cannot distinguish "wrong passphrase"
    /// from "tampered blob" (constant-time-by-construction; both
    /// surface the same way).
    #[error("backup decryption failed: wrong passphrase or tampered blob")]
    Decrypt,
    /// CBOR encode / decode failure on the inner envelope. Distinct
    /// from [`BackupError::Decrypt`] because reaching it means the
    /// passphrase was correct but the recovered plaintext is not a
    /// valid envelope — usually a format mismatch across major
    /// versions.
    #[error("backup payload is not a valid envelope: {0}")]
    Cbor(String),
}

/// CBOR-encoded payload sealed inside the backup blob. Holds the
/// Ed25519 private key material (operator-IR + dev-IR seeds) plus
/// human-readable metadata the restore flow surfaces to the operator
/// before writing keys into the host Keychain.
///
/// `Zeroize` + `ZeroizeOnDrop` ensure the private seeds are wiped from
/// memory when the envelope is dropped — the substrate goes to lengths
/// to keep the seeds out of long-lived allocations.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct BackupEnvelope {
    /// 32-byte Ed25519 seed for the operator IdentityRoot. `Vec<u8>`
    /// because `serde` derives don't traverse fixed-size arrays
    /// cleanly through CBOR — callers must validate the length on
    /// open (see [`open_backup`]).
    pub operator_ir_seed: Vec<u8>,
    /// 32-byte Ed25519 seed for the dev IdentityRoot. Empty when the
    /// host has no dev IR enrolled.
    pub dev_ir_seed: Vec<u8>,
    /// Envelope metadata. Not signed; rendered to the operator at
    /// restore-time for context (e.g. "Restore IRs from backup
    /// created on `<hostname>` on `<date>`. Proceed?").
    #[zeroize(skip)]
    pub metadata: BackupMetadata,
}

// `Debug` is manually implemented to redact the IdentityRoot seeds — these are
// the highest-value secrets in the system (root signing seeds). A derived
// `Debug` would print them via any `tracing::debug!(?envelope)` /
// `format!("{:?}")`. Seed lengths are shown for diagnostics; bytes never are.
impl std::fmt::Debug for BackupEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupEnvelope")
            .field(
                "operator_ir_seed",
                &format_args!("<redacted; {} bytes>", self.operator_ir_seed.len()),
            )
            .field(
                "dev_ir_seed",
                &format_args!("<redacted; {} bytes>", self.dev_ir_seed.len()),
            )
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Plain-text metadata attached to the envelope. Visible to anyone
/// who can open the backup (i.e. holds the passphrase) but never
/// rendered without an explicit operator action.
///
/// Metadata is *not* cryptographically signed by the IR — the
/// substrate would have to grow an Ed25519 surface to sign over the
/// envelope, and the threat the metadata mitigates ("which backup is
/// this?") is mitigated equally well by AEAD integrity over the
/// passphrase. A bad-actor with the passphrase already controls the
/// keys; lying about the hostname/date inside the envelope buys them
/// nothing.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BackupMetadata {
    /// RFC3339 timestamp of when the backup was created. The CLI
    /// stamps this from `chrono::Utc::now()` at backup-time.
    pub created_at: String,
    /// Daemon posture (`"prod"` / `"dev"`) the source host was
    /// running. Lets the operator catch mismatch ("I exported from
    /// dev but I'm restoring on a prod host").
    pub daemon_mode: String,
    /// Hostname of the source workstation. Surface only — restore is
    /// PORTABLE (per operator directive 2026-05-15) so the value is
    /// rendered to the operator but never blocks the flow.
    pub hostname: String,
    /// Operator IR public key, hex-encoded ed25519 raw bytes. Lets
    /// the operator confirm-at-a-glance that the right IR pair is
    /// being restored before Touch ID fires.
    pub operator_pubkey_hex: String,
}

/// Seal a [`BackupEnvelope`] into the encrypted wire form. Returns
/// the serialized sealed-blob bytes. The caller is responsible for
/// writing the bytes to disk with mode 600 (the substrate is
/// I/O-free on purpose so it stays usable from non-CLI contexts).
///
/// Refuses to proceed when `passphrase.chars().count() < `
/// [`MIN_PASSPHRASE_LEN`]. The check is on character count, not byte
/// length, so a passphrase composed of multi-byte unicode codepoints
/// still gets the floor's worth of entropy.
pub fn seal_backup(envelope: &BackupEnvelope, passphrase: &str) -> Result<Vec<u8>, BackupError> {
    let passphrase_chars = passphrase.chars().count();
    if passphrase_chars < MIN_PASSPHRASE_LEN {
        return Err(BackupError::PassphraseTooWeak {
            min: MIN_PASSPHRASE_LEN,
            got: passphrase_chars,
        });
    }

    // 1. Generate fresh salt + nonce from OS entropy. Both are
    //    cleartext on the wire (only the inner envelope is sealed).
    let mut salt = [0u8; SALT_LEN];
    os_fill(&mut salt).expect("OS entropy failure (salt)");
    let mut nonce = [0u8; NONCE_LEN];
    os_fill(&mut nonce).expect("OS entropy failure (nonce)");

    // 2. Derive the 32-byte AEAD key via Argon2id over the
    //    passphrase + salt with the compile-time-pinned cost.
    let mut key_bytes = [0u8; ARGON2_OUTPUT_LEN];
    derive_key(passphrase.as_bytes(), &salt, &mut key_bytes)?;

    // 3. CBOR-encode the inner envelope. Errors here are
    //    programmer errors (the envelope shape is owned by this
    //    crate), but we surface them rather than panic.
    let mut plaintext: Vec<u8> = Vec::new();
    ciborium::into_writer(envelope, &mut plaintext)
        .map_err(|e| BackupError::Cbor(format!("encode envelope: {e}")))?;

    // 4. AEAD-seal the plaintext. The AAD is the entire fixed-size
    //    header (8 bytes) so any tampering with magic / version /
    //    KDF id / AEAD id changes the AEAD context and forces a
    //    decryption failure.
    let header = build_header();
    let cipher = XChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|e| BackupError::Kdf(format!("AEAD init: {e}")))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|e| BackupError::Kdf(format!("AEAD seal: {e}")))?;

    // Wipe the derived key + plaintext copies before assembling the
    // outbound blob.
    key_bytes.zeroize();
    plaintext.zeroize();

    // 5. Concatenate: header || salt_len(u16 LE) || salt ||
    //    nonce_len(u16 LE) || nonce || ciphertext.
    let mut out =
        Vec::with_capacity(header.len() + 2 + salt.len() + 2 + nonce.len() + ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&(salt.len() as u16).to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&(nonce.len() as u16).to_le_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a sealed-backup blob back into a [`BackupEnvelope`]. Inverse
/// of [`seal_backup`].
///
/// Errors:
/// - [`BackupError::Malformed`] / [`BackupError::BadMagic`] /
///   [`BackupError::UnsupportedVersion`] — header rejected before
///   any KDF work happens. Lets callers fail fast on obviously-bad
///   input without the Argon2 cost.
/// - [`BackupError::Decrypt`] — passphrase wrong or ciphertext
///   tampered. Surfaced *after* the KDF runs to keep the timing
///   shape of "Argon2 always runs on open" so a passphrase-guessing
///   attacker can't distinguish "bad magic" from "wrong passphrase"
///   via wall-clock timing.
pub fn open_backup(blob: &[u8], passphrase: &str) -> Result<BackupEnvelope, BackupError> {
    // 1. Parse the fixed-size header.
    if blob.len() < 8 + 2 + SALT_LEN + 2 + NONCE_LEN + 16 {
        // 16 = Poly1305 tag size; below this floor the blob cannot
        // even hold an empty ciphertext.
        return Err(BackupError::Malformed("blob shorter than header + tag"));
    }
    if &blob[0..4] != BACKUP_MAGIC {
        return Err(BackupError::BadMagic);
    }
    let version = blob[4];
    if version != BACKUP_VERSION {
        return Err(BackupError::UnsupportedVersion(version));
    }
    let kdf_id = blob[5];
    if kdf_id != KDF_ARGON2ID_V1 {
        return Err(BackupError::UnsupportedKdf(kdf_id));
    }
    let aead_id = blob[6];
    if aead_id != AEAD_XCHACHA20_POLY1305 {
        return Err(BackupError::UnsupportedAead(aead_id));
    }
    // Byte 7 is reserved; ignored on open so a future v1.x that
    // co-opts the slot stays backward-compatible.

    // 2. Read length-prefixed salt + nonce.
    let mut cursor = 8usize;
    let salt_len = read_u16_le(blob, cursor)? as usize;
    cursor += 2;
    if salt_len != SALT_LEN {
        return Err(BackupError::Malformed("unexpected salt length"));
    }
    if blob.len() < cursor + salt_len {
        return Err(BackupError::Malformed("salt truncated"));
    }
    let salt: [u8; SALT_LEN] = blob[cursor..cursor + salt_len]
        .try_into()
        .map_err(|_| BackupError::Malformed("salt slice"))?;
    cursor += salt_len;

    let nonce_len = read_u16_le(blob, cursor)? as usize;
    cursor += 2;
    if nonce_len != NONCE_LEN {
        return Err(BackupError::Malformed("unexpected nonce length"));
    }
    if blob.len() < cursor + nonce_len {
        return Err(BackupError::Malformed("nonce truncated"));
    }
    let nonce: [u8; NONCE_LEN] = blob[cursor..cursor + nonce_len]
        .try_into()
        .map_err(|_| BackupError::Malformed("nonce slice"))?;
    cursor += nonce_len;

    // 3. Remainder is ciphertext + Poly1305 tag.
    let ciphertext = &blob[cursor..];
    if ciphertext.len() < 16 {
        return Err(BackupError::Malformed("ciphertext shorter than AEAD tag"));
    }

    // 4. Derive the key from passphrase + salt. Same pinned cost as
    //    seal — version-rotation will land via the KDF id byte.
    let mut key_bytes = [0u8; ARGON2_OUTPUT_LEN];
    derive_key(passphrase.as_bytes(), &salt, &mut key_bytes)?;

    // 5. AEAD-open. AAD must match the bytes the seal-side fed in
    //    (the fixed-size header — magic..reserved).
    let header = build_header();
    let cipher = XChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|e| BackupError::Kdf(format!("AEAD init: {e}")))?;
    let plaintext_result = cipher.decrypt(
        XNonce::from_slice(&nonce),
        Payload {
            msg: ciphertext,
            aad: &header,
        },
    );
    key_bytes.zeroize();
    let mut plaintext = plaintext_result.map_err(|_| BackupError::Decrypt)?;

    // 6. CBOR-decode + validate the recovered envelope. Length
    //    invariants enforced here so a malformed payload surfaces
    //    as `Cbor(...)`, not silently corrupted private keys.
    let envelope: BackupEnvelope = ciborium::from_reader(plaintext.as_slice())
        .map_err(|e| BackupError::Cbor(format!("decode envelope: {e}")))?;
    plaintext.zeroize();

    if envelope.operator_ir_seed.len() != 32 {
        return Err(BackupError::Cbor(format!(
            "operator_ir_seed length {} (expected 32)",
            envelope.operator_ir_seed.len()
        )));
    }
    if !envelope.dev_ir_seed.is_empty() && envelope.dev_ir_seed.len() != 32 {
        return Err(BackupError::Cbor(format!(
            "dev_ir_seed length {} (expected 0 or 32)",
            envelope.dev_ir_seed.len()
        )));
    }
    Ok(envelope)
}

/// Build the 8-byte fixed-size header used both as the leading bytes
/// of the wire form and as the AEAD AAD. Kept as a helper so the seal
/// and open paths cannot drift apart.
fn build_header() -> [u8; 8] {
    [
        BACKUP_MAGIC[0],
        BACKUP_MAGIC[1],
        BACKUP_MAGIC[2],
        BACKUP_MAGIC[3],
        BACKUP_VERSION,
        KDF_ARGON2ID_V1,
        AEAD_XCHACHA20_POLY1305,
        RESERVED_BYTE,
    ]
}

/// Derive a 32-byte AEAD key from the passphrase + salt via Argon2id
/// with the pinned cost parameters. Internal helper — call sites
/// always wipe `out` after use.
fn derive_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    out: &mut [u8; ARGON2_OUTPUT_LEN],
) -> Result<(), BackupError> {
    let params = Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| BackupError::Kdf(format!("argon2 params: {e}")))?;
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    kdf.hash_password_into(passphrase, salt, out)
        .map_err(|e| BackupError::Kdf(format!("argon2 hash: {e}")))?;
    Ok(())
}

/// Read a little-endian u16 from `blob` at `offset`, bounds-checking
/// the slice. Helper so the parser code reads cleanly.
fn read_u16_le(blob: &[u8], offset: usize) -> Result<u16, BackupError> {
    if blob.len() < offset + 2 {
        return Err(BackupError::Malformed("u16 length field truncated"));
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&blob[offset..offset + 2]);
    Ok(u16::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_envelope_debug_redacts_ir_seeds() {
        // Secret-hygiene regression: derived Debug printed the operator/dev
        // IdentityRoot seeds (the highest-value secrets) verbatim.
        let env = sample_envelope();
        let dbg = format!("{env:?}");
        assert!(
            dbg.contains("<redacted; 32 bytes>"),
            "IR seeds must be redacted (with length): {dbg}"
        );
        // 0x11 = 17, 0x22 = 34 — raw seed bytes must not appear in any form.
        assert!(
            !dbg.contains("17, 17") && !dbg.contains("34, 34"),
            "no raw seed bytes may appear in Debug: {dbg}"
        );
        assert!(
            dbg.contains("test-host.local"),
            "non-secret metadata stays visible for context: {dbg}"
        );
    }

    fn sample_envelope() -> BackupEnvelope {
        BackupEnvelope {
            operator_ir_seed: vec![0x11u8; 32],
            dev_ir_seed: vec![0x22u8; 32],
            metadata: BackupMetadata {
                created_at: "2026-05-21T12:00:00Z".to_string(),
                daemon_mode: "prod".to_string(),
                hostname: "test-host.local".to_string(),
                operator_pubkey_hex: "ab".repeat(32),
            },
        }
    }

    fn good_passphrase() -> &'static str {
        // 20 chars — comfortably above the 16-char floor.
        "correct-horse-battery"
    }

    /// Round-trip: a sealed envelope opens back to its source under
    /// the same passphrase. Both private-key fields and the metadata
    /// survive intact.
    #[test]
    fn seal_open_round_trip() {
        let env = sample_envelope();
        let blob = seal_backup(&env, good_passphrase()).expect("seal");
        let recovered = open_backup(&blob, good_passphrase()).expect("open");
        assert_eq!(recovered.operator_ir_seed, env.operator_ir_seed);
        assert_eq!(recovered.dev_ir_seed, env.dev_ir_seed);
        assert_eq!(recovered.metadata.hostname, env.metadata.hostname);
        assert_eq!(recovered.metadata.created_at, env.metadata.created_at);
        assert_eq!(recovered.metadata.daemon_mode, env.metadata.daemon_mode);
        assert_eq!(
            recovered.metadata.operator_pubkey_hex,
            env.metadata.operator_pubkey_hex
        );
    }

    /// Negative case 1: wrong passphrase decryption fails with
    /// `BackupError::Decrypt`. The error is intentionally
    /// non-descriptive so a brute-force attacker can't distinguish
    /// "wrong passphrase" from "tampered blob".
    #[test]
    fn open_rejects_wrong_passphrase() {
        let env = sample_envelope();
        let blob = seal_backup(&env, good_passphrase()).expect("seal");
        let err = open_backup(&blob, "wrong-but-long-enough-pass").unwrap_err();
        assert_eq!(err, BackupError::Decrypt);
    }

    /// Negative case 2: a single flipped byte in the ciphertext is
    /// rejected by the Poly1305 tag check. Demonstrates the AEAD
    /// integrity property the substrate is meant to provide.
    #[test]
    fn open_rejects_tampered_ciphertext() {
        let env = sample_envelope();
        let mut blob = seal_backup(&env, good_passphrase()).expect("seal");
        // Flip a byte in the ciphertext region — past header + salt
        // length-prefix + salt + nonce length-prefix + nonce.
        let tamper_offset = blob.len() - 8;
        blob[tamper_offset] ^= 0x01;
        let err = open_backup(&blob, good_passphrase()).unwrap_err();
        assert_eq!(err, BackupError::Decrypt);
    }

    /// Negative case 3: weak passphrase is rejected up front by
    /// `seal_backup`. The floor applies to the chars-count (not byte
    /// length) so multi-byte unicode passphrases get the full
    /// strength budget.
    #[test]
    fn seal_rejects_weak_passphrase() {
        let env = sample_envelope();
        let err = seal_backup(&env, "shortpass").unwrap_err();
        match err {
            BackupError::PassphraseTooWeak { min, got } => {
                assert_eq!(min, MIN_PASSPHRASE_LEN);
                assert_eq!(got, 9);
            }
            other => panic!("expected PassphraseTooWeak, got {other:?}"),
        }
    }

    /// Negative case 4: a blob that is not an ember backup (bad
    /// magic) surfaces `BadMagic` before any KDF work runs. The blob
    /// must be at least the fixed-size floor (header + lenghts +
    /// salt + nonce + 16-byte AEAD tag); below that the parser
    /// short-circuits with `Malformed`, which is also acceptable but
    /// less specific. We pad the synthetic blob to clear the floor
    /// so the magic byte check is the load-bearing rejection.
    #[test]
    fn open_rejects_malformed_magic() {
        let mut blob = b"NOPE".to_vec();
        // Pad with zeros up to the minimum-length floor so the parser
        // gets past the length check and reaches the magic compare.
        blob.resize(8 + 2 + SALT_LEN + 2 + NONCE_LEN + 16 + 16, 0);
        let err = open_backup(&blob, good_passphrase()).unwrap_err();
        assert_eq!(err, BackupError::BadMagic);
    }

    /// Bonus negative: a truncated blob is rejected as `Malformed`
    /// rather than silently mis-interpreted.
    #[test]
    fn open_rejects_truncated_blob() {
        let env = sample_envelope();
        let blob = seal_backup(&env, good_passphrase()).expect("seal");
        let truncated = &blob[..blob.len() / 2];
        let err = open_backup(truncated, good_passphrase()).unwrap_err();
        assert!(matches!(
            err,
            BackupError::Malformed(_) | BackupError::Decrypt
        ));
    }

    /// Round-trip preserves dev_ir_seed when it's empty (host with
    /// no dev IR enrolled). The substrate accepts `Vec::new()` and
    /// the open-side length check tolerates 0 or 32.
    #[test]
    fn round_trip_with_empty_dev_seed() {
        let mut env = sample_envelope();
        env.dev_ir_seed = Vec::new();
        let blob = seal_backup(&env, good_passphrase()).expect("seal");
        let recovered = open_backup(&blob, good_passphrase()).expect("open");
        assert!(recovered.dev_ir_seed.is_empty());
        assert_eq!(recovered.operator_ir_seed, env.operator_ir_seed);
    }

    /// Distinct passphrases derive distinct keys: two sealed blobs
    /// of the same envelope under different passphrases produce
    /// different ciphertexts even with the salt fixed at the API
    /// level (here we just compare two fresh seals which have
    /// independent random salts, so ciphertext disagreement is
    /// expected; the property under test is that *open* discriminates
    /// the two passphrases).
    #[test]
    fn distinct_passphrases_produce_distinct_keys() {
        let env = sample_envelope();
        let blob_a = seal_backup(&env, "passphrase-alpha-1234567").expect("seal a");
        let blob_b = seal_backup(&env, "passphrase-bravo-7654321").expect("seal b");
        // Each opens under its own passphrase…
        assert!(open_backup(&blob_a, "passphrase-alpha-1234567").is_ok());
        assert!(open_backup(&blob_b, "passphrase-bravo-7654321").is_ok());
        // …and neither opens under the other's.
        assert_eq!(
            open_backup(&blob_a, "passphrase-bravo-7654321").unwrap_err(),
            BackupError::Decrypt
        );
        assert_eq!(
            open_backup(&blob_b, "passphrase-alpha-1234567").unwrap_err(),
            BackupError::Decrypt
        );
    }

    /// Each seal call uses fresh entropy for salt + nonce, so two
    /// seals of the same envelope under the same passphrase produce
    /// *different* ciphertexts — protects against rainbow-table /
    /// ciphertext-equality leaks.
    #[test]
    fn fresh_entropy_per_seal() {
        let env = sample_envelope();
        let blob_a = seal_backup(&env, good_passphrase()).expect("seal a");
        let blob_b = seal_backup(&env, good_passphrase()).expect("seal b");
        assert_ne!(blob_a, blob_b);
    }
}
