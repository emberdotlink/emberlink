use super::*;

// sealed_mek_blob_format_landed tests.
// META-AP-DAEMON-MEK-PERSISTENCE-C-1-SEALED-BLOB-FORMAT — T1 round-trip
// and the five negative cases (wrong passphrase, tampered magic,
// tampered ciphertext, tampered fingerprint, version mismatch).

/// Random MEK + passphrase → export → import yields the same MEK.
#[test]
fn test_sealed_blob_round_trip() {
    let mut mek = [0u8; 32];
    getrandom::fill(&mut mek).unwrap();
    let passphrase = "correct horse battery staple";
    let fp = mek_fingerprint_hex(&mek);

    let blob = export_mek_sealed(&mek, passphrase, &fp).expect("export");
    let recovered = import_mek_sealed(&blob, passphrase, &fp).expect("import");
    assert_eq!(recovered.as_slice(), &mek);
}

/// Successive exports of the same (MEK, passphrase) produce
/// distinct blobs (fresh salt + fresh nonce).
#[test]
fn test_sealed_blob_export_is_randomised() {
    let mek = [3u8; 32];
    let passphrase = "rotate-test";
    let fp = mek_fingerprint_hex(&mek);

    let a = export_mek_sealed(&mek, passphrase, &fp).unwrap();
    let b = export_mek_sealed(&mek, passphrase, &fp).unwrap();
    assert_ne!(a, b, "two exports of same MEK must produce distinct blobs");

    // Both still import to the same MEK.
    let ra = import_mek_sealed(&a, passphrase, &fp).unwrap();
    let rb = import_mek_sealed(&b, passphrase, &fp).unwrap();
    assert_eq!(ra.as_slice(), &mek);
    assert_eq!(rb.as_slice(), &mek);
}

/// Export with a fingerprint that does not match the MEK bytes is
/// refused — keeps inconsistent blobs from ever being produced.
#[test]
fn test_sealed_blob_export_refuses_wrong_fingerprint() {
    let mek = [5u8; 32];
    let fp = mek_fingerprint_hex(&[6u8; 32]); // intentionally wrong
    let err = export_mek_sealed(&mek, "p", &fp).unwrap_err();
    assert!(
        matches!(err, VaultError::SealedBlobFingerprintMismatch { .. }),
        "expected fingerprint mismatch, got: {err}"
    );
}

/// Wrong passphrase on import → AEAD failure (NOT a fingerprint
/// mismatch, because the embedded fingerprint still matches the
/// caller-supplied one — only the AEAD tag tells the truth).
#[test]
fn test_sealed_blob_wrong_passphrase_aead_fail() {
    let mek = [7u8; 32];
    let fp = mek_fingerprint_hex(&mek);

    let blob = export_mek_sealed(&mek, "correct", &fp).unwrap();
    let err = import_mek_sealed(&blob, "wrong", &fp).unwrap_err();
    assert!(
        matches!(err, VaultError::SealedBlobAeadFailure),
        "expected AEAD failure, got: {err}"
    );
}

/// Magic field tampered → bad-magic refusal before any crypto runs.
#[test]
fn test_sealed_blob_tampered_magic() {
    let mek = [8u8; 32];
    let fp = mek_fingerprint_hex(&mek);

    let mut blob = export_mek_sealed(&mek, "p", &fp).unwrap();
    blob[0] ^= 0xFF;
    let err = import_mek_sealed(&blob, "p", &fp).unwrap_err();
    assert!(
        matches!(err, VaultError::SealedBlobBadMagic { .. }),
        "expected bad-magic refusal, got: {err}"
    );
}

/// Ciphertext byte flipped → AEAD failure.
#[test]
fn test_sealed_blob_tampered_ciphertext() {
    let mek = [9u8; 32];
    let fp = mek_fingerprint_hex(&mek);

    let mut blob = export_mek_sealed(&mek, "p", &fp).unwrap();
    // The last ciphertext byte is at the very end of the blob.
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    let err = import_mek_sealed(&blob, "p", &fp).unwrap_err();
    assert!(
        matches!(err, VaultError::SealedBlobAeadFailure),
        "expected AEAD failure on tampered ciphertext, got: {err}"
    );
}

/// Fingerprint field tampered → import refuses with fingerprint
/// mismatch (the embedded fp no longer equals the caller-supplied
/// expected fp). Also confirms the embedded-fp check happens before
/// the (expensive) argon2 derive.
#[test]
fn test_sealed_blob_tampered_fingerprint() {
    let mek = [10u8; 32];
    let fp = mek_fingerprint_hex(&mek);
    let blob = export_mek_sealed(&mek, "p", &fp).unwrap();

    // Locate the fp_len byte (everything before it is fixed-size).
    // Offset = 4 (magic) + 2 (version) + 1 (kdf) + 1 (aead) + 1
    //  (salt_len) + 32 (salt) + 4 (ops) + 4 (mem) + 1 (par) + 1
    //  (nonce_len) + 24 (nonce) = 75.
    let fp_len_offset = 4 + 2 + 1 + 1 + 1 + 32 + 4 + 4 + 1 + 1 + 24;
    let fp_offset = fp_len_offset + 1;
    let fp_len = blob[fp_len_offset] as usize;
    assert_eq!(fp_len, fp.len(), "fp_len byte matches fingerprint length");

    let mut tampered = blob.clone();
    // Flip a byte inside the fingerprint string.
    tampered[fp_offset] ^= 0x20; // ASCII case-flip of a hex digit
    let err = import_mek_sealed(&tampered, "p", &fp).unwrap_err();
    assert!(
        matches!(err, VaultError::SealedBlobFingerprintMismatch { .. }),
        "expected fingerprint mismatch on tampered fp, got: {err}"
    );
}

/// Version byte forced to a value this build does not know → refusal.
#[test]
fn test_sealed_blob_version_mismatch() {
    let mek = [11u8; 32];
    let fp = mek_fingerprint_hex(&mek);
    let mut blob = export_mek_sealed(&mek, "p", &fp).unwrap();

    // Version field is at offset 4 (LE u16). Bump to 0xFFFF.
    blob[4] = 0xFF;
    blob[5] = 0xFF;
    let err = import_mek_sealed(&blob, "p", &fp).unwrap_err();
    match err {
        VaultError::SealedBlobUnknownVersion { got } => assert_eq!(got, 0xFFFF),
        other => panic!("expected unknown-version, got: {other}"),
    }
}

/// kdf_id and aead_id values outside the recognised set are refused.
#[test]
fn test_sealed_blob_unknown_kdf_or_aead() {
    let mek = [12u8; 32];
    let fp = mek_fingerprint_hex(&mek);
    let original = export_mek_sealed(&mek, "p", &fp).unwrap();

    // kdf_id is at offset 4 (magic) + 2 (version) = 6.
    let mut bad_kdf = original.clone();
    bad_kdf[6] = 0xEE;
    let err = import_mek_sealed(&bad_kdf, "p", &fp).unwrap_err();
    assert!(
        matches!(err, VaultError::SealedBlobUnknownKdf { got: 0xEE }),
        "expected unknown-kdf, got: {err}"
    );

    // aead_id is at offset 7.
    let mut bad_aead = original.clone();
    bad_aead[7] = 0xDD;
    let err = import_mek_sealed(&bad_aead, "p", &fp).unwrap_err();
    assert!(
        matches!(err, VaultError::SealedBlobUnknownAead { got: 0xDD }),
        "expected unknown-aead, got: {err}"
    );
}

/// Truncated blob (any cut point past the magic) is refused with a
/// truncation error rather than a panic.
#[test]
fn test_sealed_blob_truncated() {
    let mek = [13u8; 32];
    let fp = mek_fingerprint_hex(&mek);
    let blob = export_mek_sealed(&mek, "p", &fp).unwrap();
    // Cut just past the magic — every subsequent field is missing.
    let cut = &blob[..6];
    let err = import_mek_sealed(cut, "p", &fp).unwrap_err();
    assert!(
        matches!(err, VaultError::SealedBlobTruncated { .. }),
        "expected truncation error, got: {err}"
    );
}

/// argon2 ops field forced below the documented minimum (3) is
/// refused. Forging the field requires editing the blob in place,
/// which is the same threat model as "attacker presents a sealed
/// blob with weak KDF cost".
#[test]
fn test_sealed_blob_refuses_weak_argon2_ops() {
    let mek = [14u8; 32];
    let fp = mek_fingerprint_hex(&mek);
    let mut blob = export_mek_sealed(&mek, "p", &fp).unwrap();

    // argon2_ops is a LE u32 at offset 4 (magic) + 2 (version) + 1
    // (kdf) + 1 (aead) + 1 (salt_len) + 32 (salt) = 41.
    let ops_offset = 41;
    blob[ops_offset] = 1;
    blob[ops_offset + 1] = 0;
    blob[ops_offset + 2] = 0;
    blob[ops_offset + 3] = 0;
    let err = import_mek_sealed(&blob, "p", &fp).unwrap_err();
    assert!(
        matches!(&err, VaultError::SealedBlobInvalid(s) if s.contains("ops below minimum")),
        "expected ops-below-minimum invalid, got: {err}"
    );
}

/// MEK fingerprint format matches `blake3(MEK).hex()` exactly (the
/// Slice B encoding). Locks cross-slice compatibility.
#[test]
fn test_mek_fingerprint_hex_matches_blake3() {
    let mek = [0u8; 32];
    let fp = mek_fingerprint_hex(&mek);
    let expected = hex::encode(blake3::hash(&mek).as_bytes());
    assert_eq!(fp, expected);
    // BLAKE3 output is 32 bytes → 64 hex chars.
    assert_eq!(fp.len(), 64);
}
