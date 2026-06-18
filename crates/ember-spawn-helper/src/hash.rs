// CLASSIFICATION: PUBLIC

//! Blake3 content-hash verification for spawn directives.
//!
//! The hash check is the CRIT-B mitigation per ADR 155 Component 2: the
//! main daemon pins the construct's blake3 before each spawn, and the
//! root-privileged helper re-verifies the on-disk binary against the
//! directive's hex hash before any privilege change or exec. A swap
//! that puts a malicious binary in place between hash-pin and helper-
//! spawn must be detected here.
//!
//! ## macOS shim hash pinning
//!
//! The macOS bin additionally hash-pins the `emberd-spawn-shim` binary
//! it `posix_spawn`s. The helper's `EXPECTED_SHIM_HASH` env var is
//! rendered into the LaunchDaemon plist at install time as the blake3
//! of the shipped shim; on every spawn the helper compares the on-
//! disk shim's hash to that expected value via [`verify_content_hash`]
//! and refuses with `shim_hash_mismatch` on divergence. Same primitive,
//! different binary.

use std::path::Path;

/// `verify_content_hash` returns this on hex mismatch. The actual hex
/// is included so the helper can reply with a precise
/// [`crate::HelperFrame::HashMismatch`] and (in tests) compare against
/// the known-good value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("content_hash mismatch for {path}: expected {expected}, actual {actual}")]
pub struct HashMismatchError {
    pub path: String,
    pub expected: String,
    pub actual: String,
}

/// Errors from [`verify_content_hash`]. `Io` covers missing-file /
/// read-permission failures; `Mismatch` is the hash-divergence case.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error(transparent)]
    Mismatch(#[from] HashMismatchError),
}

/// Compute the blake3 hash of `binary_path` and compare to
/// `expected_hex` (lowercase or uppercase 64-char hex). Streams the
/// file through a [`blake3::Hasher`] to avoid slurping a large binary
/// into memory.
pub fn verify_content_hash(binary_path: &Path, expected_hex: &str) -> Result<(), VerifyError> {
    let mut file = std::fs::File::open(binary_path).map_err(|e| VerifyError::Io {
        path: binary_path.display().to_string(),
        source: e,
    })?;
    let mut hasher = blake3::Hasher::new();
    std::io::copy(&mut file, &mut hasher).map_err(|e| VerifyError::Io {
        path: binary_path.display().to_string(),
        source: e,
    })?;
    let actual = hasher.finalize().to_hex().to_string();
    if actual.eq_ignore_ascii_case(expected_hex) {
        Ok(())
    } else {
        Err(VerifyError::Mismatch(HashMismatchError {
            path: binary_path.display().to_string(),
            expected: expected_hex.to_string(),
            actual,
        }))
    }
}

/// Compute the blake3 hash of a file as a lowercase hex string.
/// Convenience for callers (notably the daemon's install path) that
/// need to publish a hash without performing a comparison.
pub fn blake3_hex_of_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn verify_matches_real_blake3() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let content = b"hello, spawn-helper";
        f.write_all(content).unwrap();
        f.flush().unwrap();
        let expected = blake3::hash(content).to_hex().to_string();
        assert!(verify_content_hash(f.path(), &expected).is_ok());
    }

    #[test]
    fn verify_is_case_insensitive() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"case test").unwrap();
        f.flush().unwrap();
        let upper = blake3::hash(b"case test")
            .to_hex()
            .to_string()
            .to_uppercase();
        assert!(verify_content_hash(f.path(), &upper).is_ok());
    }

    #[test]
    fn verify_rejects_mismatch() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"real content").unwrap();
        f.flush().unwrap();
        let wrong = "0".repeat(64);
        let result = verify_content_hash(f.path(), &wrong);
        match result {
            Err(VerifyError::Mismatch(HashMismatchError {
                actual, expected, ..
            })) => {
                assert_eq!(expected, wrong);
                assert_eq!(actual, blake3::hash(b"real content").to_hex().to_string());
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_io_error_on_missing_file() {
        let result = verify_content_hash(Path::new("/nonexistent-spawn-helper-hash-test"), "0");
        assert!(matches!(result, Err(VerifyError::Io { .. })));
    }

    #[test]
    fn blake3_hex_of_file_matches_in_memory_hash() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"shim-hash-source").unwrap();
        f.flush().unwrap();
        let computed = blake3_hex_of_file(f.path()).unwrap();
        let expected = blake3::hash(b"shim-hash-source").to_hex().to_string();
        assert_eq!(computed, expected);
    }
}
