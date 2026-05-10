//! Publisher-side `ember construct sign` — produces a JSON sidecar at
//! `<binary>.sig` per `docs/construct-signing-pipeline.md` §Build-time signing
//! flow.
//!
//! Hash: `blake3(binary_bytes || construct_toml_bytes)` — `build_ts` is NOT
//! included in the hash so the same source tree produces the same blake3 across
//! re-builds (reproducibility requirement in the design doc).
//!
//! Sidecar schema_version = 1.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use chrono::Utc;
use clap::Parser;
use ed25519_dalek::Signer as _;
use serde_json::json;

use core_crypto::canonicalize_jcs;

/// Arguments for `ember construct sign`.
#[derive(Debug, Parser)]
pub struct SignConstructArgs {
    /// Path to the compiled binary (the Construct executable).
    #[arg(long)]
    pub binary: PathBuf,

    /// Path to the construct.toml embedded policy file.
    #[arg(long)]
    pub construct_toml: PathBuf,

    /// Semver version string (e.g. `1.0.0`).
    #[arg(long)]
    pub version: String,

    /// Path to the publisher's Ed25519 secret key file (raw 32-byte seed;
    /// if file is longer, the first 32 bytes are used).
    #[arg(long)]
    pub identity_root_keypath: PathBuf,
}

/// Parsed `meta` section of construct.toml (only what we need for signing).
#[derive(Debug, serde::Deserialize)]
struct ConstructMeta {
    publisher: String,
    name: String,
}

#[derive(Debug, serde::Deserialize)]
struct ConstructToml {
    meta: ConstructMeta,
}

/// Sign a Construct binary and write a `.sig` sidecar file.
///
/// # Errors
///
/// Returns a boxed error if any I/O, parse, or signing step fails.
pub fn sign_construct(args: &SignConstructArgs) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Read binary and construct.toml bytes.
    let binary_bytes = std::fs::read(&args.binary)?;
    let toml_bytes = std::fs::read(&args.construct_toml)?;

    eprintln!(
        "[construct sign] reading binary ({} bytes) + construct.toml ({} bytes)",
        binary_bytes.len(),
        toml_bytes.len()
    );

    // 2. Compute blake3 over binary_bytes || construct_toml_bytes.
    //    build_ts is NOT in the hash (reproducibility).
    let mut hasher = blake3::Hasher::new();
    hasher.update(&binary_bytes);
    hasher.update(&toml_bytes);
    let hash = hasher.finalize();
    let blake3_hex = hex::encode(hash.as_bytes());
    let blake3_field = format!("blake3:{}", blake3_hex);

    eprintln!("[construct sign] blake3 = {}", blake3_field);

    // 3. Parse meta.publisher and meta.name from construct.toml.
    let toml_str = std::str::from_utf8(&toml_bytes)?;
    let parsed: ConstructToml = toml::from_str(toml_str)?;
    let publisher_did = &parsed.meta.publisher;
    let name = &parsed.meta.name;

    // 4. Build canonical-encoded JSON payload via JCS.
    let build_ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let payload_value = json!({
        "blake3": blake3_field,
        "build_ts": build_ts,
        "name": name,
        "publisher_did": publisher_did,
        "version": args.version,
    });
    let canonical_payload = canonicalize_jcs(&payload_value)?;

    eprintln!(
        "[construct sign] canonical signing payload (JCS):\n                 {}",
        String::from_utf8_lossy(&canonical_payload)
    );

    // 5. Read Ed25519 secret key — raw 32-byte seed (first 32 bytes of file).
    let key_bytes = std::fs::read(&args.identity_root_keypath)?;
    if key_bytes.len() < 32 {
        return Err(format!(
            "identity-root-keypath file is too short: {} bytes (need at least 32)",
            key_bytes.len()
        )
        .into());
    }
    let seed: [u8; 32] = key_bytes[..32].try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);

    // 6. Sign the canonical payload.
    let signature = signing_key.sign(&canonical_payload);
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    let signature_field = format!("ed25519:{}", sig_b64);

    eprintln!("[construct sign] ed25519 signature: {}", signature_field);

    // 7. Write sidecar JSON.
    let sidecar = json!({
        "schema_version": 1,
        "publisher_did": publisher_did,
        "name": name,
        "version": args.version,
        "blake3": blake3_field,
        "build_ts": build_ts,
        "signature": signature_field,
        "signature_alg": "ed25519",
    });
    let sidecar_json = serde_json::to_string_pretty(&sidecar)?;

    let sig_path = sig_path_for(&args.binary);
    std::fs::write(&sig_path, &sidecar_json)?;

    eprintln!("[construct sign] wrote {}", sig_path.display());
    eprintln!("[construct sign] OK");

    Ok(())
}

fn sig_path_for(binary: &Path) -> PathBuf {
    let mut p = binary.to_path_buf();
    let name = p
        .file_name()
        .map(|n| format!("{}.sig", n.to_string_lossy()))
        .unwrap_or_else(|| "binary.sig".to_string());
    p.set_file_name(name);
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn make_temp_key() -> (tempfile::NamedTempFile, [u8; 32]) {
        let seed: [u8; 32] = {
            let mut s = [0u8; 32];
            for (i, b) in s.iter_mut().enumerate() {
                *b = (i + 1) as u8;
            }
            s
        };
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&seed).unwrap();
        f.flush().unwrap();
        (f, seed)
    }

    #[test]
    fn sign_construct_produces_expected_sidecar_shape() {
        let dir = tempfile::tempdir().unwrap();

        // Fake binary bytes.
        let binary_path = dir.path().join("ember-gh");
        std::fs::write(&binary_path, b"fake-binary-bytes").unwrap();

        // Minimal construct.toml with required meta fields.
        let toml_path = dir.path().join("construct.toml");
        std::fs::write(
            &toml_path,
            b"[meta]\npublisher = \"did:emberlink\"\nname = \"ember-gh\"\n",
        )
        .unwrap();

        let (key_file, _seed) = make_temp_key();

        let args = SignConstructArgs {
            binary: binary_path.clone(),
            construct_toml: toml_path,
            version: "1.0.0".to_string(),
            identity_root_keypath: key_file.path().to_path_buf(),
        };

        sign_construct(&args).expect("sign_construct should succeed");

        // Verify sidecar was written.
        let sig_path = dir.path().join("ember-gh.sig");
        assert!(sig_path.exists(), "sidecar .sig file must exist");

        let sidecar_str = std::fs::read_to_string(&sig_path).unwrap();
        let sidecar: serde_json::Value = serde_json::from_str(&sidecar_str).unwrap();

        assert_eq!(sidecar["schema_version"], 1);
        assert_eq!(sidecar["publisher_did"], "did:emberlink");
        assert_eq!(sidecar["name"], "ember-gh");
        assert_eq!(sidecar["version"], "1.0.0");
        assert_eq!(sidecar["signature_alg"], "ed25519");

        // blake3 field has correct prefix and encodes binary || toml.
        let blake3_field = sidecar["blake3"].as_str().unwrap();
        assert!(
            blake3_field.starts_with("blake3:"),
            "blake3 field must have blake3: prefix"
        );

        // Verify reproducibility: recompute the hash ourselves.
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"fake-binary-bytes");
        hasher.update(b"[meta]\npublisher = \"did:emberlink\"\nname = \"ember-gh\"\n");
        let expected_hex = hex::encode(hasher.finalize().as_bytes());
        assert_eq!(
            blake3_field,
            format!("blake3:{}", expected_hex),
            "blake3 hash must match binary||toml concatenation"
        );

        // signature field has correct prefix.
        let sig_field = sidecar["signature"].as_str().unwrap();
        assert!(
            sig_field.starts_with("ed25519:"),
            "signature field must have ed25519: prefix"
        );

        // build_ts is present in the sidecar.
        assert!(
            sidecar["build_ts"].is_string(),
            "build_ts must be a string in sidecar"
        );
    }
}
