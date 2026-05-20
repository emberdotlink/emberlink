//! design Phase 4 step 2: GH App interactive provisioning.
//!
//! Opens the pre-filled creation URL in the operator's browser, prompts
//! for App ID + PEM path, persists to ~/.config/emberlink-dev/github.env
//! (App ID) + github-app.pem (private key, mode 640 group ember-clients-dev).
//!

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// The pre-filled GitHub App creation URL for the dev ember GH App.
pub fn gh_app_creation_url() -> &'static str {
    "https://github.com/settings/apps/new?name=ember-dev&url=https%3A%2F%2Femberlink.dev&webhook_active=false&public=false&request_oauth_on_install=false"
}

/// Record describing a provisioned GH App.
pub struct GhAppRecord {
    /// Numeric App ID from the GitHub App settings page.
    pub app_id: u64,
    /// Absolute path to the PEM file on disk (within `~/.config/emberlink-dev/`).
    pub pem_path: PathBuf,
}

/// Resolve the dev config directory: `~/.config/emberlink-dev/`.
pub fn dev_config_dir() -> Result<PathBuf, String> {
    let home =
        dirs_next::home_dir().ok_or_else(|| "cannot determine home directory".to_string())?;
    Ok(home.join(".config").join("emberlink-dev"))
}

/// Copy PEM bytes from `src_bytes` to `dest`, setting mode 0640.
///
/// Returns the blake3 hash of the PEM content (64-char hex) so the operator
/// can verify the copy out-of-band.
pub fn copy_pem_with_mode(src_bytes: &[u8], dest: &PathBuf) -> Result<String, String> {
    fs::write(dest, src_bytes)
        .map_err(|e| format!("failed to write PEM to {}: {e}", dest.display()))?;

    let mut perms = fs::metadata(dest)
        .map_err(|e| format!("failed to stat {}: {e}", dest.display()))?
        .permissions();
    perms.set_mode(0o640);
    fs::set_permissions(dest, perms)
        .map_err(|e| format!("failed to chmod 0640 {}: {e}", dest.display()))?;

    let hash = blake3::hash(src_bytes);
    Ok(hex::encode(hash.as_bytes()))
}

/// Write `EMBER_ENGINE_APP_ID=<app_id>` to `config_dir/github.env`.
pub fn write_github_env(config_dir: &PathBuf, app_id: u64) -> Result<(), String> {
    fs::create_dir_all(config_dir)
        .map_err(|e| format!("failed to create config dir {}: {e}", config_dir.display()))?;
    let env_path = config_dir.join("github.env");
    let content = format!("EMBER_ENGINE_APP_ID={app_id}\n");
    fs::write(&env_path, content)
        .map_err(|e| format!("failed to write {}: {e}", env_path.display()))?;
    Ok(())
}

fn parse_app_id_from_env(content: &str) -> Result<u64, String> {
    for line in content.lines() {
        if let Some(val) = line.strip_prefix("EMBER_ENGINE_APP_ID=") {
            return val
                .trim()
                .parse::<u64>()
                .map_err(|e| format!("invalid App ID value in github.env: {e}"));
        }
    }
    Err("EMBER_ENGINE_APP_ID not found in github.env".to_string())
}

/// Idempotent: if `~/.config/emberlink-dev/github.env` and
/// `~/.config/emberlink-dev/github-app.pem` both exist with non-empty content,
/// return the existing record.
///
/// Otherwise print the creation URL and attempt env-var bypass for CI, or
/// return an error asking the operator to provision manually.
pub fn ensure_gh_app() -> Result<GhAppRecord, String> {
    let config_dir = dev_config_dir()?;
    let env_path = config_dir.join("github.env");
    let pem_dest = config_dir.join("github-app.pem");

    // Idempotency check: both files must exist and be non-empty.
    if env_path.exists() && pem_dest.exists() {
        let env_content = fs::read_to_string(&env_path)
            .map_err(|e| format!("failed to read {}: {e}", env_path.display()))?;
        let pem_content = fs::read(&pem_dest)
            .map_err(|e| format!("failed to read {}: {e}", pem_dest.display()))?;

        if !env_content.trim().is_empty() && !pem_content.is_empty() {
            let app_id = parse_app_id_from_env(&env_content)
                .map_err(|e| format!("existing github.env has invalid EMBER_ENGINE_APP_ID: {e}"))?;
            return Ok(GhAppRecord {
                app_id,
                pem_path: pem_dest,
            });
        }
    }

    // Interactive provisioning stub: print the URL.
    println!("[ember dev install] phase 2: GH App provisioning");
    println!("  Open this URL in your browser to create the ember-dev GitHub App:");
    println!("  {}", gh_app_creation_url());
    println!();
    println!("  After creating the App, set EMBER_DEV_GH_APP_ID and EMBER_DEV_GH_APP_PEM");
    println!("  env vars and re-run 'ember dev install'.");

    // Try env-var bypass (for CI / non-interactive).
    let app_id_str = std::env::var("EMBER_DEV_GH_APP_ID").unwrap_or_default();
    let pem_path_str = std::env::var("EMBER_DEV_GH_APP_PEM").unwrap_or_default();

    if app_id_str.is_empty() || pem_path_str.is_empty() {
        return Err(
            "GH App not provisioned: set EMBER_DEV_GH_APP_ID and EMBER_DEV_GH_APP_PEM \
             env vars, or run 'ember dev install' interactively after visiting the URL above"
                .to_string(),
        );
    }

    let app_id: u64 = app_id_str
        .trim()
        .parse()
        .map_err(|e| format!("EMBER_DEV_GH_APP_ID must be a positive integer: {e}"))?;

    let src_path = PathBuf::from(pem_path_str.trim());
    let pem_bytes = fs::read(&src_path)
        .map_err(|e| format!("failed to read PEM from {}: {e}", src_path.display()))?;

    fs::create_dir_all(&config_dir)
        .map_err(|e| format!("failed to create config dir {}: {e}", config_dir.display()))?;

    let hash_hex = copy_pem_with_mode(&pem_bytes, &pem_dest)?;
    println!(
        "  PEM copied to {} (blake3: {})",
        pem_dest.display(),
        hash_hex
    );

    write_github_env(&config_dir, app_id)?;
    println!("  App ID {app_id} written to {}", env_path.display());

    Ok(GhAppRecord {
        app_id,
        pem_path: pem_dest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn creation_url_contains_expected_params() {
        let url = gh_app_creation_url();
        assert!(
            url.contains("github.com/settings/apps/new"),
            "must point to GH app creation"
        );
        assert!(url.contains("name=ember-dev"), "must include app name");
        assert!(url.contains("webhook_active=false"), "must disable webhook");
        assert!(url.contains("public=false"), "must be private app");
    }

    #[test]
    fn copy_pem_sets_mode_0640() {
        let tmp = TempDir::new().unwrap();
        let dest = tmp.path().join("test.pem");
        let pem_bytes = b"\x2d----BEGIN RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----\n";

        let hash = copy_pem_with_mode(pem_bytes, &dest).unwrap();

        let written = fs::read(&dest).unwrap();
        assert_eq!(written, pem_bytes);

        let meta = fs::metadata(&dest).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "PEM file must have mode 0640, got {mode:o}");

        assert!(!hash.is_empty());
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "hash must be hex"
        );
    }

    #[test]
    fn copy_pem_hash_is_deterministic() {
        let tmp = TempDir::new().unwrap();
        let dest1 = tmp.path().join("a.pem");
        let dest2 = tmp.path().join("b.pem");
        let pem_bytes = b"test pem content";

        let hash1 = copy_pem_with_mode(pem_bytes, &dest1).unwrap();
        let hash2 = copy_pem_with_mode(pem_bytes, &dest2).unwrap();
        assert_eq!(hash1, hash2, "same content must produce same hash");
    }

    #[test]
    fn write_github_env_creates_file() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path().to_path_buf();

        write_github_env(&config_dir, 12345).unwrap();

        let env_path = config_dir.join("github.env");
        assert!(env_path.exists());
        let content = fs::read_to_string(&env_path).unwrap();
        assert!(
            content.contains("EMBER_ENGINE_APP_ID=12345"),
            "must write App ID: {content}"
        );
    }

    #[test]
    fn parse_app_id_from_env_roundtrips() {
        let content = "EMBER_ENGINE_APP_ID=99999\n";
        let id = parse_app_id_from_env(content).unwrap();
        assert_eq!(id, 99999);
    }
}
