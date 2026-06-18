//! ADR 157 Phase 4 step 2: GH App interactive provisioning.
//!
//! Opens the pre-filled creation URL in the operator's browser, prompts
//! for App ID + PEM path, then persists them into the shared operator
//! authority bundle (`github.env` + `github-app.pem`) used by dev runtimes.
//!
//! CLASSIFICATION: PUBLIC

use std::fs;
use std::io::{self, IsTerminal as _, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::dev_runtime::DevRuntimeEnv;

/// The pre-filled GitHub App creation URL for the dev ember GH App.
pub fn gh_app_creation_url() -> &'static str {
    "https://github.com/settings/apps/new?name=ember-dev&url=https%3A%2F%2Femberlink.dev&webhook_active=false&public=false&request_oauth_on_install=false"
}

/// Record describing a provisioned GH App.
pub struct GhAppRecord {
    /// Numeric App ID from the GitHub App settings page.
    pub app_id: u64,
    /// Absolute path to the PEM file on disk inside the shared operator authority bundle.
    pub pem_path: PathBuf,
}

fn operator_authority_dir_from_runtime(runtime: &DevRuntimeEnv) -> Result<PathBuf, String> {
    runtime
        .gh_app_env_path
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            format!(
                "github env path has no parent directory: {}",
                runtime.gh_app_env_path.display()
            )
        })
}

/// Resolve the shared operator authority directory used by dev runtimes.
pub fn operator_authority_dir() -> Result<PathBuf, String> {
    let runtime = crate::dev_runtime::resolve_current_dev_runtime()?;
    operator_authority_dir_from_runtime(&runtime)
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

fn parse_app_id_value(raw: &str, source: &str) -> Result<u64, String> {
    raw.trim()
        .parse::<u64>()
        .map_err(|e| format!("{source} must be a positive integer: {e}"))
}

fn validate_pem_bytes(src_bytes: &[u8]) -> Result<(), String> {
    let pem_str =
        std::str::from_utf8(src_bytes).map_err(|e| format!("PEM is not valid UTF-8 text: {e}"))?;
    let pem = pem::parse(pem_str).map_err(|e| format!("PEM parse failed: {e}"))?;
    if !pem.tag().contains("PRIVATE KEY") {
        return Err(format!(
            "PEM must contain a private key block, got {}",
            pem.tag()
        ));
    }
    Ok(())
}

fn persist_gh_app(
    config_dir: &PathBuf,
    app_id: u64,
    pem_bytes: &[u8],
) -> Result<GhAppRecord, String> {
    validate_pem_bytes(pem_bytes)?;
    fs::create_dir_all(config_dir)
        .map_err(|e| format!("failed to create config dir {}: {e}", config_dir.display()))?;

    let env_path = config_dir.join("github.env");
    let pem_dest = config_dir.join("github-app.pem");
    let hash_hex = copy_pem_with_mode(pem_bytes, &pem_dest)?;
    println!(
        "  PEM copied to {} (blake3: {})",
        pem_dest.display(),
        hash_hex
    );

    write_github_env(config_dir, app_id)?;
    println!("  App ID {app_id} written to {}", env_path.display());

    Ok(GhAppRecord {
        app_id,
        pem_path: pem_dest,
    })
}

fn prompt_line(prompt: &str) -> Result<String, String> {
    print!("{prompt}");
    io::stdout()
        .flush()
        .map_err(|e| format!("flush prompt: {e}"))?;
    let mut buf = String::new();
    io::stdin()
        .read_line(&mut buf)
        .map_err(|e| format!("read prompt response: {e}"))?;
    Ok(buf.trim().to_string())
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

fn existing_gh_app_record(config_dir: &Path) -> Result<Option<GhAppRecord>, String> {
    let env_path = config_dir.join("github.env");
    let pem_dest = config_dir.join("github-app.pem");

    if !env_path.exists() || !pem_dest.exists() {
        return Ok(None);
    }

    let env_content = fs::read_to_string(&env_path)
        .map_err(|e| format!("failed to read {}: {e}", env_path.display()))?;
    let pem_content =
        fs::read(&pem_dest).map_err(|e| format!("failed to read {}: {e}", pem_dest.display()))?;

    if env_content.trim().is_empty() || pem_content.is_empty() {
        return Ok(None);
    }

    let app_id = parse_app_id_from_env(&env_content)
        .map_err(|e| format!("existing github.env has invalid EMBER_ENGINE_APP_ID: {e}"))?;
    validate_pem_bytes(&pem_content)
        .map_err(|e| format!("existing github-app.pem is invalid: {e}"))?;
    Ok(Some(GhAppRecord {
        app_id,
        pem_path: pem_dest,
    }))
}

/// Read the existing dev GitHub App record without prompting or mutating
/// filesystem state.
pub fn read_existing_gh_app() -> Result<Option<GhAppRecord>, String> {
    let config_dir = operator_authority_dir()?;
    existing_gh_app_record(&config_dir)
}

/// Idempotent: if the shared operator authority bundle already has a populated
/// `github.env` + `github-app.pem`, return the existing record.
///
/// Otherwise print the creation URL, accept either env-var bypass input or
/// interactive stdin prompts, and persist the resulting App ID + PEM.
pub fn ensure_gh_app() -> Result<GhAppRecord, String> {
    let config_dir = operator_authority_dir()?;

    // Idempotency check: both files must exist and be non-empty.
    if let Some(record) = existing_gh_app_record(&config_dir)? {
        return Ok(record);
    }

    println!("[ember dev install] phase 2: GH App provisioning");
    println!("  Open this URL in your browser to create the ember-dev GitHub App:");
    println!("  {}", gh_app_creation_url());
    println!();
    println!("  You can either set EMBER_DEV_GH_APP_ID + EMBER_DEV_GH_APP_PEM");
    println!("  or paste the values here when the App is ready.");

    // Try env-var bypass (for CI / non-interactive).
    let app_id_str = std::env::var("EMBER_DEV_GH_APP_ID").unwrap_or_default();
    let pem_path_str = std::env::var("EMBER_DEV_GH_APP_PEM").unwrap_or_default();

    if !app_id_str.is_empty() || !pem_path_str.is_empty() {
        if app_id_str.is_empty() || pem_path_str.is_empty() {
            return Err(
                "GH App provisioning requires both EMBER_DEV_GH_APP_ID and EMBER_DEV_GH_APP_PEM"
                    .to_string(),
            );
        }
        let app_id = parse_app_id_value(&app_id_str, "EMBER_DEV_GH_APP_ID")?;
        let src_path = PathBuf::from(pem_path_str.trim());
        let pem_bytes = fs::read(&src_path)
            .map_err(|e| format!("failed to read PEM from {}: {e}", src_path.display()))?;
        return persist_gh_app(&config_dir, app_id, &pem_bytes);
    }

    if !io::stdin().is_terminal() {
        return Err(
            "GH App not provisioned: set EMBER_DEV_GH_APP_ID and EMBER_DEV_GH_APP_PEM \
             env vars, or run 'ember dev install' interactively after visiting the URL above"
                .to_string(),
        );
    }

    println!();
    let app_id = parse_app_id_value(&prompt_line("  GitHub App ID: ")?, "GitHub App ID")?;
    let pem_path = PathBuf::from(prompt_line("  PEM path: ")?);
    let pem_bytes = fs::read(&pem_path)
        .map_err(|e| format!("failed to read PEM from {}: {e}", pem_path.display()))?;
    persist_gh_app(&config_dir, app_id, &pem_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_runtime::derive_dev_runtime_env;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn fake_private_key_pem(label: &str, body: &str) -> String {
        format!(
            "{}{}-----\n{}\n{}{}-----\n",
            "-----BEGIN ",
            label,
            body,
            "-----END ",
            label
        )
    }

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
        let pem = fake_private_key_pem("RSA PRIVATE KEY", "FAKE");
        let pem_bytes = pem.as_bytes();

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

    #[test]
    fn parse_app_id_value_rejects_non_numeric_input() {
        let err = parse_app_id_value("abc", "GitHub App ID").expect_err("must reject non-numeric");
        assert!(err.contains("positive integer"), "unexpected error: {err}");
    }

    #[test]
    fn validate_pem_bytes_accepts_private_key_pem() {
        let pem = fake_private_key_pem("PRIVATE KEY", "RkFLRQ==");
        validate_pem_bytes(pem.as_bytes()).expect("valid private key PEM must pass");
    }

    #[test]
    fn validate_pem_bytes_rejects_non_pem_input() {
        let err = validate_pem_bytes(b"not a pem").expect_err("non-PEM must fail");
        assert!(err.contains("PEM"), "unexpected error: {err}");
    }

    #[test]
    fn existing_gh_app_record_returns_none_when_files_absent() {
        let tmp = TempDir::new().unwrap();
        let record = existing_gh_app_record(tmp.path()).unwrap();
        assert!(record.is_none(), "missing config must return None");
    }

    #[test]
    fn existing_gh_app_record_reads_existing_files() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path().to_path_buf();
        write_github_env(&config_dir, 424242).unwrap();
        let pem = fake_private_key_pem("PRIVATE KEY", "RkFLRQ==");
        copy_pem_with_mode(
            pem.as_bytes(),
            &config_dir.join("github-app.pem"),
        )
        .unwrap();

        let record = existing_gh_app_record(&config_dir)
            .unwrap()
            .expect("record must be present");
        assert_eq!(record.app_id, 424242);
        assert_eq!(record.pem_path, config_dir.join("github-app.pem"));
    }

    #[test]
    fn persist_gh_app_writes_env_and_pem() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path().to_path_buf();
        let pem = fake_private_key_pem("PRIVATE KEY", "RkFLRQ==");
        let record = persist_gh_app(
            &config_dir,
            31337,
            pem.as_bytes(),
        )
        .expect("persist must succeed");
        assert_eq!(record.app_id, 31337);
        assert!(config_dir.join("github.env").exists());
        assert!(config_dir.join("github-app.pem").exists());
    }

    #[test]
    fn operator_authority_dir_from_runtime_uses_shared_operator_authority_root() {
        let runtime = derive_dev_runtime_env(
            Path::new("/home/tester"),
            Path::new("/tmp/emberlink-dev/worktree-a"),
        );
        let dir = operator_authority_dir_from_runtime(&runtime).expect("authority dir");
        assert_eq!(dir, PathBuf::from("/home/tester/.config/emberlink-dev"));
    }
}
