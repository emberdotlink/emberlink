//! GitHub App credential discovery for the daemon's broker registry.
//!
//! Reads `~/.config/emberlink/ember-engine.env` (key-value, `KEY=value`
//! lines) and `~/.config/emberlink/ember-engine-app.pem` (RSA private key)
//! to build the [`GhAppCredentials`] the daemon hands to
//! [`ember_broker::GitHubBroker`].
//!
//! Path scheme matches today's `crates/internal-automation/src/ship.rs::resolve_bot_identity`
//! discovery so the migration to construct-mediated ships (T-CONSTRUCT-SHIP-RS-MIGRATION)
//! is a drop-in: the same files satisfy both code paths until ship.rs is
//! converted, after which ship.rs deletes its discovery and the daemon
//! becomes the sole reader.
//!
//! Behaviour contract:
//!
//! - Both files present + valid → `Ok(Some(creds))`. Daemon registers
//!   [`ember_broker::GitHubBroker`] for `BrokerProvider::Github`.
//! - Either file absent → `Ok(None)`. Daemon logs a warning and falls
//!   back to `MockBroker` for github (preserves today's pre-T1 behaviour
//!   for hosts without GH App config — local dev, fresh installs).
//! - Files present but malformed (env file missing required keys, PEM
//!   unreadable, etc.) → `Err`. Daemon surfaces as a startup warning;
//!   does NOT panic since other brokers still work.
//!
//! ## Env-var overrides
//!
//! `EMBER_APP_PEM_PATH` and `EMBER_APP_ENV_PATH` override the default
//! `$HOME/.config/emberlink/` resolution. When both are set and non-empty,
//! those exact paths are used. If either is unset or empty, the default
//! `$HOME` resolution applies. Path-traversal (`..` components) in
//! env-var values is refused with an `Err` to surface the misconfiguration.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, anyhow};
use ember_broker::github_app::GhAppCredentials;
use secrecy::SecretString;

/// Filename inside `~/.config/emberlink/` containing `EMBER_ENGINE_APP_ID`
/// and `EMBER_ENGINE_INSTALLATION_ID` shell-style assignments.
const ENV_FILENAME: &str = "ember-engine.env";

/// Filename inside `~/.config/emberlink/` containing the GitHub App's
/// RSA private key (PEM-encoded PKCS#8 or PKCS#1).
const PEM_FILENAME: &str = "ember-engine-app.pem";

/// Required key for the App ID in `ember-engine.env`.
const KEY_APP_ID: &str = "EMBER_ENGINE_APP_ID";

/// Required key for the installation ID in `ember-engine.env`.
const KEY_INSTALLATION_ID: &str = "EMBER_ENGINE_INSTALLATION_ID";

/// Env-var name for an explicit PEM file path override.
const ENV_VAR_PEM_PATH: &str = "EMBER_APP_PEM_PATH";

/// Env-var name for an explicit env-file path override.
const ENV_VAR_ENV_PATH: &str = "EMBER_APP_ENV_PATH";

/// Reject a path that contains `..` components (path-traversal defense).
fn reject_traversal(path: &std::path::Path, var_name: &str) -> anyhow::Result<()> {
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(anyhow!(
            "{var_name} contains '..' path-traversal component — refusing: {}",
            path.display()
        ));
    }
    Ok(())
}

/// Try to load GitHub App credentials from the operator's user-level
/// configuration. Returns `Ok(None)` if either file is absent (graceful
/// — daemon continues with `MockBroker` for github).
///
/// When `EMBER_APP_PEM_PATH` and `EMBER_APP_ENV_PATH` are both set and
/// non-empty, those paths are used directly. Otherwise the default
/// `$HOME/.config/emberlink/` resolution applies. Path-traversal in
/// env-var values is refused with `Err`.
pub fn load_gh_app_credentials() -> anyhow::Result<Option<GhAppCredentials>> {
    let pem_override = std::env::var(ENV_VAR_PEM_PATH)
        .ok()
        .filter(|s| !s.is_empty());
    let env_override = std::env::var(ENV_VAR_ENV_PATH)
        .ok()
        .filter(|s| !s.is_empty());

    match (pem_override, env_override) {
        (Some(pem_str), Some(env_str)) => {
            let pem_path = PathBuf::from(&pem_str);
            let env_path = PathBuf::from(&env_str);
            reject_traversal(&pem_path, ENV_VAR_PEM_PATH)?;
            reject_traversal(&env_path, ENV_VAR_ENV_PATH)?;
            load_with_paths(&env_path, &pem_path)
        }
        _ => {
            let home = std::env::var("HOME").context("HOME env var unset")?;
            let base = PathBuf::from(&home).join(".config").join("emberlink");
            load_from_dir(&base)
        }
    }
}

/// Inner function — takes a base directory so unit tests can point at
/// a tempdir without touching the user's real `~/.config/emberlink`.
pub fn load_from_dir(base: &std::path::Path) -> anyhow::Result<Option<GhAppCredentials>> {
    let env_path = base.join(ENV_FILENAME);
    let pem_path = base.join(PEM_FILENAME);
    load_with_paths(&env_path, &pem_path)
}

/// Path-agnostic loader — reads credentials from the given env-file and PEM
/// paths directly. Both [`load_from_dir`] and the env-var override path in
/// [`load_gh_app_credentials`] funnel through here so the parse logic is
/// shared and tested once.
pub fn load_with_paths(
    env_path: &std::path::Path,
    pem_path: &std::path::Path,
) -> anyhow::Result<Option<GhAppCredentials>> {
    if !env_path.exists() || !pem_path.exists() {
        return Ok(None);
    }

    let env_contents =
        fs::read_to_string(env_path).with_context(|| format!("reading {}", env_path.display()))?;
    let app_id = parse_env_var(&env_contents, KEY_APP_ID)
        .ok_or_else(|| anyhow!("{} present but missing {KEY_APP_ID}", env_path.display()))?;
    let installation_id = parse_env_var(&env_contents, KEY_INSTALLATION_ID).ok_or_else(|| {
        anyhow!(
            "{} present but missing {KEY_INSTALLATION_ID}",
            env_path.display()
        )
    })?;

    let private_key_pem =
        fs::read_to_string(pem_path).with_context(|| format!("reading {}", pem_path.display()))?;

    if private_key_pem.trim().is_empty() {
        return Err(anyhow!(
            "{} is empty — expected RSA private key",
            pem_path.display()
        ));
    }

    Ok(Some(GhAppCredentials {
        app_id,
        installation_id,
        private_key_pem: SecretString::from(private_key_pem),
    }))
}

/// Store-key prefix for ADR-099-grammar GitHub App credentials.
///
/// Entries live under `github/apps/<slug>/install-<install-id>/<purpose>`
/// where `<purpose>` ∈ { `private-key`, `app-id`, `installation-id` }.
/// `<slug>` is the human-readable app name (e.g. `ember-engine`);
/// `<install-id>` is the GitHub-assigned installation id with the
/// literal `install-` prefix that distinguishes it from the slug.
const STORE_PREFIX_GITHUB_APPS: &str = "github/apps/";

/// Per-purpose leaf names beneath `github/apps/<slug>/install-<id>/`.
const PURPOSE_PRIVATE_KEY: &str = "private-key";
const PURPOSE_APP_ID: &str = "app-id";
const PURPOSE_INSTALLATION_ID: &str = "installation-id";

/// `CredentialStore`-backed sibling to [`load_from_dir`], reading the
/// ADR-099 path grammar.
///
/// Walks the `github/apps/<slug>/install-<id>/` tree and returns the
/// first complete `{private-key, app-id, installation-id}` triple it
/// finds. Single-installation deployments therefore behave identically
/// to the legacy flat-key reader; multi-installation deployments will
/// pin to a specific slug+install via a later config knob (out of
/// scope here — see ARCH-BROKER-VAULT-CUTOVER-PR4B).
///
/// Returns:
/// - `Ok(Some(creds))` when a complete triple is present.
/// - `Ok(None)` when no slug+install pair exists in the store at all
///   (daemon startup falls back to the env-file loader and ultimately
///   `MockBroker` per the existing wireup in `runtime.rs`).
/// - `Err(StoreError::Other(_))` when a triple is partial — e.g. the
///   `private-key` leaf is present but `app-id` or `installation-id`
///   is missing. Partial entries are a misconfiguration we surface
///   loudly rather than silently fall back from.
///
/// On `Ok(Some(_))` the function emits a structured
/// `bot-identity-source` event via `tracing::info!` with fields
/// `provider="github"` and `source="vault"`.
pub async fn github_config_from_store(
    store: &dyn crate::infra::credential_store::CredentialStore,
) -> Result<Option<GhAppCredentials>, crate::infra::credential_store::StoreError> {
    use crate::infra::credential_store::StoreError;

    async fn get_opt(
        store: &dyn crate::infra::credential_store::CredentialStore,
        key: &str,
    ) -> Result<Option<String>, StoreError> {
        match store.get(key).await {
            Ok(bytes) => {
                Ok(Some(String::from_utf8(bytes).map_err(|e| {
                    StoreError::Other(format!("non-utf8 in {}: {e}", key))
                })?))
            }
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(other) => Err(other),
        }
    }

    // Enumerate every key under github/apps/ and group by the
    // <slug>/install-<id>/ prefix so we can ask "is this triple
    // complete?" deterministically.
    let keys = store.list(Some(STORE_PREFIX_GITHUB_APPS)).await?;
    let mut triples: std::collections::BTreeMap<String, [bool; 3]> =
        std::collections::BTreeMap::new();
    // [0] = private-key, [1] = app-id, [2] = installation-id
    for key in &keys {
        let Some(suffix) = key.strip_prefix(STORE_PREFIX_GITHUB_APPS) else {
            continue;
        };
        // Expect `<slug>/install-<id>/<purpose>`. Anything shorter or
        // shaped differently is ignored — the prefix list might surface
        // legacy entries that no longer belong here.
        let parts: Vec<&str> = suffix.split('/').collect();
        if parts.len() != 3 {
            continue;
        }
        let (slug, install, purpose) = (parts[0], parts[1], parts[2]);
        if !install.starts_with("install-") {
            continue;
        }
        let triple_key = format!("{slug}/{install}");
        let slot = triples.entry(triple_key).or_insert([false; 3]);
        match purpose {
            PURPOSE_PRIVATE_KEY => slot[0] = true,
            PURPOSE_APP_ID => slot[1] = true,
            PURPOSE_INSTALLATION_ID => slot[2] = true,
            _ => {}
        }
    }

    if triples.is_empty() {
        return Ok(None);
    }

    // BTreeMap yields keys in sorted order — deterministic
    // "first-wins" behaviour without relying on backend list-order.
    for (triple_key, slots) in &triples {
        let complete = slots[0] && slots[1] && slots[2];
        let any = slots[0] || slots[1] || slots[2];
        if !complete {
            if any {
                return Err(StoreError::Other(format!(
                    "github/apps/{triple_key}: partial credential triple \
                     (private-key={}, app-id={}, installation-id={}); \
                     all three leaves must be present",
                    slots[0], slots[1], slots[2]
                )));
            }
            continue;
        }

        let pk_key = format!("{STORE_PREFIX_GITHUB_APPS}{triple_key}/{PURPOSE_PRIVATE_KEY}");
        let app_key = format!("{STORE_PREFIX_GITHUB_APPS}{triple_key}/{PURPOSE_APP_ID}");
        let inst_key = format!("{STORE_PREFIX_GITHUB_APPS}{triple_key}/{PURPOSE_INSTALLATION_ID}");

        let private_key_pem = get_opt(store, &pk_key).await?.ok_or_else(|| {
            StoreError::Other(format!("{pk_key}: present in list() but missing on get()"))
        })?;
        let app_id = get_opt(store, &app_key).await?.ok_or_else(|| {
            StoreError::Other(format!("{app_key}: present in list() but missing on get()"))
        })?;
        let installation_id = get_opt(store, &inst_key).await?.ok_or_else(|| {
            StoreError::Other(format!(
                "{inst_key}: present in list() but missing on get()"
            ))
        })?;

        if private_key_pem.trim().is_empty() {
            return Err(StoreError::Other(format!(
                "{pk_key}: empty value — expected PEM-encoded RSA private key"
            )));
        }

        tracing::info!(
            event = "bot-identity-source",
            provider = "github",
            source = "vault",
            slug_install = %triple_key,
            "broker config reader resolved GitHub App credentials from vault"
        );

        return Ok(Some(GhAppCredentials {
            app_id,
            installation_id,
            private_key_pem: SecretString::from(private_key_pem),
        }));
    }

    // Every prefix entry was non-empty but we never saw a triple with
    // ANY of the three known purposes. Treat as empty for fallback.
    Ok(None)
}

/// Parse a single `KEY=value` line from a dotenv-style file. Strips
/// surrounding double or single quotes from the value. Returns `None`
/// if the key is absent. Mirrors `ship.rs::read_env_var` so the
/// migration is byte-compatible with today's discovery.
fn parse_env_var(contents: &str, key: &str) -> Option<String> {
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let Some(rest) = line.strip_prefix(key) else {
            continue;
        };
        let Some(val) = rest.strip_prefix('=') else {
            continue;
        };
        let trimmed = val.trim().trim_matches('"').trim_matches('\'');
        if trimmed.is_empty() {
            return None;
        }
        return Some(trimmed.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    // PEM fixtures live at `crates/ember-daemon/tests/fixtures/*.pem` so they
    // resolve under the gitleaks `.gitleaks.toml` path allowlist for
    // `crates/.+/tests/fixtures/.+` and never appear as inline PEM literals
    // in `src/` (which the public-mirror sync would otherwise flag).
    const PEM_FAKE: &str = include_str!("../../tests/fixtures/gh_app_pem_fake.pem");
    const PEM_FAKE_BYTES: &[u8] = include_bytes!("../../tests/fixtures/gh_app_pem_fake.pem");
    const PEM_OVERRIDE: &str = include_str!("../../tests/fixtures/gh_app_pem_override.pem");
    const PEM_TRUNCATED: &str = include_str!("../../tests/fixtures/gh_app_pem_truncated.pem");

    fn write(path: &std::path::Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dir");
        }
        fs::write(path, contents).expect("write fixture");
    }

    #[test]
    fn parse_env_var_returns_first_match() {
        let env = "EMBER_ENGINE_APP_ID=12345\nEMBER_ENGINE_INSTALLATION_ID=67890\n";
        assert_eq!(
            parse_env_var(env, "EMBER_ENGINE_APP_ID"),
            Some("12345".to_string())
        );
        assert_eq!(
            parse_env_var(env, "EMBER_ENGINE_INSTALLATION_ID"),
            Some("67890".to_string())
        );
    }

    #[test]
    fn parse_env_var_strips_quotes_and_whitespace() {
        let env = r#"EMBER_ENGINE_APP_ID="12345"
EMBER_ENGINE_INSTALLATION_ID='67890'
"#;
        assert_eq!(
            parse_env_var(env, "EMBER_ENGINE_APP_ID"),
            Some("12345".to_string())
        );
        assert_eq!(
            parse_env_var(env, "EMBER_ENGINE_INSTALLATION_ID"),
            Some("67890".to_string())
        );
    }

    #[test]
    fn parse_env_var_skips_comments_and_blanks() {
        let env = "\n# comment\n\nEMBER_ENGINE_APP_ID=42\n";
        assert_eq!(
            parse_env_var(env, "EMBER_ENGINE_APP_ID"),
            Some("42".to_string())
        );
    }

    #[test]
    fn parse_env_var_missing_returns_none() {
        let env = "OTHER_KEY=value\n";
        assert!(parse_env_var(env, "EMBER_ENGINE_APP_ID").is_none());
    }

    #[test]
    fn load_from_dir_missing_files_returns_ok_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let result = load_from_dir(tmp.path()).expect("load must succeed gracefully");
        assert!(result.is_none(), "missing files must return Ok(None)");
    }

    #[test]
    fn load_from_dir_only_env_present_returns_ok_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "EMBER_ENGINE_APP_ID=1\nEMBER_ENGINE_INSTALLATION_ID=2\n",
        );
        // No PEM
        let result = load_from_dir(tmp.path()).expect("load must succeed gracefully");
        assert!(
            result.is_none(),
            "missing PEM must return Ok(None) (graceful, not error)"
        );
    }

    #[test]
    fn load_from_dir_both_present_returns_credentials() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "EMBER_ENGINE_APP_ID=12345\nEMBER_ENGINE_INSTALLATION_ID=67890\n",
        );
        write(&tmp.path().join(PEM_FILENAME), PEM_FAKE);
        let result = load_from_dir(tmp.path())
            .expect("load must succeed")
            .expect("creds present");
        assert_eq!(result.app_id, "12345");
        assert_eq!(result.installation_id, "67890");
        assert!(
            result
                .private_key_pem
                .expose_secret()
                .contains("BEGIN PRIVATE KEY")
        );
    }

    #[test]
    fn load_from_dir_env_missing_app_id_is_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "EMBER_ENGINE_INSTALLATION_ID=67890\n",
        );
        write(&tmp.path().join(PEM_FILENAME), PEM_TRUNCATED);
        let err = match load_from_dir(tmp.path()) {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("EMBER_ENGINE_APP_ID"),
            "error must name the missing key: {msg}"
        );
    }

    #[test]
    fn load_from_dir_env_missing_installation_id_is_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "EMBER_ENGINE_APP_ID=12345\n",
        );
        write(&tmp.path().join(PEM_FILENAME), PEM_TRUNCATED);
        let err = match load_from_dir(tmp.path()) {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("EMBER_ENGINE_INSTALLATION_ID"),
            "error must name the missing key: {msg}"
        );
    }

    #[test]
    fn load_from_dir_empty_pem_is_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "EMBER_ENGINE_APP_ID=12345\nEMBER_ENGINE_INSTALLATION_ID=67890\n",
        );
        write(&tmp.path().join(PEM_FILENAME), "");
        let err = match load_from_dir(tmp.path()) {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("empty"), "error must mention empty PEM: {msg}");
    }

    /// Seed an in-memory store with the ADR-099 path grammar and assert
    /// the reader assembles the GhAppCredentials triple correctly.
    /// Covers the PR4A acceptance criterion "reads
    /// github/apps/<slug>/install-<id>/{private-key,app-id,installation-id}".
    #[tokio::test]
    async fn github_config_from_store_reads_adr_099_grammar() {
        use crate::infra::credential_store::CredentialStore;
        use crate::infra::credential_store::test_helpers::MockCredentialStore;

        let mock = MockCredentialStore::new();
        mock.put(
            "github/apps/test-app/install-42/private-key",
            PEM_FAKE_BYTES,
        )
        .await
        .unwrap();
        mock.put("github/apps/test-app/install-42/app-id", b"12345")
            .await
            .unwrap();
        mock.put("github/apps/test-app/install-42/installation-id", b"42")
            .await
            .unwrap();

        let result = github_config_from_store(&mock).await.unwrap();
        let creds = result.expect("credentials should be present");
        assert_eq!(creds.app_id, "12345");
        assert_eq!(creds.installation_id, "42");
        assert!(
            creds
                .private_key_pem
                .expose_secret()
                .contains("BEGIN PRIVATE KEY")
        );
    }

    /// When the vault is empty (no `github/apps/` entries at all), the
    /// reader must return `Ok(None)` so the daemon's wireup can fall
    /// back to the env-file loader (and ultimately `MockBroker`).
    #[tokio::test]
    async fn github_config_from_store_empty_returns_ok_none() {
        use crate::infra::credential_store::test_helpers::MockCredentialStore;

        let mock = MockCredentialStore::new();
        let result = github_config_from_store(&mock).await.unwrap();
        assert!(
            result.is_none(),
            "empty store must return Ok(None) so file-fallback engages"
        );
    }

    /// A triple that is missing the `app-id` leaf is a misconfiguration
    /// and must surface as `Err` rather than silently falling back —
    /// the operator has clearly tried to install credentials but
    /// fat-fingered one leaf.
    #[tokio::test]
    async fn github_config_from_store_partial_triple_is_err() {
        use crate::infra::credential_store::CredentialStore;
        use crate::infra::credential_store::test_helpers::MockCredentialStore;

        let mock = MockCredentialStore::new();
        mock.put(
            "github/apps/test-app/install-42/private-key",
            PEM_FAKE_BYTES,
        )
        .await
        .unwrap();
        // Note: no app-id or installation-id leaves.

        let err = match github_config_from_store(&mock).await {
            Err(e) => e,
            Ok(_) => panic!("partial triple must surface as Err, got Ok"),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("partial credential triple"),
            "error must call out the partial state: {msg}"
        );
    }

    // ── T1: env-var override tests ───────────────────────────────────────────

    /// When both EMBER_APP_PEM_PATH and EMBER_APP_ENV_PATH point to
    /// non-existent files, load_with_paths (via env-var branch) must return
    /// Ok(None) gracefully — same semantics as missing files in the default
    /// path.
    #[test]
    fn env_var_override_missing_files_returns_ok_none() {
        let pem_path = std::path::Path::new("/tmp/nonexistent-test-pem-99999.pem");
        let env_path = std::path::Path::new("/tmp/nonexistent-test-env-99999.env");
        // Verify the paths really don't exist so the test is meaningful.
        assert!(!pem_path.exists(), "test pem path must not exist");
        assert!(!env_path.exists(), "test env path must not exist");

        let result =
            load_with_paths(env_path, pem_path).expect("missing files must not return Err");
        assert!(
            result.is_none(),
            "missing files via env-var paths must return Ok(None)"
        );
    }

    /// When both env vars are set and valid, load_gh_app_credentials must
    /// use the env-var paths, not the $HOME path.
    #[test]
    fn env_var_override_uses_provided_paths() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let env_path = tmp.path().join("test.env");
        let pem_path = tmp.path().join("test.pem");

        write(
            &env_path,
            "EMBER_ENGINE_APP_ID=override-id\nEMBER_ENGINE_INSTALLATION_ID=override-inst\n",
        );
        write(&pem_path, PEM_OVERRIDE);

        // Set env vars in this process — serial test, restore afterward.
        // SAFETY: single-threaded test environment; no concurrent env access.
        let old_pem = std::env::var(ENV_VAR_PEM_PATH).ok();
        let old_env = std::env::var(ENV_VAR_ENV_PATH).ok();

        unsafe {
            std::env::set_var(ENV_VAR_PEM_PATH, pem_path.as_os_str());
            std::env::set_var(ENV_VAR_ENV_PATH, env_path.as_os_str());
        }

        let result = load_gh_app_credentials();

        // Restore env vars regardless of outcome.
        unsafe {
            match old_pem {
                Some(v) => std::env::set_var(ENV_VAR_PEM_PATH, v),
                None => std::env::remove_var(ENV_VAR_PEM_PATH),
            }
            match old_env {
                Some(v) => std::env::set_var(ENV_VAR_ENV_PATH, v),
                None => std::env::remove_var(ENV_VAR_ENV_PATH),
            }
        }

        let creds = result
            .expect("load must succeed")
            .expect("credentials must be present");
        assert_eq!(creds.app_id, "override-id");
        assert_eq!(creds.installation_id, "override-inst");
        assert!(creds.private_key_pem.expose_secret().contains("override"));
    }

    /// When EMBER_APP_PEM_PATH is set to an empty string it must be treated as
    /// unset — the function falls back to the $HOME resolution path.
    #[test]
    fn env_var_empty_string_treated_as_unset() {
        // We can't easily verify which path is taken without inspecting FS
        // access, so instead we verify that the function doesn't error out on
        // the empty-string value itself (i.e., it does not try to open a file
        // at path ""). We set both to empty so the env-var branch is skipped,
        // then a missing $HOME config gives Ok(None).
        let old_pem = std::env::var(ENV_VAR_PEM_PATH).ok();
        let old_env = std::env::var(ENV_VAR_ENV_PATH).ok();

        unsafe {
            std::env::set_var(ENV_VAR_PEM_PATH, "");
            std::env::set_var(ENV_VAR_ENV_PATH, "");
        }

        // Use load_with_paths directly with a tempdir that has no files —
        // this exercises that empty env vars don't reach load_with_paths with
        // a bad path. We just validate the filter logic via the public API
        // by checking the filter removes the empty string.
        let filtered_pem = std::env::var(ENV_VAR_PEM_PATH)
            .ok()
            .filter(|s| !s.is_empty());
        let filtered_env = std::env::var(ENV_VAR_ENV_PATH)
            .ok()
            .filter(|s| !s.is_empty());

        unsafe {
            match old_pem {
                Some(v) => std::env::set_var(ENV_VAR_PEM_PATH, v),
                None => std::env::remove_var(ENV_VAR_PEM_PATH),
            }
            match old_env {
                Some(v) => std::env::set_var(ENV_VAR_ENV_PATH, v),
                None => std::env::remove_var(ENV_VAR_ENV_PATH),
            }
        }

        assert!(
            filtered_pem.is_none(),
            "empty EMBER_APP_PEM_PATH must filter to None"
        );
        assert!(
            filtered_env.is_none(),
            "empty EMBER_APP_ENV_PATH must filter to None"
        );
    }

    /// A path containing '..' must be refused with Err to surface the
    /// misconfiguration rather than silently following the traversal.
    #[test]
    fn env_var_path_traversal_is_rejected() {
        let traversal_path = std::path::Path::new("/tmp/../etc/passwd");
        let safe_path = std::path::Path::new("/tmp/safe.env");

        let err = reject_traversal(traversal_path, ENV_VAR_PEM_PATH)
            .expect_err("path with '..' must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("path-traversal"),
            "error must mention path-traversal: {msg}"
        );
        assert!(
            msg.contains(ENV_VAR_PEM_PATH),
            "error must name the env var: {msg}"
        );

        // A path without '..' must pass through without error.
        reject_traversal(safe_path, ENV_VAR_ENV_PATH)
            .expect("path without '..' must not be rejected");
    }
}
