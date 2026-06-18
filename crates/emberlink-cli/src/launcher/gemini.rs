//! `ember gemini` launcher (ADR 215 §2).
//!
//! Governs Google's Gemini CLI on its free "Sign in with Google" (Code Assist)
//! OAuth tier. Mirrors the codex HOST lane's credential-safe shape: the daemon
//! stands up a per-session loopback proxy that injects a daemon-refreshed OAuth
//! Bearer server-side, and this launcher relocates the gemini-cli's home so the
//! child cannot reach the durable credential.
//!
//! Structural credential absence (operator-locked, ADR 215 §2):
//! - The daemon holds the durable `refresh_token` (harvested into the vault by
//!   `ember init --for gemini`; refreshed in-daemon by `resolve_oauth_bearer`).
//! - This launcher relocates `GEMINI_CLI_HOME` to a per-session dir and writes a
//!   SANITIZED `oauth_creds.json` there — the host's short-lived `access_token`
//!   (which the proxy strips and replaces upstream anyway) with the durable
//!   `refresh_token` DROPPED and a far-future `expiry_date` so the CLI never
//!   attempts a (doomed, refresh-token-less) refresh against Google directly.
//! - `CODE_ASSIST_ENDPOINT` points the CLI's Code Assist calls at the loopback
//!   proxy; `GOOGLE_GENAI_USE_GCA=true` selects the OAuth (`LOGIN_WITH_GOOGLE`)
//!   lane; a clean `settings.json` (no `security.auth.selectedType`) lets that
//!   env selection win.
//!
//! Fail-closed: any IO/parse error PROPAGATES (the caller's `?` aborts the
//! launch before the child spawns) — never log-and-continue, which could let the
//! gemini-cli fall through to a host login or an ambient credential.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::launcher::claude_code::{
    cohort_a_construct_specs, managed_prod_construct_specs, maybe_print_host_mode_disclaimer,
    prod_required_constructs_present, verify_construct_manifest_before_spawn,
};
use crate::launcher::core::{LauncherInvocation, SessionRegistration, resolve_shadow_dir};
use crate::launcher::path_shadow::{ConstructSpec, install_path_shadow, shadow_bin_dir};
use crate::launcher::session_rpc::{
    register_session_rpc_with_workflow_and_workspace_ref, with_session_close,
};

const GEMINI_BIN_CANDIDATES: &[&str] = &["gemini"];

/// Ambient Google credential / auth-selector env stripped from the child so the
/// brokered OAuth lane is the ONLY reachable auth path. We do NOT strip
/// `GOOGLE_GENAI_USE_GCA` — the launcher SETS it to `true` (selects the
/// `LOGIN_WITH_GOOGLE` lane, highest precedence in the gemini-cli's
/// `getAuthTypeFromEnv`).
///
/// CRITICAL (adversarial H1/M1): this is the load-bearing backstop. Even if a
/// leftover `security.auth.selectedType` (from a system / workspace settings
/// layer that out-ranks our pinned user setting) selects a NON-OAuth lane, the
/// child must have NO ambient credential to authenticate that lane with — so
/// it fails closed rather than silently bypassing the proxy with a real
/// credential. So we strip every ambient credential input the gemini-cli reads:
/// the api-key lane (`GEMINI_API_KEY`/`GOOGLE_API_KEY`), the gateway lane
/// (`GOOGLE_GEMINI_BASE_URL`), and the Vertex / ADC lanes
/// (`GOOGLE_GENAI_USE_VERTEXAI`, `GOOGLE_CLOUD_PROJECT[_ID]`,
/// `GOOGLE_CLOUD_LOCATION`, `GOOGLE_APPLICATION_CREDENTIALS`,
/// `GOOGLE_CLOUD_ACCESS_TOKEN`, `CLOUD_SHELL`, `GEMINI_CLI_USE_COMPUTE_ADC`).
/// `GEMINI_FORCE_ENCRYPTED_FILE_STORAGE` is stripped so the CLI reads our
/// relocated sanitized `oauth_creds.json` (the file lane) rather than the OS
/// keychain — which would otherwise hold the durable refresh token.
const GEMINI_STRIPPED_ENV: &[&str] = &[
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_GENAI_USE_VERTEXAI",
    "GOOGLE_GEMINI_BASE_URL",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_PROJECT_ID",
    "GOOGLE_CLOUD_LOCATION",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_ACCESS_TOKEN",
    "CLOUD_SHELL",
    "GEMINI_CLI_USE_COMPUTE_ADC",
    "GEMINI_FORCE_ENCRYPTED_FILE_STORAGE",
];

/// `expiry_date` (ms epoch) far enough in the future that google-auth-library
/// never treats the cached token as expiring — so the gemini-cli never attempts
/// a refresh (which would fail, since we drop the `refresh_token`). The proxy
/// replaces the Bearer on every upstream call regardless of this value. Year
/// 2100; a fixed constant so the launcher needs no wall-clock read.
const SANITIZED_TOKEN_EXPIRY_MS: u64 = 4_102_444_800_000;

pub fn resolve_gemini_bin() -> String {
    resolve_gemini_bin_path()
        .unwrap_or_else(|_| PathBuf::from("gemini"))
        .to_string_lossy()
        .into_owned()
}

pub fn resolve_gemini_bin_path() -> io::Result<PathBuf> {
    if let Ok(override_bin) = std::env::var("EMBER_GEMINI_BIN")
        && !override_bin.trim().is_empty()
    {
        return Ok(PathBuf::from(override_bin));
    }

    for binary in GEMINI_BIN_CANDIDATES {
        let Some(path) = which_on_path(binary) else {
            continue;
        };
        if looks_like_mise_shim(&path)
            && let Some(real_bin) = resolve_mise_managed_binary(binary)
        {
            return Ok(real_bin);
        }
        return Ok(path);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "could not resolve `gemini` on PATH; install the Gemini CLI or set EMBER_GEMINI_BIN to its path",
    ))
}

pub fn resolve_persona_name() -> String {
    if let Ok(v) = std::env::var("EMBER_PERSONA")
        && !v.is_empty()
    {
        return v;
    }
    crate::launcher::default_persona_id_for_runtime("gemini", None)
}

fn resolve_safe_launch_cwd() -> PathBuf {
    std::env::current_dir()
        .ok()
        .filter(|path| path.exists())
        .or_else(|| resolve_home_dir().filter(|path| path.exists()))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

fn resolve_home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .or_else(dirs_next::home_dir)
}

fn which_on_path(binary: &str) -> Option<PathBuf> {
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let candidate = dir.join(binary);
        if path_is_executable(&candidate).ok()? {
            return Some(candidate);
        }
    }
    None
}

fn path_is_executable(path: &Path) -> io::Result<bool> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    if !metadata.is_file() {
        return Ok(false);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        Ok(metadata.permissions().mode() & 0o111 != 0)
    }

    #[cfg(not(unix))]
    {
        Ok(true)
    }
}

fn looks_like_mise_shim(path: &Path) -> bool {
    let path_text = path.to_string_lossy();
    path_text.contains("/mise/shims/") || path.file_name().is_some_and(|name| name == "mise")
}

fn resolve_mise_managed_binary(binary: &str) -> Option<PathBuf> {
    let output = Command::new("mise")
        .arg("which")
        .arg(binary)
        .current_dir(resolve_safe_launch_cwd())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let resolved = String::from_utf8(output.stdout).ok()?;
    let trimmed = resolved.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

/// The host gemini config dir: `$GEMINI_CLI_HOME/.gemini` if `GEMINI_CLI_HOME`
/// is set (the gemini-cli's `homedir()` honours it), else `~/.gemini`.
fn host_gemini_dir() -> Option<PathBuf> {
    let home = std::env::var_os("GEMINI_CLI_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(resolve_home_dir)?;
    Some(home.join(".gemini"))
}

/// Relocate `GEMINI_CLI_HOME` to a per-session, sha256(canonical-host-home)-keyed
/// directory under the operator cache, and write a clean `settings.json` + a
/// SANITIZED `oauth_creds.json` (host access token, NO refresh token, far-future
/// expiry) into its `.gemini/` subdir. Returns the relocated home root to export
/// as `GEMINI_CLI_HOME`.
///
/// Why relocate: the gemini-cli reads `oauth_creds.json` from
/// `homedir()/.gemini`, and `homedir()` honours `GEMINI_CLI_HOME`. Relocating to
/// a per-session dir whose `oauth_creds.json` carries NO `refresh_token` means
/// the child cannot reach the durable credential (daemon-only) — the proxy
/// injects the daemon-refreshed Bearer on every upstream call. The host's own
/// `~/.gemini/oauth_creds.json` (with the real refresh token) is never exposed
/// to the child.
///
/// Fail-closed: a missing host `oauth_creds.json` is an ERROR (the operator must
/// sign in with Google on the host first), not a silent fall-through to a fresh
/// in-CLI browser login.
fn write_session_gemini_home() -> io::Result<PathBuf> {
    use sha2::{Digest, Sha256};

    let host_gemini = host_gemini_dir()
        .ok_or_else(|| io::Error::other("could not resolve a host GEMINI_CLI_HOME or home dir"))?;

    // Read + sanitize the host oauth_creds BEFORE relocating, so a missing
    // sign-in fails closed with actionable guidance.
    let host_creds_path = host_gemini.join("oauth_creds.json");
    let sanitized_creds = sanitize_host_oauth_creds(&host_creds_path)?;

    // sha256(canonical host gemini dir) keys the relocation, mirroring codex's
    // CODEX_HOME relocation. canonicalize() requires the path to exist; fall back
    // to the lexical path otherwise (the only invariant is that the relocated
    // path DIFFERS from the host path, which it always will).
    let canonical = std::fs::canonicalize(&host_gemini).unwrap_or(host_gemini);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_os_str().as_encoded_bytes());
    let home_key = hex::encode(hasher.finalize());

    // Per-session relocation root under the OPERATOR cache dir (owner-only): the
    // `ember gemini` launcher runs as the operator uid, while `~/.ember` is owned
    // by the daemon uid on a separate-uid install (writing there fails closed
    // with EPERM). Mirrors `codex-sessions`.
    let session_root = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| resolve_home_dir().map(|h| h.join(".cache")))
        .ok_or_else(|| io::Error::other("could not resolve cache dir for gemini session root"))?
        .join("emberlink")
        .join("gemini-sessions")
        .join(&home_key);
    let gemini_subdir = session_root.join(".gemini");
    std::fs::create_dir_all(&gemini_subdir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&session_root, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&gemini_subdir, std::fs::Permissions::from_mode(0o700))?;
    }

    // USER settings: positively PIN the OAuth lane
    // (`security.auth.selectedType = "oauth-personal"`). The gemini-cli's
    // interactive path requires a `selectedType` (env alone only wins on the
    // non-interactive path), so pinning it here makes `ember gemini` select the
    // brokered OAuth lane without an auth dialog (adversarial L2) and defends the
    // user layer against a stale api-key/vertex selection.
    std::fs::write(
        gemini_subdir.join("settings.json"),
        "{\"security\":{\"auth\":{\"selectedType\":\"oauth-personal\"}}}\n",
    )?;
    // SYSTEM settings neutralizer (adversarial H1): the gemini-cli merges five
    // settings layers and the SYSTEM layer WINS LAST — a host/MDM system
    // `settings.json` carrying `selectedType: "vertex-ai"` (or an `enforcedType`)
    // would out-rank our user pin and the env. We point
    // `GEMINI_CLI_SYSTEM_SETTINGS_PATH` (honoured by the CLI's
    // `getSystemSettingsPath`) at this empty file so the system layer cannot
    // carry a competing selection. The launcher exports the path in
    // `run_with_registration_with_workspace_ref`.
    std::fs::write(gemini_subdir.join("system-settings.json"), "{}\n")?;
    std::fs::write(gemini_subdir.join("oauth_creds.json"), sanitized_creds)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            gemini_subdir.join("oauth_creds.json"),
            std::fs::Permissions::from_mode(0o600),
        )?;
    }

    Ok(session_root)
}

/// The relocated system-settings neutralizer path for a given relocated
/// `GEMINI_CLI_HOME` root (see [`write_session_gemini_home`]).
fn system_settings_path_for(gemini_home: &Path) -> PathBuf {
    gemini_home.join(".gemini").join("system-settings.json")
}

/// Read the host `oauth_creds.json`, drop the durable `refresh_token`, and set a
/// far-future `expiry_date` so the child CLI is "signed in" (won't trigger a
/// browser login) but cannot refresh against Google directly. The proxy replaces
/// the Bearer upstream regardless. Returns the serialized sanitized blob.
fn sanitize_host_oauth_creds(host_creds_path: &Path) -> io::Result<String> {
    let raw = match std::fs::read(host_creds_path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "no Gemini Code Assist sign-in found at {}.\n  Sign in with Google on the host first (run `gemini` once and choose \"Login with Google\"), then run `ember init --for gemini` to import it, before `ember gemini`.",
                    host_creds_path.display()
                ),
            ));
        }
        Err(e) => return Err(e),
    };

    let parsed: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "parse host gemini oauth_creds at {}: {e}; re-run the Gemini \"Login with Google\" flow on the host",
                host_creds_path.display()
            ),
        )
    })?;

    let access_token = parsed
        .get("access_token")
        .and_then(|v| v.as_str())
        .unwrap_or("ember-brokered-placeholder");
    let token_type = parsed
        .get("token_type")
        .and_then(|v| v.as_str())
        .unwrap_or("Bearer");

    // Build the sanitized blob: keep the short-lived access token + scope/id
    // (the proxy replaces the Bearer upstream), set a far-future expiry, and OMIT
    // `refresh_token` (the durable credential — daemon-only, operator-locked).
    let mut sanitized = serde_json::Map::new();
    sanitized.insert("access_token".to_string(), serde_json::json!(access_token));
    sanitized.insert("token_type".to_string(), serde_json::json!(token_type));
    if let Some(scope) = parsed.get("scope").and_then(|v| v.as_str()) {
        sanitized.insert("scope".to_string(), serde_json::json!(scope));
    }
    if let Some(id_token) = parsed.get("id_token").and_then(|v| v.as_str()) {
        sanitized.insert("id_token".to_string(), serde_json::json!(id_token));
    }
    sanitized.insert(
        "expiry_date".to_string(),
        serde_json::json!(SANITIZED_TOKEN_EXPIRY_MS),
    );

    let mut out = serde_json::to_string_pretty(&serde_json::Value::Object(sanitized))
        .map_err(|e| io::Error::other(format!("serialize sanitized gemini oauth_creds: {e}")))?;
    out.push('\n');
    Ok(out)
}

pub fn run_with_registration(
    bin: &str,
    extra_args: &[String],
    persona: &str,
    registration: &SessionRegistration,
    socket_path: &Path,
    shadow_dir: &Path,
) -> io::Result<i32> {
    run_with_registration_with_workspace_ref(
        bin,
        extra_args,
        persona,
        registration,
        socket_path,
        shadow_dir,
        None,
    )
}

fn run_with_registration_with_workspace_ref(
    bin: &str,
    extra_args: &[String],
    persona: &str,
    registration: &SessionRegistration,
    socket_path: &Path,
    shadow_dir: &Path,
    workspace_ref: Option<&str>,
) -> io::Result<i32> {
    let target_dir = std::env::current_dir()?;
    let launch_cwd = resolve_safe_launch_cwd();
    let mut extra_env = vec![
        ("EMBER_PERSONA".to_string(), persona.to_string()),
        (
            "EMBER_BROKER_CWD".to_string(),
            target_dir.to_string_lossy().into_owned(),
        ),
    ];
    if let Some(ref git_proxy_url) = registration.git_proxy_url {
        extra_env.push(("EMBER_GIT_PROXY_URL".to_string(), git_proxy_url.clone()));
    }
    if let Some(ref sock) = registration.ssh_auth_sock {
        extra_env.push(("SSH_AUTH_SOCK".to_string(), sock.clone()));
    }
    if let Some(workspace_ref) = workspace_ref {
        extra_env.push((
            crate::launcher::worktree::WORKSPACE_REF_ENV.to_string(),
            workspace_ref.to_string(),
        ));
    }
    if let Some(runtime_id) = workspace_ref
        .and_then(|value| value.strip_prefix("managed_worktree:"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        extra_env.push((
            crate::dev_runtime::DEV_RUNTIME_ID_ENV.to_string(),
            runtime_id.to_string(),
        ));
    }

    // ADR 215 §2 — when the daemon stood up the per-session Code Assist loopback
    // proxy, relocate GEMINI_CLI_HOME to a sha256(canonical)-keyed dir with a
    // sanitized (refresh-token-less) oauth_creds + clean settings, point the CLI
    // at the proxy (CODE_ASSIST_ENDPOINT) on the OAuth lane (GOOGLE_GENAI_USE_GCA),
    // and strip ambient Google credentials. Fail-closed: a relocation/sanitize
    // failure aborts the launch (the `?`) rather than letting the gemini-cli fall
    // back to a host login or ambient credential.
    let mut stripped_env: &[&str] = &[];
    match registration.gemini_proxy_url.as_deref() {
        Some(endpoint) => {
            let gemini_home = write_session_gemini_home()?;
            let system_settings = system_settings_path_for(&gemini_home);
            extra_env.push((
                "GEMINI_CLI_HOME".to_string(),
                gemini_home.to_string_lossy().into_owned(),
            ));
            // Neutralize the system settings layer (adversarial H1) so it cannot
            // out-rank our pinned OAuth selection.
            extra_env.push((
                "GEMINI_CLI_SYSTEM_SETTINGS_PATH".to_string(),
                system_settings.to_string_lossy().into_owned(),
            ));
            extra_env.push(("CODE_ASSIST_ENDPOINT".to_string(), endpoint.to_string()));
            extra_env.push(("GOOGLE_GENAI_USE_GCA".to_string(), "true".to_string()));
            stripped_env = GEMINI_STRIPPED_ENV;
        }
        None => {
            // Fail closed (adversarial L1): a gemini session with no daemon
            // Code Assist proxy URL must NOT launch — without relocation + strip
            // the child would fall through to the host `~/.gemini` (real refresh
            // token) and ambient credentials with no brokering. This only happens
            // against a daemon too old to carry the ADR 215 §2 gemini lane.
            return Err(io::Error::other(
                "register_session returned no gemini Code Assist proxy URL — the daemon is too old for the brokered Gemini lane (ADR 215 §2). Refusing to launch unbrokered. Update emberd (`sudo ember daemon install`) and retry.",
            ));
        }
    }

    with_session_close(
        &registration.session_id,
        socket_path,
        "ember gemini",
        "ember gemini",
        || {
            crate::launcher::core::run_with_registration(
                LauncherInvocation {
                    launcher_name: "gemini",
                    binary: bin,
                    extra_args,
                    socket_path,
                    shadow_bin_dir: shadow_dir,
                    current_dir: Some(&launch_cwd),
                    stripped_env,
                },
                registration,
                extra_env,
            )
        },
    )
}

pub fn launch_gemini(extra_args: &[String], socket_path: &Path) -> io::Result<i32> {
    launch_gemini_with_shadow_dir(extra_args, socket_path, None)
}

pub fn launch_gemini_with_shadow_dir(
    extra_args: &[String],
    socket_path: &Path,
    shadow_dir_override: Option<&Path>,
) -> io::Result<i32> {
    let bin = resolve_gemini_bin();
    let persona = resolve_persona_name();
    let shadow_dir = shadow_dir_override
        .map(PathBuf::from)
        .unwrap_or_else(resolve_shadow_dir);
    let construct_specs = cohort_a_construct_specs();
    launch_gemini_with_shadow_dir_and_constructs(
        extra_args,
        socket_path,
        &shadow_dir,
        &bin,
        &persona,
        &construct_specs,
    )
}

pub fn launch_gemini_with_shadow_dir_and_constructs(
    extra_args: &[String],
    socket_path: &Path,
    shadow_dir: &Path,
    bin: &str,
    persona: &str,
    construct_specs: &[ConstructSpec],
) -> io::Result<i32> {
    launch_gemini_with_shadow_dir_and_constructs_with_workspace_ref(
        extra_args,
        socket_path,
        shadow_dir,
        bin,
        persona,
        construct_specs,
        false,
        None,
        None,
        None,
    )
}

// Launcher plumbing signature matches the shared harness registry adapter.
#[allow(clippy::too_many_arguments)]
pub fn launch_gemini_with_shadow_dir_and_constructs_with_workspace_ref(
    extra_args: &[String],
    socket_path: &Path,
    shadow_dir: &Path,
    bin: &str,
    persona: &str,
    construct_specs: &[ConstructSpec],
    authority_strict: bool,
    delegated_template: Option<&str>,
    attach_runtime_persona_id: Option<&str>,
    workspace_ref: Option<&str>,
) -> io::Result<i32> {
    crate::launcher::core::ensure_broker_safe_launch_cwd("gemini")?;
    install_gemini_path_shadow(shadow_dir, construct_specs)?;

    let delegation_template_name =
        crate::launcher::claude_code::resolve_delegation_template_for_launch(
            delegated_template,
            "ember gemini",
        )
        .map_err(io::Error::other)?;

    let registration = register_session_rpc_with_workflow_and_workspace_ref(
        persona,
        socket_path,
        delegation_template_name.as_deref(),
        authority_strict,
        attach_runtime_persona_id,
        workspace_ref,
        "ember gemini",
        "ember gemini",
    )
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("not found")
            || msg.contains("no such persona")
            || msg.contains("unknown persona")
        {
            io::Error::new(
                e.kind(),
                "no Gemini persona found.\n  Run `ember init --for gemini` to import your Google Code Assist sign-in and provision the brokered grant, or set $EMBER_PERSONA to an existing persona name.",
            )
        } else {
            e
        }
    })?;

    maybe_print_host_mode_disclaimer()?;

    let bin_dir = shadow_bin_dir(shadow_dir);
    run_with_registration_with_workspace_ref(
        bin,
        extra_args,
        persona,
        &registration,
        socket_path,
        &bin_dir,
        workspace_ref,
    )
}

fn install_gemini_path_shadow(
    shadow_dir: &Path,
    construct_specs: &[ConstructSpec],
) -> io::Result<()> {
    if let Some(verified_constructs) = verify_construct_manifest_before_spawn(construct_specs)? {
        crate::launcher::claude_code::install_verified_path_shadow(shadow_dir, &verified_constructs)
    } else {
        install_path_shadow(shadow_dir, construct_specs)
    }
}

pub fn prod_construct_specs_or_error() -> io::Result<Vec<ConstructSpec>> {
    let specs = managed_prod_construct_specs();
    if !prod_required_constructs_present(&specs) {
        return Err(io::Error::other(
            "prod construct bundle is incomplete: expected managed `ember-gh` and `ember-git` from the installed product, not repo-built target artifacts. Repair or reinstall the managed product before running `ember gemini --prod`.",
        ));
    }
    Ok(specs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = std::env::var_os(key);
            // SAFETY: tests serialise environment mutation with ENV_LOCK.
            unsafe { std::env::set_var(key, value.as_ref()) };
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            // SAFETY: tests serialise environment mutation with ENV_LOCK.
            unsafe { std::env::remove_var(key) };
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                // SAFETY: tests serialise environment mutation with ENV_LOCK.
                unsafe { std::env::set_var(self.key, previous) };
            } else {
                // SAFETY: tests serialise environment mutation with ENV_LOCK.
                unsafe { std::env::remove_var(self.key) };
            }
        }
    }

    #[test]
    fn resolve_gemini_bin_honors_override() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set("EMBER_GEMINI_BIN", "/opt/custom-gemini");
        assert_eq!(
            resolve_gemini_bin_path().unwrap(),
            PathBuf::from("/opt/custom-gemini")
        );
    }

    #[test]
    fn resolve_persona_name_defaults_to_gemini_default() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::remove("EMBER_PERSONA");
        assert_eq!(resolve_persona_name(), "gemini-default");
    }

    #[test]
    fn sanitize_drops_refresh_token_and_pins_far_future_expiry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let creds = tmp.path().join("oauth_creds.json");
        std::fs::write(
            &creds,
            r#"{"access_token":"ya29.host-real","refresh_token":"1//host-durable-secret","token_type":"Bearer","scope":"https://www.googleapis.com/auth/cloud-platform","id_token":"eyJhbGc","expiry_date":1718000000000}"#,
        )
        .expect("write host creds");

        let out = sanitize_host_oauth_creds(&creds).expect("sanitize");
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("parse sanitized");

        // The durable refresh token MUST NOT survive into the child's home.
        assert!(
            parsed.get("refresh_token").is_none(),
            "refresh_token must be dropped from the relocated oauth_creds"
        );
        assert!(
            !out.contains("host-durable-secret"),
            "no trace of the durable refresh token in the serialized child creds"
        );
        // The short-lived access token is preserved (the proxy replaces it upstream).
        assert_eq!(
            parsed.get("access_token").and_then(|v| v.as_str()),
            Some("ya29.host-real")
        );
        assert_eq!(
            parsed.get("token_type").and_then(|v| v.as_str()),
            Some("Bearer")
        );
        // Far-future expiry suppresses the (doomed, refresh-token-less) refresh.
        assert_eq!(
            parsed.get("expiry_date").and_then(|v| v.as_u64()),
            Some(SANITIZED_TOKEN_EXPIRY_MS)
        );
    }

    #[test]
    fn sanitize_missing_host_creds_fails_closed_with_guidance() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("nope").join("oauth_creds.json");
        let err = sanitize_host_oauth_creds(&missing).expect_err("must fail closed");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(
            err.to_string().contains("Sign in with Google"),
            "missing-creds error must guide the operator to sign in: {err}"
        );
    }

    #[test]
    fn stripped_env_covers_ambient_credential_inputs() {
        // Adversarial H1/M1: the strip list is the load-bearing backstop — every
        // ambient credential input that a leftover non-OAuth `selectedType` could
        // authenticate with MUST be stripped so the child fails closed instead of
        // bypassing the proxy with a real credential.
        for required in [
            "GEMINI_API_KEY",
            "GOOGLE_API_KEY",
            "GOOGLE_GENAI_USE_VERTEXAI",
            "GOOGLE_GEMINI_BASE_URL",
            "GOOGLE_CLOUD_PROJECT",
            "GOOGLE_CLOUD_LOCATION",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GOOGLE_CLOUD_ACCESS_TOKEN",
            "GEMINI_FORCE_ENCRYPTED_FILE_STORAGE",
        ] {
            assert!(
                GEMINI_STRIPPED_ENV.contains(&required),
                "GEMINI_STRIPPED_ENV must strip the ambient credential input {required}"
            );
        }
        // We must NOT strip the OAuth lane selector — the launcher SETS it.
        assert!(!GEMINI_STRIPPED_ENV.contains(&"GOOGLE_GENAI_USE_GCA"));
    }

    #[test]
    fn write_session_home_pins_oauth_neutralizes_system_and_drops_refresh_token() {
        let _lock = ENV_LOCK.lock().unwrap();
        let host = tempfile::tempdir().expect("host tmp");
        let cache = tempfile::tempdir().expect("cache tmp");
        std::fs::create_dir_all(host.path().join(".gemini")).expect("host .gemini");
        std::fs::write(
            host.path().join(".gemini").join("oauth_creds.json"),
            r#"{"access_token":"ya29.real","refresh_token":"1//durable-secret","token_type":"Bearer","scope":"s","expiry_date":1718000000000}"#,
        )
        .expect("host creds");

        let _home = EnvGuard::set("GEMINI_CLI_HOME", host.path());
        let _cache_guard = EnvGuard::set("XDG_CACHE_HOME", cache.path());

        let session_root = write_session_gemini_home().expect("relocate");
        let gemini_dir = session_root.join(".gemini");

        // OAuth lane pinned in the relocated USER settings (L2 + user-layer defense).
        let settings = std::fs::read_to_string(gemini_dir.join("settings.json")).unwrap();
        assert!(
            settings.contains("oauth-personal"),
            "relocated settings must pin selectedType=oauth-personal: {settings}"
        );
        // System-settings neutralizer present + empty (H1).
        assert_eq!(
            std::fs::read_to_string(gemini_dir.join("system-settings.json")).unwrap(),
            "{}\n"
        );
        assert_eq!(
            system_settings_path_for(&session_root),
            gemini_dir.join("system-settings.json")
        );
        // Sanitized creds: durable refresh token dropped.
        let creds = std::fs::read_to_string(gemini_dir.join("oauth_creds.json")).unwrap();
        assert!(!creds.contains("durable-secret"), "refresh token must not reach the child home");
        assert!(creds.contains("ya29.real"), "short-lived access token preserved");
        // Relocated under the operator cache, not the host home.
        assert!(session_root.starts_with(cache.path()));
    }

    #[test]
    fn sanitize_tolerates_placeholder_access_token_when_absent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let creds = tmp.path().join("oauth_creds.json");
        // A creds blob with only a refresh token (no access token) still yields a
        // usable sanitized blob (placeholder access token; proxy injects the real
        // Bearer) — and still drops the refresh token.
        std::fs::write(&creds, r#"{"refresh_token":"1//durable","token_type":"Bearer"}"#)
            .expect("write");
        let out = sanitize_host_oauth_creds(&creds).expect("sanitize");
        assert!(!out.contains("durable"), "refresh token dropped");
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            parsed.get("access_token").and_then(|v| v.as_str()),
            Some("ember-brokered-placeholder")
        );
    }
}
