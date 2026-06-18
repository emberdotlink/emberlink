//! `ember codex` launcher.
//!
//! This mirrors the shipped `ember claude` host-launch contract:
//! install the PATH shadow, register a daemon session, inject Ember session
//! env vars into the child, and close the session on exit.

use std::fs;
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

pub fn resolve_codex_bin() -> String {
    resolve_codex_bin_path()
        .unwrap_or_else(|_| PathBuf::from("codex"))
        .to_string_lossy()
        .into_owned()
}

pub fn resolve_codex_bin_path() -> io::Result<PathBuf> {
    if let Ok(override_bin) = std::env::var("EMBER_CODEX_BIN")
        && !override_bin.trim().is_empty()
    {
        return Ok(PathBuf::from(override_bin));
    }

    let Some(path) = which_on_path("codex") else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "could not resolve `codex` on PATH",
        ));
    };

    if looks_like_mise_shim(&path)
        && let Some(real_bin) = resolve_mise_managed_binary("codex")
    {
        return Ok(real_bin);
    }

    Ok(path)
}

pub fn resolve_codex_runtime_root() -> io::Result<PathBuf> {
    let bin = resolve_codex_bin_path()?;
    if let Some(parent) = bin.parent()
        && parent.file_name().is_some_and(|name| name == "bin")
        && let Some(root) = parent.parent()
    {
        return Ok(root.to_path_buf());
    }
    bin.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other(format!("codex binary has no parent: {}", bin.display())))
}

fn resolve_home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .or_else(dirs_next::home_dir)
}

pub fn resolve_container_codex_runtime_root() -> io::Result<PathBuf> {
    if let Ok(override_root) = std::env::var("EMBER_CODEX_CONTAINER_RUNTIME_ROOT")
        && !override_root.trim().is_empty()
    {
        return Ok(PathBuf::from(override_root));
    }

    let host_root = resolve_codex_runtime_root()?;
    let version = installed_codex_version(&host_root)?;
    let arch = container_codex_arch()?;
    let cache_root = codex_container_runtime_cache_root()?;
    let target_root = cache_root.join(format!("linux-{arch}")).join(&version);
    if container_codex_runtime_is_ready(&target_root, &version, arch)? {
        return Ok(target_root);
    }

    stage_container_codex_runtime(&host_root, &version, arch, &target_root)?;
    Ok(target_root)
}

pub fn resolve_codex_config_dir() -> Option<PathBuf> {
    let home = resolve_home_dir()?;
    let config_dir = home.join(".codex");
    config_dir.exists().then_some(config_dir)
}

fn codex_portable_auth_path(config_dir: &Path) -> PathBuf {
    config_dir.join("auth.json")
}

pub fn require_codex_config_dir_for_isolated() -> io::Result<PathBuf> {
    let Some(config_dir) = resolve_codex_config_dir() else {
        return Err(io::Error::other(
            "no host Codex auth state found at `~/.codex/auth.json`. Run `codex login` on the host first, or use `codex login --device-auth` on a headless host, or use `ember codex --host` until native auth is ready.",
        ));
    };

    let auth_path = codex_portable_auth_path(&config_dir);
    if !auth_path.is_file() {
        return Err(io::Error::other(format!(
            "no portable host Codex auth state found at `{}`. `ember init --for codex` can create `~/.codex/hooks.json`, but isolated `ember codex` needs the host login to materialize `auth.json`. Run `codex login` on the host first, or use `codex login --device-auth` on a headless host, or use `ember codex --host` until native auth is ready.",
            auth_path.display()
        )));
    }

    Ok(config_dir)
}

pub fn resolve_persona_name() -> String {
    if let Ok(v) = std::env::var("EMBER_PERSONA")
        && !v.is_empty()
    {
        return v;
    }
    crate::onboarding::codex::codex_persona_name()
}

fn resolve_safe_launch_cwd() -> PathBuf {
    std::env::current_dir()
        .ok()
        .filter(|path| path.exists())
        .or_else(|| resolve_home_dir().filter(|path| path.exists()))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
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

fn codex_container_runtime_cache_root() -> io::Result<PathBuf> {
    Ok(dirs_next::data_local_dir()
        .unwrap_or_else(|| {
            resolve_home_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join(".local")
                .join("share")
        })
        .join("emberlink")
        .join("codex-runtime"))
}

fn installed_codex_version(runtime_root: &Path) -> io::Result<String> {
    let package_json = runtime_root
        .join("lib")
        .join("node_modules")
        .join("@openai")
        .join("codex")
        .join("package.json");
    let raw = fs::read_to_string(&package_json)?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|err| io::Error::other(format!("parse {}: {err}", package_json.display())))?;
    value
        .get("version")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| io::Error::other(format!("missing version in {}", package_json.display())))
}

fn container_codex_runtime_is_ready(
    runtime_root: &Path,
    version: &str,
    arch: &str,
) -> io::Result<bool> {
    if !runtime_root.join("bin").join("codex").exists() {
        return Ok(false);
    }
    let package_json = runtime_root
        .join("lib")
        .join("node_modules")
        .join("@openai")
        .join("codex")
        .join("package.json");
    let raw = match fs::read_to_string(&package_json) {
        Ok(raw) => raw,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    let value: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|err| io::Error::other(format!("parse {}: {err}", package_json.display())))?;
    let top_level_ok = value
        .get("version")
        .and_then(|v| v.as_str())
        .is_some_and(|actual| actual == version);
    if !top_level_ok {
        return Ok(false);
    }
    let optional_json = runtime_root
        .join("lib")
        .join("node_modules")
        .join("@openai")
        .join("codex")
        .join("node_modules")
        .join("@openai")
        .join(format!("codex-linux-{arch}"))
        .join("package.json");
    let optional_raw = match fs::read_to_string(&optional_json) {
        Ok(raw) => raw,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    let optional_value: serde_json::Value = serde_json::from_str(&optional_raw)
        .map_err(|err| io::Error::other(format!("parse {}: {err}", optional_json.display())))?;
    Ok(optional_value
        .get("version")
        .and_then(|v| v.as_str())
        .is_some_and(|actual| actual == format!("{version}-linux-{arch}")))
}

fn container_codex_arch() -> io::Result<&'static str> {
    match std::env::consts::ARCH {
        "aarch64" => Ok("arm64"),
        "x86_64" => Ok("x64"),
        other => Err(io::Error::other(format!(
            "unsupported host/container arch for isolated Codex runtime staging: {other}"
        ))),
    }
}

fn npm_for_codex_runtime(runtime_root: &Path) -> PathBuf {
    runtime_root
        .join("bin")
        .join(if cfg!(windows) { "npm.cmd" } else { "npm" })
}

fn stage_container_codex_runtime(
    host_runtime_root: &Path,
    version: &str,
    arch: &str,
    target_root: &Path,
) -> io::Result<()> {
    if let Some(parent) = target_root.parent() {
        fs::create_dir_all(parent)?;
    }
    if target_root.exists() {
        fs::remove_dir_all(target_root)?;
    }
    let staging_root = target_root.with_extension(format!("tmp-{}", std::process::id()));
    if staging_root.exists() {
        fs::remove_dir_all(&staging_root)?;
    }
    fs::create_dir_all(&staging_root)?;

    let npm = npm_for_codex_runtime(host_runtime_root);
    let package_spec = format!("@openai/codex@{version}");
    let output = Command::new(&npm)
        .arg("install")
        .arg("--global")
        .arg("--prefix")
        .arg(&staging_root)
        .arg("--include=optional")
        .arg("--no-audit")
        .arg("--no-fund")
        .arg(package_spec)
        .current_dir(resolve_safe_launch_cwd())
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let _ = fs::remove_dir_all(&staging_root);
        return Err(io::Error::other(format!(
            "failed to stage isolated Codex runtime for linux-{arch}: {}\n{}{}",
            output.status, stdout, stderr
        )));
    }
    replace_with_container_codex_platform_package(&npm, &staging_root, version, arch)?;

    if target_root.exists() {
        let _ = fs::remove_dir_all(&staging_root);
        return Ok(());
    }
    fs::rename(&staging_root, target_root)?;
    Ok(())
}

fn replace_with_container_codex_platform_package(
    npm: &Path,
    staging_root: &Path,
    version: &str,
    arch: &str,
) -> io::Result<()> {
    let scoped_root = staging_root
        .join("lib")
        .join("node_modules")
        .join("@openai");
    let package_root = scoped_root.join("codex");
    let optional_dep_root = package_root
        .join("node_modules")
        .join("@openai")
        .join(format!("codex-linux-{arch}"));
    let platform_root = staging_root.with_extension(format!("platform-{}", std::process::id()));
    if platform_root.exists() {
        fs::remove_dir_all(&platform_root)?;
    }
    let package_spec = format!("@openai/codex@{version}-linux-{arch}");
    let output = Command::new(npm)
        .arg("install")
        .arg("--force")
        .arg("--global")
        .arg("--prefix")
        .arg(&platform_root)
        .arg("--no-audit")
        .arg("--no-fund")
        .arg(package_spec)
        .current_dir(resolve_safe_launch_cwd())
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let _ = fs::remove_dir_all(&platform_root);
        return Err(io::Error::other(format!(
            "failed to stage isolated Codex linux package in {}: {}\n{}{}",
            platform_root.display(),
            output.status,
            stdout,
            stderr
        )));
    }
    let platform_package_root = platform_root
        .join("lib")
        .join("node_modules")
        .join("@openai")
        .join("codex");
    if let Some(parent) = optional_dep_root.parent() {
        fs::create_dir_all(parent)?;
    }
    if optional_dep_root.exists() {
        fs::remove_dir_all(&optional_dep_root)?;
    }
    fs::rename(&platform_package_root, &optional_dep_root)?;
    let _ = fs::remove_dir_all(&platform_root);
    Ok(())
}

/// Environment variables stripped from the codex child so it can never reach
/// an ambient OpenAI credential — the brokered loopback proxy is the only path.
/// (P22-S2 / ADR 197 codex, INV-6.)
pub(crate) const CODEX_STRIPPED_ENV: &[&str] =
    &["CODEX_API_KEY", "CODEX_ACCESS_TOKEN", "OPENAI_API_KEY"];

const CODEX_BROKERED_PERMISSION_PROFILE: &str = "ember-brokered";

/// Relocate `CODEX_HOME` to a per-session, sha256(canonical-CODEX_HOME)-keyed
/// directory and write an `config.toml` that points codex's `responses` wire at
/// the brokered loopback proxy with NO OpenAI auth.
///
/// Why the sha256 key: codex keys its keychain auth slot ("Codex Auth") by
/// `sha256(CODEX_HOME)`. Relocating `CODEX_HOME` to a different path yields a
/// different keychain key, so the global keychain credential is unreachable
/// from this session — the child cannot fall back to a stored OpenAI login.
///
/// `codex_responses_url` is the daemon-returned `http://127.0.0.1:<port>/v1`.
/// codex appends `/responses` to the provider `base_url`, so the URL must end
/// in `/v1` (matches the validated harness `base_url`).
///
/// Fail-closed: any IO error PROPAGATES (the caller's `?` aborts the launch
/// before the child spawns). We never log-and-continue — a partial config or a
/// missing relocation would let codex fall through to its global auth.
fn write_session_codex_home(
    codex_responses_url: &str,
    daemon_socket_path: &Path,
) -> io::Result<PathBuf> {
    use sha2::{Digest, Sha256};

    let daemon_socket_root = daemon_socket_path
        .parent()
        .ok_or_else(|| {
            io::Error::other(format!(
                "daemon socket path has no parent: {}",
                daemon_socket_path.display()
            ))
        })
        .map(Path::to_path_buf)?;
    let daemon_socket_root =
        std::fs::canonicalize(&daemon_socket_root).unwrap_or(daemon_socket_root);
    let daemon_socket_root = toml_basic_string(&daemon_socket_root.to_string_lossy());
    let codex_responses_url = toml_basic_string(codex_responses_url);

    // Resolve + canonicalize the host CODEX_HOME (defeats symlinks; macOS
    // /var -> /private/var). Fall back to ~/.codex when CODEX_HOME is unset.
    let host_codex_home = std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| resolve_home_dir().map(|h| h.join(".codex")))
        .ok_or_else(|| io::Error::other("could not resolve a host CODEX_HOME or home dir"))?;
    // canonicalize() requires the path to exist; the host CODEX_HOME may not
    // (fresh install). Canonicalize when present, else hash the lexical path —
    // the only invariant that matters for keychain neutralization is that the
    // relocated path DIFFERS from the host path, which it always will.
    let canonical = std::fs::canonicalize(&host_codex_home).unwrap_or(host_codex_home);

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_os_str().as_encoded_bytes());
    let home_key = hex::encode(hasher.finalize());

    // Per-session relocation root under the OPERATOR cache dir (owner-only).
    //
    // This MUST be operator-writable: the `ember codex` launcher runs as the
    // operator uid, while `~/.ember` is owned by the separate daemon uid
    // (`ember:ember-clients`, group-read-only) on a separate-uid install. Writing
    // the relocated CODEX_HOME under `~/.ember` fails closed with EPERM
    // (`os error 1`) and bricks the launch. The cache root (`$XDG_CACHE_HOME` or
    // `~/.cache`, → `emberlink/codex-sessions/<key>`) is operator-owned, mirroring
    // `codex_container_runtime_cache_root`. The sha256(canonical-CODEX_HOME) key
    // — the load-bearing keychain-neutralization property — is unchanged.
    let session_root = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| resolve_home_dir().map(|h| h.join(".cache")))
        .ok_or_else(|| io::Error::other("could not resolve cache dir for codex session root"))?
        .join("emberlink")
        .join("codex-sessions")
        .join(&home_key);
    fs::create_dir_all(&session_root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&session_root, fs::Permissions::from_mode(0o700))?;
    }

    // Unauthenticated provider pointed at the brokered loopback proxy. Keys
    // match the validated codex 0.134.0 harness (/tmp/ept2/run.sh):
    //   model_provider = "ember"; [model_providers.ember] base_url/wire_api/
    //   requires_openai_auth = false (NO env_key → no bearer the child holds).
    //
    // Codex `exec` only carries Unix socket allowlists into command execution
    // when the newer permission-profile path is active and the network proxy
    // feature is enabled. The profile below keeps Codex's native workspace
    // sandbox, constrains shell network to localhost, and grants exactly the
    // daemon socket directory needed for brokered Ember tools.
    let config_toml = format!(
        "model_provider = \"ember\"\n\
         default_permissions = \"{CODEX_BROKERED_PERMISSION_PROFILE}\"\n\
         \n\
         [features]\n\
         network_proxy = true\n\
         \n\
         [model_providers.ember]\n\
         name = \"Ember Broker\"\n\
         base_url = \"{codex_responses_url}\"\n\
         wire_api = \"responses\"\n\
         requires_openai_auth = false\n\
         \n\
         [permissions.{CODEX_BROKERED_PERMISSION_PROFILE}]\n\
         description = \"Ember brokered Codex host profile\"\n\
         extends = \":workspace\"\n\
         \n\
         [permissions.{CODEX_BROKERED_PERMISSION_PROFILE}.network]\n\
         enabled = true\n\
         \n\
         [permissions.{CODEX_BROKERED_PERMISSION_PROFILE}.network.domains]\n\
         \"localhost\" = \"allow\"\n\
         \"127.0.0.1\" = \"allow\"\n\
         \n\
         [permissions.{CODEX_BROKERED_PERMISSION_PROFILE}.network.unix_sockets]\n\
         \"{daemon_socket_root}\" = \"allow\"\n"
    );
    fs::write(session_root.join("config.toml"), config_toml)?;

    Ok(session_root)
}

fn toml_basic_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn codex_args_with_workspace(target_dir: &Path, extra_args: &[String]) -> Vec<String> {
    if extra_args.iter().any(|arg| arg == "-C" || arg == "--cd") {
        return extra_args.to_vec();
    }

    let mut args = Vec::with_capacity(extra_args.len() + 2);
    args.push("-C".to_string());
    args.push(target_dir.to_string_lossy().into_owned());
    args.extend(extra_args.iter().cloned());
    args
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
    let codex_args = codex_args_with_workspace(&target_dir, extra_args);
    let launch_cwd = resolve_safe_launch_cwd();
    let mut extra_env = vec![("EMBER_PERSONA".to_string(), persona.to_string())];
    // Export EMBER_BROKER_CWD so a top-level host launch (no managed-worktree
    // workspace_ref) gives the construct runtime a cwd fallback
    // (`broker_exec_compat_cwd`, consulted only when workspace_ref is absent);
    // otherwise host-launched brokered tools fail "requires …workspace_ref".
    extra_env.push((
        "EMBER_BROKER_CWD".to_string(),
        target_dir.to_string_lossy().into_owned(),
    ));
    if let Some(ref gpu) = registration.git_proxy_url {
        extra_env.push(("EMBER_GIT_PROXY_URL".to_string(), gpu.clone()));
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

    // P22-S2 (ADR 197 codex) — when the daemon stood up the per-session
    // loopback responses proxy, relocate CODEX_HOME to a sha256(canonical)-keyed
    // dir with an unauthenticated provider pointed at the proxy, and strip the
    // ambient OpenAI credentials from the child env. Fail-closed: a config-write
    // failure aborts the launch (the `?`) rather than letting codex fall back to
    // its global auth.
    let mut stripped_env: &[&str] = &[];
    if let Some(url) = registration.codex_responses_proxy_url.as_deref() {
        let codex_home = write_session_codex_home(url, socket_path)?;
        extra_env.push((
            "CODEX_HOME".to_string(),
            codex_home.to_string_lossy().into_owned(),
        ));
        stripped_env = CODEX_STRIPPED_ENV;
    }

    with_session_close(
        &registration.session_id,
        socket_path,
        "ember codex",
        "ember codex",
        || {
            crate::launcher::core::run_with_registration(
                LauncherInvocation {
                    launcher_name: "codex",
                    binary: bin,
                    extra_args: &codex_args,
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

pub fn launch_codex(extra_args: &[String], socket_path: &Path) -> io::Result<i32> {
    launch_codex_with_shadow_dir(extra_args, socket_path, None)
}

pub fn launch_codex_with_shadow_dir(
    extra_args: &[String],
    socket_path: &Path,
    shadow_dir_override: Option<&Path>,
) -> io::Result<i32> {
    let bin = resolve_codex_bin();
    let persona = resolve_persona_name();
    let shadow_dir = shadow_dir_override
        .map(PathBuf::from)
        .unwrap_or_else(resolve_shadow_dir);
    let construct_specs = cohort_a_construct_specs();
    launch_codex_with_shadow_dir_and_constructs(
        extra_args,
        socket_path,
        &shadow_dir,
        &bin,
        &persona,
        &construct_specs,
    )
}

pub fn launch_codex_with_shadow_dir_and_constructs(
    extra_args: &[String],
    socket_path: &Path,
    shadow_dir: &Path,
    bin: &str,
    persona: &str,
    construct_specs: &[ConstructSpec],
) -> io::Result<i32> {
    launch_codex_with_shadow_dir_and_constructs_with_workspace_ref(
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

// Launcher plumbing signature — structurally many params; refactor would touch call sites in other files.
#[allow(clippy::too_many_arguments)]
pub fn launch_codex_with_shadow_dir_and_constructs_with_runtime_id(
    extra_args: &[String],
    socket_path: &Path,
    shadow_dir: &Path,
    bin: &str,
    persona: &str,
    construct_specs: &[ConstructSpec],
    authority_strict: bool,
    delegated_template: Option<&str>,
    attach_runtime_persona_id: Option<&str>,
    dev_runtime_id: Option<&str>,
) -> io::Result<i32> {
    let workspace_ref = dev_runtime_id.map(|runtime_id| format!("managed_worktree:{runtime_id}"));
    launch_codex_with_shadow_dir_and_constructs_with_workspace_ref(
        extra_args,
        socket_path,
        shadow_dir,
        bin,
        persona,
        construct_specs,
        authority_strict,
        delegated_template,
        attach_runtime_persona_id,
        workspace_ref.as_deref(),
    )
}

// Launcher plumbing signature — structurally many params; refactor would touch call sites in other files.
#[allow(clippy::too_many_arguments)]
pub fn launch_codex_with_shadow_dir_and_constructs_with_workspace_ref(
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
    crate::launcher::core::ensure_broker_safe_launch_cwd("codex")?;
    install_codex_path_shadow(shadow_dir, construct_specs)?;

    let delegation_template_name =
        crate::launcher::claude_code::resolve_delegation_template_for_launch(
            delegated_template,
            "ember codex",
        )
        .map_err(io::Error::other)?;

    let registration = register_session_rpc_with_workflow_and_workspace_ref(
        persona,
        socket_path,
        delegation_template_name.as_deref(),
        authority_strict,
        attach_runtime_persona_id,
        workspace_ref,
        "ember codex",
        "ember codex",
    )
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("not found")
            || msg.contains("no such persona")
            || msg.contains("unknown persona")
        {
            io::Error::new(
                e.kind(),
                "no Codex persona found.\n  Run `ember init --for codex` first, or set $EMBER_PERSONA to an existing persona name."
                    .to_string(),
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

fn install_codex_path_shadow(
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
            "prod construct bundle is incomplete: expected managed `ember-gh` and `ember-git` from the installed product, not repo-built target artifacts. Repair or reinstall the managed product before running `ember codex --prod`.",
        ));
    }
    Ok(specs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn env_lock() -> &'static Mutex<()> {
        &crate::PROCESS_ENV_CWD_TEST_LOCK
    }

    fn fixture() -> SessionRegistration {
        SessionRegistration {
            session_id: "sess_fixture".to_string(),
            grant_id: "grt_fixture".to_string(),
            proxy_url: "http://127.0.0.1:9999".to_string(),
            persona_id: None,
            anthropic_base_url: None,
            anthropic_custom_headers: None,
            git_proxy_url: None,
            cursor_egress_proxy_url: None,
            codex_responses_proxy_url: None,
            gemini_proxy_url: None,
            ssh_auth_sock: None,
            delegation_id: None,
            delegation_template: None,
            authority_posture: crate::launcher::core::AuthorityPosture::from_components(
                false, None,
            ),
            bridge_client_bundle: None,
            attachment_id: Some("att_fixture".to_string()),
            attachment_endpoint_token: Some("ep_fixture".to_string()),
            anthropic_unix_socket: None,
            leaf_report_nonce: None,
        }
    }

    // Launch-contract regression: a top-level host launch (no managed-worktree
    // workspace_ref) MUST export EMBER_BROKER_CWD so the construct runtime's
    // cwd fallback fires; the script also asserts no spurious EMBER_WORKSPACE_REF
    // is set on the top-level lane.
    #[cfg(unix)]
    #[test]
    fn run_with_registration_exports_broker_cwd_for_construct_fallback() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let script = tmp.path().join("check-broker-cwd-env.sh");
        write_executable(
            &script,
            "#!/bin/sh\n[ \"$EMBER_BROKER_CWD\" = \"$(pwd)\" ] || exit 47\n[ -z \"$EMBER_WORKSPACE_REF\" ] || exit 48\nexit 0\n",
        );

        let code = run_with_registration_with_workspace_ref(
            script.to_str().expect("utf8 script path"),
            &[],
            "codex-default",
            &fixture(),
            Path::new("/nonexistent.sock"),
            tmp.path(),
            None,
        )
        .expect("spawn broker-cwd checker");

        assert_eq!(
            code, 0,
            "top-level host launch must export broker cwd for construct execution fallback"
        );
    }

    struct EnvGuard {
        home: Option<std::ffi::OsString>,
        path: Option<std::ffi::OsString>,
        xdg_data_home: Option<std::ffi::OsString>,
        xdg_cache_home: Option<std::ffi::OsString>,
        codex_home: Option<std::ffi::OsString>,
        codex_bin: Option<std::ffi::OsString>,
        codex_container_runtime_root: Option<std::ffi::OsString>,
        ember_binary_manifest: Option<std::ffi::OsString>,
        ember_trust_roots: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn capture() -> Self {
            Self {
                home: std::env::var_os("HOME"),
                path: std::env::var_os("PATH"),
                xdg_data_home: std::env::var_os("XDG_DATA_HOME"),
                xdg_cache_home: std::env::var_os("XDG_CACHE_HOME"),
                codex_home: std::env::var_os("CODEX_HOME"),
                codex_bin: std::env::var_os("EMBER_CODEX_BIN"),
                codex_container_runtime_root: std::env::var_os(
                    "EMBER_CODEX_CONTAINER_RUNTIME_ROOT",
                ),
                ember_binary_manifest: std::env::var_os("EMBER_BINARY_MANIFEST"),
                ember_trust_roots: std::env::var_os("EMBER_TRUST_ROOTS"),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: test-only environment restoration under a process-wide lock.
            unsafe {
                match &self.home {
                    Some(value) => std::env::set_var("HOME", value),
                    None => std::env::remove_var("HOME"),
                }
                match &self.path {
                    Some(value) => std::env::set_var("PATH", value),
                    None => std::env::remove_var("PATH"),
                }
                match &self.xdg_data_home {
                    Some(value) => std::env::set_var("XDG_DATA_HOME", value),
                    None => std::env::remove_var("XDG_DATA_HOME"),
                }
                match &self.xdg_cache_home {
                    Some(value) => std::env::set_var("XDG_CACHE_HOME", value),
                    None => std::env::remove_var("XDG_CACHE_HOME"),
                }
                match &self.codex_home {
                    Some(value) => std::env::set_var("CODEX_HOME", value),
                    None => std::env::remove_var("CODEX_HOME"),
                }
                match &self.codex_bin {
                    Some(value) => std::env::set_var("EMBER_CODEX_BIN", value),
                    None => std::env::remove_var("EMBER_CODEX_BIN"),
                }
                match &self.codex_container_runtime_root {
                    Some(value) => std::env::set_var("EMBER_CODEX_CONTAINER_RUNTIME_ROOT", value),
                    None => std::env::remove_var("EMBER_CODEX_CONTAINER_RUNTIME_ROOT"),
                }
                match &self.ember_binary_manifest {
                    Some(value) => std::env::set_var("EMBER_BINARY_MANIFEST", value),
                    None => std::env::remove_var("EMBER_BINARY_MANIFEST"),
                }
                match &self.ember_trust_roots {
                    Some(value) => std::env::set_var("EMBER_TRUST_ROOTS", value),
                    None => std::env::remove_var("EMBER_TRUST_ROOTS"),
                }
            }
        }
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, contents: &str) {
        use std::os::unix::fs::PermissionsExt as _;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dir");
        }
        std::fs::write(path, contents).expect("write executable");
        let mut perms = std::fs::metadata(path)
            .expect("read executable metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).expect("set executable permissions");
    }

    fn write_package_json(path: &Path, version: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create package parent");
        }
        std::fs::write(path, format!(r#"{{"version":"{version}"}}"#)).expect("write package json");
    }

    #[cfg(unix)]
    fn blake3_content_hash(path: &Path) -> String {
        let bytes = std::fs::read(path).expect("read construct");
        format!("blake3:{}", hex::encode(blake3::hash(&bytes).as_bytes()))
    }

    #[cfg(unix)]
    fn manifest_entry(
        tool_name: &str,
        path: &Path,
        content_hash: String,
    ) -> ember_daemon::binary_manifest::BinaryManifestEntry {
        ember_daemon::binary_manifest::BinaryManifestEntry {
            tool_name: tool_name.to_string(),
            version: "0.3.0-test".to_string(),
            content_hash,
            absolute_path: path.to_path_buf(),
            installed_at: 0,
            publisher: "did:emberlink".to_string(),
            channel: ember_daemon::binary_manifest::BinaryDistributionChannel::Bundled,
        }
    }

    #[cfg(unix)]
    fn install_fake_host_runtime(runtime_root: &Path, version: &str) {
        write_executable(
            &runtime_root.join("bin").join("codex"),
            "#!/bin/sh\nexit 0\n",
        );
        write_executable(
            &runtime_root.join("bin").join("npm"),
            r#"#!/bin/sh
set -eu
prefix=""
package=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--prefix" ]; then
    prefix="$2"
    shift 2
    continue
  fi
  package="$1"
  shift
done
case "$package" in
  @openai/codex@*-linux-*)
    version="${package#@openai/codex@}"
    mkdir -p "$prefix/lib/node_modules/@openai/codex"
    printf '{"version":"%s"}\n' "$version" > "$prefix/lib/node_modules/@openai/codex/package.json"
    ;;
  @openai/codex@*)
    version="${package#@openai/codex@}"
    mkdir -p "$prefix/bin" "$prefix/lib/node_modules/@openai/codex"
    printf '#!/bin/sh\nexit 0\n' > "$prefix/bin/codex"
    chmod +x "$prefix/bin/codex"
    printf '{"version":"%s"}\n' "$version" > "$prefix/lib/node_modules/@openai/codex/package.json"
    ;;
  *)
    echo "unexpected package: $package" >&2
    exit 99
    ;;
esac
printf '%s\n' "$package" >> "$(dirname "$0")/npm.log"
"#,
        );
        write_package_json(
            &runtime_root
                .join("lib")
                .join("node_modules")
                .join("@openai")
                .join("codex")
                .join("package.json"),
            version,
        );
    }

    #[cfg(unix)]
    fn write_ready_container_runtime(runtime_root: &Path, version: &str, arch: &str) {
        write_executable(
            &runtime_root.join("bin").join("codex"),
            "#!/bin/sh\nexit 0\n",
        );
        write_package_json(
            &runtime_root
                .join("lib")
                .join("node_modules")
                .join("@openai")
                .join("codex")
                .join("package.json"),
            version,
        );
        write_package_json(
            &runtime_root
                .join("lib")
                .join("node_modules")
                .join("@openai")
                .join("codex")
                .join("node_modules")
                .join("@openai")
                .join(format!("codex-linux-{arch}"))
                .join("package.json"),
            &format!("{version}-linux-{arch}"),
        );
    }

    #[test]
    fn resolve_codex_bin_honors_override() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::capture();
        unsafe { std::env::set_var("EMBER_CODEX_BIN", "/usr/local/bin/codex-test") };
        assert_eq!(resolve_codex_bin(), "/usr/local/bin/codex-test");
    }

    #[test]
    fn resolve_persona_name_defaults_to_codex_runtime() {
        let _g = crate::EMBER_PERSONA_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("EMBER_PERSONA").ok();
        unsafe { std::env::remove_var("EMBER_PERSONA") };
        assert_eq!(resolve_persona_name(), "codex-default");
        match prior {
            Some(v) => unsafe { std::env::set_var("EMBER_PERSONA", v) },
            None => unsafe { std::env::remove_var("EMBER_PERSONA") },
        }
    }

    #[test]
    fn looks_like_mise_shim_detects_standard_mise_shim_path() {
        assert!(looks_like_mise_shim(Path::new(
            "/Users/example/.local/share/mise/shims/codex"
        )));
        assert!(!looks_like_mise_shim(Path::new("/usr/local/bin/codex")));
    }

    #[cfg(unix)]
    #[test]
    fn codex_shadow_install_uses_verified_manifest_layout() {
        use ed25519_dalek::SigningKey;
        use ember_daemon::binary_manifest::{BinaryManifest, write_signed_manifest};

        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::capture();
        let tmp = tempfile::tempdir().expect("tempdir");
        let construct = tmp.path().join("constructs").join("ember-gh");
        write_executable(&construct, "#!/bin/sh\necho verified-gh\n");
        let manifest_path = tmp.path().join("manifest.toml");
        let manifest = BinaryManifest {
            entries: vec![manifest_entry(
                "ember-gh",
                &construct,
                blake3_content_hash(&construct),
            )],
        };
        let signer = SigningKey::from_bytes(&[11u8; 32]);
        write_signed_manifest(&manifest, &signer, &manifest_path).expect("write signed manifest");
        unsafe {
            std::env::set_var("EMBER_BINARY_MANIFEST", &manifest_path);
            std::env::set_var(
                "EMBER_TRUST_ROOTS",
                hex::encode(signer.verifying_key().to_bytes()),
            );
        }

        let shadow = tmp.path().join("shadow");
        install_codex_path_shadow(
            &shadow,
            &[ConstructSpec {
                tool_name: "gh".to_string(),
                target_binary: construct.clone(),
            }],
        )
        .expect("install verified codex shadow");

        let shim = shadow_bin_dir(&shadow).join("gh");
        assert!(
            !shim.symlink_metadata().unwrap().file_type().is_symlink(),
            "Codex must use the signed verified regular-file shim layout"
        );
        assert_eq!(
            std::fs::read_to_string(&shim).unwrap(),
            "#!/bin/sh\necho verified-gh\n"
        );
        assert_eq!(
            std::fs::read_link(shadow_bin_dir(&shadow).join("ember-gh")).unwrap(),
            shim
        );
    }

    #[test]
    fn codex_args_with_workspace_prepends_cd_when_missing() {
        let args = codex_args_with_workspace(Path::new("/tmp/worktree"), &["--help".to_string()]);
        assert_eq!(args, vec!["-C", "/tmp/worktree", "--help"]);
    }

    #[test]
    fn codex_args_with_workspace_respects_explicit_cd_flag() {
        let args = codex_args_with_workspace(
            Path::new("/tmp/worktree"),
            &[
                "--cd".to_string(),
                "/somewhere-else".to_string(),
                "--help".to_string(),
            ],
        );
        assert_eq!(args, vec!["--cd", "/somewhere-else", "--help"]);
    }

    #[test]
    fn resolve_codex_runtime_root_prefers_install_root_above_bin_dir() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::capture();
        let tmp = tempfile::tempdir().expect("tempdir");
        let runtime_root = tmp.path().join("node").join("24.14.1");
        let bin_dir = runtime_root.join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create bin dir");
        let fake_bin = bin_dir.join("codex");
        std::fs::write(&fake_bin, "#!/bin/sh\nexit 0\n").expect("write fake codex");
        unsafe { std::env::set_var("EMBER_CODEX_BIN", &fake_bin) };

        let resolved = resolve_codex_runtime_root().expect("resolve runtime root");
        assert_eq!(resolved, runtime_root);
    }

    #[test]
    fn resolve_codex_config_dir_reads_canonical_home_dot_codex() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::capture();
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path().join("home");
        let config = home.join(".codex");
        std::fs::create_dir_all(&config).expect("create codex config dir");
        unsafe { std::env::set_var("HOME", &home) };

        let resolved = resolve_codex_config_dir().expect("resolve codex config dir");
        assert_eq!(resolved, config);
    }

    #[test]
    fn require_codex_config_dir_for_isolated_guides_host_login_when_missing() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::capture();
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&home).expect("create home");
        unsafe { std::env::set_var("HOME", &home) };

        let err = require_codex_config_dir_for_isolated()
            .expect_err("missing ~/.codex must fail for isolated Codex");
        let msg = err.to_string();
        assert!(msg.contains("auth.json"), "got: {msg}");
        assert!(msg.contains("codex login"), "got: {msg}");
        assert!(msg.contains("codex login --device-auth"), "got: {msg}");
        assert!(msg.contains("ember codex --host"), "got: {msg}");
        assert!(msg.contains("~/.codex"), "got: {msg}");
    }

    #[test]
    fn require_codex_config_dir_for_isolated_rejects_hooks_only_codex_dir() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::capture();
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path().join("home");
        let config = home.join(".codex");
        std::fs::create_dir_all(&config).expect("create codex config dir");
        std::fs::write(config.join("hooks.json"), "{}").expect("write hooks json");
        unsafe { std::env::set_var("HOME", &home) };

        let err = require_codex_config_dir_for_isolated()
            .expect_err("hooks-only ~/.codex must fail for isolated Codex");
        let msg = err.to_string();
        assert!(msg.contains("auth.json"), "got: {msg}");
        assert!(msg.contains("hooks.json"), "got: {msg}");
        assert!(msg.contains("codex login"), "got: {msg}");
    }

    #[test]
    fn resolve_container_codex_runtime_root_honors_override() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::capture();
        let override_root = PathBuf::from("/tmp/ember-codex-runtime-override");
        unsafe { std::env::set_var("EMBER_CODEX_CONTAINER_RUNTIME_ROOT", &override_root) };

        let resolved =
            resolve_container_codex_runtime_root().expect("resolve container runtime root");
        assert_eq!(resolved, override_root);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_container_codex_runtime_root_stages_linux_runtime_under_cache_root() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::capture();
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path().join("home");
        let xdg_data_home = tmp.path().join("xdg-data");
        std::fs::create_dir_all(&home).expect("create home");
        std::fs::create_dir_all(&xdg_data_home).expect("create xdg data home");
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("XDG_DATA_HOME", &xdg_data_home);
        }

        let host_runtime_root = tmp.path().join("host-runtime");
        install_fake_host_runtime(&host_runtime_root, "1.2.3");
        unsafe {
            std::env::set_var(
                "EMBER_CODEX_BIN",
                host_runtime_root.join("bin").join("codex"),
            )
        };

        let arch = container_codex_arch().expect("supported arch");
        let expected = codex_container_runtime_cache_root()
            .expect("cache root")
            .join(format!("linux-{arch}"))
            .join("1.2.3");

        let resolved =
            resolve_container_codex_runtime_root().expect("resolve staged container runtime");

        assert_eq!(resolved, expected);
        assert_ne!(resolved, host_runtime_root);
        assert!(
            container_codex_runtime_is_ready(&resolved, "1.2.3", arch)
                .expect("check staged runtime"),
            "staged runtime must contain the linux-specific optional package"
        );
        let npm_log = std::fs::read_to_string(host_runtime_root.join("bin").join("npm.log"))
            .expect("read fake npm log");
        assert!(npm_log.contains("@openai/codex@1.2.3"));
        assert!(npm_log.contains(&format!("@openai/codex@1.2.3-linux-{arch}")));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_container_codex_runtime_root_reuses_ready_cache_without_restaging() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::capture();
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path().join("home");
        let xdg_data_home = tmp.path().join("xdg-data");
        std::fs::create_dir_all(&home).expect("create home");
        std::fs::create_dir_all(&xdg_data_home).expect("create xdg data home");
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("XDG_DATA_HOME", &xdg_data_home);
        }

        let host_runtime_root = tmp.path().join("host-runtime");
        install_fake_host_runtime(&host_runtime_root, "1.2.3");
        unsafe {
            std::env::set_var(
                "EMBER_CODEX_BIN",
                host_runtime_root.join("bin").join("codex"),
            )
        };

        let arch = container_codex_arch().expect("supported arch");
        let ready_root = codex_container_runtime_cache_root()
            .expect("cache root")
            .join(format!("linux-{arch}"))
            .join("1.2.3");
        write_ready_container_runtime(&ready_root, "1.2.3", arch);

        let resolved =
            resolve_container_codex_runtime_root().expect("resolve ready container runtime");

        assert_eq!(resolved, ready_root);
        assert!(
            !host_runtime_root.join("bin").join("npm.log").exists(),
            "ready cache should skip the fake npm staging path"
        );
    }

    // ---- P22-S2 / ADR 197 codex: CODEX_HOME relocation + config writer ----

    #[test]
    fn codex_stripped_env_contains_the_three_keys() {
        assert_eq!(
            CODEX_STRIPPED_ENV,
            &["CODEX_API_KEY", "CODEX_ACCESS_TOKEN", "OPENAI_API_KEY"]
        );
    }

    #[test]
    fn write_session_codex_home_writes_unauthenticated_provider() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::capture();
        let tmp = tempfile::tempdir().expect("tempdir");
        // Point HOME + CODEX_HOME into the tempdir so the relocation lands
        // somewhere we can inspect and clean up.
        let host_codex_home = tmp.path().join("host-codex");
        std::fs::create_dir_all(&host_codex_home).unwrap();
        unsafe {
            std::env::set_var("HOME", tmp.path());
            std::env::set_var("CODEX_HOME", &host_codex_home);
            // Force the cache-root fallback to HOME/.cache so the path assertion
            // is hermetic regardless of the host's XDG_CACHE_HOME.
            std::env::remove_var("XDG_CACHE_HOME");
        }

        let url = "http://127.0.0.1:54999/v1";
        let socket_path = tmp.path().join("run").join("daemon.sock");
        std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();
        let session_home =
            write_session_codex_home(url, &socket_path).expect("write_session_codex_home");
        let config =
            std::fs::read_to_string(session_home.join("config.toml")).expect("config.toml written");

        assert!(config.contains("base_url = \"http://127.0.0.1:54999/v1\""));
        assert!(config.contains("wire_api = \"responses\""));
        assert!(config.contains("requires_openai_auth = false"));
        assert!(config.contains("model_provider = \"ember\""));
        assert!(config.contains("default_permissions = \"ember-brokered\""));
        assert!(config.contains("[features]\nnetwork_proxy = true"));
        assert!(config.contains("[permissions.ember-brokered]"));
        assert!(config.contains("extends = \":workspace\""));
        assert!(config.contains("[permissions.ember-brokered.network]\nenabled = true"));
        assert!(config.contains("[permissions.ember-brokered.network.domains]"));
        assert!(config.contains("\"localhost\" = \"allow\""));
        assert!(config.contains("\"127.0.0.1\" = \"allow\""));
        assert!(config.contains("[permissions.ember-brokered.network.unix_sockets]"));
        let socket_root = std::fs::canonicalize(socket_path.parent().unwrap()).unwrap();
        assert!(config.contains(&format!("\"{}\" = \"allow\"", socket_root.display())));
        // No API key / env_key may appear — the child holds no credential.
        assert!(!config.to_lowercase().contains("api_key"));
        assert!(!config.contains("env_key"));
        // Relocated under the operator cache dir
        // (~/.cache/emberlink/codex-sessions/<sha256-key>/) — operator-writable,
        // unlike daemon-owned ~/.ember. Test sets HOME=tmp and no XDG_CACHE_HOME,
        // so it resolves to tmp/.cache.
        assert!(
            session_home.starts_with(
                tmp.path()
                    .join(".cache")
                    .join("emberlink")
                    .join("codex-sessions")
            ),
            "relocated home must live under ~/.cache/emberlink/codex-sessions, got {}",
            session_home.display()
        );
    }

    #[test]
    fn write_session_codex_home_is_canonical_keyed() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::capture();
        let tmp = tempfile::tempdir().expect("tempdir");

        let real_codex = tmp.path().join("real-codex");
        std::fs::create_dir_all(&real_codex).unwrap();
        // A symlink that resolves to the same canonical target must key the
        // relocation to the same sha256 dir.
        let link = tmp.path().join("link-codex");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_codex, &link).unwrap();

        unsafe {
            std::env::set_var("HOME", tmp.path());
            std::env::set_var("CODEX_HOME", &real_codex);
        }
        let socket_path = tmp.path().join("run").join("daemon.sock");
        std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();

        let via_real = write_session_codex_home("http://127.0.0.1:1/v1", &socket_path).unwrap();

        unsafe {
            std::env::set_var("CODEX_HOME", &link);
        }
        let via_link = write_session_codex_home("http://127.0.0.1:1/v1", &socket_path).unwrap();

        #[cfg(unix)]
        assert_eq!(
            via_real, via_link,
            "a symlinked CODEX_HOME must hash to the same relocation key as its canonical target"
        );
    }
}
