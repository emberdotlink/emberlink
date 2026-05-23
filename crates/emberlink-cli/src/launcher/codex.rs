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
    prod_required_constructs_present,
};
use crate::launcher::core::{LauncherInvocation, SessionRegistration, resolve_shadow_dir};
use crate::launcher::path_shadow::{ConstructSpec, install_path_shadow, shadow_bin_dir};
use crate::launcher::session_rpc::{register_session_rpc, with_session_close};

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
    let home = dirs_next::home_dir()?;
    let config_dir = home.join(".codex");
    config_dir.exists().then_some(config_dir)
}

pub fn require_codex_config_dir_for_isolated() -> io::Result<PathBuf> {
    resolve_codex_config_dir().ok_or_else(|| {
        io::Error::other(
            "no host Codex auth state found at `~/.codex`. Run `codex login` on the host first, or use `codex login --device-auth` on a headless host, or use `ember codex --host` until native auth is ready.",
        )
    })
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
    dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"))
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
            dirs_next::home_dir()
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
    run_with_registration_with_runtime_id(
        bin,
        extra_args,
        persona,
        registration,
        socket_path,
        shadow_dir,
        None,
    )
}

fn run_with_registration_with_runtime_id(
    bin: &str,
    extra_args: &[String],
    persona: &str,
    registration: &SessionRegistration,
    socket_path: &Path,
    shadow_dir: &Path,
    dev_runtime_id: Option<&str>,
) -> io::Result<i32> {
    let target_dir = std::env::current_dir()?;
    let codex_args = codex_args_with_workspace(&target_dir, extra_args);
    let launch_cwd = resolve_safe_launch_cwd();
    let mut extra_env = vec![("EMBER_PERSONA".to_string(), persona.to_string())];
    if let Some(ref gpu) = registration.git_proxy_url {
        extra_env.push(("EMBER_GIT_PROXY_URL".to_string(), gpu.clone()));
    }
    if let Some(ref sock) = registration.ssh_auth_sock {
        extra_env.push(("SSH_AUTH_SOCK".to_string(), sock.clone()));
    }
    if let Some(runtime_id) = dev_runtime_id {
        extra_env.push((
            crate::dev_runtime::DEV_RUNTIME_ID_ENV.to_string(),
            runtime_id.to_string(),
        ));
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
    launch_codex_with_shadow_dir_and_constructs_with_runtime_id(
        extra_args,
        socket_path,
        shadow_dir,
        bin,
        persona,
        construct_specs,
        None,
    )
}

pub fn launch_codex_with_shadow_dir_and_constructs_with_runtime_id(
    extra_args: &[String],
    socket_path: &Path,
    shadow_dir: &Path,
    bin: &str,
    persona: &str,
    construct_specs: &[ConstructSpec],
    dev_runtime_id: Option<&str>,
) -> io::Result<i32> {
    crate::launcher::core::ensure_broker_safe_launch_cwd("codex")?;
    install_path_shadow(shadow_dir, construct_specs)?;

    let registration = register_session_rpc(persona, socket_path, "ember codex", "ember codex")
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
    run_with_registration_with_runtime_id(
        bin,
        extra_args,
        persona,
        &registration,
        socket_path,
        &bin_dir,
        dev_runtime_id,
    )
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
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EnvGuard {
        home: Option<std::ffi::OsString>,
        xdg_data_home: Option<std::ffi::OsString>,
        codex_bin: Option<std::ffi::OsString>,
        codex_container_runtime_root: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn capture() -> Self {
            Self {
                home: std::env::var_os("HOME"),
                xdg_data_home: std::env::var_os("XDG_DATA_HOME"),
                codex_bin: std::env::var_os("EMBER_CODEX_BIN"),
                codex_container_runtime_root: std::env::var_os(
                    "EMBER_CODEX_CONTAINER_RUNTIME_ROOT",
                ),
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
                match &self.xdg_data_home {
                    Some(value) => std::env::set_var("XDG_DATA_HOME", value),
                    None => std::env::remove_var("XDG_DATA_HOME"),
                }
                match &self.codex_bin {
                    Some(value) => std::env::set_var("EMBER_CODEX_BIN", value),
                    None => std::env::remove_var("EMBER_CODEX_BIN"),
                }
                match &self.codex_container_runtime_root {
                    Some(value) => std::env::set_var("EMBER_CODEX_CONTAINER_RUNTIME_ROOT", value),
                    None => std::env::remove_var("EMBER_CODEX_CONTAINER_RUNTIME_ROOT"),
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
        let mut perms = std::fs::metadata(path).expect("read executable metadata").permissions();
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
    fn install_fake_host_runtime(runtime_root: &Path, version: &str) {
        write_executable(&runtime_root.join("bin").join("codex"), "#!/bin/sh\nexit 0\n");
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
        write_executable(&runtime_root.join("bin").join("codex"), "#!/bin/sh\nexit 0\n");
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
            "/Users/operator/.local/share/mise/shims/codex"
        )));
        assert!(!looks_like_mise_shim(Path::new("/usr/local/bin/codex")));
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
        assert!(msg.contains("codex login"), "got: {msg}");
        assert!(msg.contains("codex login --device-auth"), "got: {msg}");
        assert!(msg.contains("ember codex --host"), "got: {msg}");
        assert!(msg.contains("~/.codex"), "got: {msg}");
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
        unsafe { std::env::set_var("EMBER_CODEX_BIN", host_runtime_root.join("bin").join("codex")) };

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
        unsafe { std::env::set_var("EMBER_CODEX_BIN", host_runtime_root.join("bin").join("codex")) };

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
}
