//! `ember cursor` launcher.
//!
//! Baseline Cursor support is a session/PATH/tool-governance lane. Cursor's
//! model account/session remains Cursor-owned unless a future local-provider
//! mediation mode is explicitly designed.

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

const CURSOR_BIN_CANDIDATES: &[&str] = &["cursor-agent", "cursor"];
const CURSOR_PROXY_ENV: &[&str] = &[
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

pub fn resolve_cursor_bin() -> String {
    resolve_cursor_bin_path()
        .unwrap_or_else(|_| PathBuf::from("cursor-agent"))
        .to_string_lossy()
        .into_owned()
}

pub fn resolve_cursor_bin_path() -> io::Result<PathBuf> {
    if let Ok(override_bin) = std::env::var("EMBER_CURSOR_BIN")
        && !override_bin.trim().is_empty()
    {
        return Ok(PathBuf::from(override_bin));
    }

    for binary in CURSOR_BIN_CANDIDATES {
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
        "could not resolve `cursor-agent` or `cursor` on PATH; set EMBER_CURSOR_BIN to the Cursor CLI binary",
    ))
}

pub fn resolve_persona_name() -> String {
    if let Ok(v) = std::env::var("EMBER_PERSONA")
        && !v.is_empty()
    {
        return v;
    }
    crate::launcher::default_persona_id_for_runtime("cursor", None)
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
    if let Some(ref cursor_egress_proxy_url) = registration.cursor_egress_proxy_url {
        for key in [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            extra_env.push((key.to_string(), cursor_egress_proxy_url.clone()));
        }
        extra_env.push((
            "EMBER_CURSOR_EGRESS_PROXY_URL".to_string(),
            cursor_egress_proxy_url.clone(),
        ));
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

    // Do not derive HTTPS_PROXY from registration.proxy_url or git_proxy_url.
    // Those are credential projector URLs, not Cursor-compatible generic
    // CONNECT egress. Cursor gets proxy env only from cursor_egress_proxy_url.
    with_session_close(
        &registration.session_id,
        socket_path,
        "ember cursor",
        "ember cursor",
        || {
            crate::launcher::core::run_with_registration(
                LauncherInvocation {
                    launcher_name: "cursor",
                    binary: bin,
                    extra_args,
                    socket_path,
                    shadow_bin_dir: shadow_dir,
                    current_dir: Some(&launch_cwd),
                    stripped_env: CURSOR_PROXY_ENV,
                },
                registration,
                extra_env,
            )
        },
    )
}

pub fn launch_cursor(extra_args: &[String], socket_path: &Path) -> io::Result<i32> {
    launch_cursor_with_shadow_dir(extra_args, socket_path, None)
}

pub fn launch_cursor_with_shadow_dir(
    extra_args: &[String],
    socket_path: &Path,
    shadow_dir_override: Option<&Path>,
) -> io::Result<i32> {
    let bin = resolve_cursor_bin();
    let persona = resolve_persona_name();
    let shadow_dir = shadow_dir_override
        .map(PathBuf::from)
        .unwrap_or_else(resolve_shadow_dir);
    let construct_specs = cohort_a_construct_specs();
    launch_cursor_with_shadow_dir_and_constructs(
        extra_args,
        socket_path,
        &shadow_dir,
        &bin,
        &persona,
        &construct_specs,
    )
}

pub fn launch_cursor_with_shadow_dir_and_constructs(
    extra_args: &[String],
    socket_path: &Path,
    shadow_dir: &Path,
    bin: &str,
    persona: &str,
    construct_specs: &[ConstructSpec],
) -> io::Result<i32> {
    launch_cursor_with_shadow_dir_and_constructs_with_workspace_ref(
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
pub fn launch_cursor_with_shadow_dir_and_constructs_with_workspace_ref(
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
    crate::launcher::core::ensure_broker_safe_launch_cwd("cursor")?;
    install_cursor_path_shadow(shadow_dir, construct_specs)?;

    let delegation_template_name =
        crate::launcher::claude_code::resolve_delegation_template_for_launch(
            delegated_template,
            "ember cursor",
        )
        .map_err(io::Error::other)?;

    let registration = register_session_rpc_with_workflow_and_workspace_ref(
        persona,
        socket_path,
        delegation_template_name.as_deref(),
        authority_strict,
        attach_runtime_persona_id,
        workspace_ref,
        "ember cursor",
        "ember cursor",
    )
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("not found")
            || msg.contains("no such persona")
            || msg.contains("unknown persona")
        {
            io::Error::new(
                e.kind(),
                "no Cursor persona found.\n  Create one with `ember persona create cursor-default` or set $EMBER_PERSONA to an existing persona name. Baseline Cursor model auth remains Cursor-owned.",
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

fn install_cursor_path_shadow(
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
            "prod construct bundle is incomplete: expected managed `ember-gh` and `ember-git` from the installed product, not repo-built target artifacts. Repair or reinstall the managed product before running `ember cursor --prod`.",
        ));
    }
    Ok(specs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::launcher::core::{AuthorityPosture, SessionRegistration};
    use std::os::unix::fs::PermissionsExt as _;
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

    fn fixture_registration() -> SessionRegistration {
        SessionRegistration {
            session_id: "sess_cursor_fixture".to_string(),
            grant_id: "grant_cursor_fixture".to_string(),
            proxy_url: "http://127.0.0.1:8484".to_string(),
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
            authority_posture: AuthorityPosture::from_components(false, None),
            bridge_client_bundle: None,
            attachment_id: Some("att_cursor_fixture".to_string()),
            attachment_endpoint_token: Some("ep_cursor_fixture".to_string()),
            anthropic_unix_socket: None,
            leaf_report_nonce: None,
        }
    }

    fn write_executable(path: &Path, body: &str) {
        std::fs::write(path, body).expect("write executable");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod executable");
    }

    #[test]
    fn resolve_cursor_bin_honors_override() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set("EMBER_CURSOR_BIN", "/opt/custom-cursor");

        assert_eq!(
            resolve_cursor_bin_path().unwrap(),
            PathBuf::from("/opt/custom-cursor")
        );
    }

    #[test]
    fn resolve_persona_name_defaults_to_cursor_default() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::remove("EMBER_PERSONA");

        assert_eq!(resolve_persona_name(), "cursor-default");
    }

    #[test]
    fn cursor_launch_strips_ambient_proxy_env_without_daemon_egress_url() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _https = EnvGuard::set("HTTPS_PROXY", "http://ambient.invalid:1");
        let _https_lower = EnvGuard::set("https_proxy", "http://ambient.invalid:1");
        let _http = EnvGuard::set("HTTP_PROXY", "http://ambient.invalid:2");
        let _http_lower = EnvGuard::set("http_proxy", "http://ambient.invalid:2");
        let _all = EnvGuard::set("ALL_PROXY", "http://ambient.invalid:3");
        let _all_lower = EnvGuard::set("all_proxy", "http://ambient.invalid:3");
        let _no_proxy = EnvGuard::set("NO_PROXY", "cursor.com");
        let _no_proxy_lower = EnvGuard::set("no_proxy", "cursor.com");
        let tmp = tempfile::tempdir().expect("tempdir");
        let script = tmp.path().join("check-no-proxy-env.sh");
        write_executable(
            &script,
            "#!/bin/sh\n\
             [ -z \"${HTTPS_PROXY+x}\" ] || exit 61\n\
             [ -z \"${https_proxy+x}\" ] || exit 62\n\
             [ -z \"${HTTP_PROXY+x}\" ] || exit 63\n\
             [ -z \"${http_proxy+x}\" ] || exit 64\n\
             [ -z \"${ALL_PROXY+x}\" ] || exit 65\n\
             [ -z \"${all_proxy+x}\" ] || exit 66\n\
             [ -z \"${NO_PROXY+x}\" ] || exit 67\n\
             [ -z \"${no_proxy+x}\" ] || exit 68\n\
             [ -z \"${EMBER_CURSOR_EGRESS_PROXY_URL+x}\" ] || exit 69\n\
             exit 0\n",
        );

        let code = run_with_registration(
            script.to_str().expect("utf8 script path"),
            &[],
            "cursor-default",
            &fixture_registration(),
            Path::new("/tmp/nonexistent-ember.sock"),
            tmp.path(),
        )
        .expect("run script");

        assert_eq!(code, 0);
    }

    #[test]
    fn cursor_launch_injects_daemon_cursor_egress_proxy_env() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _https = EnvGuard::set("HTTPS_PROXY", "http://ambient.invalid:1");
        let _no_proxy = EnvGuard::set("NO_PROXY", "cursor.com");
        let _no_proxy_lower = EnvGuard::set("no_proxy", "cursor.com");
        let tmp = tempfile::tempdir().expect("tempdir");
        let script = tmp.path().join("check-cursor-egress-env.sh");
        write_executable(
            &script,
            "#!/bin/sh\n\
             expected='http://127.0.0.1:61234'\n\
             [ \"$HTTPS_PROXY\" = \"$expected\" ] || exit 71\n\
             [ \"$https_proxy\" = \"$expected\" ] || exit 72\n\
             [ \"$HTTP_PROXY\" = \"$expected\" ] || exit 73\n\
             [ \"$http_proxy\" = \"$expected\" ] || exit 74\n\
             [ \"$ALL_PROXY\" = \"$expected\" ] || exit 75\n\
             [ \"$all_proxy\" = \"$expected\" ] || exit 76\n\
             [ \"$EMBER_CURSOR_EGRESS_PROXY_URL\" = \"$expected\" ] || exit 77\n\
             [ -z \"${NO_PROXY+x}\" ] || exit 78\n\
             [ -z \"${no_proxy+x}\" ] || exit 79\n\
             exit 0\n",
        );
        let mut registration = fixture_registration();
        registration.cursor_egress_proxy_url = Some("http://127.0.0.1:61234".to_string());

        let code = run_with_registration(
            script.to_str().expect("utf8 script path"),
            &[],
            "cursor-default",
            &registration,
            Path::new("/tmp/nonexistent-ember.sock"),
            tmp.path(),
        )
        .expect("run script");

        assert_eq!(code, 0);
    }
}
