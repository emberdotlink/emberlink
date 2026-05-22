//! `ember codex` launcher.
//!
//! This mirrors the shipped `ember claude-code` host-launch contract:
//! install the PATH shadow, register a daemon session, inject Ember session
//! env vars into the child, and close the session on exit.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::launcher::claude_code::{
    SessionRegistration, close_session_rpc, cohort_a_construct_specs, managed_prod_construct_specs,
    maybe_print_host_mode_disclaimer, prod_required_constructs_present, register_session_rpc,
    resolve_shadow_dir,
};
use crate::launcher::path_shadow::{ConstructSpec, install_path_shadow, shadow_bin_dir};

pub fn resolve_codex_bin() -> String {
    std::env::var("EMBER_CODEX_BIN").unwrap_or_else(|_| "codex".to_string())
}

pub fn resolve_persona_name() -> String {
    if let Ok(v) = std::env::var("EMBER_PERSONA")
        && !v.is_empty()
    {
        return v;
    }
    crate::onboarding::codex::codex_persona_name()
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
    eprintln!(
        "ember codex: launching {bin} (session={}, grant={}, proxy={})",
        registration.session_id, registration.grant_id, registration.proxy_url,
    );

    let parent_path = std::env::var("PATH").unwrap_or_default();
    let child_path = format!("{}:{}", shadow_dir.display(), parent_path);

    let mut cmd = Command::new(bin);
    cmd.args(extra_args)
        .env("EMBER_GRANT_ID", &registration.grant_id)
        .env("EMBER_PROXY_URL", &registration.proxy_url)
        .env("EMBER_SOCKET_PATH", socket_path.as_os_str())
        .env("EMBER_DAEMON_SOCKET", socket_path.as_os_str())
        .env("EMBER_SESSION_ID", &registration.session_id)
        .env("EMBER_PERSONA", persona)
        .env("PATH", &child_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(ref gpu) = registration.git_proxy_url {
        cmd.env("EMBER_GIT_PROXY_URL", gpu);
    }
    if let Some(ref sock) = registration.ssh_auth_sock {
        cmd.env("SSH_AUTH_SOCK", sock);
    }
    if let Some(runtime_id) = dev_runtime_id {
        cmd.env(crate::dev_runtime::DEV_RUNTIME_ID_ENV, runtime_id);
    }
    let status = cmd.status().map_err(|e| {
        io::Error::new(e.kind(), format!("ember codex: failed to spawn {bin}: {e}"))
    })?;

    close_session_rpc(&registration.session_id, socket_path);
    Ok(status.code().unwrap_or(1))
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
    install_path_shadow(shadow_dir, construct_specs)?;

    let registration = register_session_rpc(persona, socket_path).map_err(|e| {
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

    #[test]
    fn resolve_codex_bin_honors_override() {
        let prior = std::env::var("EMBER_CODEX_BIN").ok();
        unsafe { std::env::set_var("EMBER_CODEX_BIN", "/usr/local/bin/codex-test") };
        assert_eq!(resolve_codex_bin(), "/usr/local/bin/codex-test");
        match prior {
            Some(v) => unsafe { std::env::set_var("EMBER_CODEX_BIN", v) },
            None => unsafe { std::env::remove_var("EMBER_CODEX_BIN") },
        }
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
}
