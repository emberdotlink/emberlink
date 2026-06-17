//! `ember codex [--dev|--prod]` compatibility wrapper.

use std::io;

pub use crate::claude_code_launcher::{Flavor, LaunchEnv, build_launch_env, ping_daemon};

pub fn launch(
    flavor: Flavor,
    authority_strict: bool,
    delegated_template: Option<&str>,
    attach_runtime_persona_id: Option<&str>,
    extra_args: &[String],
) -> io::Result<()> {
    launch_with_workspace_ref(
        flavor,
        authority_strict,
        delegated_template,
        attach_runtime_persona_id,
        extra_args,
        None,
    )
}

pub fn launch_with_workspace_ref(
    flavor: Flavor,
    authority_strict: bool,
    delegated_template: Option<&str>,
    attach_runtime_persona_id: Option<&str>,
    extra_args: &[String],
    workspace_ref: Option<&str>,
) -> io::Result<()> {
    let env = build_launch_env(flavor)?;
    ping_daemon(&env, flavor)?;
    if let Some(runtime_banner) = env.runtime_banner.as_deref() {
        eprintln!("ember --dev runtime: {runtime_banner}");
    }
    let bin = crate::launcher::codex::resolve_codex_bin();
    let persona = crate::launcher::codex::resolve_persona_name();
    let construct_specs = match flavor {
        Flavor::Prod => crate::launcher::codex::prod_construct_specs_or_error()?,
        Flavor::Dev => crate::launcher::claude_code::cohort_a_construct_specs(),
    };
    let child_workspace_ref =
        crate::claude_code_launcher::child_workspace_ref_for_launch(&env, workspace_ref);
    let code =
        crate::launcher::codex::launch_codex_with_shadow_dir_and_constructs_with_workspace_ref(
            extra_args,
            &env.ember_daemon_socket,
            &env.shadow_root,
            &bin,
            &persona,
            &construct_specs,
            authority_strict,
            delegated_template,
            attach_runtime_persona_id,
            child_workspace_ref.as_deref(),
        )?;
    std::process::exit(code);
}
