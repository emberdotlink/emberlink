//! `ember session ...` helpers.
//!
//! `tail` remains the live-sidecar stopgap for cohort A.
//! `open` is the canonical session-launch contract: top-level launchers like
//! `ember claude` should delegate into one request shape rather than
//! teach parallel models. The mutable dev lane re-execs through the current
//! worktree's staged `ember` binary so internal sessions exercise the same
//! candidate CLI that `ember dev sync` just built.

use std::path::PathBuf;
use std::process::Command;

use crate::delegation_prompt::{DelegationPromptError, TemplateMeta};
use crate::launcher::harness::HarnessKind;
use crate::launcher::session_rpc::with_session_close;
use crate::launcher::worktree::{
    LiveState, clear_stale_live_lock, ensure_worktree_from_base, git_current_branch,
    live_state_for_path, new_live_metadata, new_session_metadata, resolve_branch_for_launch,
    resolve_repo_root, workspace_ref_for_worktree, worktree_path_for_session, write_live_meta,
    write_session_meta,
};
use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OpenSurface {
    #[value(name = "claude", alias = "claude-code")]
    ClaudeCode,
    #[value(name = "codex")]
    Codex,
    #[value(name = "cursor")]
    Cursor,
    #[value(name = "gemini")]
    Gemini,
}

// ===========================================================================
// Harness registry — the single source of per-harness launch behavior.
//
// ADD A NEW HARNESS HERE (e.g. `ember gemini`, `ember cursor`): append one
// [`HarnessSpec`] row to [`HARNESSES`] and add a provider launch module. Do
// NOT add `match surface { ... }` arms scattered across this file — every
// dispatch helper and launch entry point below reads this table, so a new
// harness is a data row plus its provider launch fns, never a shared
// match-arm edit. (Parallel sessions adding harnesses collide precisely on
// shared match arms; a table row is append-only and merge-clean.)
// ===========================================================================

/// Result shared by every harness launch entry point.
type LaunchResult = Result<(), Box<dyn std::error::Error>>;
/// Non-worktree session-open entry point: `(request)`.
type OpenFn = fn(&OpenRequest) -> LaunchResult;
/// Managed-worktree host launch: `(request, workspace_ref)`.
type HostLaunchFn = fn(&OpenRequest, &str) -> LaunchResult;
/// Managed-worktree sandvault launch: `(request, prepared_clone_path, workspace_ref)`.
type SandvaultLaunchFn = fn(&OpenRequest, &std::path::Path, &str) -> LaunchResult;

/// Per-harness launch descriptor. See the module-level note above for how to
/// add a harness.
pub struct HarnessSpec {
    /// The surface this row describes.
    pub surface: OpenSurface,
    /// Operator-facing launcher command, e.g. `"ember claude"`.
    pub command: &'static str,
    /// Human display name used in messages, e.g. `"Claude"`.
    pub display_name: &'static str,
    /// Short lowercase label used in event / log / error strings, e.g. `"claude"`.
    pub label: &'static str,
    /// A copy-pasteable example invocation, surfaced in actionable errors.
    pub example: &'static str,
    /// The session / live-metadata harness kind.
    pub harness_kind: HarnessKind,
    /// Recognizer for target-native subcommands that must not be mistaken for a
    /// prompt or managed-worktree name (codex has `exec`/`review`/…; claude has
    /// none). `None` = the harness exposes no passthrough subcommands.
    pub known_subcommand: Option<fn(&str) -> bool>,
    /// Non-worktree session-open entry point.
    pub open: OpenFn,
    /// Host launch for a managed worktree (workspace ref supplied).
    pub launch_host: HostLaunchFn,
    /// Sandvault launch for a managed worktree (prepared clone path + workspace ref).
    pub launch_sandvault: SandvaultLaunchFn,
}

/// The registered harnesses. Total over [`OpenSurface`] by construction —
/// [`harness_spec`] panics if a variant is missing a row, which a unit test
/// guards so the panic can never reach a release.
pub const HARNESSES: &[HarnessSpec] = &[
    HarnessSpec {
        surface: OpenSurface::ClaudeCode,
        command: "ember claude",
        display_name: "Claude",
        label: "claude",
        example:
            "ember claude --worktree archie --purpose \"GitHub setup friction\" -- --print hello",
        harness_kind: HarnessKind::Claude,
        known_subcommand: None,
        open: cmd_session_open_claude_code,
        launch_host: claude_launch_host_for_worktree,
        launch_sandvault: claude_launch_sandvault_for_worktree,
    },
    HarnessSpec {
        surface: OpenSurface::Codex,
        command: "ember codex",
        display_name: "Codex",
        label: "codex",
        example:
            "ember codex --worktree archie --purpose \"GitHub setup friction\" -- --no-alt-screen",
        harness_kind: HarnessKind::Codex,
        known_subcommand: Some(is_known_codex_subcommand),
        open: cmd_session_open_codex,
        launch_host: codex_launch_host_for_worktree,
        launch_sandvault: codex_launch_sandvault_for_worktree,
    },
    HarnessSpec {
        surface: OpenSurface::Cursor,
        command: "ember cursor",
        display_name: "Cursor",
        label: "cursor",
        example: "ember cursor --worktree archie --purpose \"GitHub setup friction\" -- --help",
        harness_kind: HarnessKind::Cursor,
        known_subcommand: None,
        open: cmd_session_open_cursor,
        launch_host: cursor_launch_host_for_worktree,
        launch_sandvault: cursor_launch_sandvault_for_worktree,
    },
    HarnessSpec {
        surface: OpenSurface::Gemini,
        command: "ember gemini",
        display_name: "Gemini",
        label: "gemini",
        example: "ember gemini --worktree archie --purpose \"GitHub setup friction\" -- --help",
        harness_kind: HarnessKind::Gemini,
        known_subcommand: None,
        open: cmd_session_open_gemini,
        launch_host: gemini_launch_host_for_worktree,
        launch_sandvault: gemini_launch_sandvault_for_worktree,
    },
];

/// Look up the [`HarnessSpec`] for a surface. Every [`OpenSurface`] variant has
/// exactly one row in [`HARNESSES`]; the lookup is total by construction.
pub fn harness_spec(surface: OpenSurface) -> &'static HarnessSpec {
    HARNESSES
        .iter()
        .find(|h| h.surface == surface)
        .expect("every OpenSurface has a HarnessSpec row in HARNESSES")
}

/// True if `arg` is a target-native passthrough subcommand for this harness
/// (so it must not be treated as a prompt or managed-worktree name).
fn surface_known_subcommand(surface: OpenSurface, arg: &str) -> bool {
    harness_spec(surface)
        .known_subcommand
        .is_some_and(|recognizes| recognizes(arg))
}

// --- Per-harness managed-worktree launch wrappers ------------------------------
// These adapt each provider's launch fn to the uniform `HarnessSpec` fn-pointer
// signature, absorbing per-provider pre-processing (claude resolves its
// delegation template; codex forwards the request's template verbatim).

fn claude_launch_host_for_worktree(
    request: &OpenRequest,
    workspace_ref: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let delegation_template = resolve_claude_delegation_template_for_request(request)?;
    launch_claude_code_host(
        request.lane,
        request.authority_strict,
        delegation_template.as_deref(),
        request.attach_runtime_persona_id.as_deref(),
        &request.extra_args,
        Some(workspace_ref),
    )
}

fn codex_launch_host_for_worktree(
    request: &OpenRequest,
    workspace_ref: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    launch_codex_host(
        request.lane,
        request.authority_strict,
        request.delegated_template.as_deref(),
        request.attach_runtime_persona_id.as_deref(),
        &request.extra_args,
        Some(workspace_ref),
    )
}

fn cursor_launch_host_for_worktree(
    request: &OpenRequest,
    workspace_ref: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    launch_cursor_host(
        request.lane,
        request.authority_strict,
        request.delegated_template.as_deref(),
        request.attach_runtime_persona_id.as_deref(),
        &request.extra_args,
        Some(workspace_ref),
    )
}

fn claude_launch_sandvault_for_worktree(
    request: &OpenRequest,
    prepared_path: &std::path::Path,
    workspace_ref: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let delegation_template = resolve_claude_delegation_template_for_request(request)?;
    launch_claude_code_sandvault(
        request,
        delegation_template.as_deref(),
        prepared_path,
        workspace_ref,
    )
}

fn codex_launch_sandvault_for_worktree(
    request: &OpenRequest,
    prepared_path: &std::path::Path,
    workspace_ref: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    launch_codex_sandvault(request, prepared_path, workspace_ref)
}

fn cursor_launch_sandvault_for_worktree(
    _request: &OpenRequest,
    _prepared_path: &std::path::Path,
    _workspace_ref: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Err(
        "`ember cursor --sandbox sandvault` is not wired yet; baseline Cursor launch is host-only until a governed loopback-projector mediation lane is designed"
            .into(),
    )
}

fn gemini_launch_host_for_worktree(
    request: &OpenRequest,
    workspace_ref: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    launch_gemini_host(
        request.lane,
        request.authority_strict,
        request.delegated_template.as_deref(),
        request.attach_runtime_persona_id.as_deref(),
        &request.extra_args,
        Some(workspace_ref),
    )
}

fn gemini_launch_sandvault_for_worktree(
    _request: &OpenRequest,
    _prepared_path: &std::path::Path,
    _workspace_ref: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // ADR 215 §2: the gemini Code Assist loopback proxy is HOST-only (the daemon
    // returns no per-session proxy URL for container sessions yet), so sandvault
    // placement fails closed rather than launching without credential brokering.
    Err(
        "`ember gemini --sandbox sandvault` is not wired yet; the brokered Gemini Code Assist lane is host-only until a container-side loopback-projector mediation lane is designed"
            .into(),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenLane {
    Prod,
    Dev,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OpenPlacement {
    Auto,
    Host,
    Isolated,
    Sandvault,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorktreeRequest {
    pub session_name: String,
    pub branch: Option<String>,
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRequest {
    pub surface: OpenSurface,
    pub lane: OpenLane,
    pub placement: OpenPlacement,
    pub authority_strict: bool,
    pub delegated_template: Option<String>,
    pub attach_runtime_persona_id: Option<String>,
    pub fork_runtime: bool,
    pub backend_hint: Option<String>,
    pub preset: Option<String>,
    pub worktree: Option<ManagedWorktreeRequest>,
    pub extra_args: Vec<String>,
}

// Ember launcher flags that, if they appear in the forwarded (trailing) args,
// were almost certainly meant for the launcher but landed after the first
// passthrough token (clap's `trailing_var_arg` captures everything from there
// on). Detecting them lets us emit an actionable "put launcher options first"
// error instead of forwarding e.g. `--fork` to Claude, which rejects it with a
// cryptic "unknown option" (cost a real session on 2026-05-28). The
// runtime-placement/posture flags (`--strict`, `--delegated`, `--attach`,
// `--fork`) were added in P9-S4 but never added here — keep this list in sync
// with the `ember claude` / `ember codex` launcher flags in `bin/ember.rs`.
const MISPLACED_LAUNCHER_FLAGS: &[&str] = &[
    "--dev",
    "--prod",
    "--host",
    "--isolated",
    "--sandbox",
    "--strict",
    "--delegated",
    "--attach",
    "--fork",
    "--backend",
    "--preset",
    "--branch",
    "--purpose",
];

fn launcher_command(surface: OpenSurface) -> &'static str {
    harness_spec(surface).command
}

fn surface_name(surface: OpenSurface) -> &'static str {
    harness_spec(surface).display_name
}

fn launcher_example(surface: OpenSurface) -> &'static str {
    harness_spec(surface).example
}

fn is_known_codex_subcommand(arg: &str) -> bool {
    matches!(
        arg,
        "exec"
            | "review"
            | "login"
            | "logout"
            | "mcp"
            | "plugin"
            | "mcp-server"
            | "app-server"
            | "remote-control"
            | "app"
            | "completion"
            | "update"
            | "doctor"
            | "sandbox"
            | "debug"
            | "apply"
            | "resume"
            | "fork"
            | "cloud"
            | "exec-server"
            | "features"
            | "help"
    )
}

fn misplaced_launcher_args_error(surface: OpenSurface, extra_args: &[String]) -> Option<String> {
    let misplaced_flag = extra_args
        .iter()
        .find(|arg| MISPLACED_LAUNCHER_FLAGS.contains(&arg.as_str()))?;
    Some(format!(
        "launcher option `{misplaced_flag}` appeared after forwarded {} args. Put Ember launcher options before target args, and use `--` before forwarded {} flags.\n  Example: `{}`\n  A bare token after `{}` is forwarded to {} as its prompt or subcommand.",
        surface_name(surface),
        surface_name(surface),
        launcher_example(surface),
        launcher_command(surface),
        surface_name(surface),
    ))
}

fn misplaced_help_request_error(surface: OpenSurface, extra_args: &[String]) -> Option<String> {
    if !extra_args.iter().any(|arg| arg == "--help") {
        return None;
    }
    if extra_args.len() == 1 && extra_args[0] == "--help" {
        return None;
    }
    // A target-native subcommand as the first token means `--help` is the
    // subcommand's help, not a misplaced launcher `--help`. (Claude exposes no
    // such subcommands, so this is a no-op there.)
    if extra_args
        .first()
        .is_some_and(|arg| surface_known_subcommand(surface, arg))
    {
        return None;
    }
    Some(format!(
        "`--help` was forwarded after target args. Use `{} --help` for Ember help, or `{} -- --help` to forward target help explicitly.",
        launcher_command(surface),
        launcher_command(surface),
    ))
}

fn ambiguous_prompt_with_flags_error(
    surface: OpenSurface,
    worktree: Option<&str>,
    extra_args: &[String],
) -> Option<String> {
    if worktree.is_some() || extra_args.len() < 2 {
        return None;
    }
    let first = extra_args.first()?;
    if first.starts_with('-') {
        return None;
    }
    if surface_known_subcommand(surface, first) {
        return None;
    }
    if !extra_args.iter().skip(1).any(|arg| arg.starts_with('-')) {
        return None;
    }
    Some(format!(
        "the bare token `{first}` is being forwarded to {} as a prompt while later arguments look like forwarded {} flags. If `{first}` is the managed worktree/session name, spell it as `{} --worktree {first} -- ...`.\n  Example: `{}`",
        surface_name(surface),
        surface_name(surface),
        launcher_command(surface),
        launcher_example(surface),
    ))
}

fn infer_managed_worktree_name(
    surface: OpenSurface,
    branch: &Option<String>,
    purpose: &Option<String>,
    extra_args: &mut Vec<String>,
) -> Option<String> {
    let candidate = extra_args.first()?.clone();
    if candidate.starts_with('-') {
        return None;
    }
    if surface_known_subcommand(surface, &candidate) {
        return None;
    }
    if branch.is_none() && purpose.is_none() && extra_args.len() != 1 {
        return None;
    }
    extra_args.remove(0);
    Some(candidate)
}

// RPC/plumbing signature — threads CLI flags to the constructor; structurally many params.
#[allow(clippy::too_many_arguments)]
pub fn build_open_request(
    surface: OpenSurface,
    dev: bool,
    host: bool,
    isolated: bool,
    authority_strict: bool,
    delegated_template: Option<String>,
    attach_runtime_persona_id: Option<String>,
    fork_runtime: bool,
    backend_hint: Option<String>,
    preset: Option<String>,
    worktree: Option<String>,
    branch: Option<String>,
    purpose: Option<String>,
    extra_args: Vec<String>,
) -> Result<OpenRequest, String> {
    build_open_request_with_sandvault(
        surface,
        dev,
        host,
        isolated,
        false,
        authority_strict,
        delegated_template,
        attach_runtime_persona_id,
        fork_runtime,
        backend_hint,
        preset,
        worktree,
        branch,
        purpose,
        extra_args,
    )
}

// RPC/plumbing signature — threads CLI flags to the constructor; structurally many params.
#[allow(clippy::too_many_arguments)]
pub fn build_open_request_with_sandvault(
    surface: OpenSurface,
    dev: bool,
    host: bool,
    isolated: bool,
    sandvault: bool,
    authority_strict: bool,
    delegated_template: Option<String>,
    attach_runtime_persona_id: Option<String>,
    fork_runtime: bool,
    backend_hint: Option<String>,
    preset: Option<String>,
    worktree: Option<String>,
    branch: Option<String>,
    purpose: Option<String>,
    extra_args: Vec<String>,
) -> Result<OpenRequest, String> {
    let override_count = [host, isolated, sandvault]
        .into_iter()
        .filter(|selected| *selected)
        .count();
    if override_count > 1 {
        return Err(
            "choose exactly one placement override: `--host`, `--isolated`, or `--sandbox sandvault`"
                .into(),
        );
    }
    let placement = if host {
        OpenPlacement::Host
    } else if isolated {
        OpenPlacement::Isolated
    } else if sandvault {
        OpenPlacement::Sandvault
    } else {
        OpenPlacement::Auto
    };

    if (backend_hint.is_some() || preset.is_some()) && placement != OpenPlacement::Isolated {
        return Err(
            "backend hints and presets only apply to isolated placement; add `--isolated`".into(),
        );
    }

    let mut extra_args = extra_args;

    if fork_runtime && attach_runtime_persona_id.is_some() {
        return Err(
            "choose exactly one runtime placement: `--fork` or `--attach <runtime-persona-id>`"
                .into(),
        );
    }

    if let Some(err) = misplaced_launcher_args_error(surface, &extra_args) {
        return Err(err);
    }
    if let Some(err) = misplaced_help_request_error(surface, &extra_args) {
        return Err(err);
    }

    let worktree = worktree
        .or_else(|| infer_managed_worktree_name(surface, &branch, &purpose, &mut extra_args));

    if worktree.is_none() && (branch.is_some() || purpose.is_some()) {
        return Err("`--branch` and `--purpose` require `--worktree <name>`".into());
    }
    if let Some(err) = ambiguous_prompt_with_flags_error(surface, worktree.as_deref(), &extra_args)
    {
        return Err(err);
    }

    Ok(OpenRequest {
        surface,
        lane: if dev { OpenLane::Dev } else { OpenLane::Prod },
        placement,
        authority_strict,
        delegated_template,
        attach_runtime_persona_id,
        fork_runtime,
        backend_hint,
        preset,
        worktree: worktree.map(|session_name| ManagedWorktreeRequest {
            session_name,
            branch,
            purpose,
        }),
        extra_args,
    })
}

// RPC/plumbing signature — threads CLI flags to the constructor; structurally many params.
#[allow(clippy::too_many_arguments)]
pub fn claude_code_alias_request(
    dev: bool,
    host: bool,
    isolated: bool,
    authority_strict: bool,
    delegated_template: Option<String>,
    attach_runtime_persona_id: Option<String>,
    fork_runtime: bool,
    backend_hint: Option<String>,
    preset: Option<String>,
    worktree: Option<String>,
    branch: Option<String>,
    purpose: Option<String>,
    extra_args: &[String],
) -> Result<OpenRequest, String> {
    claude_code_alias_request_with_sandvault(
        dev,
        host,
        isolated,
        false,
        authority_strict,
        delegated_template,
        attach_runtime_persona_id,
        fork_runtime,
        backend_hint,
        preset,
        worktree,
        branch,
        purpose,
        extra_args,
    )
}

// RPC/plumbing signature — threads CLI flags to the constructor; structurally many params.
#[allow(clippy::too_many_arguments)]
pub fn claude_code_alias_request_with_sandvault(
    dev: bool,
    host: bool,
    isolated: bool,
    sandvault: bool,
    authority_strict: bool,
    delegated_template: Option<String>,
    attach_runtime_persona_id: Option<String>,
    fork_runtime: bool,
    backend_hint: Option<String>,
    preset: Option<String>,
    worktree: Option<String>,
    branch: Option<String>,
    purpose: Option<String>,
    extra_args: &[String],
) -> Result<OpenRequest, String> {
    build_open_request_with_sandvault(
        OpenSurface::ClaudeCode,
        dev,
        host,
        isolated,
        sandvault,
        authority_strict,
        delegated_template,
        attach_runtime_persona_id,
        fork_runtime,
        backend_hint,
        preset,
        worktree,
        branch,
        purpose,
        extra_args.to_vec(),
    )
}

// RPC/plumbing signature — threads CLI flags to the constructor; structurally many params.
#[allow(clippy::too_many_arguments)]
pub fn codex_alias_request(
    dev: bool,
    host: bool,
    isolated: bool,
    authority_strict: bool,
    delegated_template: Option<String>,
    attach_runtime_persona_id: Option<String>,
    fork_runtime: bool,
    backend_hint: Option<String>,
    preset: Option<String>,
    worktree: Option<String>,
    branch: Option<String>,
    purpose: Option<String>,
    extra_args: &[String],
) -> Result<OpenRequest, String> {
    codex_alias_request_with_sandvault(
        dev,
        host,
        isolated,
        false,
        authority_strict,
        delegated_template,
        attach_runtime_persona_id,
        fork_runtime,
        backend_hint,
        preset,
        worktree,
        branch,
        purpose,
        extra_args,
    )
}

// RPC/plumbing signature — threads CLI flags to the constructor; structurally many params.
#[allow(clippy::too_many_arguments)]
pub fn codex_alias_request_with_sandvault(
    dev: bool,
    host: bool,
    isolated: bool,
    sandvault: bool,
    authority_strict: bool,
    delegated_template: Option<String>,
    attach_runtime_persona_id: Option<String>,
    fork_runtime: bool,
    backend_hint: Option<String>,
    preset: Option<String>,
    worktree: Option<String>,
    branch: Option<String>,
    purpose: Option<String>,
    extra_args: &[String],
) -> Result<OpenRequest, String> {
    build_open_request_with_sandvault(
        OpenSurface::Codex,
        dev,
        host,
        isolated,
        sandvault,
        authority_strict,
        delegated_template,
        attach_runtime_persona_id,
        fork_runtime,
        backend_hint,
        preset,
        worktree,
        branch,
        purpose,
        extra_args.to_vec(),
    )
}

// RPC/plumbing signature — threads CLI flags to the constructor; structurally many params.
#[allow(clippy::too_many_arguments)]
pub fn cursor_alias_request(
    dev: bool,
    host: bool,
    isolated: bool,
    authority_strict: bool,
    delegated_template: Option<String>,
    attach_runtime_persona_id: Option<String>,
    fork_runtime: bool,
    backend_hint: Option<String>,
    preset: Option<String>,
    worktree: Option<String>,
    branch: Option<String>,
    purpose: Option<String>,
    extra_args: &[String],
) -> Result<OpenRequest, String> {
    cursor_alias_request_with_sandvault(
        dev,
        host,
        isolated,
        false,
        authority_strict,
        delegated_template,
        attach_runtime_persona_id,
        fork_runtime,
        backend_hint,
        preset,
        worktree,
        branch,
        purpose,
        extra_args,
    )
}

// RPC/plumbing signature — threads CLI flags to the constructor; structurally many params.
#[allow(clippy::too_many_arguments)]
pub fn cursor_alias_request_with_sandvault(
    dev: bool,
    host: bool,
    isolated: bool,
    sandvault: bool,
    authority_strict: bool,
    delegated_template: Option<String>,
    attach_runtime_persona_id: Option<String>,
    fork_runtime: bool,
    backend_hint: Option<String>,
    preset: Option<String>,
    worktree: Option<String>,
    branch: Option<String>,
    purpose: Option<String>,
    extra_args: &[String],
) -> Result<OpenRequest, String> {
    build_open_request_with_sandvault(
        OpenSurface::Cursor,
        dev,
        host,
        isolated,
        sandvault,
        authority_strict,
        delegated_template,
        attach_runtime_persona_id,
        fork_runtime,
        backend_hint,
        preset,
        worktree,
        branch,
        purpose,
        extra_args.to_vec(),
    )
}

// RPC/plumbing signature — threads CLI flags to the constructor; structurally many params.
#[allow(clippy::too_many_arguments)]
pub fn gemini_alias_request(
    dev: bool,
    host: bool,
    isolated: bool,
    sandvault: bool,
    authority_strict: bool,
    delegated_template: Option<String>,
    attach_runtime_persona_id: Option<String>,
    fork_runtime: bool,
    backend_hint: Option<String>,
    preset: Option<String>,
    worktree: Option<String>,
    branch: Option<String>,
    purpose: Option<String>,
    extra_args: &[String],
) -> Result<OpenRequest, String> {
    build_open_request_with_sandvault(
        OpenSurface::Gemini,
        dev,
        host,
        isolated,
        sandvault,
        authority_strict,
        delegated_template,
        attach_runtime_persona_id,
        fork_runtime,
        backend_hint,
        preset,
        worktree,
        branch,
        purpose,
        extra_args.to_vec(),
    )
}

pub fn cmd_session_open(request: &OpenRequest) -> Result<(), Box<dyn std::error::Error>> {
    if request.fork_runtime {
        eprintln!(
            "ember {}: opening a fresh Runtime Persona (--fork)",
            surface_label(request.surface)
        );
    }
    if request.worktree.is_some() {
        return cmd_session_open_managed_worktree(request);
    }
    (harness_spec(request.surface).open)(request)
}

struct LiveLockGuard {
    path: PathBuf,
}

impl LiveLockGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for LiveLockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.path.join(".agent-live"));
    }
}

struct CwdGuard {
    previous: PathBuf,
}

impl CwdGuard {
    fn change_to(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let previous = std::env::current_dir()?;
        std::env::set_current_dir(path)?;
        Ok(Self { previous })
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.previous);
    }
}

fn parent_pid() -> Option<u32> {
    std::env::var("PPID").ok()?.parse::<u32>().ok()
}

fn harness_kind(surface: OpenSurface) -> HarnessKind {
    harness_spec(surface).harness_kind
}

fn surface_label(surface: OpenSurface) -> &'static str {
    harness_spec(surface).label
}

fn cmd_session_open_managed_worktree(
    request: &OpenRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let worktree = request
        .worktree
        .as_ref()
        .ok_or("managed-worktree request missing metadata")?;
    if request.placement == OpenPlacement::Sandvault {
        return cmd_session_open_sandvault_managed_worktree(request);
    }
    if request.placement == OpenPlacement::Isolated {
        return Err(format!(
            "managed worktree launch is host-only for now; remove `--isolated` from `session open {}`",
            surface_label(request.surface)
        )
        .into());
    }

    let repo_root = resolve_repo_root()?;
    let worktree_path = worktree_path_for_session(&repo_root, &worktree.session_name)?;
    let branch = resolve_branch_for_launch(
        &worktree_path,
        &worktree.session_name,
        worktree.branch.as_deref(),
    )?;

    if worktree_path.exists() {
        let _ = clear_stale_live_lock(&worktree_path);
        if let LiveState::Live(pid) = live_state_for_path(&worktree_path)? {
            return Err(format!(
                "managed worktree already has a live owner at {} (pid {}); use a distinct worktree name or wait for the current owner to exit",
                worktree_path.display(),
                pid
            )
            .into());
        }
    }

    ensure_worktree_from_base(&repo_root, &worktree_path, &branch, "origin/main")?;

    let session_meta = new_session_metadata(
        &worktree.session_name,
        &git_current_branch(&worktree_path)?,
        harness_kind(request.surface),
        worktree.purpose.as_deref().unwrap_or(""),
        &worktree_path,
    );
    write_session_meta(&session_meta)?;

    let live_meta = new_live_metadata(
        &worktree.session_name,
        harness_kind(request.surface),
        std::process::id(),
        parent_pid(),
        &worktree_path,
    );
    write_live_meta(&live_meta)?;
    let _live_guard = LiveLockGuard::new(worktree_path.clone());
    let _cwd_guard = CwdGuard::change_to(&worktree_path)?;
    let workspace_ref = workspace_ref_for_worktree(&worktree_path);

    eprintln!(
        "Managed worktree: {} [{}] (workspace={})",
        worktree_path.display(),
        surface_label(request.surface),
        workspace_ref
    );
    if request.placement == OpenPlacement::Auto {
        eprintln!(
            "Launch mode: using the host path for `{}`",
            surface_label(request.surface)
        );
    }

    (harness_spec(request.surface).launch_host)(request, &workspace_ref)
}

fn cmd_session_open_sandvault_managed_worktree(
    request: &OpenRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    if request.lane == OpenLane::Dev {
        return Err(
            "`--sandbox sandvault` is currently wired only for the prod daemon lane".into(),
        );
    }

    let worktree = request
        .worktree
        .as_ref()
        .ok_or("managed-worktree request missing metadata")?;
    let repo_root = resolve_repo_root()?;
    let worktree_path = crate::up::sandvault::worktree_path_for_session(&worktree.session_name)?;
    let branch = resolve_branch_for_launch(
        &worktree_path,
        &worktree.session_name,
        worktree.branch.as_deref(),
    )?;

    if worktree_path.exists() {
        let _ = clear_stale_live_lock(&worktree_path);
        if let LiveState::Live(pid) = live_state_for_path(&worktree_path)? {
            return Err(format!(
                "Sandvault managed worktree already has a live owner at {} (pid {}); use a distinct worktree name or wait for the current owner to exit",
                worktree_path.display(),
                pid
            )
            .into());
        }
    }

    let prepared =
        crate::up::sandvault::ensure_managed_clone_from_base(&repo_root, &worktree_path, &branch)?;
    let session_meta = new_session_metadata(
        &worktree.session_name,
        &prepared.branch,
        harness_kind(request.surface),
        worktree.purpose.as_deref().unwrap_or(""),
        &prepared.path,
    );
    write_session_meta(&session_meta)?;

    let live_meta = new_live_metadata(
        &worktree.session_name,
        harness_kind(request.surface),
        std::process::id(),
        parent_pid(),
        &prepared.path,
    );
    write_live_meta(&live_meta)?;
    let _live_guard = LiveLockGuard::new(prepared.path.clone());
    let _cwd_guard = CwdGuard::change_to(&prepared.path)?;
    let workspace_ref = workspace_ref_for_worktree(&prepared.path);

    eprintln!(
        "Sandvault worktree: {} [{}] (workspace={})",
        prepared.path.display(),
        surface_label(request.surface),
        workspace_ref
    );

    (harness_spec(request.surface).launch_sandvault)(request, &prepared.path, &workspace_ref)
}

fn cmd_session_open_claude_code(request: &OpenRequest) -> Result<(), Box<dyn std::error::Error>> {
    if request.lane == OpenLane::Dev {
        maybe_reexec_via_dev_cli()?;
        let mut request = request.clone();
        request.delegated_template = resolve_claude_delegation_template_for_request(&request)?;
        return match request.placement {
            OpenPlacement::Host => launch_claude_code_host(
                request.lane,
                request.authority_strict,
                request.delegated_template.as_deref(),
                request.attach_runtime_persona_id.as_deref(),
                &request.extra_args,
                None,
            ),
            OpenPlacement::Auto => {
                eprintln!(
                    "ember claude: dev isolated launch is not ready yet; using the host dev runtime"
                );
                launch_claude_code_host(
                    request.lane,
                    request.authority_strict,
                    request.delegated_template.as_deref(),
                    request.attach_runtime_persona_id.as_deref(),
                    &request.extra_args,
                    None,
                )
            }
            OpenPlacement::Isolated => Err(
                "isolated `session open claude --dev` is not wired yet; the current dev lane remains host/worktree-scoped"
                    .into(),
            ),
            OpenPlacement::Sandvault => Err(
                "`ember claude --sandbox sandvault --dev` is not wired yet; use the prod lane with `--worktree`"
                    .into(),
            ),
        };
    }

    let mut request = request.clone();
    request.delegated_template = resolve_claude_delegation_template_for_request(&request)?;

    match request.placement {
        OpenPlacement::Host => launch_claude_code_host(
            request.lane,
            request.authority_strict,
            request.delegated_template.as_deref(),
            request.attach_runtime_persona_id.as_deref(),
            &request.extra_args,
            None,
        ),
        OpenPlacement::Auto => launch_claude_code_auto(&request),
        OpenPlacement::Isolated => launch_claude_code_isolated(&request),
        OpenPlacement::Sandvault => {
            Err("`ember claude --sandbox sandvault` currently requires `--worktree <name>`".into())
        }
    }
}

fn delegation_template_install_root_for_lane(lane: OpenLane) -> PathBuf {
    match lane {
        OpenLane::Prod => PathBuf::from(crate::install_paths::PROD_INSTALL_ROOT),
        OpenLane::Dev => crate::dev_runtime::resolve_current_dev_runtime()
            .map(|runtime| runtime.install_root)
            .unwrap_or_else(|_| PathBuf::from(crate::install_paths::DEV_INSTALL_ROOT)),
    }
}

fn source_delegation_template_install_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn list_launcher_delegation_templates(
    install_root: &std::path::Path,
) -> Result<Vec<TemplateMeta>, DelegationPromptError> {
    match crate::delegation_prompt::list_templates(install_root) {
        Ok(templates) => Ok(templates),
        Err(DelegationPromptError::NoTemplates { .. }) => {
            let source_root = source_delegation_template_install_root();
            if source_root == install_root {
                crate::delegation_prompt::list_templates(install_root)
            } else {
                crate::delegation_prompt::list_templates(&source_root)
            }
        }
        Err(e) => Err(e),
    }
}

fn resolve_claude_delegation_template_for_request(
    request: &OpenRequest,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    resolve_claude_delegation_template_for_request_with_selector(request, |templates| {
        crate::delegation_prompt::prompt_for_template_with_cache(templates)
    })
    .map_err(|e| std::io::Error::other(e).into())
}

fn resolve_claude_delegation_template_for_request_with_selector<F>(
    request: &OpenRequest,
    selector: F,
) -> Result<Option<String>, String>
where
    F: FnOnce(&[TemplateMeta]) -> Result<TemplateMeta, DelegationPromptError>,
{
    let explicit = crate::launcher::claude_code::resolve_delegation_template_for_launch(
        request.delegated_template.as_deref(),
        "ember claude",
    )?;
    if explicit.is_some() {
        return Ok(explicit);
    }

    // pregrant_launcher_wire_landed / pregrant_launcher_prompt_ux_landed:
    // no explicit --delegated override means the launcher opens
    // the delegation selector and passes the chosen template into session-open,
    // where the daemon lowers the template's authority into the runtime
    // persona's `StandingGrant` atomically with registration (per ADR 205 §6).
    let install_root = delegation_template_install_root_for_lane(request.lane);
    let templates = list_launcher_delegation_templates(&install_root).map_err(|e| {
        format!(
            "ember claude: delegation selector unavailable: {e}\n  retry with `ember claude --delegated <template>` or repair the bundled delegation templates"
        )
    })?;
    let selected = selector(&templates).map_err(|e| {
        format!(
            "ember claude: delegation selection failed: {e}\n  retry with `ember claude --delegated <template>`"
        )
    })?;
    crate::launcher::claude_code::resolve_delegation_template_for_launch(
        Some(&selected.name),
        "ember claude",
    )?;
    eprintln!(
        "ember claude: selected delegation `{}` (ttl={}s)",
        selected.name, selected.ttl_secs
    );
    Ok(Some(selected.name))
}

fn launch_claude_code_auto(request: &OpenRequest) -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = std::env::current_dir()?;
    match crate::up::detect_isolated_claude_code_capability(
        &current_dir,
        request.backend_hint.as_deref(),
    )? {
        crate::up::IsolatedClaudeCodeCapability::Ready { .. } => {
            launch_claude_code_isolated(request)
        }
        crate::up::IsolatedClaudeCodeCapability::Unavailable { reason } => {
            eprintln!("ember claude: isolated path unavailable; using host launcher ({reason})");
            launch_claude_code_host(
                request.lane,
                request.authority_strict,
                request.delegated_template.as_deref(),
                request.attach_runtime_persona_id.as_deref(),
                &request.extra_args,
                None,
            )
        }
    }
}

/// ADR 207 seam 4 — classify a `register_session` failure as "the daemon
/// bridge lane is not available". The isolated container lane structurally
/// requires the ADR 154 bridge; when `[daemon].bridge_bind` is unset (or the
/// listener could not bind) the daemon refuses the bridge-client bundle with
/// these distinctive messages (see
/// `ember-daemon::infra::handlers::session::mint_register_session_bridge_client_bundle`).
/// Matching the message (not a brittle RPC code, which is shared with vault-lock
/// states) keeps the classifier narrow: only the bridge-disabled case fails
/// soft; every other registration error still surfaces hard.
fn is_bridge_unavailable_error(msg: &str) -> bool {
    msg.contains("bridge listener is not configured")
        || msg.contains("bridge listener must bind a concrete port")
}

/// ADR 207 seam 4 / §"Bridge enablement on `--isolated`" — fail soft when the
/// isolated container lane cannot come up because the daemon bridge is not
/// enabled. `--auto` falls back to the host launcher (`host_launch`); an
/// explicit `--isolated` returns the canonical, actionable guidance instead of
/// a raw RPC error. `harness_label` is the user-facing command (e.g.
/// `"ember claude"`).
fn fail_soft_bridge_unavailable<F>(
    request: &OpenRequest,
    harness_label: &str,
    host_launch: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnOnce(&OpenRequest) -> Result<(), Box<dyn std::error::Error>>,
{
    if request.placement == OpenPlacement::Auto {
        eprintln!(
            "{harness_label}: isolated container lane unavailable (daemon bridge not enabled); using host launcher"
        );
        host_launch(request)
    } else {
        Err(format!(
            "{harness_label} --isolated needs the daemon bridge, which is not enabled.\n  \
             Enable it by setting `[daemon].bridge_bind` (or the EMBER_BRIDGE_BIND env var) and \
             restarting the daemon, or run `{harness_label}` without `--isolated` for a host session."
        )
        .into())
    }
}

fn launch_claude_code_isolated(request: &OpenRequest) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        crate::claude_code_launcher::build_launch_env(crate::claude_code_launcher::Flavor::Prod)?;
    crate::claude_code_launcher::ping_daemon(&env, crate::claude_code_launcher::Flavor::Prod)?;
    let persona = crate::launcher::claude_code::resolve_persona_name();
    let delegation_template = crate::launcher::claude_code::resolve_delegation_template_for_launch(
        request.delegated_template.as_deref(),
        "ember claude",
    )
    .map_err(std::io::Error::other)?;
    let registration = match crate::launcher::session_rpc::register_session_rpc_with_isolated_bridge(
        &persona,
        &env.ember_daemon_socket,
        delegation_template.as_deref(),
        request.authority_strict,
        request.attach_runtime_persona_id.as_deref(),
        "ember claude",
        "ember claude --isolated",
    ) {
        Ok(registration) => registration,
        // ADR 207 seam 4 — bridge lane disabled: fail soft (auto → host;
        // explicit --isolated → canonical guidance) instead of a raw RPC error.
        Err(e) if is_bridge_unavailable_error(&e.to_string()) => {
            return fail_soft_bridge_unavailable(request, "ember claude", |req| {
                launch_claude_code_host(
                    req.lane,
                    req.authority_strict,
                    req.delegated_template.as_deref(),
                    req.attach_runtime_persona_id.as_deref(),
                    &req.extra_args,
                    None,
                )
            });
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found")
                || msg.contains("no such persona")
                || msg.contains("unknown persona")
            {
                return Err(std::io::Error::new(
                    e.kind(),
                    "no cohort-A persona found.\n  Run `ember init --for claude` first, or set $EMBER_PERSONA to an existing persona name.".to_string(),
                )
                .into());
            }
            return Err(e.into());
        }
    };
    let code = with_session_close(
        &registration.session_id,
        &env.ember_daemon_socket,
        "ember claude",
        "ember claude --isolated",
        || {
            crate::up::launch_harness_isolated(crate::up::IsolatedHarnessLaunch {
                harness: HarnessKind::Claude,
                persona: persona.clone(),
                registration: registration.clone(),
                daemon_socket_path: env.ember_daemon_socket.clone(),
                extra_args: request.extra_args.clone(),
                backend_hint: request.backend_hint.clone(),
                preset: request.preset.clone(),
                workspace_root: std::env::current_dir()?,
                shadow_root: env.shadow_root.clone(),
                codex_runtime_source: None,
                codex_config_source: None,
            })
        },
    )?;
    std::process::exit(code);
}

fn launch_claude_code_sandvault(
    request: &OpenRequest,
    delegated_template: Option<&str>,
    workspace_root: &std::path::Path,
    workspace_ref: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        crate::claude_code_launcher::build_launch_env(crate::claude_code_launcher::Flavor::Prod)?;
    crate::claude_code_launcher::ping_daemon(&env, crate::claude_code_launcher::Flavor::Prod)?;
    let persona = crate::launcher::claude_code::resolve_persona_name();
    let registration = crate::launcher::session_rpc::register_session_rpc_with_isolated_bridge(
        &persona,
        &env.ember_daemon_socket,
        delegated_template,
        request.authority_strict,
        request.attach_runtime_persona_id.as_deref(),
        "ember sandvault",
        "ember claude --sandbox sandvault",
    )
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("not found")
            || msg.contains("no such persona")
            || msg.contains("unknown persona")
        {
            std::io::Error::new(
                e.kind(),
                "no cohort-A persona found.\n  Run `ember init --for claude` first, or set $EMBER_PERSONA to an existing persona name.".to_string(),
            )
        } else {
            e
        }
    })?;
    if registration.anthropic_base_url.is_none() || registration.anthropic_custom_headers.is_none()
    {
        return Err(
            "Sandvault Claude launch requires a brokered Anthropic gateway grant; refusing to rely on sandbox-user native model auth"
                .into(),
        );
    }
    let construct_specs = crate::launcher::claude_code::managed_prod_construct_specs();
    if !crate::launcher::claude_code::prod_required_constructs_present(&construct_specs) {
        return Err(
            "prod construct bundle is incomplete: expected managed `ember-gh` and `ember-git` before launching Sandvault"
                .into(),
        );
    }
    let code = with_session_close(
        &registration.session_id,
        &env.ember_daemon_socket,
        "ember sandvault",
        "ember claude --sandbox sandvault",
        || {
            crate::up::sandvault::launch_harness_sandvault(
                crate::up::sandvault::SandvaultHarnessLaunch {
                    harness: HarnessKind::Claude,
                    registration: registration.clone(),
                    workspace_root: workspace_root.to_path_buf(),
                    workspace_ref: workspace_ref.to_string(),
                    shadow_root: workspace_root.join(".ember").join("sandvault-shadow"),
                    construct_specs,
                    persona: persona.clone(),
                    extra_args: request.extra_args.clone(),
                },
            )
        },
    )?;
    std::process::exit(code);
}

fn launch_claude_code_host(
    lane: OpenLane,
    authority_strict: bool,
    delegated_template: Option<&str>,
    attach_runtime_persona_id: Option<&str>,
    extra_args: &[String],
    workspace_ref: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let flavor = match lane {
        OpenLane::Prod => crate::claude_code_launcher::Flavor::Prod,
        OpenLane::Dev => crate::claude_code_launcher::Flavor::Dev,
    };
    crate::claude_code_launcher::launch_with_workspace_ref(
        flavor,
        authority_strict,
        delegated_template,
        attach_runtime_persona_id,
        extra_args,
        workspace_ref,
    )?;
    Ok(())
}

fn maybe_reexec_via_dev_cli() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = crate::dev_runtime::resolve_current_dev_runtime()?;
    let dev_cli = runtime.install_root.join("ember");

    if !dev_cli.exists() {
        return Err(format!(
            "worktree dev CLI missing at {}; run `ember dev install` or `ember dev sync` before launching `--dev` sessions",
            dev_cli.display()
        )
        .into());
    }

    let current_exe = std::env::current_exe()?;
    if !should_reexec_via_dev_cli(&current_exe, &dev_cli) {
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        let err = Command::new(&dev_cli)
            .args(std::env::args_os().skip(1))
            .exec();
        return Err(format!("re-exec dev CLI {}: {err}", dev_cli.display()).into());
    }

    #[allow(unreachable_code)]
    {
        let status = Command::new(&dev_cli)
            .args(std::env::args_os().skip(1))
            .status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn should_reexec_via_dev_cli(current_exe: &std::path::Path, dev_cli: &std::path::Path) -> bool {
    normalize_existing_path(current_exe) != normalize_existing_path(dev_cli)
}

fn normalize_existing_path(path: &std::path::Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn cmd_session_open_codex(request: &OpenRequest) -> Result<(), Box<dyn std::error::Error>> {
    match request.lane {
        OpenLane::Dev => {
            maybe_reexec_via_dev_cli()?;
            match request.placement {
                OpenPlacement::Host => launch_codex_host(
                    request.lane,
                    request.authority_strict,
                    request.delegated_template.as_deref(),
                    request.attach_runtime_persona_id.as_deref(),
                    &request.extra_args,
                    None,
                ),
                OpenPlacement::Auto => {
                    eprintln!(
                        "ember codex: dev isolated launch is not ready yet; using the host dev runtime"
                    );
                    launch_codex_host(
                        request.lane,
                        request.authority_strict,
                        request.delegated_template.as_deref(),
                        request.attach_runtime_persona_id.as_deref(),
                        &request.extra_args,
                        None,
                    )
                }
                OpenPlacement::Isolated => Err(
                    "isolated `session open codex --dev` is not wired yet; the current dev lane remains host/worktree-scoped"
                        .into(),
                ),
                OpenPlacement::Sandvault => Err(
                    "`ember codex --sandbox sandvault --dev` is not wired yet; use the prod lane with `--worktree`"
                        .into(),
                ),
            }
        }
        OpenLane::Prod => match request.placement {
            OpenPlacement::Host => launch_codex_host(
                request.lane,
                request.authority_strict,
                request.delegated_template.as_deref(),
                request.attach_runtime_persona_id.as_deref(),
                &request.extra_args,
                None,
            ),
            OpenPlacement::Auto => launch_codex_auto(request),
            OpenPlacement::Isolated => launch_codex_isolated(request),
            OpenPlacement::Sandvault => Err(
                "`ember codex --sandbox sandvault` currently requires `--worktree <name>`".into(),
            ),
        },
    }
}

fn launch_codex_auto(request: &OpenRequest) -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = std::env::current_dir()?;
    match crate::up::detect_isolated_claude_code_capability(
        &current_dir,
        request.backend_hint.as_deref(),
    )? {
        crate::up::IsolatedClaudeCodeCapability::Ready { .. } => {
            match (
                crate::launcher::codex::require_codex_config_dir_for_isolated(),
                codex_isolated_runtime_source(),
            ) {
                (Err(err), _) => {
                    eprintln!(
                        "ember codex: isolated path unavailable; using host launcher ({err})"
                    );
                    launch_codex_host(
                        request.lane,
                        request.authority_strict,
                        request.delegated_template.as_deref(),
                        request.attach_runtime_persona_id.as_deref(),
                        &request.extra_args,
                        None,
                    )
                }
                (_, Err(err)) => {
                    eprintln!(
                        "ember codex: isolated path unavailable; using host launcher ({err})"
                    );
                    launch_codex_host(
                        request.lane,
                        request.authority_strict,
                        request.delegated_template.as_deref(),
                        request.attach_runtime_persona_id.as_deref(),
                        &request.extra_args,
                        None,
                    )
                }
                (Ok(_), Ok(_)) => launch_codex_isolated(request),
            }
        }
        crate::up::IsolatedClaudeCodeCapability::Unavailable { reason } => {
            eprintln!("ember codex: isolated path unavailable; using host launcher ({reason})");
            launch_codex_host(
                request.lane,
                request.authority_strict,
                request.delegated_template.as_deref(),
                request.attach_runtime_persona_id.as_deref(),
                &request.extra_args,
                None,
            )
        }
    }
}

fn codex_isolated_runtime_source() -> std::io::Result<Option<PathBuf>> {
    if crate::up::isolated_container_binary_override("EMBER_CODEX_BIN")?.is_some() {
        return Ok(None);
    }
    crate::launcher::codex::resolve_container_codex_runtime_root().map(Some)
}

fn launch_codex_isolated(request: &OpenRequest) -> Result<(), Box<dyn std::error::Error>> {
    let env = crate::codex_launcher::build_launch_env(crate::codex_launcher::Flavor::Prod)?;
    crate::codex_launcher::ping_daemon(&env, crate::codex_launcher::Flavor::Prod)?;
    let codex_config_source = crate::launcher::codex::require_codex_config_dir_for_isolated()?;
    let persona = crate::launcher::codex::resolve_persona_name();
    let delegation_template = crate::launcher::claude_code::resolve_delegation_template_for_launch(
        request.delegated_template.as_deref(),
        "ember codex",
    )
    .map_err(std::io::Error::other)?;
    let registration = match crate::launcher::session_rpc::register_session_rpc_with_isolated_bridge(
        &persona,
        &env.ember_daemon_socket,
        delegation_template.as_deref(),
        request.authority_strict,
        request.attach_runtime_persona_id.as_deref(),
        "ember codex",
        "ember codex --isolated",
    ) {
        Ok(registration) => registration,
        // ADR 207 seam 4 — bridge lane disabled: fail soft (auto → host;
        // explicit --isolated → canonical guidance) instead of a raw RPC error.
        Err(e) if is_bridge_unavailable_error(&e.to_string()) => {
            return fail_soft_bridge_unavailable(request, "ember codex", |req| {
                launch_codex_host(
                    req.lane,
                    req.authority_strict,
                    req.delegated_template.as_deref(),
                    req.attach_runtime_persona_id.as_deref(),
                    &req.extra_args,
                    None,
                )
            });
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found")
                || msg.contains("no such persona")
                || msg.contains("unknown persona")
            {
                return Err(std::io::Error::new(
                    e.kind(),
                    "no Codex persona found.\n  Run `ember init --for codex` first, or set $EMBER_PERSONA to an existing persona name.".to_string(),
                )
                .into());
            }
            return Err(e.into());
        }
    };
    let code = with_session_close(
        &registration.session_id,
        &env.ember_daemon_socket,
        "ember codex",
        "ember codex --isolated",
        || {
            crate::up::launch_harness_isolated(crate::up::IsolatedHarnessLaunch {
                harness: HarnessKind::Codex,
                persona: persona.clone(),
                registration: registration.clone(),
                daemon_socket_path: env.ember_daemon_socket.clone(),
                extra_args: request.extra_args.clone(),
                backend_hint: request.backend_hint.clone(),
                preset: request.preset.clone(),
                workspace_root: std::env::current_dir()?,
                shadow_root: env.shadow_root.clone(),
                codex_runtime_source: codex_isolated_runtime_source()?,
                codex_config_source: Some(codex_config_source.clone()),
            })
        },
    )?;
    std::process::exit(code);
}

fn launch_codex_sandvault(
    request: &OpenRequest,
    workspace_root: &std::path::Path,
    workspace_ref: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = crate::codex_launcher::build_launch_env(crate::codex_launcher::Flavor::Prod)?;
    crate::codex_launcher::ping_daemon(&env, crate::codex_launcher::Flavor::Prod)?;
    let persona = crate::launcher::codex::resolve_persona_name();
    let delegation_template = crate::launcher::claude_code::resolve_delegation_template_for_launch(
        request.delegated_template.as_deref(),
        "ember codex",
    )
    .map_err(std::io::Error::other)?;
    let registration = crate::launcher::session_rpc::register_session_rpc_with_isolated_bridge(
        &persona,
        &env.ember_daemon_socket,
        delegation_template.as_deref(),
        request.authority_strict,
        request.attach_runtime_persona_id.as_deref(),
        "ember codex",
        "ember codex --sandbox sandvault",
    )
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("not found")
            || msg.contains("no such persona")
            || msg.contains("unknown persona")
        {
            std::io::Error::new(
                e.kind(),
                "no Codex persona found.\n  Run `ember init --for codex` first, or set $EMBER_PERSONA to an existing persona name.".to_string(),
            )
        } else {
            e
        }
    })?;
    if registration.codex_responses_proxy_url.is_none() {
        return Err(
            "Sandvault Codex launch requires the brokered Codex responses proxy; refusing to rely on sandbox-user native model auth"
                .into(),
        );
    }
    let construct_specs = crate::launcher::codex::prod_construct_specs_or_error()?;
    let code = with_session_close(
        &registration.session_id,
        &env.ember_daemon_socket,
        "ember codex",
        "ember codex --sandbox sandvault",
        || {
            crate::up::sandvault::launch_harness_sandvault(
                crate::up::sandvault::SandvaultHarnessLaunch {
                    harness: HarnessKind::Codex,
                    registration: registration.clone(),
                    workspace_root: workspace_root.to_path_buf(),
                    workspace_ref: workspace_ref.to_string(),
                    shadow_root: workspace_root.join(".ember").join("sandvault-shadow"),
                    construct_specs,
                    persona: persona.clone(),
                    extra_args: request.extra_args.clone(),
                },
            )
        },
    )?;
    std::process::exit(code);
}

fn launch_codex_host(
    lane: OpenLane,
    authority_strict: bool,
    delegated_template: Option<&str>,
    attach_runtime_persona_id: Option<&str>,
    extra_args: &[String],
    workspace_ref: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let flavor = match lane {
        OpenLane::Prod => crate::codex_launcher::Flavor::Prod,
        OpenLane::Dev => crate::codex_launcher::Flavor::Dev,
    };
    crate::codex_launcher::launch_with_workspace_ref(
        flavor,
        authority_strict,
        delegated_template,
        attach_runtime_persona_id,
        extra_args,
        workspace_ref,
    )?;
    Ok(())
}

fn cmd_session_open_cursor(request: &OpenRequest) -> Result<(), Box<dyn std::error::Error>> {
    match request.lane {
        OpenLane::Dev => {
            maybe_reexec_via_dev_cli()?;
            match request.placement {
                OpenPlacement::Host | OpenPlacement::Auto => launch_cursor_host(
                    request.lane,
                    request.authority_strict,
                    request.delegated_template.as_deref(),
                    request.attach_runtime_persona_id.as_deref(),
                    &request.extra_args,
                    None,
                ),
                OpenPlacement::Isolated => Err(
                    "isolated `session open cursor --dev` is not wired yet; baseline Cursor launch is host-only until a governed loopback-projector mediation lane is designed"
                        .into(),
                ),
                OpenPlacement::Sandvault => Err(
                    "`ember cursor --sandbox sandvault --dev` is not wired yet; baseline Cursor launch is host-only"
                        .into(),
                ),
            }
        }
        OpenLane::Prod => match request.placement {
            OpenPlacement::Host | OpenPlacement::Auto => launch_cursor_host(
                request.lane,
                request.authority_strict,
                request.delegated_template.as_deref(),
                request.attach_runtime_persona_id.as_deref(),
                &request.extra_args,
                None,
            ),
            OpenPlacement::Isolated => Err(
                "isolated `ember cursor` is not wired yet; baseline Cursor launch is host-only until a governed loopback-projector mediation lane is designed"
                    .into(),
            ),
            OpenPlacement::Sandvault => Err(
                "`ember cursor --sandbox sandvault` is not wired yet; baseline Cursor launch is host-only until a governed loopback-projector mediation lane is designed"
                    .into(),
            ),
        },
    }
}

fn launch_cursor_host(
    lane: OpenLane,
    authority_strict: bool,
    delegated_template: Option<&str>,
    attach_runtime_persona_id: Option<&str>,
    extra_args: &[String],
    workspace_ref: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let flavor = match lane {
        OpenLane::Prod => crate::claude_code_launcher::Flavor::Prod,
        OpenLane::Dev => crate::claude_code_launcher::Flavor::Dev,
    };
    let env = crate::claude_code_launcher::build_launch_env(flavor)?;
    crate::claude_code_launcher::ping_daemon(&env, flavor)?;
    if let Some(message) = env.runtime_banner.as_deref() {
        eprintln!("{message}");
    }

    let bin = crate::launcher::cursor::resolve_cursor_bin_path()?
        .to_string_lossy()
        .into_owned();
    let persona = crate::launcher::cursor::resolve_persona_name();
    let construct_specs = match lane {
        OpenLane::Prod => crate::launcher::cursor::prod_construct_specs_or_error()?,
        OpenLane::Dev => crate::launcher::claude_code::cohort_a_construct_specs(),
    };
    let child_workspace_ref =
        crate::claude_code_launcher::child_workspace_ref_for_launch(&env, workspace_ref);
    let code =
        crate::launcher::cursor::launch_cursor_with_shadow_dir_and_constructs_with_workspace_ref(
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

fn cmd_session_open_gemini(request: &OpenRequest) -> Result<(), Box<dyn std::error::Error>> {
    // ADR 215 §2: the brokered Gemini Code Assist lane is host-only (the daemon's
    // per-session loopback proxy is host-bound). Isolated/sandvault fail closed.
    match request.lane {
        OpenLane::Dev => {
            maybe_reexec_via_dev_cli()?;
            match request.placement {
                OpenPlacement::Host | OpenPlacement::Auto => launch_gemini_host(
                    request.lane,
                    request.authority_strict,
                    request.delegated_template.as_deref(),
                    request.attach_runtime_persona_id.as_deref(),
                    &request.extra_args,
                    None,
                ),
                OpenPlacement::Isolated => Err(
                    "isolated `session open gemini --dev` is not wired yet; the brokered Gemini Code Assist lane is host-only"
                        .into(),
                ),
                OpenPlacement::Sandvault => Err(
                    "`ember gemini --sandbox sandvault --dev` is not wired yet; the brokered Gemini Code Assist lane is host-only"
                        .into(),
                ),
            }
        }
        OpenLane::Prod => match request.placement {
            OpenPlacement::Host | OpenPlacement::Auto => launch_gemini_host(
                request.lane,
                request.authority_strict,
                request.delegated_template.as_deref(),
                request.attach_runtime_persona_id.as_deref(),
                &request.extra_args,
                None,
            ),
            OpenPlacement::Isolated => Err(
                "isolated `ember gemini` is not wired yet; the brokered Gemini Code Assist lane is host-only until a container-side mediation lane is designed"
                    .into(),
            ),
            OpenPlacement::Sandvault => Err(
                "`ember gemini --sandbox sandvault` is not wired yet; the brokered Gemini Code Assist lane is host-only until a container-side mediation lane is designed"
                    .into(),
            ),
        },
    }
}

fn launch_gemini_host(
    lane: OpenLane,
    authority_strict: bool,
    delegated_template: Option<&str>,
    attach_runtime_persona_id: Option<&str>,
    extra_args: &[String],
    workspace_ref: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let flavor = match lane {
        OpenLane::Prod => crate::claude_code_launcher::Flavor::Prod,
        OpenLane::Dev => crate::claude_code_launcher::Flavor::Dev,
    };
    let env = crate::claude_code_launcher::build_launch_env(flavor)?;
    crate::claude_code_launcher::ping_daemon(&env, flavor)?;
    if let Some(message) = env.runtime_banner.as_deref() {
        eprintln!("{message}");
    }

    let bin = crate::launcher::gemini::resolve_gemini_bin_path()?
        .to_string_lossy()
        .into_owned();
    let persona = crate::launcher::gemini::resolve_persona_name();
    let construct_specs = match lane {
        OpenLane::Prod => crate::launcher::gemini::prod_construct_specs_or_error()?,
        OpenLane::Dev => crate::launcher::claude_code::cohort_a_construct_specs(),
    };
    let child_workspace_ref =
        crate::claude_code_launcher::child_workspace_ref_for_launch(&env, workspace_ref);
    let code =
        crate::launcher::gemini::launch_gemini_with_shadow_dir_and_constructs_with_workspace_ref(
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

pub fn cmd_session_tail(
    session_id: Option<&str>,
    pretty: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let id = match session_id {
        Some(s) => s.to_string(),
        None => active_session_id()?,
    };

    let sidecar = sidecar_path(&id);
    if !sidecar.exists() {
        return Err(format!("session sidecar not found: {}", sidecar.display()).into());
    }

    if pretty {
        // Pipe `tail -f` through `jq` for human formatting; fall back to
        // raw if jq is missing.
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "tail -f -- {} | jq -C -r '. as $line | \"\\($line.ts // \"-\")  \\($line.event // $line.kind // \"?\")  \\($line | tostring)\"' || tail -f -- {}",
                shell_escape(&sidecar),
                shell_escape(&sidecar),
            ))
            .status()?;
        if !status.success() {
            return Err(format!("tail exited with status {status}").into());
        }
    } else {
        let status = Command::new("tail")
            .arg("-f")
            .arg("--")
            .arg(&sidecar)
            .status()?;
        if !status.success() {
            return Err(format!("tail exited with status {status}").into());
        }
    }
    Ok(())
}

fn sidecar_path(session_id: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".ember")
        .join("sessions")
        .join(session_id)
        .join("sidecar.jsonl")
}

fn active_session_id() -> Result<String, Box<dyn std::error::Error>> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let active = PathBuf::from(home)
        .join(".ember")
        .join("sessions")
        .join("active");
    let id = std::fs::read_to_string(&active)
        .map_err(|e| format!("no active session ({}): {e}", active.display()))?;
    Ok(id.trim().to_string())
}

fn shell_escape(p: &std::path::Path) -> String {
    // Minimal shell-safe quoting — sidecar paths are under $HOME/.ember/sessions/<id>/sidecar.jsonl
    // which is alphanumeric + dot + slash. Single-quote-wrap to be safe.
    format!("'{}'", p.display().to_string().replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::Mutex;

    // Totality guard for the harness registry: every `OpenSurface` ValueEnum
    // variant must have exactly one `HARNESSES` row, so `harness_spec`'s
    // `.expect()` can never reach a release. Enumerated from clap's
    // `value_variants()` so a newly-added surface is covered automatically —
    // forget the table row and this test panics rather than the binary.
    #[test]
    fn every_surface_has_exactly_one_harness_spec() {
        for surface in OpenSurface::value_variants() {
            let matches = HARNESSES.iter().filter(|h| h.surface == *surface).count();
            assert_eq!(
                matches, 1,
                "OpenSurface::{surface:?} must have exactly one HARNESSES row, found {matches}"
            );
            // Exercises the lookup path the dispatch helpers rely on.
            let _ = harness_spec(*surface);
        }
        assert_eq!(
            HARNESSES.len(),
            OpenSurface::value_variants().len(),
            "HARNESSES must have one row per OpenSurface variant (no extras)"
        );
    }

    // ADR 207 seam 4 — isolated-lane bridge fail-soft.

    fn open_request_for(surface: OpenSurface, placement: OpenPlacement) -> OpenRequest {
        OpenRequest {
            surface,
            lane: OpenLane::Prod,
            placement,
            authority_strict: false,
            delegated_template: None,
            attach_runtime_persona_id: None,
            fork_runtime: false,
            backend_hint: None,
            preset: None,
            worktree: None,
            extra_args: Vec::new(),
        }
    }

    #[test]
    fn is_bridge_unavailable_error_matches_daemon_bridge_disabled_messages() {
        assert!(is_bridge_unavailable_error(
            "daemon error: register_session: daemon bridge listener is not configured"
        ));
        assert!(is_bridge_unavailable_error(
            "daemon error: register_session: daemon bridge listener must bind a concrete port"
        ));
    }

    #[test]
    fn is_bridge_unavailable_error_rejects_unrelated_errors() {
        // Persona-not-found and generic failures must still surface hard, not
        // silently fall back to host.
        assert!(!is_bridge_unavailable_error("no such persona"));
        assert!(!is_bridge_unavailable_error(
            "daemon error: authority_class_not_met"
        ));
        assert!(!is_bridge_unavailable_error(
            "daemon not running (socket: ...)"
        ));
        assert!(!is_bridge_unavailable_error(""));
    }

    #[test]
    fn fail_soft_bridge_unavailable_auto_falls_back_to_host() {
        let request = open_request_for(OpenSurface::ClaudeCode, OpenPlacement::Auto);
        let mut host_called = false;
        let result = fail_soft_bridge_unavailable(&request, "ember claude", |_req| {
            host_called = true;
            Ok(())
        });
        assert!(
            result.is_ok(),
            "auto placement falls back to the host launcher"
        );
        assert!(host_called, "host launcher was invoked on auto fallback");
    }

    #[test]
    fn fail_soft_bridge_unavailable_explicit_isolated_returns_canonical_guidance() {
        let request = open_request_for(OpenSurface::Codex, OpenPlacement::Isolated);
        let mut host_called = false;
        let result = fail_soft_bridge_unavailable(&request, "ember codex", |_req| {
            host_called = true;
            Ok(())
        });
        let err = result.expect_err("explicit --isolated returns guidance, not a host fallback");
        assert!(
            !host_called,
            "host launcher must NOT be invoked for an explicit --isolated request"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("bridge_bind"),
            "guidance names bridge_bind: {msg}"
        );
        assert!(
            msg.contains("--isolated"),
            "guidance mentions the isolated flag: {msg}"
        );
        assert!(
            msg.contains("ember codex"),
            "guidance uses the harness label: {msg}"
        );
    }

    fn env_lock() -> &'static Mutex<()> {
        &crate::PROCESS_ENV_CWD_TEST_LOCK
    }

    fn capture_cwd() -> PathBuf {
        std::env::current_dir().unwrap_or_else(|_| {
            let fallback = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            std::env::set_current_dir(&fallback).expect("restore test cwd fallback");
            fallback
        })
    }

    struct SessionEnvGuard {
        home: Option<OsString>,
        ember_codex_bin: Option<OsString>,
        ember_dev_runtime_id: Option<OsString>,
        ember_dev_worktree_root: Option<OsString>,
        cwd: PathBuf,
    }

    impl SessionEnvGuard {
        fn capture() -> Self {
            Self {
                home: std::env::var_os("HOME"),
                ember_codex_bin: std::env::var_os("EMBER_CODEX_BIN"),
                ember_dev_runtime_id: std::env::var_os(crate::dev_runtime::DEV_RUNTIME_ID_ENV),
                ember_dev_worktree_root: std::env::var_os("EMBER_DEV_WORKTREE_ROOT"),
                cwd: capture_cwd(),
            }
        }
    }

    impl Drop for SessionEnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.home {
                    Some(value) => std::env::set_var("HOME", value),
                    None => std::env::remove_var("HOME"),
                }
                match &self.ember_codex_bin {
                    Some(value) => std::env::set_var("EMBER_CODEX_BIN", value),
                    None => std::env::remove_var("EMBER_CODEX_BIN"),
                }
                match &self.ember_dev_runtime_id {
                    Some(value) => std::env::set_var(crate::dev_runtime::DEV_RUNTIME_ID_ENV, value),
                    None => std::env::remove_var(crate::dev_runtime::DEV_RUNTIME_ID_ENV),
                }
                match &self.ember_dev_worktree_root {
                    Some(value) => std::env::set_var("EMBER_DEV_WORKTREE_ROOT", value),
                    None => std::env::remove_var("EMBER_DEV_WORKTREE_ROOT"),
                }
            }
            std::env::set_current_dir(&self.cwd).expect("restore cwd");
        }
    }

    fn dev_host_request(surface: OpenSurface) -> OpenRequest {
        build_open_request(
            surface,
            true,
            true,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
        )
        .expect("dev host request")
    }

    fn assert_dev_launch_requires_staged_cli(surface: OpenSurface) {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = SessionEnvGuard::capture();
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path().join("home");
        let workspace = tmp.path().join("workspace");
        std::fs::create_dir_all(&home).expect("create home");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        std::fs::write(workspace.join("Cargo.toml"), "[workspace]\n").expect("write Cargo.toml");

        unsafe {
            std::env::set_var("HOME", &home);
            std::env::remove_var(crate::dev_runtime::DEV_RUNTIME_ID_ENV);
            std::env::remove_var("EMBER_DEV_WORKTREE_ROOT");
        }
        std::env::set_current_dir(&workspace).expect("set cwd");

        let err = cmd_session_open(&dev_host_request(surface)).expect_err("missing staged dev CLI");
        let msg = err.to_string();
        assert!(
            msg.contains("worktree dev CLI missing"),
            "dev lane must fail fast on missing staged CLI, got: {msg}"
        );
    }

    #[test]
    fn build_open_request_defaults_to_prod_and_auto() {
        let request = build_open_request(
            OpenSurface::ClaudeCode,
            false,
            false,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            vec!["--print".into()],
        )
        .expect("request");
        assert_eq!(request.lane, OpenLane::Prod);
        assert_eq!(request.placement, OpenPlacement::Auto);
        assert_eq!(request.extra_args, vec!["--print".to_string()]);
    }

    #[test]
    fn build_open_request_rejects_backend_without_isolated() {
        let err = build_open_request(
            OpenSurface::ClaudeCode,
            false,
            true,
            false,
            false,
            None,
            None,
            false,
            Some("docker".into()),
            None,
            None,
            None,
            None,
            Vec::new(),
        )
        .expect_err("must reject backend without isolated");
        assert!(err.contains("--isolated"), "got: {err}");
    }

    #[test]
    fn codex_isolated_runtime_source_skips_host_runtime_when_container_override_set() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = SessionEnvGuard::capture();
        unsafe {
            std::env::set_var("EMBER_CODEX_BIN", "/work/repo/.ember/codex-standin");
        }

        let source = codex_isolated_runtime_source().expect("container override is valid");

        assert!(
            source.is_none(),
            "container-visible Codex override must not require host runtime staging"
        );
    }

    #[test]
    fn codex_isolated_runtime_source_rejects_host_only_override() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = SessionEnvGuard::capture();
        unsafe {
            std::env::set_var("EMBER_CODEX_BIN", "/tmp/codex-test");
        }

        let err = codex_isolated_runtime_source()
            .expect_err("host-only override path must be refused for isolated Codex");
        let msg = err.to_string();

        assert!(msg.contains("EMBER_CODEX_BIN"), "got: {msg}");
        assert!(msg.contains("/work/repo"), "got: {msg}");
    }

    #[test]
    fn build_open_request_accepts_isolated_backend_and_preset() {
        let request = build_open_request(
            OpenSurface::ClaudeCode,
            true,
            false,
            true,
            false,
            None,
            None,
            false,
            Some("orbstack".into()),
            Some("autopilot".into()),
            None,
            None,
            None,
            Vec::new(),
        )
        .expect("request");
        assert_eq!(request.lane, OpenLane::Dev);
        assert_eq!(request.placement, OpenPlacement::Isolated);
        assert_eq!(request.backend_hint.as_deref(), Some("orbstack"));
        assert_eq!(request.preset.as_deref(), Some("autopilot"));
    }

    #[test]
    fn build_open_request_accepts_sandvault_placement() {
        let request = build_open_request_with_sandvault(
            OpenSurface::ClaudeCode,
            false,
            false,
            false,
            true,
            false,
            None,
            None,
            false,
            None,
            None,
            Some("sv-smoke".into()),
            None,
            None,
            Vec::new(),
        )
        .expect("request");
        assert_eq!(request.placement, OpenPlacement::Sandvault);
        assert_eq!(
            request
                .worktree
                .as_ref()
                .map(|worktree| worktree.session_name.as_str()),
            Some("sv-smoke")
        );
    }

    #[test]
    fn build_open_request_rejects_sandvault_with_host() {
        let err = build_open_request_with_sandvault(
            OpenSurface::ClaudeCode,
            false,
            true,
            false,
            true,
            false,
            None,
            None,
            false,
            None,
            None,
            Some("sv-smoke".into()),
            None,
            None,
            Vec::new(),
        )
        .expect_err("host and sandvault must conflict");
        assert!(err.contains("--sandbox sandvault"), "got: {err}");
    }

    #[test]
    fn build_open_request_rejects_backend_with_sandvault() {
        let err = build_open_request_with_sandvault(
            OpenSurface::ClaudeCode,
            false,
            false,
            false,
            true,
            false,
            None,
            None,
            false,
            Some("docker".into()),
            None,
            Some("sv-smoke".into()),
            None,
            None,
            Vec::new(),
        )
        .expect_err("backend hints stay isolated-only");
        assert!(err.contains("--isolated"), "got: {err}");
    }

    #[test]
    fn claude_code_alias_request_keeps_auto_default() {
        let request = claude_code_alias_request(
            false,
            false,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            &["--dangerously-skip-permissions".into()],
        )
        .expect("request");
        assert_eq!(request.surface, OpenSurface::ClaudeCode);
        assert_eq!(request.lane, OpenLane::Prod);
        assert_eq!(request.placement, OpenPlacement::Auto);
        assert_eq!(
            request.extra_args,
            vec!["--dangerously-skip-permissions".to_string()]
        );
    }

    #[test]
    fn claude_code_alias_request_accepts_isolated_controls() {
        let request = claude_code_alias_request(
            false,
            false,
            true,
            false,
            None,
            None,
            false,
            Some("docker".into()),
            Some("autopilot".into()),
            None,
            None,
            None,
            &[],
        )
        .expect("request");
        assert_eq!(request.placement, OpenPlacement::Isolated);
        assert_eq!(request.backend_hint.as_deref(), Some("docker"));
        assert_eq!(request.preset.as_deref(), Some("autopilot"));
    }

    #[test]
    fn build_open_request_accepts_auto_without_backend_or_preset() {
        let request = build_open_request(
            OpenSurface::ClaudeCode,
            false,
            false,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
        )
        .expect("request");
        assert_eq!(request.placement, OpenPlacement::Auto);
    }

    #[test]
    fn build_open_request_rejects_branch_without_worktree() {
        let err = build_open_request(
            OpenSurface::ClaudeCode,
            false,
            false,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            Some("agent/auth-posture/20260522-170000".into()),
            None,
            Vec::new(),
        )
        .expect_err("must reject branch without worktree");
        assert!(err.contains("--worktree"), "got: {err}");
    }

    #[test]
    fn build_open_request_preserves_managed_worktree_request() {
        let request = build_open_request(
            OpenSurface::ClaudeCode,
            true,
            true,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            Some("auth-posture".into()),
            Some("agent/auth-posture/20260522-170000".into()),
            Some("release proof".into()),
            vec!["--print".into()],
        )
        .expect("request");
        let worktree = request.worktree.expect("worktree");
        assert_eq!(worktree.session_name, "auth-posture");
        assert_eq!(
            worktree.branch.as_deref(),
            Some("agent/auth-posture/20260522-170000")
        );
        assert_eq!(worktree.purpose.as_deref(), Some("release proof"));
    }

    #[test]
    fn build_open_request_keeps_explicit_delegated_template() {
        let request = build_open_request(
            OpenSurface::ClaudeCode,
            false,
            false,
            false,
            false,
            Some("landing-page-edits".into()),
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
        )
        .expect("request");
        assert_eq!(
            request.delegated_template.as_deref(),
            Some("landing-page-edits")
        );
    }

    #[test]
    fn claude_workflow_selector_runs_when_no_explicit_template() {
        let _g = crate::EMBER_PERSONA_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("EMBER_DELEGATION_TEMPLATE").ok();
        unsafe { std::env::remove_var("EMBER_DELEGATION_TEMPLATE") };

        let request = build_open_request(
            OpenSurface::ClaudeCode,
            false,
            false,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
        )
        .expect("request");
        let selected =
            resolve_claude_delegation_template_for_request_with_selector(&request, |templates| {
                templates
                    .iter()
                    .find(|template| template.name == "emberd-development")
                    .cloned()
                    .ok_or(DelegationPromptError::NoTemplates {
                        install_root: PathBuf::from("<test>"),
                    })
            })
            .expect("selector should choose bundled template");

        match prior {
            Some(value) => unsafe { std::env::set_var("EMBER_DELEGATION_TEMPLATE", value) },
            None => unsafe { std::env::remove_var("EMBER_DELEGATION_TEMPLATE") },
        }

        // pregrant_launcher_wire_landed: no explicit --delegated invokes the
        // selector and feeds the chosen template into session-open.
        assert_eq!(selected.as_deref(), Some("emberd-development"));
    }

    #[test]
    fn claude_workflow_selector_skips_prompt_for_explicit_workflow() {
        let request = build_open_request(
            OpenSurface::ClaudeCode,
            false,
            false,
            false,
            false,
            Some("landing-page-edits".into()),
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
        )
        .expect("request");
        let selected =
            resolve_claude_delegation_template_for_request_with_selector(&request, |_templates| {
                panic!("explicit --delegated must skip the selector")
            })
            .expect("explicit template should resolve");
        assert_eq!(selected.as_deref(), Some("landing-page-edits"));
    }

    #[test]
    fn build_open_request_accepts_explicit_fork_runtime() {
        let request = build_open_request(
            OpenSurface::ClaudeCode,
            false,
            false,
            false,
            false,
            Some("landing-page-edits".into()),
            None,
            true,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
        )
        .expect("request");

        assert!(request.fork_runtime);
        assert_eq!(
            request.delegated_template.as_deref(),
            Some("landing-page-edits")
        );
    }

    #[test]
    fn build_open_request_rejects_fork_with_attach() {
        let err = build_open_request(
            OpenSurface::ClaudeCode,
            false,
            false,
            false,
            false,
            None,
            Some("runtime-one".into()),
            true,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
        )
        .expect_err("fork and attach must conflict");

        assert!(err.contains("--fork"), "got: {err}");
        assert!(err.contains("--attach"), "got: {err}");
    }

    #[test]
    fn should_reexec_via_dev_cli_when_current_exe_differs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let current_exe = tmp.path().join("ember-host");
        let dev_cli = tmp.path().join("ember-dev");
        std::fs::write(&current_exe, b"host").expect("write current");
        std::fs::write(&dev_cli, b"dev").expect("write dev");

        assert!(should_reexec_via_dev_cli(&current_exe, &dev_cli));
    }

    #[test]
    fn should_not_reexec_via_dev_cli_when_current_exe_matches() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dev_cli = tmp.path().join("ember");
        std::fs::write(&dev_cli, b"dev").expect("write dev");

        assert!(!should_reexec_via_dev_cli(&dev_cli, &dev_cli));
    }

    #[test]
    fn claude_dev_launch_requires_staged_cli() {
        assert_dev_launch_requires_staged_cli(OpenSurface::ClaudeCode);
    }

    #[test]
    fn codex_dev_launch_requires_staged_cli() {
        assert_dev_launch_requires_staged_cli(OpenSurface::Codex);
    }

    #[test]
    fn codex_alias_request_keeps_auto_default() {
        let request = codex_alias_request(
            false,
            false,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            &[],
        )
        .expect("codex alias request");
        assert_eq!(request.surface, OpenSurface::Codex);
        assert_eq!(request.lane, OpenLane::Prod);
        assert_eq!(request.placement, OpenPlacement::Auto);
    }

    #[test]
    fn build_open_request_infers_worktree_from_legacy_purpose_shape() {
        let request = build_open_request(
            OpenSurface::Codex,
            false,
            false,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            Some("forge-register-session-rpc".into()),
            None,
            Some("daemon-owned register-session rpc seam".into()),
            Vec::new(),
        )
        .expect("legacy managed-worktree shorthand should stay compatible");
        let worktree = request.worktree.expect("worktree");
        assert_eq!(worktree.session_name, "forge-register-session-rpc");
        assert_eq!(
            worktree.purpose.as_deref(),
            Some("daemon-owned register-session rpc seam")
        );
        assert!(
            request.extra_args.is_empty(),
            "got: {:?}",
            request.extra_args
        );
    }

    #[test]
    fn build_open_request_does_not_infer_worktree_from_codex_subcommand() {
        let err = build_open_request(
            OpenSurface::Codex,
            false,
            false,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            Some("daemon-owned register-session rpc seam".into()),
            None,
            vec!["exec".into()],
        )
        .expect_err("known codex subcommands must not be reinterpreted as worktree names");
        assert!(err.contains("--worktree"), "got: {err}");
    }

    #[test]
    fn codex_alias_request_infers_single_bare_slug_as_worktree() {
        let request = codex_alias_request(
            false,
            false,
            false,
            false,
            Some("release-proof".into()),
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            &["forge-register-session-rpc".into()],
        )
        .expect("single bare codex slug should infer a managed worktree");
        let worktree = request.worktree.expect("managed worktree");
        assert_eq!(worktree.session_name, "forge-register-session-rpc");
        assert_eq!(request.extra_args, Vec::<String>::new());
    }

    #[test]
    fn codex_alias_request_rejects_misplaced_launcher_flags_in_extra_args() {
        let err = codex_alias_request(
            false,
            false,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            &[
                "forge-register-session-rpc".into(),
                "--purpose".into(),
                "daemon-owned register-session rpc seam".into(),
            ],
        )
        .expect_err("misplaced launcher flag must fail");
        assert!(err.contains("launcher option `--purpose`"), "got: {err}");
        assert!(err.contains("ember codex --worktree archie"), "got: {err}");
    }

    #[test]
    fn claude_alias_request_rejects_runtime_flags_after_resume() {
        // Regression: `ember claude --resume <id> --fork` forwarded `--fork`
        // to Claude (cryptic "unknown option --fork") because `--fork` was
        // missing from MISPLACED_LAUNCHER_FLAGS. The P9-S4 runtime-placement /
        // posture flags must trip the misplaced-launcher guard.
        for flag in ["--fork", "--strict", "--attach", "--delegated"] {
            let err = claude_code_alias_request(
                false,
                false,
                false,
                false,
                None,
                None,
                false,
                None,
                None,
                None,
                None,
                None,
                &[
                    "--resume".into(),
                    "a3c3ba3f-8d61-42c9-904f-437b93237a7e".into(),
                    flag.into(),
                ],
            )
            .expect_err(&format!("misplaced `{flag}` after --resume must fail"));
            assert!(
                err.contains(&format!("launcher option `{flag}`")),
                "got: {err}"
            );
        }
    }

    #[test]
    fn codex_alias_request_rejects_misplaced_help_after_prompt() {
        let err = codex_alias_request(
            false,
            false,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            &["forge-register-session-rpc".into(), "--help".into()],
        )
        .expect_err("misplaced help must fail");
        assert!(err.contains("ember codex --help"), "got: {err}");
        assert!(err.contains("ember codex -- --help"), "got: {err}");
    }

    #[test]
    fn claude_alias_request_allows_forwarded_native_worktree_resume_flags() {
        let request = claude_code_alias_request(
            false,
            true,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            &[
                "--worktree".into(),
                "horchata".into(),
                "--resume".into(),
                "55f5be16-4e3a-4d54-a930-08016c581295".into(),
            ],
        )
        .expect("forwarded native Claude worktree flags should stay allowed");
        assert!(request.worktree.is_none(), "got: {:?}", request.worktree);
        assert_eq!(
            request.extra_args,
            vec![
                "--worktree".to_string(),
                "horchata".to_string(),
                "--resume".to_string(),
                "55f5be16-4e3a-4d54-a930-08016c581295".to_string()
            ]
        );
    }

    #[test]
    fn codex_alias_request_keeps_explicit_delegated_template() {
        let request = codex_alias_request(
            false,
            false,
            false,
            false,
            Some("release-proof".into()),
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            &[],
        )
        .expect("codex alias request");
        assert_eq!(request.surface, OpenSurface::Codex);
        assert_eq!(request.delegated_template.as_deref(), Some("release-proof"));
    }
}
