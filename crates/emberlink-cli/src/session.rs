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

use clap::ValueEnum;
use crate::launcher::harness::HarnessKind;
use crate::launcher::worktree::{
    LiveState, clear_stale_live_lock, ensure_worktree_from_base, git_current_branch,
    live_state_for_path, new_live_metadata, new_session_metadata, resolve_branch_for_launch,
    resolve_repo_root, runtime_id_for_worktree, worktree_path_for_session, write_live_meta,
    write_session_meta,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OpenSurface {
    #[value(name = "claude", alias = "claude-code")]
    ClaudeCode,
    #[value(name = "codex")]
    Codex,
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
    pub backend_hint: Option<String>,
    pub preset: Option<String>,
    pub worktree: Option<ManagedWorktreeRequest>,
    pub extra_args: Vec<String>,
}

pub fn build_open_request(
    surface: OpenSurface,
    dev: bool,
    host: bool,
    isolated: bool,
    backend_hint: Option<String>,
    preset: Option<String>,
    worktree: Option<String>,
    branch: Option<String>,
    purpose: Option<String>,
    extra_args: Vec<String>,
) -> Result<OpenRequest, String> {
    let placement = match (host, isolated) {
        (true, true) => {
            return Err("choose exactly one placement override: `--host` or `--isolated`".into());
        }
        (true, false) => OpenPlacement::Host,
        (false, true) => OpenPlacement::Isolated,
        (false, false) => OpenPlacement::Auto,
    };

    if (backend_hint.is_some() || preset.is_some()) && placement != OpenPlacement::Isolated {
        return Err(
            "backend hints and presets only apply to isolated placement; add `--isolated`".into(),
        );
    }

    if worktree.is_none() && (branch.is_some() || purpose.is_some()) {
        return Err("`--branch` and `--purpose` require `--worktree <name>`".into());
    }

    Ok(OpenRequest {
        surface,
        lane: if dev { OpenLane::Dev } else { OpenLane::Prod },
        placement,
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

pub fn claude_code_alias_request(
    dev: bool,
    host: bool,
    isolated: bool,
    backend_hint: Option<String>,
    preset: Option<String>,
    worktree: Option<String>,
    branch: Option<String>,
    purpose: Option<String>,
    extra_args: &[String],
) -> Result<OpenRequest, String> {
    build_open_request(
        OpenSurface::ClaudeCode,
        dev,
        host,
        isolated,
        backend_hint,
        preset,
        worktree,
        branch,
        purpose,
        extra_args.to_vec(),
    )
}

pub fn codex_alias_request(
    dev: bool,
    host: bool,
    isolated: bool,
    backend_hint: Option<String>,
    preset: Option<String>,
    worktree: Option<String>,
    branch: Option<String>,
    purpose: Option<String>,
    extra_args: &[String],
) -> Result<OpenRequest, String> {
    build_open_request(
        OpenSurface::Codex,
        dev,
        host,
        isolated,
        backend_hint,
        preset,
        worktree,
        branch,
        purpose,
        extra_args.to_vec(),
    )
}

pub fn cmd_session_open(request: &OpenRequest) -> Result<(), Box<dyn std::error::Error>> {
    if request.worktree.is_some() {
        return cmd_session_open_managed_worktree(request);
    }
    match request.surface {
        OpenSurface::ClaudeCode => cmd_session_open_claude_code(request),
        OpenSurface::Codex => cmd_session_open_codex(request),
    }
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
    match surface {
        OpenSurface::ClaudeCode => HarnessKind::Claude,
        OpenSurface::Codex => HarnessKind::Codex,
    }
}

fn surface_label(surface: OpenSurface) -> &'static str {
    match surface {
        OpenSurface::ClaudeCode => "claude",
        OpenSurface::Codex => "codex",
    }
}

fn cmd_session_open_managed_worktree(
    request: &OpenRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let worktree = request
        .worktree
        .as_ref()
        .ok_or("managed-worktree request missing metadata")?;
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

    eprintln!(
        "ember session open: {} managed worktree {} (runtime={})",
        surface_label(request.surface),
        worktree_path.display(),
        runtime_id_for_worktree(&worktree_path)
    );
    if request.placement == OpenPlacement::Auto {
        eprintln!(
            "ember session open: managed worktree launch uses the host path for `{}`",
            surface_label(request.surface)
        );
    }

    match request.surface {
        OpenSurface::ClaudeCode => launch_claude_code_host(request.lane, &request.extra_args),
        OpenSurface::Codex => launch_codex_host(request.lane, &request.extra_args),
    }
}

fn cmd_session_open_claude_code(request: &OpenRequest) -> Result<(), Box<dyn std::error::Error>> {
    if request.lane == OpenLane::Dev {
        maybe_reexec_via_dev_cli()?;
        return match request.placement {
            OpenPlacement::Host => launch_claude_code_host(request.lane, &request.extra_args),
            OpenPlacement::Auto => {
                eprintln!(
                    "ember session open: isolated dev launch is not wired yet; using the host dev runtime for `claude --dev`"
                );
                launch_claude_code_host(request.lane, &request.extra_args)
            }
            OpenPlacement::Isolated => Err(
                "isolated `session open claude --dev` is not wired yet; the current dev lane remains host/worktree-scoped"
                    .into(),
            ),
        };
    }

    match request.placement {
        OpenPlacement::Host => launch_claude_code_host(request.lane, &request.extra_args),
        OpenPlacement::Auto => launch_claude_code_auto(request),
        OpenPlacement::Isolated => launch_claude_code_isolated(request),
    }
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
            eprintln!(
                "ember session open: isolated path unavailable ({reason}); falling back to the host launcher"
            );
            launch_claude_code_host(request.lane, &request.extra_args)
        }
    }
}

fn launch_claude_code_isolated(
    request: &OpenRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    if !request.extra_args.is_empty() {
        return Err(
            "isolated `session open claude` does not forward trailing Claude arguments yet; use the host launcher path for custom Claude args on current main"
                .into(),
        );
    }
    crate::up::open_claude_code_isolated(
        request.preset.as_deref(),
        request.backend_hint.as_deref(),
    )?;
    Ok(())
}

fn launch_claude_code_host(
    lane: OpenLane,
    extra_args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let flavor = match lane {
        OpenLane::Prod => crate::claude_code_launcher::Flavor::Prod,
        OpenLane::Dev => crate::claude_code_launcher::Flavor::Dev,
    };
    crate::claude_code_launcher::launch(flavor, extra_args)?;
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

        let err = Command::new(&dev_cli).args(std::env::args_os().skip(1)).exec();
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
        OpenLane::Dev => match request.placement {
            OpenPlacement::Host => launch_codex_host(request.lane, &request.extra_args),
            OpenPlacement::Auto => {
                eprintln!(
                    "ember session open: isolated dev launch is not wired yet; using the host dev runtime for `codex --dev`"
                );
                launch_codex_host(request.lane, &request.extra_args)
            }
            OpenPlacement::Isolated => Err(
                "isolated `session open codex --dev` is not wired yet; the current dev lane remains host/worktree-scoped"
                    .into(),
            ),
        },
        OpenLane::Prod => match request.placement {
            OpenPlacement::Host => launch_codex_host(request.lane, &request.extra_args),
            OpenPlacement::Auto => {
                eprintln!(
                    "ember session open: isolated Codex launch is not wired yet; using the host launcher"
                );
                launch_codex_host(request.lane, &request.extra_args)
            }
            OpenPlacement::Isolated => Err(
                "isolated `session open codex` is not wired yet on current main; use the host launcher path for now"
                    .into(),
            ),
        },
    }
}

fn launch_codex_host(
    lane: OpenLane,
    extra_args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let flavor = match lane {
        OpenLane::Prod => crate::codex_launcher::Flavor::Prod,
        OpenLane::Dev => crate::codex_launcher::Flavor::Dev,
    };
    crate::codex_launcher::launch(flavor, extra_args)?;
    Ok(())
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

    #[test]
    fn build_open_request_defaults_to_prod_and_auto() {
        let request = build_open_request(
            OpenSurface::ClaudeCode,
            false,
            false,
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
    fn build_open_request_accepts_isolated_backend_and_preset() {
        let request = build_open_request(
            OpenSurface::ClaudeCode,
            true,
            false,
            true,
            Some("orbstack".into()),
            Some("headless".into()),
            None,
            None,
            None,
            Vec::new(),
        )
        .expect("request");
        assert_eq!(request.lane, OpenLane::Dev);
        assert_eq!(request.placement, OpenPlacement::Isolated);
        assert_eq!(request.backend_hint.as_deref(), Some("orbstack"));
        assert_eq!(request.preset.as_deref(), Some("headless"));
    }

    #[test]
    fn claude_code_alias_request_keeps_auto_default() {
        let request = claude_code_alias_request(
            false,
            false,
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
            Some("docker".into()),
            Some("headless".into()),
            None,
            None,
            None,
            &[],
        )
        .expect("request");
        assert_eq!(request.placement, OpenPlacement::Isolated);
        assert_eq!(request.backend_hint.as_deref(), Some("docker"));
        assert_eq!(request.preset.as_deref(), Some("headless"));
    }

    #[test]
    fn build_open_request_accepts_auto_without_backend_or_preset() {
        let request = build_open_request(
            OpenSurface::ClaudeCode,
            false,
            false,
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
    fn codex_alias_request_keeps_auto_default() {
        let request = codex_alias_request(false, false, false, None, None, None, None, None, &[])
            .expect("codex alias request");
        assert_eq!(request.surface, OpenSurface::Codex);
        assert_eq!(request.lane, OpenLane::Prod);
        assert_eq!(request.placement, OpenPlacement::Auto);
    }
}
