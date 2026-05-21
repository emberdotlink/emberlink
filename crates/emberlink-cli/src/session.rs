//! `ember session ...` helpers.
//!
//! `tail` remains the live-sidecar stopgap for cohort A.
//! `open` is the canonical session-launch contract: top-level launchers like
//! `ember claude-code` should delegate into one request shape rather than
//! teach parallel models.

use std::path::PathBuf;
use std::process::Command;

use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OpenSurface {
    #[value(name = "claude-code")]
    ClaudeCode,
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
pub struct OpenRequest {
    pub surface: OpenSurface,
    pub lane: OpenLane,
    pub placement: OpenPlacement,
    pub backend_hint: Option<String>,
    pub preset: Option<String>,
    pub extra_args: Vec<String>,
}

pub fn build_open_request(
    surface: OpenSurface,
    dev: bool,
    host: bool,
    isolated: bool,
    backend_hint: Option<String>,
    preset: Option<String>,
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

    Ok(OpenRequest {
        surface,
        lane: if dev { OpenLane::Dev } else { OpenLane::Prod },
        placement,
        backend_hint,
        preset,
        extra_args,
    })
}

pub fn claude_code_alias_request(
    dev: bool,
    host: bool,
    isolated: bool,
    backend_hint: Option<String>,
    preset: Option<String>,
    extra_args: &[String],
) -> Result<OpenRequest, String> {
    build_open_request(
        OpenSurface::ClaudeCode,
        dev,
        host,
        isolated,
        backend_hint,
        preset,
        extra_args.to_vec(),
    )
}

pub fn cmd_session_open(request: &OpenRequest) -> Result<(), Box<dyn std::error::Error>> {
    match request.surface {
        OpenSurface::ClaudeCode => cmd_session_open_claude_code(request),
    }
}

fn cmd_session_open_claude_code(request: &OpenRequest) -> Result<(), Box<dyn std::error::Error>> {
    if request.lane == OpenLane::Dev {
        return match request.placement {
            OpenPlacement::Host => launch_claude_code_host(request.lane, &request.extra_args),
            OpenPlacement::Auto => {
                eprintln!(
                    "ember session open: isolated dev launch is not wired yet; using the host dev runtime for `claude-code --dev`"
                );
                launch_claude_code_host(request.lane, &request.extra_args)
            }
            OpenPlacement::Isolated => Err(
                "isolated `session open claude-code --dev` is not wired yet; the current dev lane remains host/worktree-scoped"
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
            "isolated `session open claude-code` does not forward trailing Claude arguments yet; use the host launcher path for custom Claude args on current main"
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
            Vec::new(),
        )
        .expect("request");
        assert_eq!(request.placement, OpenPlacement::Auto);
    }
}
