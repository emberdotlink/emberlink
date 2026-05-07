//! `ember session tail [<id>] [--pretty]` — cohort A live-tail stopgap.
//!
//! Per walk-resolution ESC-9: live-view partition. Tails the session
//! sidecar JSONL at `~/.ember/sessions/<id>/sidecar.jsonl`.

use std::path::PathBuf;
use std::process::Command;

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
    let active = PathBuf::from(home).join(".ember").join("sessions").join("active");
    let id = std::fs::read_to_string(&active)
        .map_err(|e| format!("no active session ({}): {e}", active.display()))?;
    Ok(id.trim().to_string())
}

fn shell_escape(p: &std::path::Path) -> String {
    // Minimal shell-safe quoting — sidecar paths are under $HOME/.ember/sessions/<id>/sidecar.jsonl
    // which is alphanumeric + dot + slash. Single-quote-wrap to be safe.
    format!("'{}'", p.display().to_string().replace('\'', "'\\''"))
}
