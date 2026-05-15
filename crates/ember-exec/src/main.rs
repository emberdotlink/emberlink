//!
//! `ember-exec` — privileged sidecar that verifies, privilege-drops, and execs
//! a target binary on behalf of an in-container agent. Per design §8 and the
//! implementation-note-27 decomposition.
//!
//! This is subtask A (BIN-UDS): bin scaffold + UDS accept loop + the
//! `SpawnDirective` wire shape. Hash verification (subtask B) and PtyBridge
//! integration (subtask C) land in subsequent PRs; this binary currently
//! replies with a placeholder `HashMismatch` to any `SpawnDirective` it
//! receives so the wire shape is exercised end-to-end without performing
//! any actual privilege change or exec.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use ember_exec::spawn::handle_spawn_directive;
use ember_exec::uds::{read_frame, ExecFrame};
use tokio::net::UnixListener;

#[derive(Parser, Debug)]
#[command(name = "ember-exec", version, about = "Privileged exec sidecar (implementation-note-27)")]
struct Cli {
    /// Path to the Unix-domain socket to bind. Refuses paths under `/tmp/`
    /// without `--allow-tmp` — the production deployment binds under the
    /// daemon's data dir, not in a world-writable directory.
    #[arg(long)]
    socket: PathBuf,

    /// Opt-in to binding under `/tmp/`. Useful for integration tests.
    #[arg(long, default_value_t = false)]
    allow_tmp: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(msg) = validate_socket_path(&cli.socket, cli.allow_tmp) {
        eprintln!("ember-exec: {msg}");
        return ExitCode::from(2);
    }

    // Best-effort cleanup of a stale socket file from a previous crashed run.
    let _ = std::fs::remove_file(&cli.socket);

    let listener = match UnixListener::bind(&cli.socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ember-exec: bind {} failed: {e}", cli.socket.display());
            return ExitCode::from(3);
        }
    };

    loop {
        let (mut stream, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("ember-exec: accept failed: {e}");
                continue;
            }
        };

        tokio::spawn(async move {
            // Subtask A: replay-and-reply. Read one frame; if it's a
            // SpawnDirective, send back a placeholder HashMismatch so the
            // peer sees the production-shape error frame without us
            // performing any privileged work yet. Subtask B replaces this
            // body with real hash-verify; subtask C wires the PtyBridge.
            let frame = match read_frame(&mut stream).await {
                Ok(Some(f)) => f,
                Ok(None) => return,
                Err(e) => {
                    eprintln!("ember-exec: read frame: {e}");
                    return;
                }
            };
            // implementation-note-264: the handler runs the
            // full verify → drop_priv (if root) → spawn → output → exit
            // flow against the in-flight connection. Wire-shape errors
            // (frame write fail mid-stream) close the connection; spawn
            // errors propagate to stderr for emberd to observe.
            match frame {
                ExecFrame::SpawnDirective(d) => {
                    if let Err(e) = handle_spawn_directive(d, &mut stream).await {
                        eprintln!("ember-exec: handle_spawn_directive: {e}");
                    }
                }
                other => {
                    eprintln!("ember-exec: unexpected first frame: {other:?}");
                }
            }
        });
    }
}

/// Refuse `/tmp/...` socket paths unless `--allow-tmp` is set. `/tmp` is
/// world-writable on most hosts; binding the privileged sidecar there is a
/// trivial DoS / sniffing surface. Production daemons bind under their data
/// dir (mode 0700).
fn validate_socket_path(socket: &std::path::Path, allow_tmp: bool) -> Result<(), String> {
    let s = socket.to_string_lossy();
    if s.starts_with("/tmp/") && !allow_tmp {
        return Err(format!(
            "refusing to bind under /tmp/ without --allow-tmp: {}",
            socket.display()
        ));
    }
    // Parent must exist.
    if let Some(parent) = socket.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            return Err(format!("socket parent dir does not exist: {}", parent.display()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn validate_socket_path_refuses_tmp_without_allow() {
        let path = PathBuf::from("/tmp/ember-exec.sock");
        let r = validate_socket_path(&path, false);
        assert!(r.is_err(), "/tmp/ without --allow-tmp must be refused");
        assert!(r.unwrap_err().contains("--allow-tmp"));
    }

    #[test]
    fn validate_socket_path_accepts_tmp_with_allow() {
        // Use the test's TempDir parent so it exists.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ember-exec.sock");
        let r = validate_socket_path(&path, true);
        assert!(r.is_ok(), "explicit --allow-tmp must accept tmp path: {r:?}");
    }

    #[test]
    fn validate_socket_path_refuses_missing_parent() {
        let path = PathBuf::from("/nonexistent-dir/ember-exec.sock");
        let r = validate_socket_path(&path, true);
        assert!(r.is_err(), "missing parent dir must be refused");
    }
}
