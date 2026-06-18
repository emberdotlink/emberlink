//! CLASSIFICATION: PUBLIC
//!
//! `ember-exec` — privileged sidecar that verifies, privilege-drops, and execs
//! a target binary on behalf of an in-container agent. Per ADR 140 §8 and the
//! SCION-EMBER-EXEC-AS-SERVICE decomposition.
//!
//! This is subtask A (BIN-UDS): bin scaffold + UDS accept loop + the
//! `SpawnDirective` wire shape. Hash verification (subtask B) and PtyBridge
//! integration (subtask C) land in subsequent PRs; this binary currently
//! replies with a placeholder `HashMismatch` to any `SpawnDirective` it
//! receives so the wire shape is exercised end-to-end without performing
//! any actual privilege change or exec.

// container_side_checkpoint_emitters — scaffold stub (daemon-RPC pending).
// `emit_checkpoint` writes one NDJSON line to stderr for each container-side
// lifecycle checkpoint. When the daemon socket bridge ships,
// this helper will be replaced with a daemon UDS RPC so checkpoints land in
// the daemon event log.
//
// TODO: replace stderr NDJSON with a
// real daemon RPC once the cross-uid bridge socket is available inside the
// container.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use ember_exec::spawn::handle_spawn_directive;
use ember_exec::uds::{ExecFrame, read_frame};
use tokio::net::UnixListener;

/// Write one NDJSON checkpoint line to stderr (fd 2).
///
/// Field shape: `{"checkpoint":<name>,"agent_id":<id>,"ts":<iso8601>}`
///
/// This is a scaffold stub. The real implementation will route through the
/// daemon's cross-uid bridge socket (META-AP-DAEMON-SOCKET-CROSS-UID-BRIDGE)
/// so checkpoints land in the daemon event log with proper attribution.
fn emit_checkpoint(name: &str, agent_id: &str) {
    use std::io::Write;
    let line = format_checkpoint_line(name, agent_id);
    // Write directly to stderr; ignore write errors (best-effort telemetry).
    let _ = std::io::stderr().write_all(line.as_bytes());
}

/// Format a checkpoint NDJSON line without writing it.
///
/// Separated from [`emit_checkpoint`] so tests can assert the field shape
/// without needing to capture fd 2.
fn format_checkpoint_line(name: &str, agent_id: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    // ISO-8601 UTC timestamp without pulling in chrono.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let (year, month, day) = days_to_ymd(days);
    let ts = format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z");

    // Sanitize: strip characters that would break the JSON string values.
    let name_safe = sanitize_json_string(name);
    let id_safe = sanitize_json_string(agent_id);

    format!(
        "{{\
            \"checkpoint\":\"{name_safe}\",\
            \"agent_id\":\"{id_safe}\",\
            \"ts\":\"{ts}\"\
        }}\n"
    )
}

/// Convert days since Unix epoch (1970-01-01) to (year, month, day).
/// Uses the proleptic Gregorian calendar; correct for dates ≥ 1970.
fn days_to_ymd(days: u64) -> (u64, u8, u8) {
    // Algorithm from https://www.researchgate.net/publication/316558298
    // (Neri-Schneider, 2022), adapted for u64 arithmetic.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    (year, month as u8, day as u8)
}

/// Strip JSON-unsafe characters from a string intended for a JSON string value.
fn sanitize_json_string(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '"' && *c != '\\' && !c.is_control())
        .collect()
}

#[derive(Parser, Debug)]
#[command(
    name = "ember-exec",
    version,
    about = "Privileged exec sidecar (SCION-EMBER-EXEC-AS-SERVICE)"
)]
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
            // SCION-EMBER-EXEC-C-SPAWN-INTEGRATION: the handler runs the
            // full verify → drop_priv (if root) → spawn → output → exit
            // flow against the in-flight connection. Wire-shape errors
            // (frame write fail mid-stream) close the connection; spawn
            // errors propagate to stderr for emberd to observe.
            match frame {
                ExecFrame::SpawnDirective(d) => {
                    // Emit EmberExecReady once the spawn directive is accepted
                    // and the privileged sidecar is about to hand control to
                    // the agent binary.  This is the container-side proof that
                    // the MCP handshake has been set in motion.
                    // TODO: route via
                    // daemon RPC when the cross-uid bridge socket is available.
                    let agent_id =
                        std::env::var("EMBER_AGENT_ID").unwrap_or_else(|_| "unknown".to_string());
                    emit_checkpoint("EmberExecReady", &agent_id);

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
    if let Some(parent) = socket.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        return Err(format!(
            "socket parent dir does not exist: {}",
            parent.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod checkpoint_tests {
    use super::*;

    // Tests use `format_checkpoint_line` directly to assert the NDJSON field
    // shape without capturing fd 2.  `emit_checkpoint` is the thin public
    // wrapper that writes the formatted line to stderr; it delegates all
    // formatting to `format_checkpoint_line`, so testing the formatter is
    // sufficient to cover both functions' output contract.

    #[test]
    fn emit_checkpoint_produces_parseable_ndjson() {
        // format_checkpoint_line is the inner formatter that emit_checkpoint
        // delegates to; test it directly to assert field shape.
        let line = format_checkpoint_line("EmberExecReady", "agent-test-01");
        let line = line.trim();
        assert!(
            !line.is_empty(),
            "emit_checkpoint must write at least one line"
        );
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("emit_checkpoint output must be valid JSON");
        assert_eq!(
            parsed["checkpoint"].as_str(),
            Some("EmberExecReady"),
            "checkpoint field must be EmberExecReady"
        );
        assert_eq!(
            parsed["agent_id"].as_str(),
            Some("agent-test-01"),
            "agent_id field must match"
        );
        assert!(parsed["ts"].is_string(), "ts field must be a string");
        let ts = parsed["ts"].as_str().unwrap();
        assert!(
            ts.ends_with('Z'),
            "ts must be UTC ISO-8601 (ends with Z): got {ts}"
        );
    }

    #[test]
    fn emit_checkpoint_anthropic_bootstrap_ready_field_shape() {
        let line = format_checkpoint_line("AnthropicBootstrapReady", "agent-bootstrap-02");
        let line = line.trim();
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("AnthropicBootstrapReady line must be valid JSON");
        assert_eq!(
            parsed["checkpoint"].as_str(),
            Some("AnthropicBootstrapReady")
        );
        assert_eq!(parsed["agent_id"].as_str(), Some("agent-bootstrap-02"));
        // ts must be present and non-empty.
        assert!(parsed["ts"].as_str().is_some_and(|s| !s.is_empty()));
    }

    #[test]
    fn emit_checkpoint_sanitizes_unsafe_chars() {
        // Inputs with JSON-unsafe characters must not break the NDJSON line.
        let line = format_checkpoint_line("bad\"name\\", "agent\"\x00test");
        let line = line.trim();
        // Must still parse as JSON even with bad inputs.
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("sanitized output must remain valid JSON");
        let cp = parsed["checkpoint"].as_str().unwrap_or("");
        assert!(!cp.contains('"'), "checkpoint must not contain bare quotes");
        assert!(
            !cp.contains('\\'),
            "checkpoint must not contain backslashes"
        );
    }

    #[test]
    fn days_to_ymd_known_dates() {
        // Day 0 = 1970-01-01
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        // Day 365 = 1971-01-01 (1970 was not a leap year)
        assert_eq!(days_to_ymd(365), (1971, 1, 1));
        // Day 20089 + 120 = 2025-05-01
        // 2025-01-01 is day 20089 from epoch;
        // Jan(31)+Feb(28)+Mar(31)+Apr(30) = 120 days to reach May 1.
        assert_eq!(days_to_ymd(20089 + 120), (2025, 5, 1));
    }
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
        assert!(
            r.is_ok(),
            "explicit --allow-tmp must accept tmp path: {r:?}"
        );
    }

    #[test]
    fn validate_socket_path_refuses_missing_parent() {
        let path = PathBuf::from("/nonexistent-dir/ember-exec.sock");
        let r = validate_socket_path(&path, true);
        assert!(r.is_err(), "missing parent dir must be refused");
    }
}
