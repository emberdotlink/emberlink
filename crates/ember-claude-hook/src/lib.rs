//! ember-proxy library entry.
//!
//! Exposes [`run_main`] so the `ember-proxy` binary (in this crate) and the
//! workspace bin alias in `emberlink-cli` can both call the same entry point.
//! Per implementation-note-90 / design §2: `cargo install emberlink` should produce
//! both `ember` and `ember-proxy` on `$PATH` in one step.

pub mod claude_code_hook;
pub mod evaluator;

/// Entry point for the `ember-proxy` binary.
///
/// Parsed from `std::env::args()`, dispatches to [`claude_code_hook::run`]
/// on `hook` / `--claude-code-hook`, or prints usage on `--help` / no args.
///
/// implementation-note-16: the hook dispatch path is wrapped in `std::panic::catch_unwind`
/// so any unexpected panic emits a structured JSON response and exits 0 rather
/// than producing an unstructured backtrace that Claude Code cannot consume.
/// The `allow` value in the panic response tracks `explicit_fail_open` from
/// [`core_config::EmberConfig`].
pub fn run_main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("hook") | Some("--claude-code-hook") => {
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(claude_code_hook::run));
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    let resp = claude_code_hook::HookResponse {
                        allow: false,
                        reason: format!("ember-proxy: hook error: {e}"),
                    };
                    if let Ok(line) = serde_json::to_string(&resp) {
                        println!("{line}");
                    }
                    std::process::exit(1);
                }
                Err(panic_payload) => {
                    let cfg = core_config::EmberConfig::load_or_default();
                    let allow = cfg.explicit_fail_open;
                    // Generate a short ID from the current time for correlation.
                    let id = format!(
                        "{:x}",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_nanos())
                            .unwrap_or(0)
                    );
                    let resp = serde_json::json!({
                        "allow": allow,
                        "reason": format!(
                            "ember-proxy: internal error {}; {}",
                            id,
                            if allow { "permitting" } else { "denying" }
                        ),
                    });
                    println!("{resp}");
                    // Best-effort: append to ~/.ember/sessions/<id>/hook-errors.jsonl.
                    if let Ok(home) = std::env::var("HOME") {
                        let session_id = std::env::var("EMBER_SESSION_ID")
                            .unwrap_or_else(|_| "unknown".to_string());
                        let path = std::path::Path::new(&home)
                            .join(".ember")
                            .join("sessions")
                            .join(&session_id)
                            .join("hook-errors.jsonl");
                        if let Some(parent) = path.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        let entry = serde_json::json!({
                            "id": id,
                            "panic": format!("{:?}", panic_payload),
                            "ts": std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0),
                        });
                        let _ = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&path)
                            .and_then(|mut f| {
                                use std::io::Write;
                                writeln!(f, "{entry}")
                            });
                    }
                    std::process::exit(0);
                }
            }
        }
        Some("--help") | Some("-h") | None => {
            print_usage();
        }
        Some(other) => {
            eprintln!("ember-proxy: unknown subcommand: {other}");
            print_usage();
            std::process::exit(2);
        }
    }
}

fn print_usage() {
    eprintln!(
        "ember-proxy — HTTP credential injection + Claude Code PreToolUse hook\n\n\
         USAGE:\n  \
         ember-proxy hook                  Run as Claude Code PreToolUse hook (reads JSON on stdin)\n  \
         ember-proxy --claude-code-hook    Same as `hook` (long form)\n  \
         ember-proxy --help                Show this message\n\n\
         ENV:\n  \
         EMBER_PROXY_DEV_PERMIT=1   Permit every tool call (dev fallback when emberd is unreachable)\n\n\
         INSTALL (Claude Code, ~/.claude/settings.json):\n\n  \
         {{\"hooks\": {{\"PreToolUse\": [{{\"matcher\": \"*\", \"hooks\": [\n    \
         {{\"type\": \"command\", \"command\": \"ember-proxy hook\"}}\n  \
         ]}}]}}}}\n"
    );
}
