//! Emberlink Agent — stdio JSON-line binary.
//!
//! Usage: emberlink-agent --db <path> --persona <id> [--label <label>]
//!
//! Reads one JSON request per line from stdin, writes one JSON response
//! per line to stdout. Designed for piping from AI agent tool-use frameworks.

use std::rc::Rc;

use core_state::EventStore;
use emberlink_agent::runtime::{process_line, AgentConfig, AgentRuntime};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Maximum allowed line length (1 MB). Lines exceeding this are rejected
/// to prevent memory exhaustion from a malicious or buggy client.
const MAX_LINE_BYTES: usize = 1_048_576;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    let db_path = match find_arg(&args, "--db") {
        Some(p) => p,
        None => {
            eprintln!("Usage: emberlink-agent --db <path> --persona <id> [--label <label>]");
            std::process::exit(1);
        }
    };

    let persona_id = match find_arg(&args, "--persona") {
        Some(p) => p,
        None => {
            eprintln!("Usage: emberlink-agent --db <path> --persona <id> [--label <label>]");
            std::process::exit(1);
        }
    };

    let label = find_arg(&args, "--label");

    let store = match EventStore::open(&db_path) {
        Ok(s) => Rc::new(s),
        Err(e) => {
            eprintln!("Failed to open EventStore at {db_path}: {e}");
            std::process::exit(1);
        }
    };

    let config = AgentConfig { persona_id, label };
    let runtime = AgentRuntime::new(config, store);

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                if line.len() > MAX_LINE_BYTES {
                    line.clear();
                    eprintln!("line too long (>{MAX_LINE_BYTES} bytes), rejecting");
                    let err = serde_json::json!({
                        "error": {
                            "code": "LINE_TOO_LONG",
                            "message": "request exceeds 1MB limit"
                        }
                    });
                    let _ = stdout
                        .write_all(err.to_string().as_bytes())
                        .await;
                    let _ = stdout.write_all(b"\n").await;
                    let _ = stdout.flush().await;
                    continue;
                }
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let response = process_line(&runtime, trimmed);
                let _ = stdout.write_all(response.as_bytes()).await;
                let _ = stdout.write_all(b"\n").await;
                let _ = stdout.flush().await;
            }
            Err(e) => {
                eprintln!("stdin read error: {e}");
                break;
            }
        }
    }
}

fn find_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
