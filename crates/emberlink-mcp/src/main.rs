use std::rc::Rc;

use emberlink_agent::runtime::{AgentConfig, AgentRuntime};
use emberlink_mcp::McpServer;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Maximum allowed line length (1 MB). Lines exceeding this are rejected
/// to prevent memory exhaustion from a malicious or buggy client.
const MAX_LINE_BYTES: usize = 1_048_576;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut db_path: Option<String> = None;
    let mut persona_id = "default".to_string();
    let mut label = "emberlink-mcp".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--db" => {
                i += 1;
                db_path = Some(args.get(i).expect("--db requires a path").clone());
            }
            "--persona" => {
                i += 1;
                persona_id = args.get(i).expect("--persona requires an id").clone();
            }
            "--label" => {
                i += 1;
                label = args.get(i).expect("--label requires a label").clone();
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let store = if let Some(path) = &db_path {
        match core_state::EventStore::open(path) {
            Ok(store) => {
                eprintln!("emberlink-mcp: opened store at {path}");
                Rc::new(store)
            }
            Err(e) => {
                eprintln!("emberlink-mcp: failed to open store: {e}");
                std::process::exit(1);
            }
        }
    } else {
        Rc::new(core_state::EventStore::default())
    };

    let config = AgentConfig {
        persona_id,
        label: Some(label.clone()),
    };
    let runtime = AgentRuntime::new(config, store);
    let server = McpServer::new(runtime);

    eprintln!("emberlink-mcp: server ready (label={label})");

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        if line.len() > MAX_LINE_BYTES {
            eprintln!("emberlink-mcp: line too long (>{MAX_LINE_BYTES} bytes), rejecting");
            let err = serde_json::json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": -32600,
                    "message": "request exceeds 1MB limit"
                }
            });
            let mut out = err.to_string().into_bytes();
            out.push(b'\n');
            if stdout.write_all(&out).await.is_err() {
                break;
            }
            if stdout.flush().await.is_err() {
                break;
            }
            continue;
        }
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        if let Some(response) = server.process_line(&line) {
            let mut out = response.into_bytes();
            out.push(b'\n');
            if stdout.write_all(&out).await.is_err() {
                break;
            }
            if stdout.flush().await.is_err() {
                break;
            }
        }
    }
}
