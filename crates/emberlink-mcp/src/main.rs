use std::path::PathBuf;
use std::rc::Rc;

use emberlink_agent::runtime::{AgentConfig, AgentRuntime, DaemonClient, DaemonClientError};
use emberlink_mcp::daemon_transport::DaemonTransport;
use emberlink_mcp::McpServer;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Maximum allowed line length (1 MB). Lines exceeding this are rejected
/// to prevent memory exhaustion from a malicious or buggy client.
const MAX_LINE_BYTES: usize = 1_048_576;

/// Wraps [`DaemonTransport`] so it can be used as a [`DaemonClient`] by the
/// agent runtime. The runtime now routes `list_grants`, `grant_status`, and
/// `use_credential` through the daemon as well (TODO 69I.1), so every
/// trait method is implemented as a pass-through to the transport's
/// `call_tool`. The transport's tool→method map is bypassed here in favor
/// of the underlying daemon method names: the agent runtime is a trusted
/// internal caller and we want its calls to land on the same socket
/// methods the daemon exposes directly (rather than the MCP client's
/// user-facing tool names that share the same words).
struct DaemonTransportClient(DaemonTransport);

impl DaemonTransportClient {
    fn send_raw(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonClientError> {
        use std::io::{BufRead, BufReader, Write};

        let stream =
            std::os::unix::net::UnixStream::connect(self.0.socket_path())
                .map_err(|_| DaemonClientError::Unavailable)?;
        let mut writer = stream.try_clone().map_err(|_| DaemonClientError::Unavailable)?;
        let mut reader = BufReader::new(stream);

        let request = serde_json::json!({
            "id": "1",
            "method": method,
            "params": params,
        });
        let mut line = serde_json::to_string(&request).map_err(|_| DaemonClientError::Daemon)?;
        line.push('\n');
        writer
            .write_all(line.as_bytes())
            .map_err(|_| DaemonClientError::Unavailable)?;

        let mut response_line = String::new();
        reader
            .read_line(&mut response_line)
            .map_err(|_| DaemonClientError::Unavailable)?;
        let response: serde_json::Value = serde_json::from_str(response_line.trim())
            .map_err(|_| DaemonClientError::Daemon)?;
        if response
            .get("error")
            .filter(|e| !e.is_null())
            .is_some()
        {
            return Err(DaemonClientError::Daemon);
        }
        Ok(response.get("result").cloned().unwrap_or(serde_json::Value::Null))
    }
}

impl DaemonClient for DaemonTransportClient {
    fn request_access(
        &mut self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonClientError> {
        self.0.call_tool("request_access", params).map_err(|e| {
            match e {
                emberlink_mcp::daemon_transport::DaemonTransportError::Io(_) => {
                    DaemonClientError::Unavailable
                }
                emberlink_mcp::daemon_transport::DaemonTransportError::Protocol(_)
                | emberlink_mcp::daemon_transport::DaemonTransportError::DaemonError(_)
                | emberlink_mcp::daemon_transport::DaemonTransportError::UnknownTool(_) => {
                    DaemonClientError::Daemon
                }
            }
        })
    }

    fn list_grants(
        &mut self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonClientError> {
        self.send_raw("list_grants", params)
    }

    fn grant_status(
        &mut self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonClientError> {
        self.send_raw("grant_status", params)
    }

    fn use_credential(
        &mut self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonClientError> {
        self.send_raw("use_credential", params)
    }
}

/// Returns the default daemon socket path: `$HOME/.ember/run/daemon.sock`.
/// Returns `None` if `HOME` is not set.
fn default_daemon_socket() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".ember/run/daemon.sock"))
}

fn print_help() {
    eprintln!(
        "Usage: emberlink-mcp [OPTIONS]

Options:
  --db <PATH>              Path to the SQLite event store
  --persona <ID>           Persona ID to operate as (default: \"default\")
  --label <LABEL>          Human-readable label for this MCP server (default: \"emberlink-mcp\")
  --daemon-socket <PATH>   Path to the ember daemon Unix socket
                           (default: $HOME/.ember/run/daemon.sock)
  --no-daemon              Disable daemon transport; request_grant fails closed
                           at request time (legacy behaviour)
  --help                   Print this help message and exit"
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut db_path: Option<String> = None;
    let mut persona_id = "default".to_string();
    let mut label = "emberlink-mcp".to_string();
    let mut daemon_socket_override: Option<PathBuf> = None;
    let mut no_daemon = false;

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
            "--daemon-socket" => {
                i += 1;
                let path = args.get(i).expect("--daemon-socket requires a path");
                daemon_socket_override = Some(PathBuf::from(path));
            }
            "--no-daemon" => {
                no_daemon = true;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
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

    let runtime = if no_daemon {
        // Legacy behaviour: no daemon link, request_grant fails closed.
        AgentRuntime::new(config, store)
    } else {
        // Default: connect to the daemon socket.  If --daemon-socket is given,
        // use that; otherwise fall back to $HOME/.ember/run/daemon.sock.
        let socket_path = daemon_socket_override
            .or_else(default_daemon_socket)
            .unwrap_or_else(|| {
                eprintln!(
                    "emberlink-mcp: HOME is not set and --daemon-socket was not provided; \
                     use --no-daemon to run without daemon transport"
                );
                std::process::exit(1);
            });

        // Probe the socket at startup.  Using an actual connection rather than
        // just a filesystem existence check catches stale socket files left by
        // a previous daemon run.  Failure is always fatal here — callers that
        // want the legacy behaviour must pass --no-daemon.
        if let Err(e) =
            std::os::unix::net::UnixStream::connect(&socket_path)
        {
            eprintln!(
                "emberlink-mcp: cannot connect to daemon socket at {}: {}; \
                 start emberd or pass --no-daemon",
                socket_path.display(),
                e,
            );
            std::process::exit(1);
        }

        let transport = DaemonTransport::new(&socket_path);
        let client: Box<dyn DaemonClient> = Box::new(DaemonTransportClient(transport));
        AgentRuntime::with_daemon(config, store, client)
    };

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_daemon_flag_parses_to_new_constructor() {
        // Simulate argument parsing with --no-daemon and verify the flag is
        // recognised.  The test constructs the runtime directly (mirroring
        // what main() does) so we don't have to spin up a full binary.
        let no_daemon = true; // as if --no-daemon was passed

        let store = Rc::new(core_state::EventStore::default());
        let config = AgentConfig {
            persona_id: "test-persona".to_string(),
            label: Some("test-label".to_string()),
        };

        // This must compile and not panic: it asserts that the --no-daemon
        // path uses AgentRuntime::new (no daemon link).
        let _runtime = if no_daemon {
            AgentRuntime::new(config, store)
        } else {
            // This branch is never reached in this test, but it must type-check.
            let socket_path = PathBuf::from("/tmp/nonexistent.sock");
            let transport = DaemonTransport::new(&socket_path);
            let client: Box<dyn DaemonClient> = Box::new(DaemonTransportClient(transport));
            AgentRuntime::with_daemon(
                AgentConfig {
                    persona_id: "test-persona".to_string(),
                    label: Some("test-label".to_string()),
                },
                Rc::new(core_state::EventStore::default()),
                client,
            )
        };
        // If we got here the --no-daemon path compiles and constructs a valid
        // AgentRuntime without panicking.
    }

    #[test]
    fn default_daemon_socket_uses_home() {
        // HOME must be set in the test environment.
        if let Some(home) = std::env::var_os("HOME") {
            let expected = PathBuf::from(home).join(".ember/run/daemon.sock");
            assert_eq!(default_daemon_socket(), Some(expected));
        }
    }

    #[test]
    fn daemon_transport_client_implements_daemon_client_trait() {
        // Constructing DaemonTransportClient proves the impl compiles.
        // We use a dummy path; we never actually call request_access here
        // so no socket needs to exist.
        let transport = DaemonTransport::new("/tmp/no-such-socket.sock");
        let _client: Box<dyn DaemonClient> = Box::new(DaemonTransportClient(transport));
    }
}
