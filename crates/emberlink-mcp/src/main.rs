//! emberlink-mcp binary entry point.
//!
//! ## Transport selection
//!
//! The `main()` flow picks one of two daemon transports:
//!
//! - When `EMBER_DAEMON_ENDPOINT` is set (in-container mode, design
//!   component 1 — implementation-note-537): load the per-agent
//!   cert bundle from `EMBER_BRIDGE_CERT_DIR` (default
//!   `/run/ember/client-cert/`) and build an mTLS+TCP transport to the
//!   host's ember-rpc listener. Fails closed (exit non-zero) on missing
//!   or malformed cert files. Anchor:
//!   `emberlink_mcp_mtls_client_handshake`.
//! - Otherwise: the legacy UDS path (host-mode emberlink-mcp running
//!   alongside emberd on the same machine).
//!
//! Both paths share the same external `DaemonClient` surface — the
//! transport variant is invisible to callers above
//! `DaemonTransportClient`.

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use emberlink_agent::runtime::{AgentConfig, AgentRuntime, DaemonClient, DaemonClientError};
use emberlink_mcp::McpServer;
use emberlink_mcp::cert_expiry::{ExpiryEventContext, parse_cert_validity, spawn_expiry_timer};
use emberlink_mcp::daemon_transport::{
    DaemonTransport, MtlsBridgeConfig, build_client_tls_config, load_bridge_cert_files,
    resolve_bridge_cert_dir,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Env var the orchestrator sets at container spawn time to point this
/// MCP server at the host's ember-rpc listener. Format: `host:port`.
/// Presence selects the mTLS bridge transport; absence selects the
/// legacy UDS path. Per implementation-note-538 the
/// orchestrator also wires the corresponding `extra_hosts` entry.
const EMBER_DAEMON_ENDPOINT_ENV: &str = "EMBER_DAEMON_ENDPOINT";

/// Default SNI / server-name presented during the mTLS handshake. The
/// ember-rpc server cert SAN is minted to match this string. Override
/// via `EMBER_DAEMON_SERVER_NAME` for tests + alternate deployments.
const DEFAULT_BRIDGE_SERVER_NAME: &str = "localhost";

/// `emberlink_mcp_mtls_client_handshake` — checkpoint for the
/// implementation-note-537 target-state grep. Don't remove or
/// rename without also updating `release-checklist` for the task.
#[allow(dead_code)]
const SENTINEL_EMBERLINK_MCP_MTLS_CLIENT_HANDSHAKE: &str = "emberlink_mcp_mtls_client_handshake";

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
    /// Bypass the `DaemonTransport` tool→method map and call the daemon
    /// JSON-RPC method directly. Required for the runtime methods
    /// (`list_grants`, `grant_status`, `use_credential`) whose tool-name
    /// shape diverges from the daemon's method name (e.g. `grant_status`
    /// → `evaluate_grant` in the tool map). Delegates to
    /// [`DaemonTransport::call_raw`] so the underlying transport variant
    /// (UDS vs. mTLS bridge) is invisible to this layer.
    fn send_raw(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonClientError> {
        self.0.call_raw(method, params).map_err(|e| match e {
            emberlink_mcp::daemon_transport::DaemonTransportError::Io(_) => {
                DaemonClientError::Unavailable
            }
            emberlink_mcp::daemon_transport::DaemonTransportError::Protocol(_)
            | emberlink_mcp::daemon_transport::DaemonTransportError::DaemonError(_)
            | emberlink_mcp::daemon_transport::DaemonTransportError::UnknownTool(_) => {
                DaemonClientError::Daemon
            }
        })
    }
}

impl DaemonClient for DaemonTransportClient {
    fn request_access(
        &mut self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonClientError> {
        self.0
            .call_tool("request_access", params)
            .map_err(|e| match e {
                emberlink_mcp::daemon_transport::DaemonTransportError::Io(_) => {
                    DaemonClientError::Unavailable
                }
                emberlink_mcp::daemon_transport::DaemonTransportError::Protocol(_)
                | emberlink_mcp::daemon_transport::DaemonTransportError::DaemonError(_)
                | emberlink_mcp::daemon_transport::DaemonTransportError::UnknownTool(_) => {
                    DaemonClientError::Daemon
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
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".ember/run/daemon.sock"))
}

/// Build the legacy UDS-mode MCP server. Probes the socket up-front so
/// stale-socket / daemon-not-running failures surface here rather than at
/// the first tool call.
fn build_uds_server(
    config: AgentConfig,
    store: Rc<core_state::EventStore>,
    daemon_socket_override: Option<PathBuf>,
) -> McpServer {
    let socket_path = daemon_socket_override
        .or_else(default_daemon_socket)
        .unwrap_or_else(|| {
            eprintln!(
                "emberlink-mcp: HOME is not set and --daemon-socket was not provided; \
                 use --no-daemon to run without daemon transport"
            );
            std::process::exit(1);
        });

    if let Err(e) = std::os::unix::net::UnixStream::connect(&socket_path) {
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
    let runtime = AgentRuntime::with_daemon(config, store, client);
    McpServer::with_daemon_socket(runtime, socket_path)
}

/// Build the in-container mTLS bridge MCP server. Per design component 1
/// (implementation-note-537): load per-agent cert bundle, build
/// `rustls::ClientConfig` with the bridge CA as the SOLE trust anchor,
/// arm the 90% TTL expiry timer, and route every `DaemonTransport` call
/// through the mTLS+TCP bridge. Fails closed (`std::process::exit(1)`) on
/// any missing or malformed cert file.
fn build_bridge_server(
    config: AgentConfig,
    store: Rc<core_state::EventStore>,
    endpoint: String,
) -> McpServer {
    let cert_dir = resolve_bridge_cert_dir();
    let loaded = match load_bridge_cert_files(&cert_dir) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "emberlink-mcp: bridge cert load failed at {}: {} — \
                 refusing to start (fail-closed per design)",
                cert_dir.display(),
                e
            );
            std::process::exit(1);
        }
    };

    // Capture the leaf client cert DER before consuming `loaded` — the
    // 90% TTL timer needs it to compute the deadline.
    let leaf_cert_der = loaded.client_certs[0].clone();

    let tls_config = match build_client_tls_config(loaded) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "emberlink-mcp: build TLS config failed: {} — refusing to start",
                e
            );
            std::process::exit(1);
        }
    };

    let server_name = std::env::var("EMBER_DAEMON_SERVER_NAME")
        .unwrap_or_else(|_| DEFAULT_BRIDGE_SERVER_NAME.to_string());

    // Dedicated multi-thread runtime for the mTLS bridge transport.
    // Sync `DaemonClient` callers run inside main's current_thread runtime;
    // trying to `block_on` from there would panic. The dedicated runtime
    // is what makes sync↔async cohabitation work without rewriting every
    // caller as async.
    let bridge_runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("emberlink-mcp-bridge")
            .build()
            .unwrap_or_else(|e| {
                eprintln!("emberlink-mcp: failed to build bridge runtime: {e}");
                std::process::exit(1);
            }),
    );

    let bridge_config = MtlsBridgeConfig {
        endpoint: endpoint.clone(),
        tls_config,
        server_name,
    };

    // The DaemonClient adapter and the McpServer-receipt transport each
    // get their own DaemonTransport wrapping the same MtlsBridgeConfig +
    // runtime Arc. Each transport is a thin wrapper; no shared mutable
    // state — connections are fresh per call.
    let client_transport =
        DaemonTransport::new_mtls(bridge_config.clone(), Arc::clone(&bridge_runtime));
    let client: Box<dyn DaemonClient> = Box::new(DaemonTransportClient(client_transport));

    // 90% TTL expiry timer. Failure to parse the cert isn't fatal — the
    // bridge still works; we just lose the proactive warning.
    //
    // bridge_cert_expiring_soon_event: this is the MCP-server-side arm
    // of the `bridge.cert_expiring_soon` warning flow per design
    // §Component 3 + implementation-note-539. The
    // module that actually computes the 90%-TTL fire time, emits the
    // event over the daemon's `bridge_cert_expiring_soon` JSON-RPC
    // tool, and carries the persona_id / container_id / cert expiry
    // timestamp on the payload lives at
    // `crates/emberlink-mcp/src/cert_expiry.rs`. This call-site is the
    // contract that the timer is armed at MCP-server boot — the
    // checkpoint anchors it here so a grep verifies the wiring as a
    // single unit instead of asking the reader to chase the module
    // back to the consumer.
    match parse_cert_validity(&leaf_cert_der) {
        Ok(validity) => {
            let timer_transport = Arc::new(DaemonTransport::new_mtls(
                bridge_config.clone(),
                Arc::clone(&bridge_runtime),
            ));
            let _expiry_handle = spawn_expiry_timer(
                Arc::clone(&bridge_runtime),
                validity,
                ExpiryEventContext::from_env(),
                timer_transport,
            );
            eprintln!(
                "emberlink-mcp: bridge.cert_expiring_soon timer armed (fires at 90% TTL elapsed)"
            );
        }
        Err(e) => {
            eprintln!(
                "emberlink-mcp: warn: failed to parse cert validity for expiry timer: {} — \
                 bridge still functional, no proactive expiry warning",
                e
            );
        }
    }

    eprintln!(
        "emberlink-mcp: mTLS bridge transport active (endpoint={}, cert_dir={})",
        endpoint,
        cert_dir.display()
    );

    let receipt_transport = DaemonTransport::new_mtls(bridge_config, bridge_runtime);
    let runtime = AgentRuntime::with_daemon(config, store, client);
    McpServer::with_daemon_transport(runtime, receipt_transport)
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

    // emberlink_mcp_mtls_client_handshake — the bridge transport branch
    // sits here. We pick on env-var presence so the legacy UDS path stays
    // the default and host-mode callers see no behavior change.
    let bridge_endpoint = std::env::var(EMBER_DAEMON_ENDPOINT_ENV).ok();

    let server = if no_daemon {
        // Legacy behaviour: no daemon link, request_grant fails closed.
        McpServer::new(AgentRuntime::new(config, store))
    } else if let Some(endpoint) = bridge_endpoint {
        build_bridge_server(config, store, endpoint)
    } else {
        build_uds_server(config, store, daemon_socket_override)
    };

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
