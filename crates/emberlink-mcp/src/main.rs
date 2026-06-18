//! emberlink-mcp binary entry point.
//!
//! ## Transport selection
//!
//! The `main()` flow picks one of two daemon transports:
//!
//! - When `EMBER_BRIDGE_URL` is set (in-container mode, ADR 154 component 1 —
//!   META-AP-EMBERLINK-MCP-MTLS-CLIENT; the unified in-container bridge contract
//!   per ADR 215 §4, the SAME var the construct-shim reads): load the per-agent
//!   cert bundle via the explicit `EMBER_CLIENT_CERT` / `EMBER_CLIENT_KEY` /
//!   `EMBER_CA_CERT` paths (falling back to `<EMBER_BRIDGE_CERT_DIR>/*` then the
//!   canonical `/run/ember/*`) and build an mTLS+TCP transport to the host's
//!   ember-rpc listener. Fails closed (exit non-zero) on missing or malformed
//!   cert files. Anchor: `emberlink_mcp_mtls_client_handshake`.
//! - Otherwise: the host UDS path (host-mode emberlink-mcp running
//!   alongside emberd on the same machine).
//!
//! Both paths expose the same canonical MCP control/read surface.

use std::path::PathBuf;
use std::sync::Arc;

use emberlink_mcp::McpServer;
use emberlink_mcp::cert_expiry::{
    ExpiryEventContext, RefreshState, Tier, parse_cert_validity, spawn_refresh_client,
};
use emberlink_mcp::daemon_transport::{
    DaemonTransport, MtlsBridgeConfig, build_client_tls_config, endpoint_from_bridge_url,
    load_bridge_cert_from_paths, resolve_bridge_cert_paths,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Env var the orchestrator sets at container spawn time to point this
/// MCP server at the host's ember-rpc listener. Format: `host:port`.
/// The unified in-container bridge endpoint (ADR 215 §4): a full URL
/// (`https://host.docker.internal:<port>`), the SAME var the construct-shim
/// reads. Presence selects the mTLS bridge transport; absence selects the host
/// UDS path. Per META-AP-SCION-EXTRA-HOSTS-DECLARATIVE the orchestrator also
/// wires the corresponding `extra_hosts` entry. The `host:port` for the raw mTLS
/// dial is parsed from this URL via `endpoint_from_bridge_url`.
const EMBER_BRIDGE_URL_ENV: &str = "EMBER_BRIDGE_URL";

/// Default SNI / server-name presented during the mTLS handshake. The
/// ember-rpc server cert SAN is minted to match this string. Override
/// via `EMBER_DAEMON_SERVER_NAME` for tests + alternate deployments.
const DEFAULT_BRIDGE_SERVER_NAME: &str = "localhost";

/// `emberlink_mcp_mtls_client_handshake` — checkpoint for the
/// META-AP-EMBERLINK-MCP-MTLS-CLIENT target-state grep. Don't remove or
/// rename without also updating `tasks.toml` for the task.
#[allow(dead_code)]
const SENTINEL_EMBERLINK_MCP_MTLS_CLIENT_HANDSHAKE: &str = "emberlink_mcp_mtls_client_handshake";

/// Maximum allowed line length (1 MB). Lines exceeding this are rejected
/// to prevent memory exhaustion from a malicious or buggy client.
const MAX_LINE_BYTES: usize = 1_048_576;

/// Returns the default daemon socket path: `$HOME/.ember/run/daemon.sock`.
/// Returns `None` if `HOME` is not set.
fn default_daemon_socket() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".ember/run/daemon.sock"))
}

/// Build the host UDS-mode MCP server. Probes the socket up-front so
/// stale-socket / daemon-not-running failures surface here rather than at
/// the first tool call.
fn build_uds_server(daemon_socket_override: Option<PathBuf>) -> McpServer {
    let socket_path = daemon_socket_override
        .or_else(default_daemon_socket)
        .unwrap_or_else(|| {
            eprintln!(
                "emberlink-mcp: HOME is not set and --daemon-socket was not provided; \
                 pass --daemon-socket explicitly"
            );
            std::process::exit(1);
        });

    if let Err(e) = std::os::unix::net::UnixStream::connect(&socket_path) {
        eprintln!(
            "emberlink-mcp: cannot connect to daemon socket at {}: {}; \
             start emberd or pass --daemon-socket",
            socket_path.display(),
            e,
        );
        std::process::exit(1);
    }

    McpServer::with_daemon_socket(socket_path)
}

/// Build the in-container mTLS bridge MCP server. Per ADR 154 component 1
/// (META-AP-EMBERLINK-MCP-MTLS-CLIENT): load per-agent cert bundle, build
/// `rustls::ClientConfig` with the bridge CA as the SOLE trust anchor,
/// arm the 90% TTL expiry timer, and route every `DaemonTransport` call
/// through the mTLS+TCP bridge. Fails closed (`std::process::exit(1)`) on
/// any missing or malformed cert file.
fn build_bridge_server(endpoint: String) -> McpServer {
    let (cert_path, key_path, ca_path) = resolve_bridge_cert_paths();
    let loaded = match load_bridge_cert_from_paths(&cert_path, &key_path, &ca_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "emberlink-mcp: bridge cert load failed (cert={}, key={}, ca={}): {} — \
                 refusing to start (fail-closed per ADR 154)",
                cert_path.display(),
                key_path.display(),
                ca_path.display(),
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

    // Dedicated multi-thread runtime for the mTLS bridge transport. The
    // stdio server runs on a current-thread runtime; the transport uses this
    // runtime to block on async TLS I/O without nested-runtime panics.
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

    let bridge_config = MtlsBridgeConfig::new(endpoint.clone(), tls_config, server_name);

    // 4-band cert refresh client. Failure to parse the cert isn't fatal
    // — the bridge still works; we just lose proactive refresh.
    //
    // emberlink_mcp_cert_refresh_client_landed — META-AP-EMBERLINK-MCP-
    // CERT-REFRESH-CLIENT / ADR 173 §Component 1 + §Component 5. The
    // module that owns the trigger-band scheduler, exp-backoff retry,
    // failure-cause classification, and hot-swap apply path lives at
    // `crates/emberlink-mcp/src/cert_expiry.rs`. This call-site is the
    // contract that the refresh chain is armed at MCP-server boot — the
    // checkpoint anchors it here so a grep verifies the wiring as a single
    // unit instead of asking the reader to chase the module back to the
    // consumer.
    //
    // The 90% `bridge.cert_expiring_soon` warning still fires (the
    // refresh client owns that emission at the 90% band) so M5's
    // pre-existing daemon-side wiring continues working unchanged.
    match parse_cert_validity(&leaf_cert_der) {
        Ok(validity) => {
            let timer_transport = Arc::new(DaemonTransport::new_mtls(
                bridge_config.clone(),
                Arc::clone(&bridge_runtime),
            ));
            let refresh_state = Arc::new(std::sync::RwLock::new(RefreshState::default()));
            let _refresh_handle = spawn_refresh_client(
                Arc::clone(&bridge_runtime),
                validity,
                ExpiryEventContext::from_env(),
                timer_transport,
                bridge_config.clone(),
                refresh_state,
                Tier::from_env(),
            );
            eprintln!(
                "emberlink-mcp: bridge cert refresh client armed (4-band: 50/75/90/99 \
                 with exp-backoff per ADR 173)"
            );
        }
        Err(e) => {
            eprintln!(
                "emberlink-mcp: warn: failed to parse cert validity for refresh client: {} — \
                 bridge still functional, no proactive refresh",
                e
            );
        }
    }

    eprintln!(
        "emberlink-mcp: mTLS bridge transport active (endpoint={}, cert={})",
        endpoint,
        cert_path.display()
    );

    let transport = DaemonTransport::new_mtls(bridge_config, bridge_runtime);
    McpServer::with_daemon_transport(transport)
}

fn print_help() {
    eprintln!(
        "Usage: emberlink-mcp [OPTIONS]

Options:
  --label <LABEL>          Human-readable label for this MCP server (default: \"emberlink-mcp\")
  --daemon-socket <PATH>   Path to the ember daemon Unix socket
                           (default: $HOME/.ember/run/daemon.sock)
  --help                   Print this help message and exit"
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut label = "emberlink-mcp".to_string();
    let mut daemon_socket_override: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--label" => {
                i += 1;
                label = args.get(i).expect("--label requires a label").clone();
            }
            "--daemon-socket" => {
                i += 1;
                let path = args.get(i).expect("--daemon-socket requires a path");
                daemon_socket_override = Some(PathBuf::from(path));
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

    // emberlink_mcp_mtls_client_handshake — the bridge transport branch
    // sits here. We pick on env-var presence; otherwise host mode uses the
    // local UDS daemon socket. The unified contract (ADR 215 §4) is
    // EMBER_BRIDGE_URL (a full URL); the raw mTLS dial wants host:port,
    // parsed from it.
    let bridge_endpoint = std::env::var(EMBER_BRIDGE_URL_ENV)
        .ok()
        .filter(|u| !u.is_empty())
        .map(|u| endpoint_from_bridge_url(&u));

    let server = if let Some(endpoint) = bridge_endpoint {
        build_bridge_server(endpoint)
    } else {
        build_uds_server(daemon_socket_override)
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
    fn default_daemon_socket_uses_home() {
        // HOME must be set in the test environment.
        if let Some(home) = std::env::var_os("HOME") {
            let expected = PathBuf::from(home).join(".ember/run/daemon.sock");
            assert_eq!(default_daemon_socket(), Some(expected));
        }
    }
}
