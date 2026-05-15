//! implementation-note-318 regression guard — MCP read path must see grants owned by
//! the caller's persona (and only those grants).
//!
//! The narrative being guarded is "agent asks -> human approves -> agent
//! uses it". Earlier rehearsals showed the MCP server returning an empty
//! grant list after a successful mint, which broke the loop at step 3.
//! Root cause was a stale binary in the rehearsal (the wire path in HEAD
//! already forwards the caller's `persona_id` through to the daemon
//! filter). This test locks that behavior in so a future regression is
//! caught in CI rather than in a live demo.
//!
//! Structure:
//! - Start a real daemon socket listener with a permissive auto-approve
//!   policy (so `create_grant` mints without approval).
//! - Seed two personas, a vault secret, and one operator grant per
//!   persona via the daemon socket.
//! - Build an `McpServer` configured for persona A and drive
//!   `list_grants` / `grant_status` / `use_credential` through JSON-RPC
//!   `process_line`.
//! - Assert persona A sees exactly its own grant (not persona B's).
//! - Assert `grant_status` and `use_credential` succeed for persona A's
//!   grant and fail for persona B's grant.
//!
//! Composite-grant coverage: composite grants (sandbox run) write the
//! same `grants` row with `persona_id`, and the daemon-side
//! `list_active_grants().filter(|g| g.persona_id == persona_id)` in
//! `ember-daemon/src/handler.rs` is shared across grant kinds. Persona
//! filtering on composite grants is unit-tested in
//! `ember-daemon/src/approval.rs` (see `approve_composite_mints_three_statement_grant_and_records_grant_id`)
//! — this test exercises the MCP-level round trip specifically, which
//! is where the rehearsal regression surfaced.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use ember_daemon::trust::policy::{
    ApprovalRequirement, PolicyConfig, PolicyEngine, PolicyRule, RiskLevel,
};
use ember_daemon::infra::rate_limit::RateLimiter;
use ember_daemon::infra::socket::SocketListener;
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use emberlink_agent::runtime::{AgentConfig, AgentRuntime, DaemonClient, DaemonClientError};
use emberlink_mcp::daemon_transport::DaemonTransport;
use emberlink_mcp::{JsonRpcRequest, JsonRpcResponse, McpServer};
use tempfile::TempDir;
use tokio::sync::watch;

/// Permissive policy that auto-approves every `credential.access.*`
/// action so grants mint without the approval loop — keeps the test
/// focused on the persona-filter read path, not on the approval flow
/// (which has its own unit tests).
fn auto_approve_policy() -> PolicyEngine {
    PolicyEngine::new(PolicyConfig {
        rules: vec![PolicyRule {
            action: "credential.access.*".to_string(),
            risk: RiskLevel::Low,
            requirement: ApprovalRequirement::Auto,
            tier: None,
        }],
        default_requirement: ApprovalRequirement::Auto,
        default_risk: RiskLevel::Low,
    })
}

/// Spawn the daemon listener on its own single-threaded runtime + OS
/// thread. Mirrors `ember-daemon/tests/integration.rs::spawn_listener_thread`
/// so we get the same isolation guarantees.
fn spawn_listener_thread(tmp: &TempDir) -> (std::path::PathBuf, watch::Sender<bool>) {
    let socket_path = tmp.path().join("mcp-regress.sock");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let path_for_thread = socket_path.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            let store = Rc::new(DaemonStore::open_in_memory().unwrap());
            let vault = Rc::new(Vault::new([42u8; 32]));
            // V0 schema: persona-secret writes require an attached vault.
            store.set_vault(Rc::clone(&vault));
            let policy = Rc::new(auto_approve_policy());
            let rate_limiter = Rc::new(RefCell::new(RateLimiter::default()));
            let listener = SocketListener::new(
                path_for_thread,
                shutdown_rx,
                store,
                vault,
                policy,
                rate_limiter,
            );
            listener.run().await.unwrap();
        });
    });

    (socket_path, shutdown_tx)
}

/// Thin `DaemonClient` adapter that mirrors the one in
/// `emberlink-mcp/src/main.rs`. Duplicated here rather than exported
/// because the production adapter is a private `main.rs` struct; the
/// test needs the same behavior (bypass `DaemonTransport`'s tool->method
/// remap and call socket methods directly by name).
struct TestDaemonClient(DaemonTransport);

impl TestDaemonClient {
    fn send_raw(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonClientError> {
        use std::io::{BufRead, BufReader, Write};

        let stream = std::os::unix::net::UnixStream::connect(self.0.socket_path())
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
        Ok(response
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }
}

impl DaemonClient for TestDaemonClient {
    fn request_access(
        &mut self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonClientError> {
        self.0.call_tool("request_access", params).map_err(|e| match e {
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

/// Build a fresh MCP server that routes through the shared daemon
/// socket, configured for the given persona id. The server uses a
/// disposable in-process EventStore — grants are stored in the daemon,
/// never in this local store.
fn mcp_server_for_persona(
    socket_path: &std::path::Path,
    persona_id: &str,
) -> McpServer {
    let store = Rc::new(core_state::EventStore::default());
    let config = AgentConfig {
        persona_id: persona_id.to_string(),
        label: Some(format!("test-mcp-{persona_id}")),
    };
    let transport = DaemonTransport::new(socket_path);
    let client: Box<dyn DaemonClient> = Box::new(TestDaemonClient(transport));
    let runtime = AgentRuntime::with_daemon(config, store, client);
    McpServer::with_daemon_socket(runtime, socket_path.to_path_buf())
}

/// Call a single JSON-RPC tool over `McpServer::process_line` and
/// return the parsed response. Panics on parse failure — keeps the
/// test's assertion-path readable.
fn mcp_call(server: &McpServer, id: u32, tool: &str, args: serde_json::Value) -> JsonRpcResponse {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(serde_json::json!(id)),
        method: "tools/call".to_string(),
        params: Some(serde_json::json!({
            "name": tool,
            "arguments": args,
        })),
    };
    let raw = serde_json::to_string(&req).unwrap();
    let out = server
        .process_line(&raw)
        .expect("process_line returned None for a request");
    serde_json::from_str(&out).unwrap()
}

/// Extract the textual result of a successful MCP tool call. MCP tools
/// wrap their payload as `{content: [{type: "text", text: "<json>"}]}`
/// and encode errors via `isError: true`. Panics if the call is marked
/// as an error.
fn expect_ok_text(resp: &JsonRpcResponse) -> String {
    assert!(resp.error.is_none(), "unexpected JSON-RPC error: {:?}", resp.error);
    let result = resp.result.as_ref().expect("missing result");
    let is_err = result.get("isError").and_then(|v| v.as_bool()).unwrap_or(false);
    assert!(
        !is_err,
        "tool returned isError=true: {}",
        result["content"][0]["text"].as_str().unwrap_or("<no text>")
    );
    result["content"][0]["text"]
        .as_str()
        .expect("content[0].text missing")
        .to_string()
}

/// Assert an MCP tool call came back as `isError=true`. Returns the
/// error text for further substring assertions.
fn expect_err_text(resp: &JsonRpcResponse) -> String {
    assert!(resp.error.is_none(), "unexpected JSON-RPC error: {:?}", resp.error);
    let result = resp.result.as_ref().expect("missing result");
    let is_err = result.get("isError").and_then(|v| v.as_bool()).unwrap_or(false);
    assert!(is_err, "expected isError=true, got {}", result);
    result["content"][0]["text"]
        .as_str()
        .expect("content[0].text missing")
        .to_string()
}

/// Direct daemon-socket helper for test setup (create personas, add
/// secrets, mint grants). Uses a fresh connection per call — simple
/// and parallel-safe.
fn daemon_call(
    socket_path: &std::path::Path,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    use std::io::{BufRead, BufReader, Write};
    let stream = std::os::unix::net::UnixStream::connect(socket_path)
        .map_err(|e| format!("connect: {e}"))?;
    let mut writer = stream.try_clone().map_err(|e| format!("clone: {e}"))?;
    let mut reader = BufReader::new(stream);
    let req = serde_json::json!({"id": "1", "method": method, "params": params});
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut resp_line = String::new();
    reader
        .read_line(&mut resp_line)
        .map_err(|e| format!("read: {e}"))?;
    let resp: serde_json::Value =
        serde_json::from_str(resp_line.trim()).map_err(|e| format!("parse: {e}"))?;
    if let Some(err) = resp.get("error").filter(|e| !e.is_null()) {
        return Err(format!("{err}"));
    }
    Ok(resp.get("result").cloned().unwrap_or(serde_json::Value::Null))
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_persona_filter_round_trip_operator_grant() {
    let tmp = TempDir::new().unwrap();
    let (socket_path, shutdown_tx) = spawn_listener_thread(&tmp);

    // Give the listener time to bind the socket. A polling loop is more
    // reliable than a fixed sleep on slow CI, but 250ms is plenty for a
    // local `UnixListener::bind` on every platform we target.
    tokio::time::sleep(Duration::from_millis(250)).await;

    let socket_a = socket_path.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<(), String> {
        // --- Setup: two personas, one shared vault secret, two grants -----
        let p_a = daemon_call(
            &socket_a,
            "create_persona",
            serde_json::json!({"name": "persona-a"}),
        )?;
        let persona_a = p_a["id"].as_str().unwrap().to_string();

        let p_b = daemon_call(
            &socket_a,
            "create_persona",
            serde_json::json!({"name": "persona-b"}),
        )?;
        let persona_b = p_b["id"].as_str().unwrap().to_string();

        daemon_call(
            &socket_a,
            "vault_add",
            serde_json::json!({"name": "shared-secret", "value": "s3cret-value"}),
        )?;

        let g_a = daemon_call(
            &socket_a,
            "create_grant",
            serde_json::json!({
                "persona_id": persona_a,
                "credential_name": "shared-secret",
                "scope": "read",
                "ttl_secs": 3600,
            }),
        )?;
        let grant_a = g_a["id"].as_str().unwrap().to_string();
        assert!(grant_a.starts_with("grant-"), "grant id shape: {grant_a}");

        let g_b = daemon_call(
            &socket_a,
            "create_grant",
            serde_json::json!({
                "persona_id": persona_b,
                "credential_name": "shared-secret",
                "scope": "read",
                "ttl_secs": 3600,
            }),
        )?;
        let grant_b = g_b["id"].as_str().unwrap().to_string();
        assert_ne!(grant_a, grant_b);

        // --- MCP server for persona A only ---------------------------------
        let server_a = mcp_server_for_persona(&socket_a, &persona_a);

        // list_grants must return grant_a and NOT grant_b.
        let resp = mcp_call(&server_a, 1, "list_grants", serde_json::json!({}));
        let text = expect_ok_text(&resp);
        let grants: serde_json::Value =
            serde_json::from_str(&text).expect("list_grants text must be JSON");
        let arr = grants.as_array().expect("list_grants is an array");
        let ids: Vec<&str> = arr.iter().filter_map(|g| g["grant_id"].as_str()).collect();
        assert!(
            ids.contains(&grant_a.as_str()),
            "persona A must see its own grant; got {ids:?}"
        );
        assert!(
            !ids.contains(&grant_b.as_str()),
            "persona A must NOT see persona B's grant {grant_b}; got {ids:?}"
        );
        assert_eq!(arr.len(), 1, "persona A owns exactly one grant; got {arr:?}");

        // grant_status for persona A's own grant -> active.
        let resp = mcp_call(
            &server_a,
            2,
            "grant_status",
            serde_json::json!({"grant_id": grant_a}),
        );
        let text = expect_ok_text(&resp);
        let info: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(info["grant_id"], serde_json::json!(grant_a));
        assert_eq!(info["status"], "active");

        // grant_status for persona B's grant MUST fail for persona A
        // (pinned persona_id rejects cross-persona probe).
        let resp = mcp_call(
            &server_a,
            3,
            "grant_status",
            serde_json::json!({"grant_id": grant_b}),
        );
        let err = expect_err_text(&resp);
        assert!(
            !err.is_empty(),
            "expected non-empty error text for cross-persona grant_status"
        );

        // use_credential for persona A's grant -> succeeds, returns value.
        let resp = mcp_call(
            &server_a,
            4,
            "use_credential",
            serde_json::json!({
                "grant_id": grant_a,
                "credential_id": "shared-secret",
            }),
        );
        let text = expect_ok_text(&resp);
        let payload: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["credential"]["value"], "s3cret-value");
        assert_eq!(payload["credential"]["grant_id"], serde_json::json!(grant_a));

        // use_credential for persona B's grant MUST fail for persona A.
        let resp = mcp_call(
            &server_a,
            5,
            "use_credential",
            serde_json::json!({
                "grant_id": grant_b,
                "credential_id": "shared-secret",
            }),
        );
        let err = expect_err_text(&resp);
        assert!(!err.is_empty(), "cross-persona use_credential must fail");

        // --- Symmetry: persona B sees only its own grant -------------------
        let server_b = mcp_server_for_persona(&socket_a, &persona_b);
        let resp = mcp_call(&server_b, 6, "list_grants", serde_json::json!({}));
        let text = expect_ok_text(&resp);
        let grants_b: serde_json::Value = serde_json::from_str(&text).unwrap();
        let arr_b = grants_b.as_array().unwrap();
        let ids_b: Vec<&str> = arr_b.iter().filter_map(|g| g["grant_id"].as_str()).collect();
        assert_eq!(
            ids_b,
            vec![grant_b.as_str()],
            "persona B must see exactly its own grant"
        );

        Ok(())
    })
    .await
    .unwrap();

    shutdown_tx.send(true).unwrap();
    result.expect("mcp round-trip test body failed");
}
