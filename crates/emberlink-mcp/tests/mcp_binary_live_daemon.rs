//! Binary-level MCP proof against a live daemon listener.
//!
//! The library tests already cover MCP routing internals, but the public
//! contract is the `emberlink-mcp` binary speaking JSON-RPC 2.0 over stdio.
//! This test spawns the real binary, drives it over pipes, and proves both:
//!
//! - the credential-touching tool path (`request_grant`, `grant_status`,
//!   `use_credential`) that flows through `AgentRuntime::with_daemon`
//! - the observability tool path (`list_receipts`) that bypasses the runtime
//!   and routes directly through `DaemonTransport`

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::time::Duration;

use ember_daemon::infra::rate_limit::RateLimiter;
use ember_daemon::infra::socket::SocketListener;
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use ember_daemon::trust::policy::{
    ApprovalRequirement, PolicyConfig, PolicyEngine, PolicyRule, RiskLevel,
};
use tempfile::TempDir;
use tokio::sync::watch;

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

fn spawn_listener_thread(tmp: &TempDir) -> (std::path::PathBuf, watch::Sender<bool>) {
    let socket_path = tmp.path().join("mcp-binary.sock");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let path_for_thread = socket_path.clone();

    let id_dir = tempfile::tempdir().expect("tempdir for daemon identity");
    let _ = ember_daemon::infra::receipt::init_identity(id_dir.path());
    std::mem::forget(id_dir);
    ember_daemon::trust::presence::mark_unlocked();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            let store = Rc::new(DaemonStore::open_in_memory().unwrap());
            let vault = Rc::new(Vault::new([7u8; 32]));
            store.set_vault(Rc::clone(&vault));
            let policy = Rc::new(auto_approve_policy());
            let rate_limiter = Rc::new(RefCell::new(RateLimiter::default()));
            let _vault = vault;
            let listener =
                SocketListener::new(path_for_thread, shutdown_rx, store, policy, rate_limiter)
                    .with_test_mode_synthetic_presence_token(true);
            listener.run().await.unwrap();
        });
    });

    (socket_path, shutdown_tx)
}

fn daemon_call(
    socket_path: &std::path::Path,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let stream =
        std::os::unix::net::UnixStream::connect(socket_path).map_err(|e| format!("connect: {e}"))?;
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
    Ok(resp
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

fn mcp_round_trip(
    reader: &mut BufReader<std::process::ChildStdout>,
    writer: &mut std::process::ChildStdin,
    value: serde_json::Value,
) -> serde_json::Value {
    let mut line = serde_json::to_string(&value).unwrap();
    line.push('\n');
    writer.write_all(line.as_bytes()).unwrap();
    writer.flush().unwrap();

    let mut out = String::new();
    reader.read_line(&mut out).unwrap();
    serde_json::from_str(out.trim()).unwrap()
}

fn extract_text_result(resp: &serde_json::Value) -> String {
    assert!(
        resp.get("error").is_none() || resp.get("error").unwrap().is_null(),
        "unexpected JSON-RPC error: {resp}"
    );
    let result = resp.get("result").expect("missing result");
    let is_error = result
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(!is_error, "tool returned isError=true: {result}");
    result["content"][0]["text"].as_str().unwrap().to_string()
}

fn extract_error_text(resp: &serde_json::Value) -> String {
    assert!(
        resp.get("error").is_none() || resp.get("error").unwrap().is_null(),
        "unexpected JSON-RPC error: {resp}"
    );
    let result = resp.get("result").expect("missing result");
    assert_eq!(result["isError"], serde_json::json!(true), "expected tool error");
    result["content"][0]["text"].as_str().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_binary_round_trips_live_daemon_and_no_daemon_modes() {
    let tmp = TempDir::new().unwrap();
    let (socket_path, shutdown_tx) = spawn_listener_thread(&tmp);
    tokio::time::sleep(Duration::from_millis(250)).await;

    let socket_for_setup = socket_path.clone();
    let setup = tokio::task::spawn_blocking(move || -> Result<String, String> {
        let persona = daemon_call(
            &socket_for_setup,
            "create_persona",
            serde_json::json!({"name": "mcp-binary-persona"}),
        )?;
        let persona_id = persona["id"].as_str().unwrap().to_string();

        daemon_call(
            &socket_for_setup,
            "vault_add",
            serde_json::json!({"name": "github-token", "value": "ghp_secret_value"}),
        )?;

        Ok(persona_id)
    })
    .await
    .unwrap();
    let persona_id = setup.unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_emberlink-mcp"))
        .arg("--persona")
        .arg(&persona_id)
        .arg("--label")
        .arg("test-binary")
        .arg("--daemon-socket")
        .arg(&socket_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut child_stdin = child.stdin.take().unwrap();
    let child_stdout = child.stdout.take().unwrap();
    let mut child_stdout = BufReader::new(child_stdout);

    let init = mcp_round_trip(
        &mut child_stdout,
        &mut child_stdin,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0.1"}
            }
        }),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "emberlink-mcp");

    let tools = mcp_round_trip(
        &mut child_stdout,
        &mut child_stdin,
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    );
    let tool_names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert!(tool_names.contains(&"whoami"));
    assert!(tool_names.contains(&"request_grant"));
    assert!(tool_names.contains(&"list_receipts"));

    let whoami = mcp_round_trip(
        &mut child_stdout,
        &mut child_stdin,
        serde_json::json!({
            "jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"whoami","arguments":{}}
        }),
    );
    let whoami_json: serde_json::Value =
        serde_json::from_str(&extract_text_result(&whoami)).unwrap();
    assert_eq!(whoami_json["persona_id"], serde_json::json!(persona_id));

    let request = mcp_round_trip(
        &mut child_stdout,
        &mut child_stdin,
        serde_json::json!({
            "jsonrpc":"2.0","id":4,"method":"tools/call",
            "params":{"name":"request_grant","arguments":{
                "scope":"repo:read",
                "resource_id":"github-token",
                "duration_secs":3600,
                "reason":"binary proof"
            }}
        }),
    );
    let request_json: serde_json::Value =
        serde_json::from_str(&extract_text_result(&request)).unwrap();
    let request_id = request_json["request_id"].as_str().unwrap().to_string();
    assert_eq!(request_json["status"], "approved");

    let status = mcp_round_trip(
        &mut child_stdout,
        &mut child_stdin,
        serde_json::json!({
            "jsonrpc":"2.0","id":5,"method":"tools/call",
            "params":{"name":"grant_status","arguments":{"grant_id":request_id}}
        }),
    );
    let status_json: serde_json::Value =
        serde_json::from_str(&extract_text_result(&status)).unwrap();
    let grant_id = status_json["grant_id"].as_str().unwrap().to_string();
    assert_eq!(status_json["status"], "active");

    let use_credential = mcp_round_trip(
        &mut child_stdout,
        &mut child_stdin,
        serde_json::json!({
            "jsonrpc":"2.0","id":6,"method":"tools/call",
            "params":{"name":"use_credential","arguments":{
                "grant_id":grant_id,
                "credential_id":"github-token"
            }}
        }),
    );
    let credential_json: serde_json::Value =
        serde_json::from_str(&extract_text_result(&use_credential)).unwrap();
    assert_eq!(credential_json["status"], "ok");
    assert_eq!(credential_json["credential"]["value"], "ghp_secret_value");

    let receipts = mcp_round_trip(
        &mut child_stdout,
        &mut child_stdin,
        serde_json::json!({
            "jsonrpc":"2.0","id":7,"method":"tools/call",
            "params":{"name":"list_receipts","arguments":{}}
        }),
    );
    let receipts_json: serde_json::Value =
        serde_json::from_str(&extract_text_result(&receipts)).unwrap();
    assert!(receipts_json.is_array(), "list_receipts should return a JSON array");

    drop(child_stdin);
    let status = child.wait().unwrap();
    assert!(status.success(), "emberlink-mcp exited unsuccessfully: {status}");

    let mut no_daemon_child = Command::new(env!("CARGO_BIN_EXE_emberlink-mcp"))
        .arg("--persona")
        .arg("test-no-daemon")
        .arg("--no-daemon")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut no_daemon_stdin = no_daemon_child.stdin.take().unwrap();
    let no_daemon_stdout = no_daemon_child.stdout.take().unwrap();
    let mut no_daemon_stdout = BufReader::new(no_daemon_stdout);

    let denied = mcp_round_trip(
        &mut no_daemon_stdout,
        &mut no_daemon_stdin,
        serde_json::json!({
            "jsonrpc":"2.0","id":8,"method":"tools/call",
            "params":{"name":"request_grant","arguments":{
                "scope":"repo:read",
                "resource_id":"github-token",
                "duration_secs":3600
            }}
        }),
    );
    let denied_text = extract_error_text(&denied);
    assert!(
        denied_text.contains("daemon unreachable") || denied_text.contains("access denied"),
        "unexpected no-daemon error text: {denied_text}"
    );

    drop(no_daemon_stdin);
    let status = no_daemon_child.wait().unwrap();
    assert!(
        status.success(),
        "emberlink-mcp --no-daemon exited unsuccessfully: {status}"
    );

    shutdown_tx.send(true).unwrap();
}
