//! Binary-level MCP proof against a live daemon listener.
//!
//! The public contract is the `emberlink-mcp` binary speaking JSON-RPC 2.0 over
//! stdio and exposing only canonical daemon control/read tools.

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::time::Duration;

use ember_daemon::infra::rate_limit::RateLimiter;
use ember_daemon::infra::socket::{SocketListener, new_shared_policy_engine};
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use ember_daemon::trust::policy::{
    ActionSelector, ApprovalRequirement, PolicyConfig, PolicyEngine, PolicyRule, RiskLevel,
};
use tempfile::TempDir;
use tokio::sync::watch;

fn auto_approve_policy() -> PolicyEngine {
    PolicyEngine::new(PolicyConfig {
        rules: vec![PolicyRule {
            action: ActionSelector::named("*"),
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
            let policy = new_shared_policy_engine(auto_approve_policy());
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

#[tokio::test(flavor = "multi_thread")]
async fn mcp_binary_exposes_canonical_tools_against_live_daemon() {
    let tmp = TempDir::new().unwrap();
    let (socket_path, shutdown_tx) = spawn_listener_thread(&tmp);
    tokio::time::sleep(Duration::from_millis(250)).await;

    let socket_for_setup = socket_path.clone();
    let setup = tokio::task::spawn_blocking(move || -> Result<(String, String), String> {
        let persona = daemon_call(
            &socket_for_setup,
            "create_persona",
            serde_json::json!({"name": "mcp-binary-persona"}),
        )?;
        let persona_id = persona["id"].as_str().unwrap().to_string();

        let grant = daemon_call(
            &socket_for_setup,
            "create_grant",
            serde_json::json!({
                "persona_id": persona_id,
                "credential_name": "github-token",
                "scope": "repo:read",
                "ttl_secs": 3600,
            }),
        )?;
        let grant_id = grant["id"].as_str().unwrap().to_string();

        Ok((persona_id, grant_id))
    })
    .await
    .unwrap();
    let (persona_id, grant_id) = setup.unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_emberlink-mcp"))
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
    assert_eq!(
        tool_names,
        vec![
            "session.describe",
            "catalog.search_actions",
            "access.request",
            "grant.list",
            "status.get",
            "evidence.query",
            "evidence.get",
        ]
    );

    let grants = mcp_round_trip(
        &mut child_stdout,
        &mut child_stdin,
        serde_json::json!({
            "jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"grant.list","arguments":{"persona_id": persona_id}}
        }),
    );
    let grants_json: serde_json::Value =
        serde_json::from_str(&extract_text_result(&grants)).unwrap();
    let ids: Vec<&str> = grants_json
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|grant| grant["id"].as_str())
        .collect();
    assert_eq!(ids, vec![grant_id.as_str()]);

    let old_tool = mcp_round_trip(
        &mut child_stdout,
        &mut child_stdin,
        serde_json::json!({
            "jsonrpc":"2.0","id":4,"method":"tools/call",
            "params":{"name":"request_grant","arguments":{}}
        }),
    );
    assert_eq!(old_tool["error"]["code"], -32602);

    drop(child_stdin);
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "emberlink-mcp exited unsuccessfully: {status}"
    );

    shutdown_tx.send(true).unwrap();
}
