//! Canonical MCP grant read regression guard.
//!
//! `emberlink-mcp` exposes `grant.list`, not the old agent-protocol
//! `list_grants` / `grant_status` / `use_credential` tools. This test keeps
//! the daemon-backed persona filter covered at the MCP edge without reviving
//! the retired materialization tools.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use ember_daemon::infra::rate_limit::RateLimiter;
use ember_daemon::infra::socket::{SocketListener, new_shared_policy_engine};
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use ember_daemon::trust::policy::{
    ActionSelector, ApprovalRequirement, PolicyConfig, PolicyEngine, PolicyRule, RiskLevel,
};
use emberlink_mcp::{JsonRpcRequest, JsonRpcResponse, McpServer};
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
    let socket_path = tmp.path().join("mcp-grant-list.sock");
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
            let vault = Rc::new(Vault::new([42u8; 32]));
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

fn expect_ok_text(resp: &JsonRpcResponse) -> String {
    assert!(
        resp.error.is_none(),
        "unexpected JSON-RPC error: {:?}",
        resp.error
    );
    let result = resp.result.as_ref().expect("missing result");
    let is_err = result
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
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
    Ok(resp
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_grant_list_filters_by_requested_persona() {
    let tmp = TempDir::new().unwrap();
    let (socket_path, shutdown_tx) = spawn_listener_thread(&tmp);
    tokio::time::sleep(Duration::from_millis(250)).await;

    let socket = socket_path.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<(), String> {
        let p_a = daemon_call(
            &socket,
            "create_persona",
            serde_json::json!({"name": "persona-a"}),
        )?;
        let persona_a = p_a["id"].as_str().unwrap().to_string();

        let p_b = daemon_call(
            &socket,
            "create_persona",
            serde_json::json!({"name": "persona-b"}),
        )?;
        let persona_b = p_b["id"].as_str().unwrap().to_string();

        let g_a = daemon_call(
            &socket,
            "create_grant",
            serde_json::json!({
                "persona_id": persona_a,
                "credential_name": "shared-secret",
                "scope": "read",
                "ttl_secs": 3600,
            }),
        )?;
        let grant_a = g_a["id"].as_str().unwrap().to_string();

        let g_b = daemon_call(
            &socket,
            "create_grant",
            serde_json::json!({
                "persona_id": persona_b,
                "credential_name": "shared-secret",
                "scope": "read",
                "ttl_secs": 3600,
            }),
        )?;
        let grant_b = g_b["id"].as_str().unwrap().to_string();

        let server = McpServer::with_daemon_socket(socket.clone());

        let resp = mcp_call(
            &server,
            1,
            "grant.list",
            serde_json::json!({"persona_id": persona_a}),
        );
        let grants: serde_json::Value =
            serde_json::from_str(&expect_ok_text(&resp)).expect("grant.list text must be JSON");
        let arr = grants
            .as_array()
            .expect("grant.list should return an array");
        let ids: Vec<&str> = arr.iter().filter_map(|g| g["id"].as_str()).collect();
        assert_eq!(ids, vec![grant_a.as_str()]);
        assert!(!ids.contains(&grant_b.as_str()));

        let resp = mcp_call(
            &server,
            2,
            "grant.list",
            serde_json::json!({"persona_id": persona_b}),
        );
        let grants_b: serde_json::Value = serde_json::from_str(&expect_ok_text(&resp)).unwrap();
        let ids_b: Vec<&str> = grants_b
            .as_array()
            .expect("grant.list should return an array")
            .iter()
            .filter_map(|g| g["id"].as_str())
            .collect();
        assert_eq!(ids_b, vec![grant_b.as_str()]);

        Ok(())
    })
    .await
    .unwrap();

    shutdown_tx.send(true).unwrap();
    result.expect("mcp grant.list round-trip failed");
}
