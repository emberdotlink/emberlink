use std::io::{BufRead, Write};
use std::os::unix::net::UnixListener;
use std::process::Command;

use serde_json::json;

fn spawn_broker_exec_daemon_once() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::thread::JoinHandle<serde_json::Value>,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("daemon.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind daemon socket");
    let join = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept daemon client");
        let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone daemon client"));
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .expect("read daemon json-rpc request");
        let request: serde_json::Value = serde_json::from_str(&line).expect("parse daemon request");
        assert_eq!(request["method"], "broker_exec");

        let response = json!({
            "jsonrpc": "2.0",
            "id": request.get("id").cloned().unwrap_or_else(|| json!(1)),
            "result": {
                "execution_contract": {
                    "schema_version": "execution_contract.v1",
                    "contract_id": "contract-shim-stdout-test",
                    "action_ref": {
                        "plugin_address": "registry.ember.systems/ember-systems/ember-gh",
                        "action_key": "pr_list",
                        "action_version": "v1"
                    },
                    "workspace_ref": "managed_worktree:shim-stdout-test",
                    "caller_ref": "session:shim-stdout-test",
                    "authority_ref": "grant:shim-stdout-test"
                },
                "exit_code": 0,
                "stdout_tail": "[{\"number\":1}]\n",
                "stderr_tail": ""
            }
        });
        let mut writer = stream;
        writeln!(
            writer,
            "{}",
            serde_json::to_string(&response).expect("serialize daemon response")
        )
        .expect("write daemon json-rpc response");
        request
    });
    (dir, socket_path, join)
}

#[test]
fn ember_gh_rust_log_error_preserves_json_stdout() {
    let (_dir, socket_path, join) = spawn_broker_exec_daemon_once();

    let output = Command::new(env!("CARGO_BIN_EXE_ember-gh"))
        .args([
            "pr",
            "list",
            "--repo",
            "emberdotlink/emberlink-dev",
            "--limit",
            "1",
            "--json",
            "number",
        ])
        .env("EMBER_SESSION_ID", "session-shim-stdout-test")
        .env("EMBER_ATTACHMENT_ID", "att-shim-stdout-test")
        .env(
            "EMBER_ATTACHMENT_ENDPOINT_TOKEN",
            "endpoint-shim-stdout-test",
        )
        .env("EMBER_SOCKET_PATH", &socket_path)
        .env("RUST_LOG", "error")
        .output()
        .expect("run ember-gh");

    let request = join.join().expect("mock daemon thread");
    assert_eq!(
        request["params"]["execution_contract"]["action_ref"]["action_key"],
        "pr_list"
    );
    assert!(
        output.status.success(),
        "ember-gh exited {:?}; stdout={}; stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(
        !stdout.contains("ember-construct:"),
        "construct diagnostics must not contaminate stdout: {stdout:?}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be bare gh JSON, got {stdout:?}: {e}"));
    assert_eq!(parsed, json!([{ "number": 1 }]));
}
