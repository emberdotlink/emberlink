use std::fs;
use std::io::{BufRead, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;

use serde_json::{Value, json};
use tempfile::TempDir;

fn ember_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ember")
}

fn write_config(tmp: &TempDir) -> (PathBuf, PathBuf) {
    let run_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    fs::create_dir_all(&run_dir).expect("create run dir");
    fs::create_dir_all(&data_dir).expect("create data dir");
    let config_path = tmp.path().join("config.toml");
    let content = format!(
        "[daemon]\nsocket_dir = \"{}\"\ndata_dir = \"{}\"\npid_file = \"{}\"\nlog_level = \"info\"\n",
        run_dir.display(),
        data_dir.display(),
        run_dir.join("daemon.pid").display()
    );
    fs::write(&config_path, content).expect("write config");
    (config_path, run_dir.join("daemon.sock"))
}

fn spawn_fake_daemon(socket_path: &Path, allow_repair: bool) -> thread::JoinHandle<Vec<String>> {
    let socket_path = socket_path.to_path_buf();
    let (ready_tx, ready_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let _ = fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
        ready_tx.send(()).expect("signal ready");
        let mut methods = Vec::new();
        let expected_calls = if allow_repair { 4 } else { 3 };
        for _ in 0..expected_calls {
            let (mut stream, _) = listener.accept().expect("accept fake daemon stream");
            let mut line = String::new();
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake stream"));
            reader.read_line(&mut line).expect("read fake request");
            let request: Value = serde_json::from_str(line.trim()).expect("parse request");
            let method = request["method"].as_str().expect("method").to_string();
            methods.push(method.clone());
            let result = match method.as_str() {
                "status" => json!({
                    "personas": [],
                    "grants": [],
                    "approvals": [],
                    "recent_activity": [],
                    "standing_grants": 0,
                    "audit_events_total": 0,
                    "quarantined": true,
                    "quarantine_authority": "startup_audit_chain_break",
                }),
                "audit_verify" => json!({
                    "ok": false,
                    "break": {
                        "kind": "forward_link_mismatch",
                        "at_row_id": 42,
                        "predecessor_row_id": 41,
                        "expected_prev_hash": "aa",
                        "stored_prev_hash": "bb",
                        "rows_walked_before": 40
                    },
                    "tail": null,
                }),
                "recovery_action_receipt" => {
                    assert_eq!(request["params"]["verb"], json!("audit-chain"));
                    assert_eq!(
                        request["params"]["requested_action"],
                        json!("truncate-after-row")
                    );
                    assert!(
                        request["params"]["operator_confirmation_token_hash"]
                            .as_str()
                            .is_some_and(|hash| hash.starts_with("blake3:"))
                    );
                    json!({
                        "kind": "recovery.action",
                        "receipt_id": "rct-recover-audit-chain-plan",
                        "persisted": true,
                    })
                }
                "audit_repair_chain" if allow_repair => {
                    assert_eq!(request["params"]["repair_kind"], json!("truncate"));
                    assert_eq!(request["params"]["from_row_id"], json!(41));
                    assert_eq!(request["params"]["operator_pubkey"], json!("ed25519:aa"));
                    assert_eq!(request["params"]["operator_signature_hex"], json!("bb"));
                    assert_eq!(
                        request["params"]["current_chain_tip_hash"],
                        json!("tip-hash")
                    );
                    assert_eq!(
                        request["params"]["daemon_identity_root_fingerprint"],
                        json!("daemon-root")
                    );
                    json!({
                        "ok": true,
                        "repair_id": "repair-1",
                        "tombstone_row_id": 43,
                        "truncated_row_count": 2,
                        "new_chain_tip_hash": "new-tip",
                    })
                }
                other => panic!("unexpected fake daemon method: {other}"),
            };
            let response = json!({
                "id": request["id"].clone(),
                "result": result,
            });
            let mut encoded = serde_json::to_string(&response).expect("encode response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake response");
        }
        methods
    });
    ready_rx.recv().expect("wait for fake daemon ready");
    handle
}

fn confirmation_token(stdout: &str) -> String {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("Confirmation token: "))
        .expect("confirmation token")
        .to_string()
}

#[test]
fn recover_audit_chain_dry_run_prints_structured_plan_and_receipt() {
    let tmp = TempDir::new().expect("tempdir");
    let (config_path, socket_path) = write_config(&tmp);
    let server = spawn_fake_daemon(&socket_path, false);

    let out = Command::new(ember_bin())
        .args(["recover", "audit-chain", "--dry-run"])
        .env("EMBER_CONFIG", &config_path)
        .env("HOME", tmp.path())
        .output()
        .expect("run ember recover audit-chain --dry-run");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr:\n{stderr}");
    assert!(stdout.contains("Receipt: recovery.action rct-recover-audit-chain-plan"));
    assert!(stdout.contains("State: quarantined break"));
    assert!(stdout.contains("ADR 174 tier: operator-co-signed"));
    assert!(stdout.contains("Confirmation token: audit-chain-"));
    assert!(stdout.contains("\"from_row_id\": 41"));

    let methods = server.join().expect("fake daemon thread");
    assert_eq!(
        methods,
        vec!["status", "audit_verify", "recovery_action_receipt"]
    );
}

#[test]
fn recover_audit_chain_execute_routes_retyped_plan_to_repair_rpc() {
    let dry_run_tmp = TempDir::new().expect("tempdir");
    let (dry_run_config, dry_run_socket) = write_config(&dry_run_tmp);
    let dry_run_server = spawn_fake_daemon(&dry_run_socket, false);

    let dry_run = Command::new(ember_bin())
        .args([
            "recover",
            "audit-chain",
            "--dry-run",
            "--current-chain-tip-hash",
            "tip-hash",
        ])
        .env("EMBER_CONFIG", &dry_run_config)
        .env("HOME", dry_run_tmp.path())
        .output()
        .expect("run ember recover audit-chain --dry-run");

    let dry_run_stdout = String::from_utf8_lossy(&dry_run.stdout);
    let dry_run_stderr = String::from_utf8_lossy(&dry_run.stderr);
    assert_eq!(dry_run.status.code(), Some(2), "stderr:\n{dry_run_stderr}");
    let token = confirmation_token(&dry_run_stdout);
    dry_run_server.join().expect("dry-run fake daemon thread");

    let execute_tmp = TempDir::new().expect("tempdir");
    let (execute_config, execute_socket) = write_config(&execute_tmp);
    let execute_server = spawn_fake_daemon(&execute_socket, true);

    let out = Command::new(ember_bin())
        .args([
            "recover",
            "audit-chain",
            "--confirm",
            &token,
            "--from-row-id",
            "41",
            "--operator-pubkey",
            "ed25519:aa",
            "--operator-signature-hex",
            "bb",
            "--current-chain-tip-hash",
            "tip-hash",
            "--daemon-identity-root-fingerprint",
            "daemon-root",
        ])
        .env("EMBER_CONFIG", &execute_config)
        .env("HOME", execute_tmp.path())
        .output()
        .expect("run ember recover audit-chain execute");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{stderr}");
    assert!(stdout.contains("Receipt: recovery.action rct-recover-audit-chain-plan"));
    assert!(stdout.contains("Repair: ok"));
    assert!(stdout.contains("repair_id: repair-1"));

    let methods = execute_server.join().expect("execute fake daemon thread");
    assert_eq!(
        methods,
        vec![
            "status",
            "audit_verify",
            "recovery_action_receipt",
            "audit_repair_chain"
        ]
    );
}

#[test]
fn recover_audit_chain_refuses_when_daemon_unreachable() {
    let tmp = TempDir::new().expect("tempdir");
    let (config_path, _socket_path) = write_config(&tmp);

    let out = Command::new(ember_bin())
        .args(["recover", "audit-chain", "--dry-run"])
        .env("EMBER_CONFIG", &config_path)
        .env("HOME", tmp.path())
        .output()
        .expect("run ember recover audit-chain --dry-run");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "stderr:\n{stderr}");
    assert!(
        stderr.contains("step: broker-unavailable"),
        "stderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("Receipt: recovery.action"),
        "stdout:\n{stdout}"
    );
}
