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

fn spawn_fake_daemon(socket_path: &Path) -> thread::JoinHandle<Vec<String>> {
    let socket_path = socket_path.to_path_buf();
    let (ready_tx, ready_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let _ = fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
        ready_tx.send(()).expect("signal ready");
        let mut methods = Vec::new();
        for _ in 0..6 {
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
                    "quarantined": false,
                    "quarantine_authority": null,
                }),
                "vault_status" => json!({
                    "posture": "interactive-unlocked",
                    "unlocked": true,
                    "idle_secs": 0,
                    "idle_timeout_secs": 600,
                    "live_vault_attached": true,
                    "session_pin_count": 1,
                }),
                "list_personas" => json!([]),
                "list_grants" => json!([]),
                "audit_verify" => json!({
                    "ok": true,
                    "rows_walked": 0,
                    "segments_walked": 0,
                    "sample_mode": "Full",
                    "tail": null,
                }),
                "recovery_action_receipt" => json!({
                    "kind": "recovery.action",
                    "receipt_id": "rct-recovery-diagnose-green",
                    "persisted": true,
                }),
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

#[test]
fn recover_diagnose_green_path_emits_receipt_and_exits_zero() {
    let tmp = TempDir::new().expect("tempdir");
    let (config_path, socket_path) = write_config(&tmp);
    let server = spawn_fake_daemon(&socket_path);

    let out = Command::new(ember_bin())
        .args(["recover", "diagnose"])
        .env("EMBER_CONFIG", &config_path)
        .env("HOME", tmp.path())
        .output()
        .expect("run ember recover diagnose");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{stderr}");
    assert!(stdout.contains("Receipt: recovery.action rct-recovery-diagnose-green"));
    assert!(stdout.contains("No recovery action is needed"));

    let methods = server.join().expect("fake daemon thread");
    assert_eq!(
        methods,
        vec![
            "status",
            "vault_status",
            "list_personas",
            "list_grants",
            "audit_verify",
            "recovery_action_receipt",
        ]
    );
}

#[test]
fn recover_diagnose_refuses_without_recovery_action_receipt() {
    let tmp = TempDir::new().expect("tempdir");
    let (config_path, _socket_path) = write_config(&tmp);

    let out = Command::new(ember_bin())
        .args(["recover", "diagnose"])
        .env("EMBER_CONFIG", &config_path)
        .env("HOME", tmp.path())
        .output()
        .expect("run ember recover diagnose");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "stderr:\n{stderr}");
    assert!(
        stderr.contains("could not emit recovery.action receipt through the daemon broker"),
        "stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("sudo ember daemon install"),
        "stderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("Receipt: recovery.action"),
        "stdout:\n{stdout}"
    );
}
