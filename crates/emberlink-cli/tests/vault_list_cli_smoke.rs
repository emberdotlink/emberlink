use std::fs;
use std::io::{BufRead, Write as _};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn ember_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ember")
}

fn write_test_config(tmp: &TempDir) -> PathBuf {
    let socket_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    let pid_file = socket_dir.join("emberd.pid");
    let policy_file = tmp.path().join("policy.toml");

    fs::create_dir_all(&socket_dir).expect("create socket_dir");
    fs::create_dir_all(&data_dir).expect("create data_dir");

    let config_path = tmp.path().join("config.toml");
    let content = format!(
        "[daemon]\ndata_dir = \"{}\"\nsocket_dir = \"{}\"\npid_file = \"{}\"\npolicy_file = \"{}\"\nlog_level = \"info\"\n",
        data_dir.display(),
        socket_dir.display(),
        pid_file.display(),
        policy_file.display(),
    );
    fs::write(&config_path, content.as_bytes()).expect("write config.toml");
    config_path
}

fn wait_for_socket(socket_path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !socket_path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        socket_path.exists(),
        "socket {} never appeared",
        socket_path.display()
    );
}

#[test]
fn vault_list_exits_cleanly_after_daemon_response() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = write_test_config(&tmp);
    let socket_path = tmp.path().join("run").join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let (mut stream, _) = listener.accept().expect("accept fake daemon stream");
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("vault_list"));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": [
                    {"id": 1, "name": "anthropic/claude-eval-key", "metadata": null},
                    {"id": 2, "name": "github-pat", "metadata": null}
                ],
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    wait_for_socket(&socket_path);

    let home = tmp.path().join("home");
    fs::create_dir_all(&home).expect("create temp HOME");

    let out = Command::new(ember_bin())
        .args(["vault", "list"])
        .env("HOME", &home)
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("EMBER_CONFIG", &config_path)
        .output()
        .expect("spawn ember vault list");

    server.join().expect("fake daemon thread");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let exit_code = out.status.code().unwrap_or(-1);

    assert_eq!(exit_code, 0, "expected exit 0, stderr: {stderr}");
    assert!(
        stdout.contains("anthropic/claude-eval-key"),
        "stdout must include returned credential names: {stdout}"
    );
    assert!(
        stdout.contains("github-pat"),
        "stdout must include every returned credential name: {stdout}"
    );
    assert!(
        !stderr.contains("unreachable code"),
        "vault list must not fall through into the unreachable vault-open branch: {stderr}"
    );
}
