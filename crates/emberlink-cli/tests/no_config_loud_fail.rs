//! Integration test for META-T3-USER-SOCKET-LEAK-GUARD-C.
//!
//! Pins the load_config loud-fail contract: when no `--config`,
//! `EMBER_CONFIG`, or `EMBER_DEMO_DIR` is set, AND `~/.ember/config.toml`
//! does not exist, the CLI must exit 1 with a stderr message pointing at
//! the invoking `ember init` command. The May-12 25-hour leaked-daemon incident was rooted in
//! the prior silent `DaemonConfig::default()` fallback inheriting
//! user-home paths in test contexts.

use core_crypto::Signer as _;
use std::io::{BufRead as _, Write as _};
use std::os::unix::net::UnixListener;
use std::process::Command;

fn ember_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ember")
}

fn spawn_fake_init_daemon(socket_path: std::path::PathBuf) -> std::thread::JoinHandle<()> {
    std::fs::create_dir_all(socket_path.parent().expect("socket parent"))
        .expect("create socket dir");
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind fake init daemon");

    std::thread::spawn(move || {
        let signer = core_crypto::FixtureSigner::new("no-config-init-daemon");
        let public_key = signer.public_key().0.clone();
        let persona_id = "persona-no-config";

        listener
            .set_nonblocking(true)
            .expect("set fake init daemon nonblocking");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut saw_create_persona = false;
        let mut saw_build_first_grant_receipt = false;

        while std::time::Instant::now() < deadline {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .expect("restore blocking on fake init daemon stream");
                    stream
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if saw_create_persona && saw_build_first_grant_receipt {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                    continue;
                }
                Err(err) => panic!("fake init daemon accept error: {err}"),
            };
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake init daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake init daemon request");

            let response = match request["method"].as_str().unwrap() {
                "create_persona" => {
                    saw_create_persona = true;
                    assert_eq!(request["params"]["name"], serde_json::json!("root"));
                    serde_json::json!({
                        "id": request["id"],
                        "result": {
                            "id": persona_id,
                            "name": "root",
                            "public_key": public_key,
                        },
                    })
                }
                "build_init_first_grant_receipt" => {
                    saw_build_first_grant_receipt = true;
                    assert_eq!(
                        request["params"]["persona_id"],
                        serde_json::json!(persona_id)
                    );
                    let file =
                        ember_daemon::infra::init_first_grant::build_first_grant_receipt_file(
                            persona_id, &signer,
                        )
                        .expect("build first-grant receipt");
                    serde_json::json!({
                        "id": request["id"],
                        "result": serde_json::to_value(file).expect("serialize receipt file"),
                    })
                }
                other => panic!("unexpected init daemon method: {other}"),
            };

            let mut encoded = serde_json::to_string(&response).expect("encode fake response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake init daemon response");
        }

        assert!(
            saw_create_persona,
            "fake init daemon never received create_persona"
        );
        assert!(
            saw_build_first_grant_receipt,
            "fake init daemon never received build_init_first_grant_receipt"
        );
    })
}

#[test]
fn cli_exits_loudly_when_no_config_resolves() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let default_config_exists =
        ember_daemon::infra::config::DaemonConfig::default_config_path().exists();
    if default_config_exists {
        eprintln!("note: system default config exists; no-config loud-fail branch not reachable");
        return;
    }

    // Drive the binary against a clean HOME so `~/.ember/config.toml`
    // resolves to a non-existent path inside the tempdir. Clear all
    // EMBER_* env vars so no autodiscovery path applies.
    let out = Command::new(ember_bin())
        .args(["audit", "show"])
        .env_clear()
        .env("HOME", tmp.path())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .output()
        .expect("spawn ember");

    let stderr = String::from_utf8_lossy(&out.stderr);
    let exit_code = out.status.code().unwrap_or(-1);

    assert_eq!(
        exit_code, 1,
        "expected exit 1, got {exit_code}; stderr: {stderr}"
    );
    assert!(
        stderr.contains("no ember config found"),
        "expected stderr to contain `no ember config found`; got: {stderr}"
    );
    let expected_init = format!("{} init", ember_bin());
    assert!(
        stderr.contains(&expected_init),
        "expected stderr to mention `{expected_init}`; got: {stderr}"
    );
}

#[test]
fn init_bootstraps_default_config_on_a_fresh_home() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_path = tmp.path().join(".ember/config.toml");
    let server = spawn_fake_init_daemon(tmp.path().join(".ember/run/daemon.sock"));

    let out = Command::new(ember_bin())
        .args(["--no-input", "init"])
        .env_clear()
        .env("HOME", tmp.path())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("EMBER_CONFIG", &config_path)
        .env(
            "EMBER_VAULT_PASSPHRASE",
            "test-no-config-bootstrap-passphrase",
        )
        .env("EMBER_KEYRING_SERVICE", "ember-test-no-config-bootstrap")
        .env("EMBER_KEYRING_ACCOUNT", "test-no-config-bootstrap")
        .env("EMBER_SKIP_DAEMON_INSTALL_CHECK", "1")
        .output()
        .expect("spawn ember init");
    server.join().expect("fake init daemon thread");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let exit_code = out.status.code().unwrap_or(-1);

    assert_eq!(
        exit_code, 0,
        "expected init to succeed on a fresh home; stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        config_path.exists(),
        "expected init to write ~/.ember/config.toml; stdout: {stdout}\nstderr: {stderr}"
    );
}
