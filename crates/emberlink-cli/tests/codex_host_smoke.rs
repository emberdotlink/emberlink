use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const MOCK_SESSION_ID: &str = "sess_codex_host_cli_smoke_001";
const MOCK_GRANT_ID: &str = "grt_codex_host_cli_smoke_001";
const MOCK_ATTACHMENT_ID: &str = "att_codex_host_cli_smoke_001";
const MOCK_ATTACHMENT_ENDPOINT_TOKEN: &str = "ep_codex_host_cli_smoke_001";
const MOCK_PROXY_URL: &str = "http://127.0.0.1:19494";
const MOCK_CODEX_RESPONSES_PROXY_URL: &str = "http://127.0.0.1:19495/v1";
const MOCK_PERSONA_ID: &str = "persona_codex_host_cli_smoke_001";
const MOCK_PRESENCE_TOKEN_JSON: &str = r#"{"uid":501,"scope":"class:session-runtime","expiry":{"secs_since_epoch":1779507461,"nanos_since_epoch":807776000},"signature":[1,2,3]}"#;

static HOST_CODEX_SMOKE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn ember_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ember")
}

fn short_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("ember-cli-")
        .tempdir_in("/tmp")
        .or_else(|_| tempfile::TempDir::new())
        .expect("tempdir")
}

fn mock_presence_token_value() -> serde_json::Value {
    serde_json::from_str(MOCK_PRESENCE_TOKEN_JSON).expect("mock presence token json")
}

fn spawn_mock_daemon(socket_path: PathBuf) -> Arc<AtomicBool> {
    let close_called = Arc::new(AtomicBool::new(false));
    let close_flag = Arc::clone(&close_called);

    std::thread::spawn(move || {
        let listener = UnixListener::bind(&socket_path).expect("bind mock socket");
        listener
            .set_nonblocking(true)
            .expect("set_nonblocking on mock listener");

        'accept_loop: for _ in 0..4 {
            let per_accept_deadline =
                std::time::Instant::now() + std::time::Duration::from_secs(10);
            let stream = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= per_accept_deadline {
                            break 'accept_loop;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                    Err(_) => break 'accept_loop,
                }
            };
            stream
                .set_nonblocking(false)
                .expect("restore blocking on accepted stream");
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;

            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                continue;
            }
            let req: serde_json::Value = match serde_json::from_str(line.trim()) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let method = req["method"].as_str().unwrap_or("");
            let resp = match method {
                "register_session" => serde_json::json!({
                    "id": req["id"],
                    "result": {
                        "session_id": MOCK_SESSION_ID,
                        "grant_id": MOCK_GRANT_ID,
                        "attachment_id": MOCK_ATTACHMENT_ID,
                        "attachment_endpoint_token": MOCK_ATTACHMENT_ENDPOINT_TOKEN,
                        "proxy_url": MOCK_PROXY_URL,
                        "codex_responses_proxy_url": MOCK_CODEX_RESPONSES_PROXY_URL,
                        "persona_id": MOCK_PERSONA_ID,
                        "presence_token": mock_presence_token_value(),
                    }
                }),
                "close_session" => {
                    assert_eq!(
                        req["params"]["session_id"].as_str().unwrap_or(""),
                        MOCK_SESSION_ID,
                        "close_session must pass back the same session_id"
                    );
                    close_flag.store(true, Ordering::SeqCst);
                    serde_json::json!({
                        "id": req["id"],
                        "result": { "closed": true }
                    })
                }
                other => panic!("unexpected mock daemon method: {other}"),
            };

            let mut resp_str = serde_json::to_string(&resp).unwrap();
            resp_str.push('\n');
            writer
                .write_all(resp_str.as_bytes())
                .expect("write mock response");

            if close_flag.load(Ordering::SeqCst) {
                break;
            }
        }
    });

    close_called
}

fn wait_for_socket(socket_path: &Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !socket_path.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        socket_path.exists(),
        "mock daemon socket never appeared at {}",
        socket_path.display()
    );
}

fn write_executable(path: &Path, body: &str) {
    std::fs::write(path, body).expect("write executable");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod executable");
}

fn write_default_home_config(home_dir: &Path) {
    let ember_dir = home_dir.join(".ember");
    let config_path = ember_dir.join("config.toml");
    let data_dir = ember_dir.join("data");
    let socket_dir = ember_dir.join("run");
    let pid_file = socket_dir.join("emberd.pid");
    let policy_file = ember_dir.join("policy.toml");

    std::fs::create_dir_all(&ember_dir).expect("create ~/.ember");
    let cfg = format!(
        "[daemon]\ndata_dir = \"{}\"\nsocket_dir = \"{}\"\npid_file = \"{}\"\npolicy_file = \"{}\"\nlog_level = \"info\"\n",
        data_dir.display(),
        socket_dir.display(),
        pid_file.display(),
        policy_file.display(),
    );
    std::fs::write(&config_path, cfg.as_bytes()).expect("write ~/.ember/config.toml");
}

fn make_fake_ember_binary(tmp_dir: &Path, tool: &str) {
    let bin_name = format!("ember-{tool}");
    let bin_path = tmp_dir.join(&bin_name);
    write_executable(&bin_path, "#!/bin/sh\nexit 0\n");
}

fn make_fake_codex_binary(bin_path: &Path, capture_file: &Path) {
    let capture_path = capture_file.display();
    let body = format!(
        "#!/bin/sh\nset -eu\nworkspace=\"\"\nif [ \"${{1:-}}\" = \"-C\" ] || [ \"${{1:-}}\" = \"--cd\" ]; then\n  workspace=\"$2\"\n  shift 2\nfi\nprintf '%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s' \"$workspace\" \"$EMBER_SESSION_ID\" \"$EMBER_ATTACHMENT_ID\" \"$EMBER_ATTACHMENT_ENDPOINT_TOKEN\" \"$EMBER_PROXY_URL\" \"$EMBER_SOCKET_PATH\" \"$EMBER_PERSONA\" \"$EMBER_PERSONA_ID\" \"$PATH\" \"${{EMBER_OPERATOR_PRESENCE_TOKEN-}}\" \"${{CODEX_HOME-}}\" > '{capture_path}'\nexit 0\n"
    );
    write_executable(bin_path, &body);
}

#[test]
fn ember_cli_binary_codex_host_registers_attachment_proxy_and_socket_path() {
    let _guard = HOST_CODEX_SMOKE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let tmp = short_tempdir();
    let home_dir = tmp.path().join("home");
    let fake_bin_dir = tmp.path().join("bins");
    let env_capture_file = tmp.path().join("ember-cli-codex-host-env.txt");

    std::fs::create_dir_all(&home_dir).expect("create home");
    std::fs::create_dir_all(&fake_bin_dir).expect("create fake bin dir");
    write_default_home_config(&home_dir);
    make_fake_ember_binary(&fake_bin_dir, "gh");
    make_fake_ember_binary(&fake_bin_dir, "git");

    let socket_path = home_dir.join(".ember").join("run").join("daemon.sock");
    std::fs::create_dir_all(socket_path.parent().expect("socket parent"))
        .expect("create socket dir");
    let close_called = spawn_mock_daemon(socket_path.clone());
    wait_for_socket(&socket_path);

    let fake_codex_bin = tmp.path().join("codex");
    make_fake_codex_binary(&fake_codex_bin, &env_capture_file);

    let status = std::process::Command::new(ember_bin())
        .arg("codex")
        .arg("--host")
        .env("HOME", &home_dir)
        .env("EMBER_CONFIG", home_dir.join(".ember/config.toml"))
        .env("EMBER_CODEX_BIN", &fake_codex_bin)
        .env("EMBER_PERSONA", "codex-binary-test")
        .env("XDG_CACHE_HOME", home_dir.join(".cache"))
        .env("PATH", fake_bin_dir.display().to_string())
        .status()
        .expect("spawn ember cli binary");
    assert_eq!(status.code(), Some(0), "ember codex launcher must exit 0");

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !close_called.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        close_called.load(Ordering::SeqCst),
        "binary launcher must call close_session after child exit"
    );

    let shadow_root = home_dir.join(".ember").join("shadow");
    let shadow_bin = shadow_root.join("bin");
    assert!(shadow_bin.exists(), "shadow bin dir must exist");

    let observed = std::fs::read_to_string(&env_capture_file)
        .expect("binary launcher child must have written env capture file");
    let mut lines = observed.lines();
    assert_eq!(
        lines.next(),
        Some(
            std::env::current_dir()
                .expect("current dir")
                .to_string_lossy()
                .as_ref()
        )
    );
    assert_eq!(lines.next(), Some(MOCK_SESSION_ID));
    assert_eq!(lines.next(), Some(MOCK_ATTACHMENT_ID));
    assert_eq!(lines.next(), Some(MOCK_ATTACHMENT_ENDPOINT_TOKEN));
    assert_eq!(lines.next(), Some(MOCK_PROXY_URL));
    assert_eq!(lines.next(), Some(socket_path.to_string_lossy().as_ref()));
    assert_eq!(lines.next(), Some("codex-binary-test"));
    assert_eq!(lines.next(), Some(MOCK_PERSONA_ID));
    let path_line = lines.next().unwrap_or_default();
    assert!(
        path_line.starts_with(&shadow_bin.display().to_string()),
        "binary launcher PATH must start with prod shadow/bin: {path_line}"
    );
    let token_line = lines.next().unwrap_or_default();
    assert!(
        token_line.is_empty(),
        "host codex launcher child must not receive EMBER_OPERATOR_PRESENCE_TOKEN now that broker runtime authority is session-bound: {token_line}"
    );
    let codex_home_line = lines.next().unwrap_or_default();
    assert!(
        !codex_home_line.is_empty(),
        "host codex launcher child must receive relocated CODEX_HOME"
    );
    let codex_config = std::fs::read_to_string(Path::new(codex_home_line).join("config.toml"))
        .expect("relocated CODEX_HOME must contain config.toml");
    assert!(codex_config.contains(&format!("base_url = \"{MOCK_CODEX_RESPONSES_PROXY_URL}\"")));
    assert!(codex_config.contains("requires_openai_auth = false"));
    assert!(codex_config.contains("default_permissions = \"ember-brokered\""));
    assert!(codex_config.contains("[features]\nnetwork_proxy = true"));
    assert!(codex_config.contains("[permissions.ember-brokered]"));
    assert!(codex_config.contains("extends = \":workspace\""));
    assert!(codex_config.contains("[permissions.ember-brokered.network]\nenabled = true"));
    assert!(codex_config.contains("[permissions.ember-brokered.network.domains]"));
    assert!(codex_config.contains("\"localhost\" = \"allow\""));
    assert!(codex_config.contains("\"127.0.0.1\" = \"allow\""));
    assert!(codex_config.contains("[permissions.ember-brokered.network.unix_sockets]"));
    let socket_root = std::fs::canonicalize(socket_path.parent().unwrap()).unwrap();
    assert!(codex_config.contains(&format!("\"{}\" = \"allow\"", socket_root.display())));
}
