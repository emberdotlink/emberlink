use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const MOCK_SESSION_ID: &str = "sess_isolated_cli_smoke_001";
const MOCK_GRANT_ID: &str = "grt_isolated_cli_smoke_001";
const MOCK_ATTACHMENT_ID: &str = "att_isolated_cli_smoke_001";
const MOCK_ATTACHMENT_ENDPOINT_TOKEN: &str = "ep_isolated_cli_smoke_001";
const MOCK_PROXY_URL: &str = "http://127.0.0.1:19484";
const MOCK_ANTHROPIC_HEADERS: &str = "X-Ember-Credential: anthropic/oauth-token\nX-Ember-Target: https://api.anthropic.com\nX-Ember-Attachment-Id: att_isolated_cli_smoke_001\nX-Ember-Endpoint-Token: ep_isolated_cli_smoke_001";
const MOCK_PRESENCE_TOKEN_JSON: &str = r#"{"uid":501,"scope":"class:session-runtime","expiry":{"secs_since_epoch":1779507461,"nanos_since_epoch":807776000},"signature":[1,2,3]}"#;
const MOCK_BRIDGE_CLIENT_CERT_PEM: &str =
    "-----BEGIN CERTIFICATE-----\nmock-client-cert\n-----END CERTIFICATE-----\n";
const MOCK_BRIDGE_CLIENT_KEY_PEM: &str = concat!(
    "-----BEGIN ",
    "PRIVATE KEY-----\nmock-client-key\n",
    "-----END ",
    "PRIVATE KEY-----\n"
);
const MOCK_BRIDGE_CA_PEM: &str =
    "-----BEGIN CERTIFICATE-----\nmock-ca-cert\n-----END CERTIFICATE-----\n";

static ISOLATED_SMOKE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn ember_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ember")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn isolated_session_run_root(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library")
            .join("Application Support")
            .join("emberlink")
            .join("session-open")
    } else {
        home.join(".local")
            .join("share")
            .join("emberlink")
            .join("session-open")
    }
}

fn assert_standalone_worker_compose_contract(compose: &str) {
    assert!(
        !compose.contains("\n  bridge:\n"),
        "standalone worker compose must omit bridge service: {compose}"
    );
    assert!(
        !compose.contains("\n  orchestrator:\n"),
        "standalone worker compose must omit orchestrator service: {compose}"
    );
    assert!(
        compose.contains("EMBER_BRIDGE_URL: \"https://host.docker.internal:4243\""),
        "standalone worker compose must inject the host bridge endpoint: {compose}"
    );
    assert!(
        compose.contains("target: /run/ember"),
        "standalone worker compose must mount the bridge client bundle at /run/ember: {compose}"
    );
    assert!(
        compose.contains("- \"tail -f /dev/null\""),
        "standalone worker compose must keep the worker sidecar idle: {compose}"
    );
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
                "register_session" => {
                    let mut result = serde_json::json!({
                        "session_id": MOCK_SESSION_ID,
                        "grant_id": MOCK_GRANT_ID,
                        "attachment_id": MOCK_ATTACHMENT_ID,
                        "attachment_endpoint_token": MOCK_ATTACHMENT_ENDPOINT_TOKEN,
                        "proxy_url": MOCK_PROXY_URL,
                        "anthropic_base_url": MOCK_PROXY_URL,
                        "anthropic_custom_headers": MOCK_ANTHROPIC_HEADERS,
                        "presence_token": mock_presence_token_value(),
                    });
                    if req["params"]["bridge_client_bundle"]
                        .as_bool()
                        .unwrap_or(false)
                    {
                        result["bridge_client_bundle"] = serde_json::json!({
                            "port": 4243,
                            "client_cert_pem": MOCK_BRIDGE_CLIENT_CERT_PEM,
                            "client_key_pem": MOCK_BRIDGE_CLIENT_KEY_PEM,
                            "ca_cert_pem": MOCK_BRIDGE_CA_PEM,
                        });
                    }
                    serde_json::json!({
                        "id": req["id"],
                        "result": result
                    })
                }
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

fn install_fake_docker(bin_dir: &Path, exec_exit_code: i32) -> PathBuf {
    let docker = bin_dir.join("docker");
    let log_path = bin_dir.join("docker.log");
    write_executable(
        &docker,
        &format!(
            "#!/bin/sh\n\
set -eu\n\
log='{}'\n\
printf 'CMD' >> \"$log\"\n\
for arg in \"$@\"; do\n\
  printf ' [%s]' \"$arg\" >> \"$log\"\n\
done\n\
printf '\\n' >> \"$log\"\n\
case \" $* \" in\n\
  *\" exec \"*) exit {exec_exit_code} ;;\n\
  *\" up -d \"*) echo 'stack up'; exit 0 ;;\n\
  *) exit 0 ;;\n\
esac\n",
            log_path.display()
        ),
    );
    log_path
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
        "[daemon]\ndata_dir = \"{}\"\nsocket_dir = \"{}\"\npid_file = \"{}\"\npolicy_file = \"{}\"\nlog_level = \"info\"\nbridge_bind = \"127.0.0.1:4243\"\n\n[keyring]\nservice = \"ember-daemon-test\"\naccount = \"vault\"\n",
        data_dir.display(),
        socket_dir.display(),
        pid_file.display(),
        policy_file.display(),
    );
    std::fs::write(&config_path, cfg.as_bytes()).expect("write ~/.ember/config.toml");
}

#[test]
fn ember_cli_binary_claude_isolated_uses_standalone_worker_handoff() {
    let _guard = ISOLATED_SMOKE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let tmp = short_tempdir();
    let home_dir = tmp.path().join("home");
    let fake_bin_dir = tmp.path().join("bin");
    std::fs::create_dir_all(&home_dir).expect("create home");
    std::fs::create_dir_all(&fake_bin_dir).expect("create fake bin dir");
    write_default_home_config(&home_dir);

    let docker_log = install_fake_docker(&fake_bin_dir, 23);
    write_executable(&fake_bin_dir.join("gh"), "#!/bin/sh\nexit 0\n");
    write_executable(&fake_bin_dir.join("git"), "#!/bin/sh\nexit 0\n");
    let socket_path = home_dir.join(".ember").join("run").join("daemon.sock");
    std::fs::create_dir_all(socket_path.parent().expect("socket parent"))
        .expect("create socket dir");
    let close_called = spawn_mock_daemon(socket_path.clone());
    wait_for_socket(&socket_path);

    let status = std::process::Command::new(ember_bin())
        .arg("claude")
        .arg("--isolated")
        .arg("--preset")
        .arg("dev")
        .arg("--delegated")
        .arg("emberd-development")
        .arg("--")
        .arg("-p")
        .arg("Reply with OK only.")
        .env("HOME", &home_dir)
        .env("EMBER_CONFIG", home_dir.join(".ember/config.toml"))
        .env("EMBER_PERSONA", "persona-main")
        .env("EMBER_VAULT_PASSPHRASE", "test-isolated-bridge-passphrase")
        .env("PATH", fake_bin_dir.display().to_string())
        .env(
            "EMBER_COMPOSE_TEMPLATE",
            workspace_root()
                .join("crates/emberlink-cli/templates/compose.yml.j2")
                .display()
                .to_string(),
        )
        .current_dir(workspace_root())
        .status()
        .expect("spawn ember cli binary");
    assert_eq!(
        status.code(),
        Some(23),
        "isolated launcher should bubble up compose exec exit status"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !close_called.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        close_called.load(Ordering::SeqCst),
        "binary isolated launcher must call close_session after child exit"
    );

    let session_open_root = isolated_session_run_root(&home_dir);
    assert!(
        session_open_root
            .join(format!("claude-home-{MOCK_SESSION_ID}"))
            .exists(),
        "isolated worker home must live under the operator-owned session-open root"
    );

    let compose_files: Vec<_> = std::fs::read_dir(&session_open_root)
        .expect("list session-open root")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join("compose.yml"))
        .filter(|path| path.exists())
        .collect();
    assert_eq!(compose_files.len(), 1, "expected one compose render");
    let compose = std::fs::read_to_string(&compose_files[0]).expect("read compose file");
    assert_standalone_worker_compose_contract(&compose);
    let expected_shadow_root = session_open_root.join(format!("shadow-{MOCK_SESSION_ID}"));
    let expected_shadow_source = expected_shadow_root.join("bin");
    assert!(
        compose.contains(&expected_shadow_source.display().to_string()),
        "isolated worker compose must bind-mount the projected isolated shadow/bin into the worker for brokered tools: {compose}"
    );
    assert!(
        compose.contains("target: /usr/local/lib/shadow/bin"),
        "isolated worker compose must mount the brokered tool shims at /usr/local/lib/shadow/bin: {compose}"
    );
    assert_eq!(
        std::fs::read_link(expected_shadow_source.join("gh")).expect("read projected gh link"),
        std::path::PathBuf::from("/usr/local/lib/ember/binaries/ember-gh"),
        "isolated launcher must project gh to the image-baked Linux broker shim"
    );
    assert_eq!(
        std::fs::read_link(expected_shadow_source.join("ember-gh"))
            .expect("read projected ember-gh link"),
        std::path::PathBuf::from("/usr/local/lib/ember/binaries/ember-gh"),
        "isolated launcher must project ember-gh to the image-baked Linux broker shim"
    );
    assert_eq!(
        std::fs::read_link(expected_shadow_source.join("git")).expect("read projected git link"),
        std::path::PathBuf::from("/usr/local/lib/ember/binaries/ember-git"),
        "isolated launcher must project git to the image-baked Linux broker shim"
    );
    assert_eq!(
        std::fs::read_link(expected_shadow_source.join("ember-git"))
            .expect("read projected ember-git link"),
        std::path::PathBuf::from("/usr/local/lib/ember/binaries/ember-git"),
        "isolated launcher must project ember-git to the image-baked Linux broker shim"
    );

    let docker_log = std::fs::read_to_string(docker_log).expect("read docker log");
    assert!(docker_log.contains("[up] [-d]"));
    assert!(docker_log.contains("[exec] [-T] [-w] [/work/repo]"));
    assert!(docker_log.contains("[down] [-v] [--timeout] [1]"));
    assert!(
        docker_log.contains("[-e] [ANTHROPIC_BASE_URL=http://host.docker.internal:19484]"),
        "isolated launcher must rewrite the brokered Anthropic gateway for the container: {docker_log}"
    );
    assert!(
        docker_log.contains("X-Ember-Credential: anthropic/oauth-token"),
        "isolated launcher must advertise the brokered OAuth credential identity: {docker_log}"
    );
    assert!(
        docker_log.contains("[-e] [ANTHROPIC_AUTH_TOKEN=ember-proxy-session]"),
        "isolated launcher must seed the Claude auth placeholder for pristine isolated homes: {docker_log}"
    );
    assert!(
        docker_log.contains("[-e] [PATH=/usr/local/lib/shadow/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin]"),
        "isolated launcher must prepend the brokered shadow/bin to PATH inside the worker: {docker_log}"
    );
    assert!(
        docker_log.contains("[-e] [EMBER_BRIDGE_URL=https://host.docker.internal:4243]"),
        "isolated launcher must pass the bridge endpoint into the worker child env: {docker_log}"
    );
    assert!(
        docker_log.contains(&format!(
            "[-e] [EMBER_BROKER_CWD={}]",
            workspace_root().display()
        )),
        "isolated launcher must pass the host-real broker cwd into the worker child env: {docker_log}"
    );
    assert!(
        docker_log.contains("[-e] [EMBER_CLIENT_CERT=/run/ember/client.crt]"),
        "isolated launcher must pass the bridge client cert path into the worker child env: {docker_log}"
    );
    assert!(
        docker_log.contains("[-e] [EMBER_CLIENT_KEY=/run/ember/client.key]"),
        "isolated launcher must pass the bridge client key path into the worker child env: {docker_log}"
    );
    assert!(
        docker_log.contains("[-e] [EMBER_CA_CERT=/run/ember/ca.crt]"),
        "isolated launcher must pass the bridge CA path into the worker child env: {docker_log}"
    );
    assert!(
        !docker_log.contains("[-e] [EMBER_SOCKET_PATH=/run/emberd-host/daemon.sock]"),
        "bridge-enabled isolated Claude launch must not forward legacy UDS env: {docker_log}"
    );
    assert!(
        !docker_log.contains("[-e] [EMBER_DAEMON_SOCKET=/run/emberd-host/daemon.sock]"),
        "bridge-enabled isolated Claude launch must not forward legacy UDS env: {docker_log}"
    );
    assert!(
        docker_log.contains(&format!(
            "[-e] [EMBER_GH_BINARY={}]",
            fake_bin_dir.join("gh").display()
        )),
        "isolated launcher must pass the host-real gh binary override into the worker child env: {docker_log}"
    );
    assert!(
        docker_log.contains(&format!(
            "[-e] [EMBER_GIT_BINARY={}]",
            fake_bin_dir.join("git").display()
        )),
        "isolated launcher must pass the host-real git binary override into the worker child env: {docker_log}"
    );
    assert!(
        docker_log.contains("[worker] [claude] [-p] [Reply with OK only.]"),
        "Claude isolated handoff must forward trailing args into compose exec: {docker_log}"
    );
}

#[test]
fn isolated_claude_worker_image_includes_jq_for_trusted_hooks() {
    let dockerfile =
        std::fs::read_to_string(workspace_root().join("containers/ember-claude-code/Dockerfile"))
            .expect("read worker image Dockerfile");
    assert!(
        dockerfile.contains("\n      jq \\"),
        "isolated Claude worker image must install jq so repo-trusted hooks keep parity with host launches: {dockerfile}"
    );
    assert!(
        dockerfile.contains("\n      gh \\"),
        "isolated Claude worker image must install the downstream gh CLI so brokered ember-gh has a real wrapped binary: {dockerfile}"
    );
    assert!(
        dockerfile.contains("COPY build-context/ember-gh /usr/local/lib/ember/binaries/ember-gh"),
        "isolated Claude worker image must carry a Linux ember-gh broker shim: {dockerfile}"
    );
    assert!(
        dockerfile.contains("COPY build-context/ember-git /usr/local/lib/ember/binaries/ember-git"),
        "isolated Claude worker image must carry a Linux ember-git broker shim: {dockerfile}"
    );
}
