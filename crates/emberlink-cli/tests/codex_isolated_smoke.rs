use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const MOCK_SESSION_ID: &str = "sess_isolated_codex_cli_smoke_001";
const MOCK_GRANT_ID: &str = "grt_isolated_codex_cli_smoke_001";
const MOCK_PROXY_URL: &str = "http://127.0.0.1:19484";
const MOCK_PRESENCE_TOKEN_JSON: &str = r#"{"uid":501,"scope":"class:session-runtime","expiry":{"secs_since_epoch":1779507461,"nanos_since_epoch":807776000},"signature":[1,2,3]}"#;

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

fn isolated_codex_runtime_stage_root(home: &Path, xdg_data_home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library")
            .join("Application Support")
            .join("emberlink")
            .join("codex-runtime")
    } else {
        xdg_data_home.join("emberlink").join("codex-runtime")
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
        compose.contains("EMBER_BRIDGE_URL"),
        "standalone worker compose must inject bridge env: {compose}"
    );
    assert!(
        compose.contains("- \"tail -f /dev/null\""),
        "standalone worker compose must keep the worker sidecar idle: {compose}"
    );
    assert!(
        compose.contains("target: /run/ember"),
        "standalone worker compose must mount the staged bridge client bundle: {compose}"
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

fn spawn_mock_daemon(socket_path: PathBuf, ssh_auth_sock: Option<PathBuf>) -> Arc<AtomicBool> {
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
                        "proxy_url": MOCK_PROXY_URL,
                        "presence_token": mock_presence_token_value(),
                        "bridge_client_bundle": {
                            "port": 4243,
                            "client_cert_pem": "mock-client-cert",
                            "client_key_pem": "mock-client-key",
                            "ca_cert_pem": "mock-ca-cert"
                        },
                    });
                    if let Some(sock) = ssh_auth_sock.as_ref() {
                        result["ssh_auth_sock"] =
                            serde_json::Value::String(sock.display().to_string());
                    }
                    serde_json::json!({
                        "id": req["id"],
                        "result": result,
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
        "[daemon]\ndata_dir = \"{}\"\nsocket_dir = \"{}\"\npid_file = \"{}\"\npolicy_file = \"{}\"\nlog_level = \"info\"\n",
        data_dir.display(),
        socket_dir.display(),
        pid_file.display(),
        policy_file.display(),
    );
    std::fs::write(&config_path, cfg.as_bytes()).expect("write ~/.ember/config.toml");
}

fn write_fake_codex_runtime(root: &Path) {
    let bin_dir = root.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create fake codex runtime bin dir");
    write_executable(&bin_dir.join("codex"), "#!/bin/sh\nexit 0\n");
}

fn write_fake_codex_auth_state(config_dir: &Path) {
    std::fs::create_dir_all(config_dir).expect("create fake codex config dir");
    std::fs::write(config_dir.join("auth.json"), "{}").expect("write fake auth json");
}

fn write_package_json(path: &Path, version: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create package parent");
    }
    std::fs::write(path, format!(r#"{{"version":"{version}"}}"#)).expect("write package json");
}

fn write_fake_host_runtime(root: &Path, version: &str) {
    let bin_dir = root.join("bin");
    let npm_log = bin_dir.join("npm.log");
    std::fs::create_dir_all(&bin_dir).expect("create fake host runtime bin dir");
    write_executable(&bin_dir.join("codex"), "#!/bin/sh\nexit 0\n");
    let npm_script = r#"#!/bin/sh
set -eu
prefix=""
package=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--prefix" ]; then
    prefix="$2"
    shift 2
    continue
  fi
  package="$1"
  shift
done
case "$package" in
  @openai/codex@*-linux-*)
    version="${package#@openai/codex@}"
    /bin/mkdir -p "$prefix/lib/node_modules/@openai/codex/node_modules/@openai"
    arch="${version##*-linux-}"
    base_version="${version%-linux-*}"
    printf '{"version":"%s"}\n' "$base_version" > "$prefix/lib/node_modules/@openai/codex/package.json"
    /bin/mkdir -p "$prefix/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-$arch"
    printf '{"version":"%s"}\n' "$version" > "$prefix/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-$arch/package.json"
    ;;
  @openai/codex@*)
    version="${package#@openai/codex@}"
    /bin/mkdir -p "$prefix/bin" "$prefix/lib/node_modules/@openai/codex"
    printf '#!/bin/sh\nexit 0\n' > "$prefix/bin/codex"
    /bin/chmod +x "$prefix/bin/codex"
    printf '{"version":"%s"}\n' "$version" > "$prefix/lib/node_modules/@openai/codex/package.json"
    ;;
  *)
    echo "unexpected package: $package" >&2
    exit 99
    ;;
esac
printf '%s\n' "$package" >> "__NPM_LOG__"
"#
    .replace("__NPM_LOG__", &npm_log.display().to_string());
    write_executable(&bin_dir.join("npm"), &npm_script);
    write_package_json(
        &root
            .join("lib")
            .join("node_modules")
            .join("@openai")
            .join("codex")
            .join("package.json"),
        version,
    );
}

#[test]
fn ember_cli_binary_codex_isolated_uses_standalone_worker_handoff() {
    let _guard = ISOLATED_SMOKE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let tmp = short_tempdir();
    let home_dir = tmp.path().join("home");
    let fake_bin_dir = tmp.path().join("bin");
    let fake_runtime_root = tmp.path().join("codex-runtime");
    let fake_codex_config = home_dir.join(".codex");
    std::fs::create_dir_all(&home_dir).expect("create home");
    std::fs::create_dir_all(&fake_bin_dir).expect("create fake bin dir");
    write_fake_codex_auth_state(&fake_codex_config);
    write_default_home_config(&home_dir);
    write_fake_codex_runtime(&fake_runtime_root);

    let docker_log = install_fake_docker(&fake_bin_dir, 23);
    let socket_path = home_dir.join(".ember").join("run").join("daemon.sock");
    let ssh_auth_sock = tmp.path().join("ssh-agent.sock");
    std::fs::create_dir_all(socket_path.parent().expect("socket parent"))
        .expect("create socket dir");
    std::fs::write(&ssh_auth_sock, b"").expect("write fake ssh auth sock");
    let close_called = spawn_mock_daemon(socket_path.clone(), Some(ssh_auth_sock.clone()));
    wait_for_socket(&socket_path);

    let status = std::process::Command::new(ember_bin())
        .arg("codex")
        .arg("--isolated")
        .arg("--preset")
        .arg("dev")
        .arg("--")
        .arg("--help")
        .env("HOME", &home_dir)
        .env("EMBER_CONFIG", home_dir.join(".ember/config.toml"))
        .env("EMBER_PERSONA", "persona-main")
        .env(
            "EMBER_CODEX_CONTAINER_RUNTIME_ROOT",
            fake_runtime_root.display().to_string(),
        )
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
            .join(format!("codex-home-{MOCK_SESSION_ID}"))
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
    let bridge_cert_dir = session_open_root.join(format!("bridge-certs-{MOCK_SESSION_ID}"));
    assert!(bridge_cert_dir.exists(), "bridge cert dir should be staged");
    assert!(compose.contains(&format!("source: \"{}\"", bridge_cert_dir.display())));
    assert!(compose.contains("target: /run/ember"));
    assert!(
        !compose.contains("/run/emberd-host"),
        "bridge-enabled isolated codex launch must not mount the daemon UDS: {compose}"
    );
    // ssh-agent-over-bridge S2: even when the registration carries a host
    // ssh_auth_sock path, the isolated launcher mounts NO host ssh-agent socket
    // into the worker — that bind-mount handed the in-container agent unbridged,
    // unleased, unaudited use of every host key. In-container SSH now routes
    // through the brokered S1 signer or fails closed.
    assert!(
        !compose.contains(&format!("source: \"{}\"", ssh_auth_sock.display())),
        "host ssh-agent socket must not be bind-mounted into the worker: {compose}"
    );
    assert!(
        !compose.contains("target: \"/run/ember/ssh-agent.sock\""),
        "no /run/ember/ssh-agent.sock host mount in the isolated worker: {compose}"
    );

    let docker_log = std::fs::read_to_string(docker_log).expect("read docker log");
    assert!(docker_log.contains("[up] [-d]"));
    assert!(docker_log.contains("[exec] [-T] [-w] [/work/repo]"));
    assert!(docker_log.contains("[down] [-v] [--timeout] [1]"));
    assert!(docker_log.contains("[-e] [EMBER_BRIDGE_URL=https://host.docker.internal:4243]"));
    assert!(docker_log.contains("[-e] [EMBER_CLIENT_CERT=/run/ember/client.crt]"));
    assert!(docker_log.contains("[-e] [EMBER_CLIENT_KEY=/run/ember/client.key]"));
    assert!(docker_log.contains("[-e] [EMBER_CA_CERT=/run/ember/ca.crt]"));
    assert!(
        !docker_log.contains("[-e] [EMBER_SOCKET_PATH=/run/emberd-host/daemon.sock]"),
        "bridge-enabled isolated codex launch must not forward legacy UDS env"
    );
    assert!(
        !docker_log.contains("[-e] [EMBER_DAEMON_SOCKET=/run/emberd-host/daemon.sock]"),
        "bridge-enabled isolated codex launch must not forward legacy UDS env"
    );
    assert!(
        !docker_log.contains("SSH_AUTH_SOCK="),
        "isolated worker env must not point SSH_AUTH_SOCK at a host-agent mount: {docker_log}"
    );
    assert!(
        !docker_log.contains("EMBER_SOCKET_PATH"),
        "bridge-enabled isolated worker must not use legacy daemon socket env"
    );
    assert!(
        !docker_log.contains("EMBER_DAEMON_SOCKET"),
        "bridge-enabled isolated worker must not use legacy daemon socket env"
    );
    assert!(docker_log.contains("[worker] [/usr/local/lib/ember/codex-runtime/bin/codex]"));
    assert!(docker_log.contains("[-C] [/work/repo] [--help]"));
}

#[test]
fn ember_cli_binary_codex_isolated_stages_runtime_from_host_install() {
    let _guard = ISOLATED_SMOKE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let tmp = short_tempdir();
    let home_dir = tmp.path().join("home");
    let fake_bin_dir = tmp.path().join("bin");
    let fake_host_runtime = tmp.path().join("host-runtime");
    let fake_codex_config = home_dir.join(".codex");
    let xdg_data_home = tmp.path().join("xdg-data");
    std::fs::create_dir_all(&home_dir).expect("create home");
    std::fs::create_dir_all(&fake_bin_dir).expect("create fake bin dir");
    write_fake_codex_auth_state(&fake_codex_config);
    std::fs::create_dir_all(&xdg_data_home).expect("create xdg data home");
    write_default_home_config(&home_dir);
    write_fake_host_runtime(&fake_host_runtime, "1.2.3");

    let docker_log = install_fake_docker(&fake_bin_dir, 23);
    let socket_path = home_dir.join(".ember").join("run").join("daemon.sock");
    std::fs::create_dir_all(socket_path.parent().expect("socket parent"))
        .expect("create socket dir");
    let close_called = spawn_mock_daemon(socket_path.clone(), None);
    wait_for_socket(&socket_path);

    let status = std::process::Command::new(ember_bin())
        .arg("codex")
        .arg("--isolated")
        .arg("--preset")
        .arg("dev")
        .arg("--")
        .arg("--help")
        .env("HOME", &home_dir)
        .env("XDG_DATA_HOME", &xdg_data_home)
        .env("EMBER_CONFIG", home_dir.join(".ember/config.toml"))
        .env("EMBER_PERSONA", "persona-main")
        .env(
            "PATH",
            format!(
                "{}:{}",
                fake_bin_dir.display(),
                fake_host_runtime.join("bin").display()
            ),
        )
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
    let compose_files: Vec<_> = std::fs::read_dir(&session_open_root)
        .expect("list session-open root")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join("compose.yml"))
        .filter(|path| path.exists())
        .collect();
    assert_eq!(compose_files.len(), 1, "expected one compose render");
    let compose = std::fs::read_to_string(&compose_files[0]).expect("read compose file");
    assert!(
        !compose.contains(&format!("source: \"{}\"", fake_host_runtime.display())),
        "compose must not mount the host runtime root directly: {compose}"
    );
    assert!(
        compose.contains(
            &isolated_codex_runtime_stage_root(&home_dir, &xdg_data_home)
                .display()
                .to_string()
        ),
        "compose must mount the staged container runtime from the canonical staging root: {compose}"
    );
    assert_standalone_worker_compose_contract(&compose);

    let npm_log = std::fs::read_to_string(fake_host_runtime.join("bin").join("npm.log"))
        .expect("read fake npm log");
    assert!(npm_log.contains("@openai/codex@1.2.3"));
    assert!(npm_log.contains("@openai/codex@1.2.3-linux-"));

    let docker_log = std::fs::read_to_string(docker_log).expect("read docker log");
    assert!(docker_log.contains("[worker] [/usr/local/lib/ember/codex-runtime/bin/codex]"));
    assert!(docker_log.contains("[-C] [/work/repo] [--help]"));
}

#[test]
fn ember_cli_binary_codex_isolated_requires_host_codex_auth_state() {
    let _guard = ISOLATED_SMOKE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let tmp = short_tempdir();
    let home_dir = tmp.path().join("home");
    let fake_bin_dir = tmp.path().join("bin");
    let codex_config_dir = home_dir.join(".codex");
    std::fs::create_dir_all(&home_dir).expect("create home");
    std::fs::create_dir_all(&fake_bin_dir).expect("create fake bin dir");
    std::fs::create_dir_all(&codex_config_dir).expect("create fake codex config dir");
    std::fs::write(codex_config_dir.join("hooks.json"), "{}").expect("write fake hooks json");
    write_default_home_config(&home_dir);

    let socket_path = home_dir.join(".ember").join("run").join("daemon.sock");
    std::fs::create_dir_all(socket_path.parent().expect("socket parent"))
        .expect("create socket dir");
    let _close_called = spawn_mock_daemon(socket_path.clone(), None);
    wait_for_socket(&socket_path);

    let out = std::process::Command::new(ember_bin())
        .arg("codex")
        .arg("--isolated")
        .arg("--")
        .arg("--help")
        .env("HOME", &home_dir)
        .env("EMBER_CONFIG", home_dir.join(".ember/config.toml"))
        .env("EMBER_PERSONA", "persona-main")
        .env("PATH", fake_bin_dir.display().to_string())
        .current_dir(workspace_root())
        .output()
        .expect("spawn ember cli binary");
    assert!(
        !out.status.success(),
        "isolated codex without host ~/.codex auth must fail early"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("~/.codex"), "stderr:\n{stderr}");
    assert!(stderr.contains("auth.json"), "stderr:\n{stderr}");
    assert!(stderr.contains("hooks.json"), "stderr:\n{stderr}");
    assert!(stderr.contains("codex login"), "stderr:\n{stderr}");
    assert!(
        stderr.contains("codex login --device-auth"),
        "stderr:\n{stderr}"
    );
    assert!(stderr.contains("ember codex --host"), "stderr:\n{stderr}");
    assert!(
        !stderr.contains("Compose:"),
        "missing host auth should fail before isolated stack startup; stderr:\n{stderr}"
    );
}
