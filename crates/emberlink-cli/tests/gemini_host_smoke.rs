//! T3 host-lane e2e smoke for `ember gemini` (ADR 215 §2 slice C).
//!
//! Drives the REAL `ember` binary against a mock daemon (Unix socket) that
//! returns a canned `register_session` carrying a `gemini_proxy_url`, and a fake
//! `gemini` binary that captures its injected environment. Asserts the full
//! brokered-launch contract WITHOUT a real Google sign-in:
//!   - `GEMINI_CLI_HOME` is relocated to a per-session operator-cache dir
//!   - `CODE_ASSIST_ENDPOINT` is the BARE daemon proxy URL (no `/v1`)
//!   - `GOOGLE_GENAI_USE_GCA=true` (OAuth lane selected)
//!   - `GEMINI_CLI_SYSTEM_SETTINGS_PATH` points at the relocated neutralizer
//!   - the ambient Google credential env (`GEMINI_API_KEY`,
//!     `GOOGLE_APPLICATION_CREDENTIALS`, `GEMINI_FORCE_ENCRYPTED_FILE_STORAGE`)
//!     is STRIPPED from the child
//!   - the relocated `.gemini/` carries a pinned-OAuth `settings.json`, an empty
//!     system-settings neutralizer, and a SANITIZED `oauth_creds.json` whose
//!     durable `refresh_token` was dropped (structural credential absence)
//!   - `close_session` is called after the child exits
//!
//! Mirrors `codex_host_smoke.rs`; the real Google end-to-end path is the
//! operator live-verify (it needs a real "Login with Google" credential).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const MOCK_SESSION_ID: &str = "sess_gemini_host_cli_smoke_001";
const MOCK_GRANT_ID: &str = "grt_gemini_host_cli_smoke_001";
const MOCK_ATTACHMENT_ID: &str = "att_gemini_host_cli_smoke_001";
const MOCK_ATTACHMENT_ENDPOINT_TOKEN: &str = "ep_gemini_host_cli_smoke_001";
const MOCK_PROXY_URL: &str = "http://127.0.0.1:19496";
/// BARE base — the gemini-cli appends `/v1internal:<method>`; no `/v1` suffix.
const MOCK_GEMINI_PROXY_URL: &str = "http://127.0.0.1:19497";
const MOCK_PERSONA_ID: &str = "persona_gemini_host_cli_smoke_001";
const MOCK_PRESENCE_TOKEN_JSON: &str = r#"{"uid":501,"scope":"class:session-runtime","expiry":{"secs_since_epoch":1779507461,"nanos_since_epoch":807776000},"signature":[1,2,3]}"#;
/// Durable secret seeded into the host oauth_creds; MUST NOT reach the child.
const HOST_REFRESH_TOKEN: &str = "1//host-durable-refresh-secret";
const HOST_ACCESS_TOKEN: &str = "ya29.host-short-lived-access";

static HOST_GEMINI_SMOKE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn ember_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ember")
}

fn short_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("ember-cli-gemini-")
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
                    // The gemini launcher must tag itself so the daemon stands up
                    // the Code Assist lane.
                    assert_eq!(
                        req["params"]["attestation_caller"].as_str().unwrap_or(""),
                        "gemini-code-assist-network-proxy",
                        "ember gemini must register with the gemini Code Assist attestation_caller"
                    );
                    serde_json::json!({
                        "id": req["id"],
                        "result": {
                            "session_id": MOCK_SESSION_ID,
                            "grant_id": MOCK_GRANT_ID,
                            "attachment_id": MOCK_ATTACHMENT_ID,
                            "attachment_endpoint_token": MOCK_ATTACHMENT_ENDPOINT_TOKEN,
                            "proxy_url": MOCK_PROXY_URL,
                            "gemini_proxy_url": MOCK_GEMINI_PROXY_URL,
                            "persona_id": MOCK_PERSONA_ID,
                            "presence_token": mock_presence_token_value(),
                        }
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

/// Fake `gemini` binary: captures the injected env (and the stripped vars, to
/// confirm they are unset) newline-separated to `capture_file`, then exits 0.
fn make_fake_gemini_binary(bin_path: &Path, capture_file: &Path) {
    let capture_path = capture_file.display();
    // Trailing `__END__` anchor: the last three captured fields are expected
    // to be EMPTY (stripped); without a trailing non-empty line, Rust's
    // `str::lines()` would drop those trailing empties and the positional reads
    // would shift. The checkpoint keeps every field at a stable line index.
    let body = format!(
        "#!/bin/sh\nset -eu\nprintf '%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n__END__\\n' \
         \"${{GEMINI_CLI_HOME-}}\" \
         \"${{CODE_ASSIST_ENDPOINT-}}\" \
         \"${{GOOGLE_GENAI_USE_GCA-}}\" \
         \"${{GEMINI_CLI_SYSTEM_SETTINGS_PATH-}}\" \
         \"${{EMBER_SESSION_ID-}}\" \
         \"${{EMBER_PERSONA-}}\" \
         \"$PATH\" \
         \"${{GEMINI_API_KEY-}}\" \
         \"${{GOOGLE_APPLICATION_CREDENTIALS-}}\" \
         \"${{GEMINI_FORCE_ENCRYPTED_FILE_STORAGE-}}\" > '{capture_path}'\nexit 0\n"
    );
    write_executable(bin_path, &body);
}

#[test]
fn ember_cli_binary_gemini_host_relocates_home_pins_oauth_and_drops_refresh_token() {
    let _guard = HOST_GEMINI_SMOKE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let tmp = short_tempdir();
    let home_dir = tmp.path().join("home");
    let fake_bin_dir = tmp.path().join("bins");
    let env_capture_file = tmp.path().join("ember-cli-gemini-host-env.txt");

    std::fs::create_dir_all(&home_dir).expect("create home");
    std::fs::create_dir_all(&fake_bin_dir).expect("create fake bin dir");
    write_default_home_config(&home_dir);
    make_fake_ember_binary(&fake_bin_dir, "gh");
    make_fake_ember_binary(&fake_bin_dir, "git");

    // Seed the HOST Gemini sign-in (with a durable refresh token) at
    // $HOME/.gemini/oauth_creds.json — the launcher reads + sanitizes it.
    let host_gemini_dir = home_dir.join(".gemini");
    std::fs::create_dir_all(&host_gemini_dir).expect("create host .gemini");
    std::fs::write(
        host_gemini_dir.join("oauth_creds.json"),
        format!(
            r#"{{"access_token":"{HOST_ACCESS_TOKEN}","refresh_token":"{HOST_REFRESH_TOKEN}","token_type":"Bearer","scope":"https://www.googleapis.com/auth/cloud-platform","expiry_date":1718000000000}}"#
        ),
    )
    .expect("seed host oauth_creds");

    let socket_path = home_dir.join(".ember").join("run").join("daemon.sock");
    std::fs::create_dir_all(socket_path.parent().expect("socket parent"))
        .expect("create socket dir");
    let close_called = spawn_mock_daemon(socket_path.clone());
    wait_for_socket(&socket_path);

    let fake_gemini_bin = tmp.path().join("gemini");
    make_fake_gemini_binary(&fake_gemini_bin, &env_capture_file);

    let status = std::process::Command::new(ember_bin())
        .arg("gemini")
        .arg("--host")
        .env("HOME", &home_dir)
        .env("EMBER_CONFIG", home_dir.join(".ember/config.toml"))
        .env("EMBER_GEMINI_BIN", &fake_gemini_bin)
        .env("EMBER_PERSONA", "gemini-binary-test")
        .env("XDG_CACHE_HOME", home_dir.join(".cache"))
        .env("PATH", fake_bin_dir.display().to_string())
        // Ambient Google credential env that MUST be stripped from the child:
        .env("GEMINI_API_KEY", "ambient-api-key-should-be-stripped")
        .env("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/ambient-sa-key.json")
        .env("GEMINI_FORCE_ENCRYPTED_FILE_STORAGE", "true")
        .status()
        .expect("spawn ember cli binary");
    assert_eq!(status.code(), Some(0), "ember gemini launcher must exit 0");

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !close_called.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        close_called.load(Ordering::SeqCst),
        "gemini launcher must call close_session after child exit"
    );

    let shadow_bin = home_dir.join(".ember").join("shadow").join("bin");
    assert!(shadow_bin.exists(), "shadow bin dir must exist");

    let observed = std::fs::read_to_string(&env_capture_file)
        .expect("fake gemini child must have written env capture file");
    let mut lines = observed.lines();

    let gemini_home = lines.next().unwrap_or_default().to_string();
    assert!(
        !gemini_home.is_empty(),
        "child must receive a relocated GEMINI_CLI_HOME"
    );
    assert!(
        gemini_home.starts_with(&home_dir.join(".cache").display().to_string()),
        "relocated GEMINI_CLI_HOME must live under the operator cache, got {gemini_home}"
    );
    assert_ne!(
        gemini_home,
        home_dir.display().to_string(),
        "relocated home must differ from the host home (keychain/credential neutralization)"
    );

    assert_eq!(
        lines.next(),
        Some(MOCK_GEMINI_PROXY_URL),
        "CODE_ASSIST_ENDPOINT must be the BARE daemon proxy URL (no /v1)"
    );
    assert!(
        !MOCK_GEMINI_PROXY_URL.ends_with("/v1"),
        "guard: the mock proxy URL is bare"
    );
    assert_eq!(
        lines.next(),
        Some("true"),
        "GOOGLE_GENAI_USE_GCA must select the OAuth lane"
    );
    let system_settings = lines.next().unwrap_or_default();
    assert_eq!(
        system_settings,
        Path::new(&gemini_home)
            .join(".gemini")
            .join("system-settings.json")
            .to_string_lossy(),
        "GEMINI_CLI_SYSTEM_SETTINGS_PATH must point at the relocated neutralizer"
    );
    assert_eq!(lines.next(), Some(MOCK_SESSION_ID));
    assert_eq!(lines.next(), Some("gemini-binary-test"));
    let path_line = lines.next().unwrap_or_default();
    assert!(
        path_line.starts_with(&shadow_bin.display().to_string()),
        "child PATH must start with the prod shadow/bin: {path_line}"
    );
    // The three ambient Google credential inputs must be stripped (empty).
    assert_eq!(
        lines.next(),
        Some(""),
        "GEMINI_API_KEY must be stripped from the child"
    );
    assert_eq!(
        lines.next(),
        Some(""),
        "GOOGLE_APPLICATION_CREDENTIALS must be stripped from the child"
    );
    assert_eq!(
        lines.next(),
        Some(""),
        "GEMINI_FORCE_ENCRYPTED_FILE_STORAGE must be stripped (forces the relocated file lane)"
    );

    // Relocated .gemini/ contents.
    let relocated_gemini = Path::new(&gemini_home).join(".gemini");
    let settings = std::fs::read_to_string(relocated_gemini.join("settings.json"))
        .expect("relocated settings.json");
    assert!(
        settings.contains("oauth-personal"),
        "relocated settings must pin selectedType=oauth-personal: {settings}"
    );
    assert_eq!(
        std::fs::read_to_string(relocated_gemini.join("system-settings.json"))
            .expect("relocated system-settings.json"),
        "{}\n",
        "system-settings neutralizer must be empty"
    );
    let creds = std::fs::read_to_string(relocated_gemini.join("oauth_creds.json"))
        .expect("relocated oauth_creds.json");
    assert!(
        !creds.contains(HOST_REFRESH_TOKEN),
        "durable refresh_token MUST NOT reach the child's relocated home"
    );
    assert!(
        !creds.contains("refresh_token"),
        "sanitized oauth_creds must carry no refresh_token field at all"
    );
    assert!(
        creds.contains(HOST_ACCESS_TOKEN),
        "short-lived access token is preserved (the proxy replaces the Bearer upstream)"
    );

    // The host oauth_creds (with the real refresh token) must be untouched.
    let host_creds = std::fs::read_to_string(host_gemini_dir.join("oauth_creds.json"))
        .expect("host oauth_creds untouched");
    assert!(
        host_creds.contains(HOST_REFRESH_TOKEN),
        "the host sign-in must be left intact (the launcher only writes a sanitized COPY)"
    );
}
