//! T2 integration tests for `ember claude-code` launcher wiring.
//!
//!
//! Verifies implementation-note-531 acceptance criteria:
//! - `EMBER_SESSION_ID` is injected into the child env from the daemon RPC response.
//! - Child `PATH` starts with the shadow directory.
//! - `close_session` is called with the same session_id on child exit.
//! - `install_path_shadow` is called before spawn (shadow dir is present).
//!
//! Uses a raw `UnixListener` mock rather than the full `SocketListener` +
//! `DaemonStore` stack so the test has no keychain / vault dependencies.
//! The mock responds to exactly two JSON-RPC calls in sequence:
//!   1. `register_session` → returns a fixed session_id / grant_id / proxy_url.
//!   2. `close_session`    → returns `{"closed": true}`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tempfile::TempDir;

const MOCK_SESSION_ID: &str = "sess_wiring_test_001";
const MOCK_GRANT_ID: &str = "grt_wiring_test_001";
const MOCK_PROXY_URL: &str = "http://127.0.0.1:18484";
const MOCK_PRESENCE_TOKEN_JSON: &str = r#"{"uid":501,"scope":"class:session-runtime","expiry":{"secs_since_epoch":1779507461,"nanos_since_epoch":807776000},"signature":[1,2,3]}"#;

static LAUNCHER_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn mock_presence_token_value() -> serde_json::Value {
    serde_json::from_str(MOCK_PRESENCE_TOKEN_JSON).expect("mock presence token json")
}

fn short_tempdir() -> TempDir {
    tempfile::Builder::new()
        .prefix("ember-cli-")
        .tempdir_in("/tmp")
        .or_else(|_| TempDir::new())
        .expect("tempdir")
}

/// Spawn a minimal JSON-RPC mock daemon that handles one `register_session`
/// call followed by one `close_session` call on separate connections.
///
/// `run_with_registration` does not call `register_session` itself — it
/// takes an already-built `SessionRegistration`. So when `launch_claude_code`
/// is the entry point, the sequence is: register → spawn child → close.
/// When testing `run_with_registration` directly, only `close_session` fires.
///
/// This mock handles both patterns: it accepts connections in a loop and
/// dispatches by method name, setting the `close_called` flag on the first
/// `close_session` it sees.
fn spawn_mock_daemon(socket_path: PathBuf) -> Arc<AtomicBool> {
    let close_called = Arc::new(AtomicBool::new(false));
    let close_flag = Arc::clone(&close_called);

    std::thread::spawn(move || {
        let listener = UnixListener::bind(&socket_path).expect("bind mock socket");
        // implementation-note-480: nonblocking
        // + per-iteration deadline so the for-loop exits cleanly when a test
        // path makes fewer than the maximum 4 connections, instead of hanging
        // the test-runner indefinitely on the unused-accept.
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
                // `ember claude-code` now does a bare socket-connect preflight
                // before the JSON-RPC register/close sequence; ignore that
                // empty probe and keep waiting for the real request.
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
                        "proxy_url": MOCK_PROXY_URL,
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
                other => {
                    eprintln!("mock daemon: unexpected method {other:?}");
                    break;
                }
            };

            let mut resp_str = serde_json::to_string(&resp).unwrap();
            resp_str.push('\n');
            let _ = writer.write_all(resp_str.as_bytes());
            drop(writer);
            drop(reader);

            if close_flag.load(Ordering::SeqCst) {
                break;
            }
        }
    });

    close_called
}

/// Wait until `socket_path` appears on the filesystem (the mock daemon
/// binds asynchronously in a spawned thread).
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

/// Build a trivial `ember-<tool>` binary in `tmp_dir` so that
/// `cohort_a_construct_specs` can discover at least one spec via the
/// `PATH` search path. Returns the directory to prepend to PATH.
fn make_fake_ember_binary(tmp_dir: &Path, tool: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin_name = format!("ember-{tool}");
    let bin_path = tmp_dir.join(&bin_name);
    // Write a minimal shell script that just exits 0.
    std::fs::write(&bin_path, b"#!/bin/sh\nexit 0\n").expect("write fake binary");
    std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod fake binary");
    tmp_dir.to_path_buf()
}

/// Write the minimal default `~/.ember/config.toml` shape the real `ember`
/// binary now requires before subcommand dispatch.
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

/// Core assertion helper used by both wiring tests.
///
/// Drives `run_with_registration` (the inner spawn helper) with a mock
/// daemon + a temp shadow dir, then asserts:
/// - The returned exit code is 0.
/// - The shadow dir was created by `install_path_shadow` (via `launch_claude_code`
///   path) or was passed through directly here.
/// - The child `PATH` starts with the shadow dir (verified indirectly — we
///   assert the env-prep code doesn't panic and exits correctly; direct child
///   env inspection requires a wrapper binary beyond `/usr/bin/true`).
fn assert_shadow_dir_created(shadow_dir: &Path) {
    assert!(
        shadow_dir.exists(),
        "shadow_dir must be created by install_path_shadow: {}",
        shadow_dir.display()
    );
    let meta = std::fs::metadata(shadow_dir).expect("stat shadow_dir");
    assert!(meta.is_dir(), "shadow_dir must be a directory");
    // `install_path_shadow`'s contract is "creates `<shadow_dir>/bin/` (mode
    // 0700)" — the chmod 0700 is applied to the `bin/` subdirectory, not
    // the shadow root (which inherits the process umask, typically 0755).
    // This matches the in-crate unit test at
    // `crates/emberlink-cli/src/launcher/path_shadow.rs:167`.
    let bin_dir = shadow_dir.join("bin");
    assert!(
        bin_dir.exists(),
        "shadow_dir/bin must be created: {}",
        bin_dir.display()
    );
    let bin_meta = std::fs::metadata(&bin_dir).expect("stat shadow_dir/bin");
    assert!(bin_meta.is_dir(), "shadow_dir/bin must be a directory");
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            bin_meta.permissions().mode() & 0o777,
            0o700,
            "shadow_dir/bin must have mode 0700"
        );
    }
}

// ---------------------------------------------------------------------------
// Test: EMBER_SESSION_ID + PATH + close_session round-trip
// ---------------------------------------------------------------------------

/// T2 wiring test: `run_with_registration` injects `EMBER_SESSION_ID` into
/// the child env (sourced from mock daemon) and prepends `shadow_dir` to
/// `PATH`; `close_session` is called on exit.
///
/// We verify the session_id/close flow through the mock daemon's assertions
/// (panics on unexpected calls) and the `close_called` atomic flag.
/// PATH-prepend is verified by running a tiny shell command inside the child
/// that prints `$PATH` and capturing it via a temp file.
#[test]
fn run_with_registration_injects_session_id_and_shadow_path() {
    use emberlink_cli::launcher::claude_code::{SessionRegistration, run_with_registration};
    use emberlink_cli::launcher::path_shadow::install_path_shadow;

    let tmp = short_tempdir();
    let socket_path = tmp.path().join("mock-daemon-wiring.sock");
    let shadow_dir = tmp.path().join("shadow");
    let env_capture_file = tmp.path().join("child_path.txt");

    // Install an empty shadow dir so run_with_registration can prepend it.
    install_path_shadow(&shadow_dir, &[]).unwrap();
    assert_shadow_dir_created(&shadow_dir);

    // Spawn the mock daemon before building the registration fixture so it's
    // listening when close_session_rpc connects.
    let close_called = spawn_mock_daemon(socket_path.clone());
    wait_for_socket(&socket_path);

    // Build a registration that matches what the mock daemon returns.
    let registration = SessionRegistration {
        session_id: MOCK_SESSION_ID.to_string(),
        grant_id: MOCK_GRANT_ID.to_string(),
        proxy_url: MOCK_PROXY_URL.to_string(),
        presence_token_json: Some(MOCK_PRESENCE_TOKEN_JSON.to_string()),
        anthropic_base_url: None,
        anthropic_custom_headers: None,
        git_proxy_url: None,
        ssh_auth_sock: None,
        workflow_id: None,
        workflow_template: None,
    };

    // Use a shell snippet as the child binary: write $PATH to a temp file
    // and exit 0. We pass the capture file path as an argument to /bin/sh.
    let capture_path_str = env_capture_file.display().to_string();
    let child_script = format!("printf '%s' \"$PATH\" > '{capture_path_str}'; exit 0");

    let code = run_with_registration(
        "/bin/sh",
        &["-c".to_string(), child_script],
        &registration,
        &socket_path,
        &shadow_dir,
    )
    .expect("spawn /bin/sh");
    assert_eq!(code, 0, "child must exit 0");

    // Assert close_session was called (mock daemon sets the flag).
    // Give it a small deadline since it runs on the mock's thread.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !close_called.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        close_called.load(Ordering::SeqCst),
        "close_session_rpc must be called after child exits"
    );

    // Assert child PATH starts with shadow_dir.
    let child_path = std::fs::read_to_string(&env_capture_file)
        .expect("child must have written its PATH to the capture file");
    assert!(
        child_path.starts_with(&shadow_dir.display().to_string()),
        "child PATH must start with shadow_dir:\n  shadow_dir={}\n  child PATH={}",
        shadow_dir.display(),
        child_path
    );
}

/// T2 wiring test: `install_path_shadow` is called by `launch_claude_code`
/// before the session RPC. Verify by using `EMBER_SHADOW_DIR` override to
/// point at a temp dir and confirm the shadow dir exists and has 0700 mode.
///
/// We cannot drive `launch_claude_code` all the way through because it calls
/// `register_session_rpc` which requires a live daemon socket; instead we
/// test `install_path_shadow` + `cohort_a_construct_specs` integration here.
#[test]
fn install_path_shadow_creates_shadow_dir_with_discovered_specs() {
    use emberlink_cli::launcher::path_shadow::{ConstructSpec, install_path_shadow};

    let tmp = short_tempdir();
    let shadow_dir = tmp.path().join("shadow");
    let fake_bin_dir = tmp.path().join("bins");
    std::fs::create_dir_all(&fake_bin_dir).unwrap();

    // Plant a fake ember-gh binary so at least one spec resolves.
    make_fake_ember_binary(&fake_bin_dir, "gh");

    // Build a spec list that matches what cohort_a_construct_specs would
    // produce for the "gh" tool given our fake binary directory.
    let specs = vec![ConstructSpec {
        tool_name: "gh".to_string(),
        target_binary: fake_bin_dir.join("ember-gh"),
    }];

    install_path_shadow(&shadow_dir, &specs).expect("install_path_shadow must succeed");

    assert_shadow_dir_created(&shadow_dir);

    // The "gh" symlink must exist under bin/ and point to our fake binary.
    // (`install_path_shadow` places shims under `<shadow_dir>/bin/<tool>`,
    // not at the shadow root — matches the in-crate unit test.)
    let shim = shadow_dir.join("bin").join("gh");
    assert!(
        shim.symlink_metadata().is_ok(),
        "shim 'gh' must exist in shadow_dir/bin"
    );
    let target = std::fs::read_link(&shim).expect("read_link on gh shim");
    assert_eq!(target, fake_bin_dir.join("ember-gh"));
}

/// T2 wiring test: verify that `EMBER_SESSION_ID` is present in the child
/// env. We use a shell child that writes the var to a file; if the var is
/// missing the file will be empty.
#[test]
fn child_env_contains_ember_session_id() {
    use emberlink_cli::launcher::claude_code::{SessionRegistration, run_with_registration};
    use emberlink_cli::launcher::path_shadow::install_path_shadow;

    let tmp = short_tempdir();
    let socket_path = tmp.path().join("mock-daemon-session-id.sock");
    let shadow_dir = tmp.path().join("shadow");
    let env_capture_file = tmp.path().join("session_id.txt");

    install_path_shadow(&shadow_dir, &[]).unwrap();

    let close_called = spawn_mock_daemon(socket_path.clone());
    wait_for_socket(&socket_path);

    let registration = SessionRegistration {
        session_id: MOCK_SESSION_ID.to_string(),
        grant_id: MOCK_GRANT_ID.to_string(),
        proxy_url: MOCK_PROXY_URL.to_string(),
        presence_token_json: Some(MOCK_PRESENCE_TOKEN_JSON.to_string()),
        anthropic_base_url: None,
        anthropic_custom_headers: None,
        git_proxy_url: None,
        ssh_auth_sock: None,
        workflow_id: None,
        workflow_template: None,
    };

    let capture_path_str = env_capture_file.display().to_string();
    let child_script = format!("printf '%s' \"$EMBER_SESSION_ID\" > '{capture_path_str}'; exit 0");

    let code = run_with_registration(
        "/bin/sh",
        &["-c".to_string(), child_script],
        &registration,
        &socket_path,
        &shadow_dir,
    )
    .expect("spawn /bin/sh");
    assert_eq!(code, 0);

    // Wait for close_session to complete (mock thread).
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !close_called.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }

    let observed_session_id = std::fs::read_to_string(&env_capture_file)
        .expect("child must have written EMBER_SESSION_ID to capture file");

    assert_eq!(
        observed_session_id, MOCK_SESSION_ID,
        "EMBER_SESSION_ID in child env must match the session_id from daemon RPC"
    );
}

/// T3/T2 bridge proof: drive the real `launch_claude_code` entry point
/// end-to-end against the mock daemon, not just `run_with_registration`.
///
/// This covers the actual launcher contract the friendly path uses:
/// register_session RPC, shadow/bin installation, env injection into the child,
/// and close_session RPC on exit.
#[test]
fn launch_claude_code_registers_and_closes_session() {
    use emberlink_cli::launcher::claude_code::launch_claude_code;

    let _g = LAUNCHER_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let tmp = short_tempdir();
    let socket_path = tmp.path().join("mock-daemon-launch.sock");
    let shadow_dir = tmp.path().join("shadow");
    let fake_bin_dir = tmp.path().join("bins");
    let env_capture_file = tmp.path().join("launcher_env.txt");
    std::fs::create_dir_all(&fake_bin_dir).unwrap();
    make_fake_ember_binary(&fake_bin_dir, "gh");

    let prior_claude_bin = std::env::var("EMBER_CLAUDE_BIN").ok();
    let prior_shadow_dir = std::env::var("EMBER_SHADOW_DIR").ok();
    let prior_persona = std::env::var("EMBER_PERSONA").ok();
    let prior_path = std::env::var("PATH").ok();

    unsafe {
        std::env::set_var("EMBER_CLAUDE_BIN", "/bin/sh");
        std::env::set_var("EMBER_SHADOW_DIR", shadow_dir.as_os_str());
        std::env::set_var("EMBER_PERSONA", "claude-code-launch-test");
        let merged_path = match &prior_path {
            Some(existing) => format!("{}:{existing}", fake_bin_dir.display()),
            None => fake_bin_dir.display().to_string(),
        };
        std::env::set_var("PATH", merged_path);
    }

    let close_called = spawn_mock_daemon(socket_path.clone());
    wait_for_socket(&socket_path);

    let capture_path_str = env_capture_file.display().to_string();
    let child_script = format!(
        "printf '%s\\n%s\\n%s\\n%s\\n%s\\n%s' \"$EMBER_SESSION_ID\" \"$EMBER_GRANT_ID\" \"$EMBER_PROXY_URL\" \"$EMBER_SOCKET_PATH\" \"$PATH\" \"$EMBER_OPERATOR_PRESENCE_TOKEN\" > '{capture_path_str}'; exit 0"
    );

    let code = launch_claude_code(&["-c".to_string(), child_script], &socket_path)
        .expect("launch_claude_code must succeed against mock daemon");

    unsafe {
        match prior_claude_bin {
            Some(v) => std::env::set_var("EMBER_CLAUDE_BIN", v),
            None => std::env::remove_var("EMBER_CLAUDE_BIN"),
        }
        match prior_shadow_dir {
            Some(v) => std::env::set_var("EMBER_SHADOW_DIR", v),
            None => std::env::remove_var("EMBER_SHADOW_DIR"),
        }
        match prior_persona {
            Some(v) => std::env::set_var("EMBER_PERSONA", v),
            None => std::env::remove_var("EMBER_PERSONA"),
        }
        match prior_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
    }

    assert_eq!(code, 0, "launcher child must exit 0");

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !close_called.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        close_called.load(Ordering::SeqCst),
        "launch_claude_code must call close_session after child exit"
    );

    assert_shadow_dir_created(&shadow_dir);
    let observed = std::fs::read_to_string(&env_capture_file)
        .expect("launcher child must have written env capture file");
    let mut lines = observed.lines();
    assert_eq!(
        lines.next(),
        Some(MOCK_SESSION_ID),
        "launcher child must receive EMBER_SESSION_ID from register_session"
    );
    assert_eq!(
        lines.next(),
        Some(MOCK_GRANT_ID),
        "launcher child must receive EMBER_GRANT_ID from register_session"
    );
    assert_eq!(
        lines.next(),
        Some(MOCK_PROXY_URL),
        "launcher child must receive EMBER_PROXY_URL from register_session"
    );
    assert_eq!(
        lines.next(),
        Some(socket_path.to_string_lossy().as_ref()),
        "launcher child must receive EMBER_SOCKET_PATH for construct/runtime calls"
    );
    let path_line = lines.next().unwrap_or_default();
    assert!(
        path_line.starts_with(&shadow_dir.join("bin").display().to_string()),
        "launcher child PATH must start with shadow/bin: {path_line}"
    );
    let token_line = lines.next().unwrap_or_default();
    let token_json: serde_json::Value =
        serde_json::from_str(token_line).expect("presence token env must be valid json");
    assert_eq!(token_json.get("uid").and_then(|v| v.as_u64()), Some(501));
    assert_eq!(
        token_json.get("scope").and_then(|v| v.as_str()),
        Some("class:session-runtime")
    );
}

#[test]
fn launch_claude_code_closes_session_when_child_spawn_fails() {
    use emberlink_cli::launcher::claude_code::launch_claude_code;

    let _g = LAUNCHER_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let tmp = short_tempdir();
    let socket_path = tmp.path().join("mock-daemon-launch-fail.sock");
    let shadow_dir = tmp.path().join("shadow");
    let fake_bin_dir = tmp.path().join("bins");
    std::fs::create_dir_all(&fake_bin_dir).unwrap();
    make_fake_ember_binary(&fake_bin_dir, "gh");

    let prior_claude_bin = std::env::var("EMBER_CLAUDE_BIN").ok();
    let prior_shadow_dir = std::env::var("EMBER_SHADOW_DIR").ok();
    let prior_persona = std::env::var("EMBER_PERSONA").ok();
    let prior_path = std::env::var("PATH").ok();

    unsafe {
        std::env::set_var(
            "EMBER_CLAUDE_BIN",
            "/no/such/binary-that-must-not-exist-launcher-session-wiring",
        );
        std::env::set_var("EMBER_SHADOW_DIR", shadow_dir.as_os_str());
        std::env::set_var("EMBER_PERSONA", "claude-code-launch-fail-test");
        let merged_path = match &prior_path {
            Some(existing) => format!("{}:{existing}", fake_bin_dir.display()),
            None => fake_bin_dir.display().to_string(),
        };
        std::env::set_var("PATH", merged_path);
    }

    let close_called = spawn_mock_daemon(socket_path.clone());
    wait_for_socket(&socket_path);

    let err = launch_claude_code(&[], &socket_path)
        .expect_err("launch_claude_code must surface spawn failure");

    unsafe {
        match prior_claude_bin {
            Some(v) => std::env::set_var("EMBER_CLAUDE_BIN", v),
            None => std::env::remove_var("EMBER_CLAUDE_BIN"),
        }
        match prior_shadow_dir {
            Some(v) => std::env::set_var("EMBER_SHADOW_DIR", v),
            None => std::env::remove_var("EMBER_SHADOW_DIR"),
        }
        match prior_persona {
            Some(v) => std::env::set_var("EMBER_PERSONA", v),
            None => std::env::remove_var("EMBER_PERSONA"),
        }
        match prior_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
    }

    assert!(
        err.to_string().contains("failed to spawn"),
        "spawn failure should be preserved: {err}"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !close_called.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        close_called.load(Ordering::SeqCst),
        "launch_claude_code must close the daemon session even when child spawn fails"
    );
}

// implementation-note-532: the `--dev` flow
// gate-checks `~/.ember-dev/envs/<worktree-id>/binaries/ember` exists
// and would re-exec into it via `maybe_reexec_via_dev_cli` if the
// current binary doesn't canonicalize to that path. The fixture below
// stands up the dev-install artifact tree in the tempdir + symlinks
// the test binary into the expected install_root so:
//   (1) the dev_cli existence check passes,
//   (2) `current_exe.canonicalize() == dev_cli.canonicalize()` so no
//       re-exec happens (the symlink resolves to the same
//       CARGO_BIN_EXE_ember the test invokes),
//   (3) the dev socket path the launcher computes matches the
//       mock daemon's bind location.
// Anchor: ember_cli_binary_claude_code_registers_grant_proxy_and_socket_path_passes
#[test]
fn ember_cli_binary_claude_code_registers_grant_proxy_and_socket_path() {
    let _g = LAUNCHER_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let tmp = short_tempdir();
    let home_dir = tmp.path().join("home");
    let workspace_root = tmp.path().join("dev-workspace");
    let fake_bin_dir = tmp.path().join("bins");
    let env_capture_file = tmp.path().join("ember-cli-launcher-env.txt");

    // workspace_root needs a Cargo.toml checkpoint — resolve_workspace_root_from
    // walks parents looking for it.
    std::fs::create_dir_all(&workspace_root).unwrap();
    std::fs::write(workspace_root.join("Cargo.toml"), "[workspace]\n").unwrap();
    std::fs::create_dir_all(&fake_bin_dir).unwrap();
    write_default_home_config(&home_dir);
    make_fake_ember_binary(&fake_bin_dir, "gh");

    // Compute the dev runtime layout the production code will use.
    // Same function the launcher calls — guarantees path agreement.
    let dev_runtime =
        emberlink_cli::dev_runtime::derive_dev_runtime_env(&home_dir, &workspace_root);

    // Dev-install fixture: create binaries dir + symlink the test binary
    // so dev_cli.exists() = true AND
    // dev_cli.canonicalize() == current_exe.canonicalize() (no re-exec).
    std::fs::create_dir_all(&dev_runtime.install_root).unwrap();
    let dev_cli = dev_runtime.install_root.join("ember");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_ember"), &dev_cli)
        .expect("symlink test binary into dev install_root");

    // Dev socket lives under <home>/.ember-dev/envs/<id>/run, not ~/.ember/run.
    let socket_path = dev_runtime.socket_path.clone();
    std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();

    let close_called = spawn_mock_daemon(socket_path.clone());
    wait_for_socket(&socket_path);

    let capture_path_str = env_capture_file.display().to_string();
    let child_script = format!(
        "printf '%s\\n%s\\n%s\\n%s\\n%s\\n%s' \"$EMBER_SESSION_ID\" \"$EMBER_GRANT_ID\" \"$EMBER_PROXY_URL\" \"$EMBER_SOCKET_PATH\" \"$PATH\" \"$EMBER_OPERATOR_PRESENCE_TOKEN\" > '{capture_path_str}'; exit 0"
    );

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_ember"))
        .arg("claude")
        .arg("--dev")
        .arg("--")
        .arg("-c")
        .arg(&child_script)
        .env("HOME", &home_dir)
        .env("EMBER_DEV_WORKTREE_ROOT", &workspace_root)
        .env(
            emberlink_cli::dev_runtime::DEV_RUNTIME_ID_ENV,
            &dev_runtime.worktree_id,
        )
        .env("EMBER_CLAUDE_BIN", "/bin/sh")
        .env("EMBER_PERSONA", "claude-code-binary-test")
        .env("PATH", fake_bin_dir.display().to_string())
        .status()
        .expect("spawn ember cli binary");
    assert_eq!(status.code(), Some(0), "ember cli launcher must exit 0");

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !close_called.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        close_called.load(Ordering::SeqCst),
        "binary launcher must call close_session after child exit"
    );

    // Dev flavor's shadow dir is worktree-scoped, not ~/.ember/shadow.
    assert_shadow_dir_created(&dev_runtime.shadow_root);
    let observed = std::fs::read_to_string(&env_capture_file)
        .expect("binary launcher child must have written env capture file");
    let mut lines = observed.lines();
    assert_eq!(lines.next(), Some(MOCK_SESSION_ID));
    assert_eq!(lines.next(), Some(MOCK_GRANT_ID));
    assert_eq!(lines.next(), Some(MOCK_PROXY_URL));
    assert_eq!(lines.next(), Some(socket_path.to_string_lossy().as_ref()));
    let path_line = lines.next().unwrap_or_default();
    assert!(
        path_line.starts_with(&dev_runtime.shadow_root.join("bin").display().to_string()),
        "binary launcher PATH must start with dev shadow/bin: {path_line}"
    );
    let token_line = lines.next().unwrap_or_default();
    let token_json: serde_json::Value =
        serde_json::from_str(token_line).expect("presence token env must be valid json");
    assert_eq!(token_json.get("uid").and_then(|v| v.as_u64()), Some(501));
    assert_eq!(
        token_json.get("scope").and_then(|v| v.as_str()),
        Some("class:session-runtime")
    );
}

/// T2 wiring test: when the daemon returns an Anthropic gateway bundle, the
/// launcher must pass Claude Code's documented gateway env vars through to the
/// child process unchanged.
#[test]
fn child_env_contains_anthropic_gateway_bundle_when_present() {
    use emberlink_cli::launcher::claude_code::{SessionRegistration, run_with_registration};
    use emberlink_cli::launcher::path_shadow::install_path_shadow;

    let tmp = short_tempdir();
    let socket_path = tmp.path().join("mock-daemon-anthropic-gateway.sock");
    let shadow_dir = tmp.path().join("shadow");
    let env_capture_file = tmp.path().join("anthropic_gateway_env.txt");

    install_path_shadow(&shadow_dir, &[]).unwrap();

    let close_called = spawn_mock_daemon(socket_path.clone());
    wait_for_socket(&socket_path);

    let registration = SessionRegistration {
        session_id: MOCK_SESSION_ID.to_string(),
        grant_id: MOCK_GRANT_ID.to_string(),
        proxy_url: MOCK_PROXY_URL.to_string(),
        presence_token_json: None,
        anthropic_base_url: Some(MOCK_PROXY_URL.to_string()),
        anthropic_custom_headers: Some(
            "X-Ember-Persona: persona-main\nX-Ember-Credential: anthropic-key\nX-Ember-Target: https://api.anthropic.com\nX-Ember-Grant-Id: grt-anthropic".to_string(),
        ),
        git_proxy_url: None,
        ssh_auth_sock: None,
        workflow_id: None,
        workflow_template: None,
    };

    let capture_path_str = env_capture_file.display().to_string();
    let child_script = format!(
        "printf '%s\\n%s' \"$ANTHROPIC_BASE_URL\" \"$ANTHROPIC_CUSTOM_HEADERS\" > '{capture_path_str}'; exit 0"
    );

    let code = run_with_registration(
        "/bin/sh",
        &["-c".to_string(), child_script],
        &registration,
        &socket_path,
        &shadow_dir,
    )
    .expect("spawn /bin/sh");
    assert_eq!(code, 0);

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !close_called.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }

    let observed = std::fs::read_to_string(&env_capture_file)
        .expect("child must have written Anthropic gateway env to capture file");
    assert!(
        observed.starts_with(MOCK_PROXY_URL),
        "ANTHROPIC_BASE_URL must be injected into the child env: {observed}"
    );
    assert!(
        observed.contains("X-Ember-Credential: anthropic-key"),
        "ANTHROPIC_CUSTOM_HEADERS must include X-Ember-Credential: {observed}"
    );
    assert!(
        observed.contains("X-Ember-Target: https://api.anthropic.com"),
        "ANTHROPIC_CUSTOM_HEADERS must include X-Ember-Target: {observed}"
    );
    assert!(
        observed.contains("X-Ember-Grant-Id: grt-anthropic"),
        "ANTHROPIC_CUSTOM_HEADERS must include X-Ember-Grant-Id: {observed}"
    );
}

/// T2 wiring test: when the daemon returns a session-scoped ssh-agent socket,
/// the launcher must pass it through as `SSH_AUTH_SOCK` for child git/ssh
/// processes to consume.
#[test]
fn child_env_contains_ssh_auth_sock_when_present() {
    use emberlink_cli::launcher::claude_code::{SessionRegistration, run_with_registration};
    use emberlink_cli::launcher::path_shadow::install_path_shadow;

    let tmp = short_tempdir();
    let socket_path = tmp.path().join("mock-daemon-ssh-auth.sock");
    let shadow_dir = tmp.path().join("shadow");
    let env_capture_file = tmp.path().join("ssh_auth_sock.txt");

    install_path_shadow(&shadow_dir, &[]).unwrap();

    let close_called = spawn_mock_daemon(socket_path.clone());
    wait_for_socket(&socket_path);

    let registration = SessionRegistration {
        session_id: MOCK_SESSION_ID.to_string(),
        grant_id: MOCK_GRANT_ID.to_string(),
        proxy_url: MOCK_PROXY_URL.to_string(),
        presence_token_json: None,
        anthropic_base_url: None,
        anthropic_custom_headers: None,
        git_proxy_url: None,
        ssh_auth_sock: Some("/tmp/ember-ssh-agent.sock".to_string()),
        workflow_id: None,
        workflow_template: None,
    };

    let capture_path_str = env_capture_file.display().to_string();
    let child_script = format!("printf '%s' \"$SSH_AUTH_SOCK\" > '{capture_path_str}'; exit 0");

    let code = run_with_registration(
        "/bin/sh",
        &["-c".to_string(), child_script],
        &registration,
        &socket_path,
        &shadow_dir,
    )
    .expect("spawn /bin/sh");
    assert_eq!(code, 0);

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !close_called.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }

    let observed = std::fs::read_to_string(&env_capture_file)
        .expect("child must have written SSH_AUTH_SOCK to capture file");
    assert_eq!(
        observed, "/tmp/ember-ssh-agent.sock",
        "SSH_AUTH_SOCK in child env must match the daemon-provided session socket"
    );
}
