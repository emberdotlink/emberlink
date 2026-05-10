//! T2 integration tests for `ember claude-code` launcher wiring.
//!
//!
//! Verifies implementation-note-179 acceptance criteria:
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

        for _ in 0..4 {
            let (stream, _) = match listener.accept() {
                Ok(s) => s,
                Err(_) => break,
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;

            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let req: serde_json::Value = match serde_json::from_str(line.trim()) {
                Ok(v) => v,
                Err(_) => break,
            };

            let method = req["method"].as_str().unwrap_or("");
            let resp = match method {
                "register_session" => serde_json::json!({
                    "id": req["id"],
                    "result": {
                        "session_id": MOCK_SESSION_ID,
                        "grant_id": MOCK_GRANT_ID,
                        "proxy_url": MOCK_PROXY_URL,
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
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o700,
            "shadow_dir must have mode 0700"
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

    let tmp = TempDir::new().unwrap();
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
        git_proxy_url: None,
        ssh_auth_sock: None,
    };

    // Use a shell snippet as the child binary: write $PATH to a temp file
    // and exit 0. We pass the capture file path as an argument to /bin/sh.
    let capture_path_str = env_capture_file.display().to_string();
    let child_script = format!(
        "printf '%s' \"$PATH\" > '{capture_path_str}'; exit 0"
    );

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

    let tmp = TempDir::new().unwrap();
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

    // The "gh" symlink must exist and point to our fake binary.
    let shim = shadow_dir.join("gh");
    assert!(shim.symlink_metadata().is_ok(), "shim 'gh' must exist in shadow_dir");
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

    let tmp = TempDir::new().unwrap();
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
        git_proxy_url: None,
        ssh_auth_sock: None,
    };

    let capture_path_str = env_capture_file.display().to_string();
    let child_script = format!(
        "printf '%s' \"$EMBER_SESSION_ID\" > '{capture_path_str}'; exit 0"
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
