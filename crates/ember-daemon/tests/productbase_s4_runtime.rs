//! Installed daemon artifact authentication at the real process boundary.

#[path = "../../ember-authority/tests/support/mod.rs"]
mod support;

use ember_authority::{AUTHORITY_STATE_DIRECTORY, audit::now_unix, control::AuthorityControl};
use std::{
    io::Write,
    os::unix::net::UnixStream,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for_socket(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("daemon socket never appeared at {}", path.display());
}

#[test]
fn replaced_daemon_artifact_refuses_before_opening_authority_rpc() {
    let built_daemon = std::path::PathBuf::from(env!("CARGO_BIN_EXE_emberd"));
    let installation = tempfile::tempdir().unwrap();
    let daemon_binary = installation.path().join("emberd");
    std::fs::copy(built_daemon, &daemon_binary).unwrap();

    let home = tempfile::Builder::new()
        .prefix("pb4")
        .tempdir_in("/tmp")
        .unwrap();
    let state_root = home.path().join(AUTHORITY_STATE_DIRECTORY);
    std::fs::create_dir_all(state_root.parent().unwrap()).unwrap();
    let request = support::request_for_runtime(
        home.path(),
        "pb-s4-replaced-daemon",
        daemon_binary.clone(),
        std::env::current_exe().unwrap(),
    );
    AuthorityControl::initialize_at(&state_root, request, &support::anchor(), now_unix()).unwrap();

    std::fs::OpenOptions::new()
        .append(true)
        .open(&daemon_binary)
        .unwrap()
        .write_all(b"altered")
        .unwrap();
    let output = Command::new(&daemon_binary)
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("untrusted_daemon"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!state_root.join("control.sock").exists());
}

#[test]
fn daemon_refuses_concurrent_owner_and_recovers_stale_socket() {
    let daemon_binary = std::path::PathBuf::from(env!("CARGO_BIN_EXE_emberd"));
    let home = tempfile::Builder::new()
        .prefix("pb4-daemon-lease")
        .tempdir_in("/private/tmp")
        .unwrap();
    let state_root = home.path().join(AUTHORITY_STATE_DIRECTORY);
    std::fs::create_dir_all(state_root.parent().unwrap()).unwrap();
    let request = support::request_for_runtime(
        home.path(),
        "pb-s4-daemon-lease",
        daemon_binary.clone(),
        std::env::current_exe().unwrap(),
    );
    AuthorityControl::initialize_at(&state_root, request, &support::anchor(), now_unix()).unwrap();

    let mut daemon = Daemon(
        Command::new(&daemon_binary)
            .args(["--state-dir", state_root.to_str().unwrap()])
            .env("HOME", home.path())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let socket = state_root.join("control.sock");
    wait_for_socket(&socket);

    let second = Command::new(&daemon_binary)
        .args(["--state-dir", state_root.to_str().unwrap()])
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("daemon_already_running"),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );

    daemon.0.kill().unwrap();
    daemon.0.wait().unwrap();
    assert!(
        socket.exists(),
        "forced termination should leave a stale socket"
    );

    let mut restarted = Daemon(
        Command::new(&daemon_binary)
            .args(["--state-dir", state_root.to_str().unwrap()])
            .env("HOME", home.path())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    thread::sleep(Duration::from_millis(250));
    assert!(restarted.0.try_wait().unwrap().is_none());
    UnixStream::connect(&socket).unwrap();
}
