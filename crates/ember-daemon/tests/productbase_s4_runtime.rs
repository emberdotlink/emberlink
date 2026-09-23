//! Installed daemon artifact authentication at the real process boundary.

use ember_authority::{
    audit::now_unix, control::AuthorityControl, diagnostic_bootstrap::build_request,
};
use std::{
    io::Write,
    os::unix::{
        fs::{MetadataExt as _, PermissionsExt},
        net::UnixStream,
    },
    process::{Child, Command, Output, Stdio},
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
fn wait_for_exit(mut child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        thread::sleep(Duration::from_millis(25));
    }
    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();
    panic!(
        "second daemon remained live; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn replaced_daemon_artifact_refuses_before_opening_authority_rpc() {
    let built_daemon = std::path::PathBuf::from(env!("CARGO_BIN_EXE_emberd"));
    let installation = tempfile::tempdir().unwrap();
    let daemon_binary = installation.path().join("emberd");
    std::fs::copy(built_daemon, &daemon_binary).unwrap();

    let home = tempfile::Builder::new()
        .prefix("pb4")
        .tempdir_in("/private/tmp")
        .unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_root = home.path().join("authority");
    let cli_binary = std::env::current_exe().unwrap();
    let request = build_request(home.path(), &cli_binary, &daemon_binary, now_unix()).unwrap();
    AuthorityControl::initialize(&state_root, request).unwrap();

    std::fs::OpenOptions::new()
        .append(true)
        .open(&daemon_binary)
        .unwrap()
        .write_all(b"altered")
        .unwrap();
    let output = Command::new(&daemon_binary)
        .args(["--state-dir", state_root.to_str().unwrap()])
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
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_root = home.path().join("authority");
    let cli_binary = std::env::current_exe().unwrap();
    let request = build_request(home.path(), &cli_binary, &daemon_binary, now_unix()).unwrap();
    AuthorityControl::initialize(&state_root, request).unwrap();

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
        String::from_utf8_lossy(&second.stderr).contains("authority_in_use"),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let original_socket = std::fs::symlink_metadata(&socket).unwrap();
    std::fs::remove_file(state_root.join("daemon.lock")).unwrap();
    let replacement_lock_second = wait_for_exit(
        Command::new(&daemon_binary)
            .args(["--state-dir", state_root.to_str().unwrap()])
            .env("HOME", home.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    assert!(!replacement_lock_second.status.success());
    assert!(
        String::from_utf8_lossy(&replacement_lock_second.stderr).contains("authority_in_use"),
        "{}",
        String::from_utf8_lossy(&replacement_lock_second.stderr)
    );
    let current_socket = std::fs::symlink_metadata(&socket).unwrap();
    assert_eq!(
        (current_socket.dev(), current_socket.ino()),
        (original_socket.dev(), original_socket.ino())
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

#[test]
fn daemon_sigterm_exits_cleanly_and_removes_control_socket() {
    let daemon_binary = std::path::PathBuf::from(env!("CARGO_BIN_EXE_emberd"));
    let home = tempfile::Builder::new()
        .prefix("pb4-daemon-stop")
        .tempdir_in("/private/tmp")
        .unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_root = home.path().join("authority");
    let cli_binary = std::env::current_exe().unwrap();
    let request = build_request(home.path(), &cli_binary, &daemon_binary, now_unix()).unwrap();
    AuthorityControl::initialize(&state_root, request).unwrap();

    let daemon = Command::new(&daemon_binary)
        .args(["--state-dir", state_root.to_str().unwrap()])
        .env("HOME", home.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let socket = state_root.join("control.sock");
    wait_for_socket(&socket);
    assert_eq!(
        unsafe { libc::kill(daemon.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    let output = wait_for_exit(daemon);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!socket.exists());
}
