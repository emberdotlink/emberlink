//! Installed daemon artifact authentication at the real process boundary.

#[path = "../../ember-authority/tests/support/mod.rs"]
mod support;

use ember_authority::{AUTHORITY_STATE_DIRECTORY, audit::now_unix, control::AuthorityControl};
use std::{io::Write, process::Command};

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
