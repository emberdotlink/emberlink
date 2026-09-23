//! Live product path: real `emberd` + real `ember` over the installed state
//! root. Proves S01 (Session -> typed Action -> Receipt), R01 (no Session), and
//! Receipt durability/verification after the Session and daemon are gone.

mod support;

use ember_authority::{AUTHORITY_STATE_DIRECTORY, audit::now_unix, control::AuthorityControl};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command},
    thread::sleep,
    time::{Duration, Instant},
};

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn binaries() -> (PathBuf, PathBuf) {
    let mut directory = std::env::current_exe().unwrap();
    directory.pop();
    if directory.ends_with("deps") {
        directory.pop();
    }
    (directory.join("emberd"), directory.join("ember"))
}

fn wait_for_socket(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        sleep(Duration::from_millis(25));
    }
    panic!("daemon control socket never appeared at {}", path.display());
}

fn ember(cli: &Path, home: &Path, args: &[&str]) -> (i32, String, String) {
    let output = Command::new(cli)
        .args(args)
        .env("HOME", home)
        .output()
        .unwrap();
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn live_session_action_produces_a_durable_verifiable_receipt() {
    let (daemon_binary, cli_binary) = binaries();
    assert!(daemon_binary.exists(), "build emberd before this test");
    assert!(cli_binary.exists(), "build ember before this test");

    // Short root: the Session endpoint is a Unix socket bound under this HOME,
    // and `sun_path` is limited to ~104 bytes.
    let home = tempfile::Builder::new()
        .prefix("pb4")
        .tempdir_in("/tmp")
        .unwrap();
    let state_root = home.path().join(AUTHORITY_STATE_DIRECTORY);
    std::fs::create_dir_all(state_root.parent().unwrap()).unwrap();
    let request = support::request_for_runtime(
        home.path(),
        "pb-s4-live",
        daemon_binary.clone(),
        cli_binary.clone(),
    );
    AuthorityControl::initialize_at(&state_root, request, &support::anchor(), now_unix()).unwrap();

    let daemon = Daemon(
        Command::new(&daemon_binary)
            .env("HOME", home.path())
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&state_root.join("control.sock"));

    // R01: the typed Action outside a Session never reaches the authority.
    let (code, _, stderr) = ember(
        &cli_binary,
        home.path(),
        &[
            "action",
            "run",
            ember_authority::model::ACTION_REF_TEXT,
            "--definition-digest",
            support::DEFINITION_DIGEST,
            "--input",
            "{\"challenge\":\"pb-s4-live\"}",
        ],
    );
    assert_ne!(code, 0);
    assert!(stderr.contains("session_required"), "{stderr}");

    // S01: the exact Brief invocation through the real CLI and daemon.
    let (code, stdout, stderr) = ember(
        &cli_binary,
        home.path(),
        &[
            "session",
            "open",
            "diagnostic",
            "--challenge",
            "pb-s4-live",
            "--",
            "ember",
            "action",
            "run",
            ember_authority::model::ACTION_REF_TEXT,
            "--definition-digest",
            support::DEFINITION_DIGEST,
            "--input",
            "{\"challenge\":\"pb-s4-live\"}",
        ],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let result: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(result["status"], "success");
    assert_eq!(result["facts"]["challenge"], "pb-s4-live");
    assert_eq!(result["facts"]["journal_health"], "ready");
    let receipt_id = result["receipt_id"].as_str().unwrap().to_owned();

    // Non-canonical typed input is refused before any Operation exists.
    let (code, _, stderr) = ember(
        &cli_binary,
        home.path(),
        &[
            "session",
            "open",
            "diagnostic",
            "--challenge",
            "pb-s4-live",
            "--",
            "ember",
            "action",
            "run",
            ember_authority::model::ACTION_REF_TEXT,
            "--definition-digest",
            support::DEFINITION_DIGEST,
            "--input",
            "{\"challenge\":\"pb-s4-live\", \"challenge\":\"pb-s4-live\"}",
        ],
    );
    assert_ne!(code, 0);
    assert!(stderr.contains("invalid_input"), "{stderr}");

    let (code, stdout, stderr) = ember(&cli_binary, home.path(), &["receipt", "list", "--json"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains(&receipt_id), "{stdout}");

    // S02: the Receipt survives the Session and a full daemon restart, and
    // still verifies through the restarted authority without a new Session.
    drop(daemon);
    let _ = std::fs::remove_file(state_root.join("control.sock"));
    let _restarted = Daemon(
        Command::new(&daemon_binary)
            .env("HOME", home.path())
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&state_root.join("control.sock"));
    let (code, stdout, stderr) = ember(
        &cli_binary,
        home.path(),
        &["receipt", "verify", &receipt_id],
    );
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout.trim(), format!("verified {receipt_id}"));
    let (code, stdout, stderr) = ember(&cli_binary, home.path(), &["receipt", "show", &receipt_id]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains(&receipt_id), "{stdout}");
}
