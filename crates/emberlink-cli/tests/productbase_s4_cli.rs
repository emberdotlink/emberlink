//! Real CLI Session -> typed Action -> durable Receipt product path.

use ember_authority::AUTHORITY_STATE_DIRECTORY;
use std::{
    os::unix::fs::PermissionsExt as _,
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

fn daemon_binary() -> PathBuf {
    let mut directory = std::env::current_exe().unwrap();
    directory.pop();
    if directory.ends_with("deps") {
        directory.pop();
    }
    directory.join("emberd")
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

fn ember(cli: &Path, state_root: &Path, args: &[&str]) -> (i32, String, String) {
    let output = Command::new(cli)
        .arg("--state-dir")
        .arg(state_root)
        .current_dir(
            state_root
                .ancestors()
                .nth(3)
                .expect("state root must be under the test HOME"),
        )
        .args(args)
        .output()
        .unwrap();
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn session_action_and_post_session_receipt_use_real_binaries() {
    let daemon_binary = daemon_binary();
    let cli_binary = PathBuf::from(env!("CARGO_BIN_EXE_ember"));
    assert!(
        daemon_binary.exists(),
        "run the fixed daemon test before this target"
    );

    let home = tempfile::Builder::new()
        .prefix("pb4")
        .tempdir_in("/private/tmp")
        .unwrap();
    let state_root = home.path().join(AUTHORITY_STATE_DIRECTORY);
    std::fs::create_dir_all(state_root.parent().unwrap()).unwrap();
    std::fs::set_permissions(
        state_root.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let (code, stdout, stderr) = ember(
        &cli_binary,
        &state_root,
        &[
            "init",
            "diagnostic",
            "--project",
            home.path().to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let initialized: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(initialized["state"], "initialized");
    assert_eq!(
        initialized["classification"]["production_classification"],
        "non-production"
    );
    assert_eq!(
        initialized["classification"]["deployment_class"],
        "disposable-qualification"
    );
    assert_eq!(initialized["evidence"]["kind"], "development");
    assert!(
        initialized["evidence"]["development_manifest_digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:"))
    );
    let definition_digest = initialized["action_definition_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    let (code, _, stderr) = ember(
        &cli_binary,
        &state_root,
        &[
            "init",
            "diagnostic",
            "--project",
            home.path().to_str().unwrap(),
        ],
    );
    assert_ne!(code, 0);
    assert!(stderr.contains("already_initialized"), "{stderr}");

    let daemon = Daemon(
        Command::new(&daemon_binary)
            .args(["--state-dir", state_root.to_str().unwrap()])
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&state_root.join("control.sock"));

    let already_running = Command::new(&daemon_binary)
        .args(["--state-dir", state_root.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!already_running.status.success());
    assert!(String::from_utf8_lossy(&already_running.stderr).contains("daemon_already_running"));

    let (code, stdout, stderr) = ember(&cli_binary, &state_root, &["status", "--json"]);
    assert_eq!(code, 0, "{stderr}");
    let status: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(status["state"], "ready");
    assert_eq!(
        status["classification"]["production_classification"],
        "non-production"
    );
    assert_eq!(status["initialization"]["evidence"]["kind"], "development");

    let (code, stdout, stderr) = ember(&cli_binary, &state_root, &["receipt", "list", "--json"]);
    assert_eq!(code, 0, "{stderr}");
    let initial_receipts: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(initial_receipts.as_array().unwrap().len(), 1);

    let (code, _, stderr) = ember(
        &cli_binary,
        &state_root,
        &[
            "action",
            "run",
            ember_authority::model::ACTION_REF_TEXT,
            "--definition-digest",
            definition_digest.as_str(),
            "--input",
            "{\"challenge\":\"pb-r2-ok\"}",
        ],
    );
    assert_ne!(code, 0);
    assert!(stderr.contains("session_required"), "{stderr}");
    let (_, stdout, _) = ember(&cli_binary, &state_root, &["receipt", "list", "--json"]);
    let after_refusal: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(after_refusal.as_array().unwrap().len(), 1);

    let (code, stdout, stderr) = ember(
        &cli_binary,
        &state_root,
        &[
            "session",
            "open",
            "diagnostic",
            "--challenge",
            "pb-r2-ok",
            "--",
            "ember",
            "action",
            "run",
            ember_authority::model::ACTION_REF_TEXT,
            "--definition-digest",
            definition_digest.as_str(),
            "--input",
            "{\"challenge\":\"pb-r2-ok\"}",
        ],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let result: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(result["status"], "success");
    assert_eq!(result["facts"]["challenge"], "pb-r2-ok");
    assert_eq!(result["facts"]["journal_health"], "ready");
    assert_eq!(
        result["classification"]["production_classification"],
        "non-production"
    );
    assert_eq!(result["initialization_evidence"]["kind"], "development");
    let receipt_id = result["receipt_id"].as_str().unwrap().to_owned();

    drop(daemon);
    std::fs::remove_file(state_root.join("control.sock")).unwrap();
    let _restarted = Daemon(
        Command::new(&daemon_binary)
            .args(["--state-dir", state_root.to_str().unwrap()])
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&state_root.join("control.sock"));
    let (code, stdout, stderr) = ember(&cli_binary, &state_root, &["receipt", "list", "--json"]);
    assert_eq!(code, 0, "{stderr}");
    let receipts: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(receipts.as_array().unwrap().len(), 2);
    assert!(stdout.contains(&receipt_id), "{stdout}");
    assert_eq!(
        receipts[0]["classification"]["production_classification"],
        "non-production"
    );
    let (code, stdout, stderr) = ember(
        &cli_binary,
        &state_root,
        &["receipt", "verify", &receipt_id],
    );
    assert_eq!(code, 0, "{stderr}");
    let verified: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(verified["state"], "verified");
    assert_eq!(verified["receipt_id"], receipt_id);
    assert_eq!(
        verified["classification"]["production_classification"],
        "non-production"
    );
    let (code, stdout, stderr) = ember(&cli_binary, &state_root, &["receipt", "show", &receipt_id]);
    assert_eq!(code, 0, "{stderr}");
    let shown: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        shown["body"]["classification"]["production_classification"],
        "non-production"
    );
    assert_eq!(
        shown["body"]["initialization_evidence"]["kind"],
        "development"
    );
}
