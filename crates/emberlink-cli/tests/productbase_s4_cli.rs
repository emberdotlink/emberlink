//! Real CLI Session -> typed Action -> durable Receipt product path.

use ember_authority::AUTHORITY_STATE_DIRECTORY;
use std::{
    io::Write as _,
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

fn assert_json_tamper_refused(
    cli: &Path,
    state_root: &Path,
    path: &Path,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let daemon_binary = daemon_binary();
    let daemon = Daemon(
        Command::new(&daemon_binary)
            .args(["--state-dir", state_root.to_str().unwrap()])
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&state_root.join("control.sock"));
    let original = std::fs::read(path).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    mutate(&mut value);
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    let (code, _, stderr) = ember(cli, state_root, &["status", "--json"]);
    assert_ne!(code, 0, "tampered {} was accepted", path.display());
    assert!(
        !stderr.is_empty(),
        "tampered {} gave no refusal",
        path.display()
    );
    drop(daemon);
    std::fs::write(path, original).unwrap();
    let socket = state_root.join("control.sock");
    if socket.exists() {
        std::fs::remove_file(&socket).unwrap();
    }
    let restored = Daemon(
        Command::new(&daemon_binary)
            .args(["--state-dir", state_root.to_str().unwrap()])
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&socket);
    let (code, _, stderr) = ember(cli, state_root, &["status", "--json"]);
    assert_eq!(
        code,
        0,
        "restoring {} did not recover: {stderr}",
        path.display()
    );
    drop(restored);
    if socket.exists() {
        std::fs::remove_file(socket).unwrap();
    }
}
fn expected_classification() -> serde_json::Value {
    serde_json::json!({
        "schema": "ember.development-classification/v1",
        "qualification_mode": "non-secret-diagnostic",
        "qualification_state": "provisional",
        "deployment_class": "disposable-qualification",
        "development_only": true,
        "production_classification": "non-production",
        "secret_classification": "non-secret",
        "release_provenance": "absent",
        "credential_use": "forbidden",
    })
}

fn assert_exact_classification(value: &serde_json::Value) {
    assert_eq!(value, &expected_classification());
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
    let omitted = Command::new(&cli_binary)
        .env("HOME", home.path())
        .current_dir(home.path())
        .args([
            "init",
            "diagnostic",
            "--project",
            home.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!omitted.status.success());
    assert!(String::from_utf8_lossy(&omitted.stderr).contains("state_root_unavailable"));
    assert!(!home.path().join(AUTHORITY_STATE_DIRECTORY).exists());
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
    assert_exact_classification(&initialized["classification"]);
    let initialization_receipt_id = initialized["receipt"]["receipt_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(initialized["evidence"]["kind"], "development");
    assert!(
        initialized["evidence"]["development_manifest_digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:"))
    );
    const DEFINITION_DIGEST: &str =
        "sha256:998427af8d0f017dc17eb574796759a0b6173edc9f3cdbc72a93b981e0a224e0";
    assert_eq!(initialized["action_definition_digest"], DEFINITION_DIGEST);
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
    assert!(String::from_utf8_lossy(&already_running.stderr).contains("authority_in_use"));

    let (code, stdout, stderr) = ember(&cli_binary, &state_root, &["status", "--json"]);
    assert_eq!(code, 0, "{stderr}");
    let status: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(status["state"], "ready");
    assert_eq!(status["schema"], "ember.authority-status/v1");
    assert_eq!(status["journal_health"], "ready");
    assert_eq!(status["active_sessions"], 0);
    assert!(status["maintenance_window_expiry"].as_u64().unwrap() > 0);
    assert!(
        status["initialization"]["root_intent_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    for field in [
        "development_bootstrap_attestation_digest",
        "development_manifest_digest",
        "development_qualification_record_digest",
    ] {
        assert!(
            status["initialization"]["evidence"][field]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
    }
    assert_exact_classification(&status["classification"]);
    assert_eq!(status["initialization"]["evidence"]["kind"], "development");

    let (code, stdout, stderr) = ember(&cli_binary, &state_root, &["receipt", "list", "--json"]);
    assert_eq!(code, 0, "{stderr}");
    let initial_receipts: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(initial_receipts.as_array().unwrap().len(), 1);
    assert_eq!(initial_receipts[0]["receipt_id"], initialization_receipt_id);
    assert_exact_classification(&initial_receipts[0]["classification"]);
    let generation_before_refusal = status["generation"].as_u64().unwrap();

    let (code, _, stderr) = ember(
        &cli_binary,
        &state_root,
        &[
            "action",
            "run",
            ember_authority::model::ACTION_REF_TEXT,
            "--definition-digest",
            DEFINITION_DIGEST,
            "--input",
            "{\"challenge\":\"pb-r2-ok\"}",
        ],
    );
    assert_ne!(code, 0);
    assert!(stderr.contains("session_required"), "{stderr}");
    let (_, stdout, _) = ember(&cli_binary, &state_root, &["receipt", "list", "--json"]);
    let after_refusal: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(after_refusal.as_array().unwrap().len(), 1);
    let (code, stdout, stderr) = ember(&cli_binary, &state_root, &["status", "--json"]);
    assert_eq!(code, 0, "{stderr}");
    let after_refusal_status: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        after_refusal_status["generation"],
        generation_before_refusal
    );

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
            DEFINITION_DIGEST,
            "--input",
            "{\"challenge\":\"pb-r2-ok\"}",
        ],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let result: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(result["status"], "success");
    assert_eq!(result["facts"]["challenge"], "pb-r2-ok");
    assert_eq!(result["facts"]["journal_health"], "ready");
    assert_exact_classification(&result["classification"]);
    assert_eq!(result["initialization_evidence"]["kind"], "development");
    let receipt_id = result["receipt_id"].as_str().unwrap().to_owned();
    let (code, stdout, stderr) = ember(&cli_binary, &state_root, &["status", "--json"]);
    assert_eq!(code, 0, "{stderr}");
    let post_session_status: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(post_session_status["active_sessions"], 0);

    let tip_path = state_root.join("protected-tip.json");
    let tip: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&tip_path).unwrap()).unwrap();
    let generation_path = state_root
        .join("generations")
        .join(format!("{:020}.json", tip["generation"].as_u64().unwrap()));
    let state_parent = state_root.parent().unwrap();
    let root_name = state_root.file_name().unwrap().to_str().unwrap();
    let high_water_path = state_parent.join(format!("{root_name}.high-water.json"));
    let continuity_path = state_parent.join(format!("{root_name}.continuity.json"));
    let zero_digest = format!("sha256:{}", "0".repeat(64));
    drop(daemon);
    std::fs::remove_file(state_root.join("control.sock")).unwrap();

    assert_json_tamper_refused(&cli_binary, &state_root, &generation_path, |state| {
        state["schema"] = serde_json::json!("tampered");
    });
    assert_json_tamper_refused(&cli_binary, &state_root, &generation_path, |state| {
        state["development_initialization"]["intent"]["initial_persona_id"] =
            serde_json::json!("persona:tampered");
    });
    assert_json_tamper_refused(&cli_binary, &state_root, &generation_path, |state| {
        state["development_initialization"]["bootstrap_attestation"]["attestation_signature"] =
            serde_json::json!("ed25519sig:00");
    });
    assert_json_tamper_refused(&cli_binary, &state_root, &generation_path, |state| {
        state["development_initialization"]["manifest"]["expiry"] = serde_json::json!(0);
    });
    assert_json_tamper_refused(&cli_binary, &state_root, &generation_path, |state| {
        state["development_initialization"]["qualification_record"]["schema"] =
            serde_json::json!("tampered");
    });
    assert_json_tamper_refused(&cli_binary, &state_root, &generation_path, |state| {
        state["checkpoint_digest"] = serde_json::json!(zero_digest.clone());
    });
    assert_json_tamper_refused(&cli_binary, &state_root, &generation_path, |state| {
        state["receipts"][initialization_receipt_id.as_str()]["checkpoint_digest"] =
            serde_json::json!(zero_digest.clone());
    });
    assert_json_tamper_refused(&cli_binary, &state_root, &generation_path, |state| {
        let canonical = state["receipts"][initialization_receipt_id.as_str()]["canonical_bytes"]
            .as_str()
            .unwrap();
        let mut envelope: serde_json::Value = serde_json::from_str(canonical).unwrap();
        envelope["signature"] = serde_json::json!("ed25519sig:00");
        state["receipts"][initialization_receipt_id.as_str()]["canonical_bytes"] =
            serde_json::json!(serde_json::to_string(&envelope).unwrap());
    });
    assert_json_tamper_refused(&cli_binary, &state_root, &tip_path, |tip| {
        tip["state_digest"] = serde_json::json!(zero_digest.clone());
    });
    assert_json_tamper_refused(&cli_binary, &state_root, &high_water_path, |high_water| {
        high_water["protected_tip_digest"] = serde_json::json!(zero_digest.clone());
    });
    assert_json_tamper_refused(&cli_binary, &state_root, &continuity_path, |continuity| {
        continuity["protected_tip_digest"] = serde_json::json!(zero_digest.clone());
    });

    let restarted = Daemon(
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
    assert_exact_classification(&receipts[0]["classification"]);
    let (code, stdout, stderr) = ember(
        &cli_binary,
        &state_root,
        &["receipt", "verify", &receipt_id],
    );
    assert_eq!(code, 0, "{stderr}");
    let verified: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(verified["state"], "verified");
    assert_eq!(verified["receipt_id"], receipt_id);
    assert_exact_classification(&verified["classification"]);
    let (code, stdout, stderr) = ember(&cli_binary, &state_root, &["receipt", "show", &receipt_id]);
    assert_eq!(code, 0, "{stderr}");
    let shown: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_exact_classification(&shown["body"]["classification"]);
    assert_eq!(
        shown["body"]["initialization_evidence"]["kind"],
        "development"
    );
    let (code, stdout, stderr) = ember(
        &cli_binary,
        &state_root,
        &["receipt", "verify", &initialization_receipt_id],
    );
    assert_eq!(code, 0, "{stderr}");
    let verified_initialization: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(verified_initialization["state"], "verified");
    assert_exact_classification(&verified_initialization["classification"]);
    let (code, stdout, stderr) = ember(
        &cli_binary,
        &state_root,
        &["receipt", "show", &initialization_receipt_id],
    );
    assert_eq!(code, 0, "{stderr}");
    let shown_initialization: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        shown_initialization["body"]["initialization_evidence"]["kind"],
        "development"
    );
    assert_exact_classification(&shown_initialization["body"]["classification"]);
    let mut tampered_generation = std::fs::read(&generation_path).unwrap();
    tampered_generation.push(b' ');
    std::fs::write(&generation_path, tampered_generation).unwrap();
    let (code, _, stderr) = ember(&cli_binary, &state_root, &["status", "--json"]);
    assert_ne!(code, 0);
    assert!(stderr.contains("restore_failed"), "{stderr}");

    drop(restarted);
    home.close().unwrap();

    let replacement_home = tempfile::Builder::new()
        .prefix("pb-r2-replacement")
        .tempdir_in("/private/tmp")
        .unwrap();
    let replacement_root = replacement_home.path().join(AUTHORITY_STATE_DIRECTORY);
    std::fs::create_dir_all(replacement_root.parent().unwrap()).unwrap();
    std::fs::set_permissions(
        replacement_root.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let (code, stdout, stderr) = ember(
        &cli_binary,
        &replacement_root,
        &[
            "init",
            "diagnostic",
            "--project",
            replacement_home.path().to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let replacement_daemon = Daemon(
        Command::new(&daemon_binary)
            .args(["--state-dir", replacement_root.to_str().unwrap()])
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&replacement_root.join("control.sock"));
    let (code, _, stderr) = ember(&cli_binary, &replacement_root, &["status", "--json"]);
    assert_eq!(code, 0, "{stderr}");
    drop(replacement_daemon);
    replacement_home.close().unwrap();
}
#[test]
fn replaced_cli_refuses_after_initialization() {
    let installation = tempfile::Builder::new()
        .prefix("pb-r2-cli-replacement")
        .tempdir_in("/private/tmp")
        .unwrap();
    let cli = installation.path().join("ember");
    let installed_daemon = installation.path().join("emberd");
    std::fs::copy(PathBuf::from(env!("CARGO_BIN_EXE_ember")), &cli).unwrap();
    std::fs::copy(daemon_binary(), &installed_daemon).unwrap();

    let home = tempfile::Builder::new()
        .prefix("pb-r2-cli-replacement-home")
        .tempdir_in("/private/tmp")
        .unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_root = home.path().join(AUTHORITY_STATE_DIRECTORY);
    std::fs::create_dir_all(state_root.parent().unwrap()).unwrap();
    std::fs::set_permissions(
        state_root.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let (code, _, stderr) = ember(
        &cli,
        &state_root,
        &[
            "init",
            "diagnostic",
            "--project",
            home.path().to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "{stderr}");

    let daemon = Daemon(
        Command::new(&installed_daemon)
            .args(["--state-dir", state_root.to_str().unwrap()])
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&state_root.join("control.sock"));
    let (code, _, stderr) = ember(&cli, &state_root, &["status", "--json"]);
    assert_eq!(code, 0, "{stderr}");
    let tip_path = state_root.join("protected-tip.json");
    let tip_before = std::fs::read(&tip_path).unwrap();

    std::fs::OpenOptions::new()
        .append(true)
        .open(&cli)
        .unwrap()
        .write_all(b"replacement")
        .unwrap();
    let (code, _, stderr) = ember(&cli, &state_root, &["status", "--json"]);
    assert_ne!(code, 0);
    assert!(stderr.contains("untrusted_launcher"), "{stderr}");
    assert_eq!(std::fs::read(&tip_path).unwrap(), tip_before);

    drop(daemon);
    home.close().unwrap();
}

#[test]
fn initialization_refuses_untrusted_daemon_sibling_without_state_writes() {
    let installation = tempfile::Builder::new()
        .prefix("pb-r2-install")
        .tempdir_in("/private/tmp")
        .unwrap();
    let cli = installation.path().join("ember");
    let daemon = installation.path().join("emberd");
    std::fs::copy(PathBuf::from(env!("CARGO_BIN_EXE_ember")), &cli).unwrap();

    let home = tempfile::Builder::new()
        .prefix("pb-r2-init-refusal")
        .tempdir_in("/private/tmp")
        .unwrap();
    let state_root = home.path().join(AUTHORITY_STATE_DIRECTORY);
    std::fs::create_dir_all(state_root.parent().unwrap()).unwrap();
    std::fs::set_permissions(
        state_root.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let init_args = [
        "init",
        "diagnostic",
        "--project",
        home.path().to_str().unwrap(),
    ];
    let assert_no_state = || {
        assert!(!state_root.exists());
        let parent = state_root.parent().unwrap();
        let name = state_root.file_name().unwrap().to_str().unwrap();
        assert!(!parent.join(format!("{name}.continuity.json")).exists());
        assert!(!parent.join(format!("{name}.continuity.next.json")).exists());
        assert!(!parent.join(format!("{name}.high-water.json")).exists());
    };
    let (code, _, stderr) = ember(
        &cli,
        &state_root,
        &[
            "init",
            "diagnostic",
            "--project",
            home.path().to_str().unwrap(),
            "--signer",
            "injected",
        ],
    );
    assert_ne!(code, 0);
    assert!(
        stderr.contains("invalid_initialization_command"),
        "{stderr}"
    );
    assert_no_state();

    let (code, _, stderr) = ember(&cli, &state_root, &init_args);
    assert_ne!(code, 0);
    assert!(stderr.contains("bootstrap_artifact_invalid"), "{stderr}");
    assert_no_state();

    std::os::unix::fs::symlink(daemon_binary(), &daemon).unwrap();
    let (code, _, stderr) = ember(&cli, &state_root, &init_args);
    assert_ne!(code, 0);
    assert!(stderr.contains("bootstrap_artifact_invalid"), "{stderr}");
    assert_no_state();
    std::fs::remove_file(&daemon).unwrap();

    std::fs::copy(daemon_binary(), &daemon).unwrap();
    std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o000)).unwrap();
    let (code, _, stderr) = ember(&cli, &state_root, &init_args);
    assert_ne!(code, 0);
    assert!(stderr.contains("bootstrap_artifact_invalid"), "{stderr}");
    assert_no_state();
}
