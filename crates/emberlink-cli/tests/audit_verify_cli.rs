use std::process::Command;

use tempfile::TempDir;

fn ember_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ember")
}

fn write_config(home: &TempDir) -> std::path::PathBuf {
    let ember_dir = home.path().join(".ember");
    let data_dir = ember_dir.join("data");
    let socket_dir = ember_dir.join("run");
    let pid_file = socket_dir.join("emberd.pid");
    let policy_file = ember_dir.join("policy.toml");
    let config_path = ember_dir.join("config.toml");
    std::fs::create_dir_all(&ember_dir).expect("create ~/.ember");
    std::fs::write(
        &config_path,
        format!(
            "[daemon]\ndata_dir = \"{}\"\nsocket_dir = \"{}\"\npid_file = \"{}\"\npolicy_file = \"{}\"\nlog_level = \"info\"\n",
            data_dir.display(),
            socket_dir.display(),
            pid_file.display(),
            policy_file.display(),
        ),
    )
    .expect("write config");
    config_path
}

fn run_ember_in_home(args: &[&str], home: &TempDir) -> (String, String, i32) {
    let config_path = write_config(home);
    let out = Command::new(ember_bin())
        .args(args)
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("XDG_DATA_HOME", home.path().join(".local/share"))
        .env("EMBER_CONFIG", config_path)
        .env_remove("EMBER_DEMO_DIR")
        .output()
        .expect("spawn ember");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn audit_verify_rejects_invalid_since_before_daemon_socket() {
    let home = tempfile::tempdir().unwrap();
    let (stdout, stderr, code) = run_ember_in_home(&["audit", "verify", "--since", "7x"], &home);

    assert_eq!(code, 2, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.is_empty(),
        "invalid --since should not render audit output; stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("invalid --since value"),
        "stderr should explain the usage error; stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("daemon socket"),
        "invalid --since should fail before daemon access; stderr:\n{stderr}"
    );
}
