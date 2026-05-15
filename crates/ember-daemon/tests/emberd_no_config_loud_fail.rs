//!
//! implementation-note-82 — emberd refuses to start when
//! no on-disk config exists. Closes the production silent-fallback
//! that was the May-12 25-hour leaked-daemon incident root cause.

use std::process::Command;

#[test]
fn emberd_with_no_config_exits_loudly() {
    let tmp = tempfile::tempdir().expect("create tempdir");

    let exe = env!("CARGO_BIN_EXE_emberd");
    let output = Command::new(exe)
        // Point HOME at an empty tmpdir so default_config_path() resolves to
        // a non-existent file. Clear EMBER_CONFIG so the env override doesn't
        // accidentally point at the operator's real config from the
        // surrounding test-runner env.
        .env("HOME", tmp.path())
        .env_remove("EMBER_CONFIG")
        .output()
        .expect("spawn emberd");

    assert!(
        !output.status.success(),
        "emberd must exit non-zero when no config exists; got success"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("emberd: no ember config found"),
        "loud-fail message missing from stderr: {stderr}"
    );
    assert!(
        stderr.contains("ember init"),
        "loud-fail must point at `ember init`: {stderr}"
    );
}

#[test]
fn emberd_honors_ember_config_env_override() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let bogus = tmp.path().join("definitely-not-a-config.toml");

    let exe = env!("CARGO_BIN_EXE_emberd");
    let output = Command::new(exe)
        .env("HOME", tmp.path())
        .env("EMBER_CONFIG", &bogus)
        .output()
        .expect("spawn emberd");

    assert!(!output.status.success(), "emberd must exit non-zero");

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Message must reference the EMBER_CONFIG-resolved path, not the
    // default ~/.ember/config.toml path.
    assert!(
        stderr.contains(bogus.to_string_lossy().as_ref()),
        "loud-fail must reference the EMBER_CONFIG-resolved path: {stderr}"
    );
}
