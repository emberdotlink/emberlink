//! CLASSIFICATION: PUBLIC
//!
//! META-T3-USER-SOCKET-LEAK-GUARD-B-EMBERD — emberd refuses to start when
//! no on-disk config exists. Closes the production silent-fallback
//! that was the May-12 25-hour leaked-daemon incident root cause.

use std::process::Command;

#[test]
fn emberd_with_no_config_exits_loudly() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let missing_config = tmp.path().join("missing-config.toml");

    let exe = env!("CARGO_BIN_EXE_emberd");
    let output = Command::new(exe)
        // Force config resolution to a missing temp path. The default daemon
        // config is now an ADR-218 system path and may exist on a developer
        // host, so HOME isolation alone is not sufficient.
        .env("HOME", tmp.path())
        .env("EMBER_CONFIG", &missing_config)
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
