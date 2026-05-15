//! Integration test for implementation-note-279.
//!
//! Pins the load_config loud-fail contract: when no `--config`,
//! `EMBER_CONFIG`, or `EMBER_DEMO_DIR` is set, AND `~/.ember/config.toml`
//! does not exist, the CLI must exit 1 with a stderr message pointing at
//! `ember init`. The May-12 25-hour leaked-daemon incident was rooted in
//! the prior silent `DaemonConfig::default()` fallback inheriting
//! user-home paths in test contexts.

use std::process::Command;

fn ember_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ember")
}

#[test]
fn cli_exits_loudly_when_no_config_resolves() {
    let tmp = tempfile::tempdir().expect("tmpdir");

    // Drive the binary against a clean HOME so `~/.ember/config.toml`
    // resolves to a non-existent path inside the tempdir. Clear all
    // EMBER_* env vars so no autodiscovery path applies.
    let out = Command::new(ember_bin())
        .args(["audit", "show"])
        .env_clear()
        .env("HOME", tmp.path())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .output()
        .expect("spawn ember");

    let stderr = String::from_utf8_lossy(&out.stderr);
    let exit_code = out.status.code().unwrap_or(-1);

    assert_eq!(exit_code, 1, "expected exit 1, got {exit_code}; stderr: {stderr}");
    assert!(
        stderr.contains("no ember config found"),
        "expected stderr to contain `no ember config found`; got: {stderr}"
    );
    assert!(
        stderr.contains("ember init"),
        "expected stderr to mention `ember init`; got: {stderr}"
    );
}
