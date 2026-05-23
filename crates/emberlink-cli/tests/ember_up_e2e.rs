//! Hidden `ember up` contract guard.
//!
//! The old ignored compose scaffold test went stale once the real
//! isolated/container launcher truth moved to `ember claude --isolated`.
//! Keep the filename checkpoint, but make the executable contract honest:
//! hidden `ember up` must fail fast and point older scripts at the
//! canonical isolated launcher.

use std::process::Command;

fn ember_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ember")
}

fn run_ember(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(ember_bin())
        .args(args)
        .output()
        .expect("spawn ember");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn ember_up_fails_fast_with_canonical_isolated_launcher_guidance() {
    let (stdout, stderr, code) = run_ember(&["up"]);
    assert_ne!(code, 0, "`ember up` must fail loudly once retired");
    assert!(
        stdout.trim().is_empty(),
        "legacy redirect should explain itself on stderr, not stdout: {stdout}"
    );
    assert!(
        stderr.contains("hidden legacy scaffold"),
        "expected legacy redirect rationale on stderr: {stderr}"
    );
    assert!(
        stderr.contains("ember claude --isolated"),
        "expected canonical isolated launcher guidance on stderr: {stderr}"
    );
}

#[test]
fn ember_up_threads_profile_into_redirect_guidance() {
    let (_stdout, stderr, code) = run_ember(&["up", "--profile", "demo"]);
    assert_ne!(code, 0, "`ember up --profile demo` must fail loudly");
    assert!(
        stderr.contains("ember claude --isolated --preset demo"),
        "expected profile-aware redirect guidance on stderr: {stderr}"
    );
}
