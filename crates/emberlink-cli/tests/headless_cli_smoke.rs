//! CLASSIFICATION: PUBLIC
//!
//! HEADLESS-ENROLL-CLI-ATTESTED-C — clap-parse smoke for the
//! `ember headless [enroll|revoke|status]` surface.
//!
//! The real socket round-trip is exercised by the qember.sh T3
//! scenario documented in `crates/emberlink-cli/src/headless.rs` —
//! that path needs a live daemon and is not appropriate for the
//! workspace `cargo test` gate. These tests pin only the clap
//! parsing layer: `--help` exits 0, malformed args exit non-zero,
//! the subcommand tree is reachable from the `ember` binary built
//! by this test target. Modeled on the same pattern as
//! `tests/version_flag.rs`.

use std::process::Command;

/// Path to the `ember` binary that cargo built for this test.
fn ember_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ember")
}

/// Run `ember <args...>` and capture stdout / stderr / exit code.
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
fn headless_help_lists_three_subcommands() {
    let (stdout, _stderr, code) = run_ember(&["headless", "--help"]);
    assert_eq!(code, 0, "ember headless --help should exit 0");
    assert!(
        stdout.contains("enroll"),
        "headless --help should list 'enroll'; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("revoke"),
        "headless --help should list 'revoke'; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("status"),
        "headless --help should list 'status'; stdout:\n{stdout}"
    );
}

#[test]
fn headless_enroll_help_exposes_duration_flag() {
    let (stdout, _stderr, code) = run_ember(&["headless", "enroll", "--help"]);
    assert_eq!(code, 0, "ember headless enroll --help should exit 0");
    assert!(
        stdout.contains("--input"),
        "enroll --help should advertise required --input; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("--duration"),
        "enroll --help should advertise --duration; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("--persona"),
        "enroll --help should advertise --persona; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("--yes"),
        "enroll --help should advertise --yes (non-interactive); stdout:\n{stdout}"
    );
}

#[test]
fn headless_revoke_help_exposes_enrollment_id_flag() {
    let (stdout, _stderr, code) = run_ember(&["headless", "revoke", "--help"]);
    assert_eq!(code, 0, "ember headless revoke --help should exit 0");
    assert!(
        stdout.contains("--enrollment-id"),
        "revoke --help should advertise --enrollment-id; stdout:\n{stdout}"
    );
}

#[test]
fn headless_status_help_exits_zero() {
    let (_stdout, _stderr, code) = run_ember(&["headless", "status", "--help"]);
    assert_eq!(code, 0, "ember headless status --help should exit 0");
}

#[test]
fn headless_unknown_subcommand_is_refused() {
    let (_stdout, stderr, code) = run_ember(&["headless", "extinguish"]);
    assert_ne!(
        code, 0,
        "ember headless <unknown> should exit non-zero; got 0 (stderr:\n{stderr})"
    );
}

// ─── HEADLESS-PREFLIGHT-LAYER1-CONSTRUCTS-PHASE2 — clap smoke ──────────
//
// PREFLIGHT-LAYER1-WIRED

#[test]
fn headless_help_lists_preflight_subcommand() {
    let (stdout, _stderr, code) = run_ember(&["headless", "--help"]);
    assert_eq!(code, 0, "ember headless --help should exit 0");
    assert!(
        stdout.contains("preflight"),
        "headless --help should list 'preflight'; stdout:\n{stdout}"
    );
}

#[test]
fn headless_preflight_help_exposes_input_and_json_flags() {
    let (stdout, _stderr, code) = run_ember(&["headless", "preflight", "--help"]);
    assert_eq!(code, 0, "ember headless preflight --help should exit 0");
    assert!(
        stdout.contains("--input"),
        "preflight --help should advertise --input; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("--json"),
        "preflight --help should advertise --json; stdout:\n{stdout}"
    );
}
