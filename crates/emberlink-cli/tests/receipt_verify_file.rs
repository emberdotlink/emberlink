//! Integration tests for `ember receipt verify --file <PATH>` (RECEIPT-VERIFY-FILE-MODE).
//!
//! Drives the real `ember` binary so the clap conflicts_with rule and the
//! filesystem error paths are both covered. The positive verification path
//! is covered by the unit test
//! `verify_receipt_round_trips_through_serde_json` in
//! `crates/ember-daemon/src/receipt.rs`, which exercises the same
//! deserialize-and-verify code shape without needing the daemon spawned.

use std::io::Write as _;
use std::process::{Command, Stdio};

fn ember_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ember")
}

fn run(args: &[&str]) -> (String, String, i32) {
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
fn verify_with_id_and_file_is_a_clap_conflict() {
    let (_stdout, stderr, code) =
        run(&["receipt", "verify", "abc123", "--file", "/tmp/whatever.json"]);
    assert_ne!(code, 0, "id + --file together must fail");
    let combined = stderr.to_lowercase();
    assert!(
        combined.contains("cannot be used") || combined.contains("conflict"),
        "expected clap conflict message, got stderr: {stderr}"
    );
}

#[test]
fn verify_file_with_nonexistent_path_errors() {
    let (_stdout, stderr, code) = run(&[
        "receipt",
        "verify",
        "--file",
        "/nonexistent-emberlink-receipt-9d2f1.json",
    ]);
    assert_ne!(code, 0, "missing file must fail");
    assert!(
        stderr.contains("cannot read") || stderr.contains("No such file"),
        "expected file-read error, got: {stderr}"
    );
}

#[test]
fn verify_file_with_garbage_json_errors() {
    let (_stdout, stderr, code) = {
        let mut child = Command::new(ember_bin())
            .args(["receipt", "verify", "--file", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ember");
        {
            let stdin = child.stdin.as_mut().expect("stdin");
            stdin.write_all(b"this is not a receipt").expect("write stdin");
        }
        let out = child.wait_with_output().expect("wait ember");
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.code().unwrap_or(-1),
        )
    };
    assert_ne!(code, 0, "garbage JSON on stdin must fail");
    assert!(
        stderr.contains("Grant Receipt") || stderr.contains("not a valid"),
        "expected JSON-parse error, got: {stderr}"
    );
}
