use std::process::Command;

fn ember_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ember")
}

fn assert_retired(args: &[&str]) {
    let out = Command::new(ember_bin())
        .args(args)
        .output()
        .expect("spawn ember");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code().unwrap_or(-1), 2);
    assert!(
        stdout.is_empty(),
        "retired survey must fail before printing prompts; stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("retired for v0.3.0 by operator correction 2026-06-17"),
        "stderr should explain the survey retirement; stderr:\n{stderr}"
    );
}

#[test]
fn v030_survey_no_input_refuses_before_prompting() {
    assert_retired(&["--no-input", "admin", "v030-survey", "complete"]);
}

#[test]
fn v030_survey_interactive_path_is_retired() {
    assert_retired(&["admin", "v030-survey", "complete"]);
}
