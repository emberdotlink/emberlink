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

fn help_command_names(stdout: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut in_commands = false;
    for line in stdout.lines() {
        if line == "Commands:" {
            in_commands = true;
            continue;
        }
        if in_commands {
            if line.trim().is_empty() {
                break;
            }
            if let Some(rest) = line.strip_prefix("  ")
                && let Some((name, _)) = rest.split_once(' ')
            {
                names.push(name);
            }
        }
    }
    names
}

#[test]
fn top_level_help_centers_friendly_surface() {
    let (stdout, stderr, code) = run_ember(&["--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    let names = help_command_names(&stdout);

    for visible in [
        "init",
        "daemon",
        "vault",
        "grant",
        "approval",
        "audit",
        "receipt",
        "trust",
        "status",
        "github",
        "claude-code",
        "headless",
    ] {
        assert!(
            names.contains(&visible),
            "expected top-level help to show `{visible}`; names={names:?}\nstdout:\n{stdout}"
        );
    }

    for hidden in [
        "up",
        "down",
        "device",
        "binary-pin",
        "broker",
        "bind",
        "policy",
        "cluster",
        "demo",
        "grants",
        "session",
        "construct",
        "binary",
        "kms",
        "orchestrator",
        "dev",
        "bridge",
    ] {
        assert!(
            !names.contains(&hidden),
            "expected top-level help to hide `{hidden}`; names={names:?}\nstdout:\n{stdout}"
        );
    }
}

#[test]
fn daemon_help_hides_dev_only_lifecycle_commands() {
    let (stdout, stderr, code) = run_ember(&["daemon", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    let names = help_command_names(&stdout);
    assert!(
        names.contains(&"status"),
        "expected daemon help to keep the supported status surface visible; names={names:?}\nstdout:\n{stdout}"
    );
    assert!(
        names.contains(&"install"),
        "expected daemon help to keep the canonical install surface visible; names={names:?}\nstdout:\n{stdout}"
    );
    assert!(
        !names.contains(&"install-agent"),
        "expected daemon help to hide the dev-only install-agent path; names={names:?}\nstdout:\n{stdout}"
    );
    assert!(
        !names.contains(&"uninstall-agent"),
        "expected daemon help to hide the dev-only uninstall-agent path; names={names:?}\nstdout:\n{stdout}"
    );
    assert!(
        !names.contains(&"start"),
        "expected daemon help to hide the low-level manual start path; names={names:?}\nstdout:\n{stdout}"
    );
}

#[test]
fn init_help_centers_canonical_onboarding() {
    let (stdout, stderr, code) = run_ember(&["init", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");

    assert!(
        stdout.contains("Canonical onboarding for Claude Code"),
        "expected init help to describe the friendly onboarding path; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("`~/.claude/settings.json`"),
        "expected init help to mention Claude Code wiring; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("--touch-id"),
        "expected init help to hide the stub touch-id flag; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("cohort A"),
        "expected init help to avoid internal cohort terminology; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("design"),
        "expected init help to avoid ADR references; stdout:\n{stdout}"
    );
}

#[test]
fn trust_help_lists_read_only_introspection_verbs() {
    let (stdout, stderr, code) = run_ember(&["trust", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    let names = help_command_names(&stdout);

    for visible in ["list", "show", "explain"] {
        assert!(
            names.contains(&visible),
            "expected trust help to show `{visible}`; names={names:?}\nstdout:\n{stdout}"
        );
    }
}

#[test]
fn github_help_centers_setup_and_demotes_low_level_app_surface() {
    let (stdout, stderr, code) = run_ember(&["github", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    let names = help_command_names(&stdout);

    for visible in ["status", "setup"] {
        assert!(
            names.contains(&visible),
            "expected github help to show `{visible}`; names={names:?}\nstdout:\n{stdout}"
        );
    }

    assert!(
        !names.contains(&"app"),
        "expected github help to hide the low-level app subtree; names={names:?}\nstdout:\n{stdout}"
    );

    assert!(
        stdout.contains("Recommended v0.3.0 path"),
        "expected github help to mark setup as the friendly path; stdout:\n{stdout}"
    );
}

#[test]
fn github_app_help_keeps_hidden_support_surface_reachable() {
    let (stdout, stderr, code) = run_ember(&["github", "app", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    let names = help_command_names(&stdout);

    for visible in ["install-url", "show", "register"] {
        assert!(
            names.contains(&visible),
            "expected github app help to show `{visible}`; names={names:?}\nstdout:\n{stdout}"
        );
    }

    assert!(
        stdout.contains("Hidden low-level registration surface"),
        "expected github app help to keep register scoped as a hidden support surface; stdout:\n{stdout}"
    );
}
