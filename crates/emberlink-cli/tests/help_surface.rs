use std::process::Command;

use tempfile::TempDir;

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

fn write_default_home_config(home: &TempDir) -> std::path::PathBuf {
    let ember_dir = home.path().join(".ember");
    let config_path = ember_dir.join("config.toml");
    let data_dir = ember_dir.join("data");
    let socket_dir = ember_dir.join("run");
    let pid_file = socket_dir.join("emberd.pid");
    let policy_file = ember_dir.join("policy.toml");

    std::fs::create_dir_all(&ember_dir).expect("create ~/.ember");
    let cfg = format!(
        "[daemon]\ndata_dir = \"{}\"\nsocket_dir = \"{}\"\npid_file = \"{}\"\npolicy_file = \"{}\"\nlog_level = \"info\"\n",
        data_dir.display(),
        socket_dir.display(),
        pid_file.display(),
        policy_file.display(),
    );
    std::fs::write(&config_path, cfg.as_bytes()).expect("write ~/.ember/config.toml");
    config_path
}

fn run_ember_in_home(args: &[&str], home: &TempDir) -> (String, String, i32) {
    let config_path = write_default_home_config(home);
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

fn strip_ansi(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for next in chars.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
            continue;
        }
        out.push(ch);
    }
    out
}

fn assert_compact_help(args: &[&str], expected_title: &str) {
    let (stdout, stderr, code) = run_ember(args);
    assert_eq!(code, 0, "exit non-zero for `{args:?}`. stderr: {stderr}");
    assert!(
        stdout.starts_with(&format!("{expected_title}\n")),
        "expected compact title `{expected_title}` for `{args:?}`; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("Common") || stdout.contains("Start"),
        "expected compact card sections for `{args:?}`; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("Usage:"),
        "expected compact help instead of raw clap help for `{args:?}`; stdout:\n{stdout}"
    );
}

fn visible_help_paths() -> Vec<Vec<&'static str>> {
    vec![
        vec!["init"],
        vec!["uninstall"],
        vec!["recover"],
        vec!["recover", "diagnose"],
        vec!["recover", "audit-chain"],
        vec!["recover", "vault"],
        vec!["recover", "trust"],
        vec!["recover", "daemon"],
        vec!["recover", "authority"],
        vec!["recover", "broker"],
        vec!["recover", "audit"],
        vec!["recover", "install"],
        vec!["recover", "explain"],
        vec!["daemon"],
        vec!["daemon", "stop"],
        vec!["daemon", "status"],
        vec!["daemon", "reload"],
        vec!["daemon", "install"],
        vec!["daemon", "migrate"],
        vec!["daemon", "recover-fresh"],
        vec!["daemon", "diagnose"],
        vec!["persona"],
        vec!["persona", "create"],
        vec!["persona", "list"],
        vec!["persona", "revoke"],
        vec!["vault"],
        vec!["vault", "add"],
        vec!["vault", "list"],
        vec!["vault", "get"],
        vec!["vault", "put"],
        vec!["vault", "remove"],
        vec!["vault", "export"],
        vec!["vault", "import"],
        vec!["vault", "lock"],
        vec!["vault", "unlock"],
        vec!["vault", "migrate-acl"],
        vec!["grant"],
        vec!["grant", "create"],
        vec!["grant", "delegate"],
        vec!["grant", "list"],
        vec!["grant", "revoke"],
        vec!["grant", "expire"],
        vec!["grant", "budget"],
        vec!["grant", "extend"],
        vec!["sandbox"],
        vec!["sandbox", "create"],
        vec!["sandbox", "list"],
        vec!["sandbox", "stop"],
        vec!["sandbox", "delete"],
        vec!["sandbox", "exec"],
        vec!["sandbox", "run"],
        vec!["sandbox", "run-scion"],
        vec!["approval"],
        vec!["approval", "list"],
        vec!["approval", "approve"],
        vec!["approval", "deny"],
        vec!["approval", "narrow"],
        vec!["audit"],
        vec!["audit", "show"],
        vec!["audit", "export"],
        vec!["audit", "explain"],
        vec!["audit", "query"],
        vec!["audit", "summary"],
        vec!["audit", "verify"],
        vec!["audit", "usage"],
        vec!["receipt"],
        vec!["receipt", "list"],
        vec!["receipt", "show"],
        vec!["receipt", "export"],
        vec!["receipt", "verify"],
        vec!["receipt", "tree"],
        vec!["receipt", "rollup"],
        vec!["config"],
        vec!["config", "show"],
        vec!["config", "path"],
        vec!["github"],
        vec!["github", "status"],
        vec!["github", "setup"],
        vec!["trust"],
        vec!["trust", "list"],
        vec!["trust", "show"],
        vec!["trust", "explain"],
        vec!["trust", "backup"],
        vec!["trust", "restore"],
        vec!["status"],
        vec!["doctor"],
        vec!["explain"],
        vec!["version"],
        vec!["claude"],
        vec!["codex"],
        vec!["headless"],
        vec!["headless", "enroll"],
        vec!["headless", "revoke"],
        vec!["headless", "status"],
        vec!["headless", "preflight"],
    ]
}

fn card_row_names(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("  ")?;
            let token = rest.split_whitespace().next()?;
            (!token.starts_with('-') && !token.chars().next().is_some_and(|ch| ch.is_ascii_digit()))
                .then_some(token)
        })
        .collect()
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
    let names = card_row_names(&stdout);

    for section in ["Start", "Launch", "Check", "Inspect", "Advanced", "More"] {
        assert!(
            stdout.contains(section),
            "expected top-level help to show `{section}`; stdout:\n{stdout}"
        );
    }

    for visible in [
        "init", "claude", "codex", "status", "doctor", "approval", "grant", "trust", "receipt",
        "audit", "github", "daemon", "vault", "headless", "recover",
    ] {
        assert!(
            names.contains(&visible),
            "expected top-level help to show `{visible}`; names={names:?}\nstdout:\n{stdout}"
        );
    }

    for hidden in [
        "up",
        "down",
        "admin",
        "device",
        "binary-pin",
        "broker",
        "bind",
        "policy",
        "cluster",
        "demo",
        "grants",
        "construct",
        "binary",
        "kms",
        "orchestrator",
        "dev",
        "bridge",
        "session",
    ] {
        assert!(
            !names.contains(&hidden),
            "expected top-level help to hide `{hidden}`; names={names:?}\nstdout:\n{stdout}"
        );
    }
}

#[test]
fn top_level_help_respects_explicit_color_policy() {
    let (always_stdout, always_stderr, always_code) = run_ember(&["--color", "always", "--help"]);
    assert_eq!(
        always_code, 0,
        "exit non-zero for `--color always --help`. stderr: {always_stderr}"
    );
    assert!(
        always_stdout.contains("\u{1b}["),
        "expected `--color always` to emit ANSI styling; stdout:\n{always_stdout}"
    );
    let always_plain = strip_ansi(&always_stdout);
    assert!(
        always_plain.contains("Ember"),
        "expected colorized help to keep the compact title; stdout:\n{always_stdout}"
    );
    assert!(
        always_plain.contains("Start"),
        "expected colorized help to keep the action sections; stdout:\n{always_stdout}"
    );

    let (never_stdout, never_stderr, never_code) = run_ember(&["--color", "never", "--help"]);
    assert_eq!(
        never_code, 0,
        "exit non-zero for `--color never --help`. stderr: {never_stderr}"
    );
    assert!(
        !never_stdout.contains("\u{1b}["),
        "expected `--color never` to suppress ANSI styling; stdout:\n{never_stdout}"
    );
}

#[test]
fn bare_ember_becomes_a_home_screen() {
    let home = TempDir::new().expect("tempdir");
    let (stdout, stderr, code) = run_ember_in_home(&[], &home);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout.contains("Not set up yet"),
        "expected bare ember to render the uninitialized home screen; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember init --for claude"),
        "expected bare ember to offer the canonical setup CTA; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember status"),
        "expected bare ember to keep readiness visible from the home screen; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("Commands:"),
        "expected bare ember to avoid the old clap command index; stdout:\n{stdout}"
    );
}

#[test]
fn bare_ember_with_global_color_flag_stays_on_home_screen() {
    let home = TempDir::new().expect("tempdir");
    let (stdout, stderr, code) = run_ember_in_home(&["--color", "always"], &home);
    assert_eq!(
        code, 0,
        "exit non-zero for bare ember with color flag. stderr: {stderr}"
    );
    assert!(
        stdout.contains("\u{1b}["),
        "expected `ember --color always` to style the home screen; stdout:\n{stdout}"
    );
    let plain = strip_ansi(&stdout);
    assert!(
        plain.contains("Not set up yet"),
        "expected `ember --color always` to stay on the home screen; stdout:\n{stdout}"
    );
    assert!(
        plain.contains("ember init --for claude"),
        "expected `ember --color always` to keep the canonical setup CTA; stdout:\n{stdout}"
    );
}

#[test]
fn daemon_help_hides_dev_only_lifecycle_commands() {
    let (stdout, stderr, code) = run_ember(&["daemon", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout.contains("ember daemon status"),
        "expected daemon help to keep the supported status surface visible; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("sudo ember daemon install"),
        "expected daemon help to keep the canonical install surface visible; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("install-agent"),
        "expected daemon help to hide the dev-only install-agent path; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("uninstall-agent"),
        "expected daemon help to hide the dev-only uninstall-agent path; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("ember daemon start"),
        "expected daemon help to hide the low-level manual start path; stdout:\n{stdout}"
    );
}

#[test]
fn init_help_centers_canonical_onboarding() {
    let (stdout, stderr, code) = run_ember(&["init", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");

    assert!(
        stdout.contains("Set up Ember on this machine"),
        "expected init help to describe the friendly onboarding path; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("`~/.claude/settings.json`"),
        "expected init help to mention Claude Code wiring; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("`~/.codex/hooks.json`"),
        "expected init help to mention Codex hook wiring; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("codex login status"),
        "expected init help to mention Codex's native auth lane; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("codex login --device-auth"),
        "expected init help to mention Codex's headless auth lane; stdout:\n{stdout}"
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
        !stdout.contains("ADR 120"),
        "expected init help to avoid ADR references; stdout:\n{stdout}"
    );
}

#[test]
fn claude_launcher_help_accepts_new_name_and_compat_alias() {
    for name in ["claude", "claude-code"] {
        let (stdout, stderr, code) = run_ember(&[name, "--help"]);
        assert_eq!(
            code, 0,
            "exit non-zero for `{name} --help`. stderr: {stderr}"
        );
        assert!(
            stdout
                .contains("Launch Claude with Ember-managed env, PATH wiring, and session setup."),
            "expected `{name} --help` to describe the Claude launcher; stdout:\n{stdout}"
        );
    }
}

#[test]
fn launcher_help_explains_isolated_controls() {
    let (claude_stdout, claude_stderr, claude_code) = run_ember(&["claude", "--help"]);
    assert_eq!(
        claude_code, 0,
        "exit non-zero for `claude --help`. stderr: {claude_stderr}"
    );
    assert!(
        claude_stdout.contains("Forwarded to Claude on both host and isolated paths"),
        "expected `claude --help` to describe isolated arg forwarding; stdout:\n{claude_stdout}"
    );
    assert!(
        !claude_stdout.contains("custom trailing Claude args still require the host launcher path"),
        "expected `claude --help` to drop the stale host-only caveat; stdout:\n{claude_stdout}"
    );

    for name in ["claude", "codex"] {
        let (stdout, stderr, code) = run_ember(&[name, "--help"]);
        assert_eq!(
            code, 0,
            "exit non-zero for `{name} --help`. stderr: {stderr}"
        );
        assert!(
            stdout.contains("--backend <name>"),
            "expected `{name} --help` to expose backend control; stdout:\n{stdout}"
        );
        assert!(
            stdout.contains("Requires `--isolated`"),
            "expected `{name} --help` to mark backend/preset flags as isolated-only; stdout:\n{stdout}"
        );
    }

    let (codex_stdout, codex_stderr, codex_code) = run_ember(&["codex", "--help"]);
    assert_eq!(
        codex_code, 0,
        "exit non-zero for `codex --help`. stderr: {codex_stderr}"
    );
    assert!(
        codex_stdout.contains("`codex login`"),
        "expected `codex --help` to point operators at Codex's native login lane; stdout:\n{codex_stdout}"
    );
    assert!(
        codex_stdout.contains("`codex login --device-auth`"),
        "expected `codex --help` to mention Codex's headless auth lane; stdout:\n{codex_stdout}"
    );
    assert!(
        codex_stdout.contains("`~/.codex`"),
        "expected `codex --help` to explain the host auth bind-mount in isolated mode; stdout:\n{codex_stdout}"
    );
    assert!(
        codex_stdout.contains("Leave unset to auto-detect; requires `--isolated`"),
        "expected `codex --help` to explain backend auto-detection; stdout:\n{codex_stdout}"
    );
}

#[test]
fn status_help_routes_to_doctor_and_json() {
    let (stdout, stderr, code) = run_ember(&["status", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout.contains("Show the current Ember posture and the most important next action."),
        "expected status help to use the new compact description; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember doctor"),
        "expected status help to route deeper diagnosis through doctor; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("--json"),
        "expected status help to advertise the machine contract; stdout:\n{stdout}"
    );
}

#[test]
fn doctor_help_centers_diagnosis() {
    let (stdout, stderr, code) = run_ember(&["doctor", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout
            .contains("Diagnose the current Ember posture and route you to the right repair path."),
        "expected doctor help to describe the diagnosis lane; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember explain error E-DAEMON-NOT-INSTALLED"),
        "expected doctor help to point at explainable errors; stdout:\n{stdout}"
    );
}

#[test]
fn explain_help_centers_manual_surface() {
    let (stdout, stderr, code) = run_ember(&["explain", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout.contains(
            "Show the deeper manual for a command, delegated-authority surface, or error code."
        ),
        "expected explain help to describe the deeper manual lane; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember explain init"),
        "expected explain help to offer concrete topics; stdout:\n{stdout}"
    );
}

#[test]
fn explain_status_prints_the_deeper_manual() {
    let (stdout, stderr, code) = run_ember(&["explain", "status"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout.contains("ember explain status"),
        "expected explain status to render the topic title; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("How to read it"),
        "expected explain status to include the deeper posture guide; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember doctor"),
        "expected explain status to route to doctor as the deep repair lane; stdout:\n{stdout}"
    );
}

#[test]
fn explain_grant_prints_the_deeper_manual() {
    let (stdout, stderr, code) = run_ember(&["explain", "grant"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout.contains("ember explain grant"),
        "expected explain grant to render the topic title; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("delegate: mint a narrower child grant"),
        "expected explain grant to describe delegation; stdout:\n{stdout}"
    );
}

#[test]
fn explain_audit_prints_the_quarantine_model() {
    let (stdout, stderr, code) = run_ember(&["explain", "audit"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout.contains("ember audit verify"),
        "expected explain audit to route through audit verify; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("quarantined"),
        "expected explain audit to mention quarantine relevance; stdout:\n{stdout}"
    );
}

#[test]
fn explain_unknown_topic_returns_actionable_error() {
    let (_stdout, stderr, code) = run_ember(&["explain", "nonesuch"]);
    assert_eq!(
        code, 2,
        "expected exit 2 for unknown topic; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("error[E-EXPLAIN-TOPIC-NOT-FOUND]"),
        "expected a structured explain error code; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("ember explain init"),
        "expected the error to offer a valid follow-up topic; stderr:\n{stderr}"
    );
}

#[test]
fn session_open_help_accepts_claude_target_and_compat_alias() {
    for target in ["claude", "claude-code"] {
        let (stdout, stderr, code) = run_ember(&["session", "open", target, "--help"]);
        assert_eq!(
            code, 0,
            "exit non-zero for `session open {target} --help`. stderr: {stderr}"
        );
        assert!(
            stdout.contains("Trailing arguments forwarded to the target surface"),
            "expected `session open {target} --help` to parse and show target help; stdout:\n{stdout}"
        );
    }
}

#[test]
fn session_open_help_marks_backend_and_preset_as_isolated_only() {
    for target in ["claude", "codex"] {
        let (stdout, stderr, code) = run_ember(&["session", "open", target, "--help"]);
        assert_eq!(
            code, 0,
            "exit non-zero for `session open {target} --help`. stderr: {stderr}"
        );
        assert!(
            stdout.contains("Requires `--isolated`"),
            "expected `session open {target} --help` to mark backend/preset as isolated-only; stdout:\n{stdout}"
        );
        assert!(
            stdout.contains("Force the isolated/container launcher path"),
            "expected `session open {target} --help` to use the public isolated wording; stdout:\n{stdout}"
        );
    }
}

#[test]
fn trust_help_lists_read_only_introspection_verbs() {
    let (stdout, stderr, code) = run_ember(&["trust", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(stdout.contains("ember trust list"));
    assert!(stdout.contains("ember trust show <fingerprint>"));
    assert!(stdout.contains("ember trust explain <artifact>"));
    assert!(stdout.contains("backup"));
    assert!(stdout.contains("restore"));
    assert!(
        stdout
            .contains("Inspect trust roots, explain verification chains, and manage exportable key backups."),
        "expected trust help to use the compact trust/export framing; stdout:\n{stdout}"
    );
}

#[test]
fn grant_help_centers_operator_jobs() {
    let (stdout, stderr, code) = run_ember(&["grant", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout.contains("Issue, inspect, and repair access grants"),
        "expected grant help to use the compact operator framing; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember grant create"),
        "expected grant help to lead with create; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember explain grant"),
        "expected grant help to route deep detail to explain; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember grant evaluate --grant <id> --attempt attempt.toml"),
        "expected grant help to expose the spend preflight lane; stdout:\n{stdout}"
    );
}

#[test]
fn approval_help_centers_resolution_flow() {
    let (stdout, stderr, code) = run_ember(&["approval", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout.contains("Inspect and resolve approval requests"),
        "expected approval help to use the compact operator framing; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember approval approve <id>"),
        "expected approval help to expose the main resolution path; stdout:\n{stdout}"
    );
}

#[test]
fn grant_create_help_stays_short_and_budget_aware() {
    let (stdout, stderr, code) = run_ember(&["grant", "create", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout.contains("Issue a new access grant with explicit scope"),
        "expected grant create help to use the compact framing; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("--standing"),
        "expected grant create help to expose the standing-grant path; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("budget flags"),
        "expected grant create help to group the budget controls; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("--kind spend"),
        "expected grant create help to expose the spend renderer lane; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("--vendor / --max-cents / --window / --hard-cap"),
        "expected grant create help to group spend-specific flags; stdout:\n{stdout}"
    );
}

#[test]
fn approval_approve_help_stays_short_and_standing_grant_aware() {
    let (stdout, stderr, code) = run_ember(&["approval", "approve", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout.contains("Approve one pending request"),
        "expected approval approve help to use the compact framing; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("--always"),
        "expected approval approve help to expose the standing-grant path; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("Arguments:"),
        "expected approval approve help to avoid the raw clap section layout; stdout:\n{stdout}"
    );
}

#[test]
fn audit_help_demotes_internal_chain_copy() {
    let (stdout, stderr, code) = run_ember(&["audit", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout.contains("Inspect the audit chain, quarantine posture, and exported evidence"),
        "expected audit help to use the compact framing; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember audit verify"),
        "expected audit help to show the verification lane; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("SEC-S5-V030"),
        "expected audit help to hide internal slug copy; stdout:\n{stdout}"
    );
}

#[test]
fn receipt_help_centers_verification_and_export() {
    let (stdout, stderr, code) = run_ember(&["receipt", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout.contains("Inspect and verify signed grant witnesses"),
        "expected receipt help to use the compact framing; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember receipt verify"),
        "expected receipt help to foreground verification; stdout:\n{stdout}"
    );
}

#[test]
fn audit_verify_help_stays_short_and_actionable() {
    let (stdout, stderr, code) = run_ember(&["audit", "verify", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout.contains("Verify the audit chain and surface whether repair"),
        "expected audit verify help to stay compact; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember doctor"),
        "expected audit verify help to route repair through doctor; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember audit verify --since 7d"),
        "expected audit verify help to expose the ship-gate window; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("--since <WINDOW>"),
        "expected audit verify options to expose the ship-gate window flag; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("1d") && stdout.contains("24h") && stdout.contains("ISO-8601"),
        "expected audit verify help to document accepted --since window shapes; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("SEC-S5-V030"),
        "expected audit verify help to hide internal slug copy; stdout:\n{stdout}"
    );
}

#[test]
fn audit_export_help_surfaces_signed_bundle_flags() {
    let (stdout, stderr, code) = run_ember(&["audit", "export", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    for expected in [
        "--sign",
        "--output <OUTPUT>",
        "--since <SINCE>",
        "--workflow <WORKFLOW>",
        "--redact <RULE,...>",
    ] {
        assert!(
            stdout.contains(expected),
            "expected audit export help to show `{expected}`; stdout:\n{stdout}"
        );
    }
}

#[test]
fn audit_summary_help_surfaces_ship_gate_window_and_json() {
    let (stdout, stderr, code) = run_ember(&["audit", "summary", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    for expected in [
        "--since <SINCE>",
        "--workflow <WORKFLOW>",
        "--persona <PERSONA>",
        "--format <FORMAT>",
        "--json",
    ] {
        assert!(
            stdout.contains(expected),
            "expected audit summary help to show `{expected}`; stdout:\n{stdout}"
        );
    }
}

#[test]
fn receipt_verify_help_stays_short_and_offline_first() {
    let (stdout, stderr, code) = run_ember(&["receipt", "verify", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout
            .contains("Verify a receipt by local ID, exported JSON file, or offline tree export."),
        "expected receipt verify help to use the compact framing; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("--tree <path>"),
        "expected receipt verify help to expose offline tree verification; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("Beat 8 demo close"),
        "expected receipt verify help to avoid internal program copy; stdout:\n{stdout}"
    );
}

#[test]
fn github_help_centers_setup_and_demotes_low_level_app_surface() {
    let (stdout, stderr, code) = run_ember(&["github", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout.contains("ember github status"),
        "expected github help to show the status surface; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember github setup"),
        "expected github help to show the setup surface; stdout:\n{stdout}"
    );

    assert!(
        !stdout.contains("github app"),
        "expected github help to hide the low-level app subtree; stdout:\n{stdout}"
    );

    assert!(
        stdout.contains("Inspect or repair the GitHub App lane"),
        "expected github help to stay on the operator-facing lane; stdout:\n{stdout}"
    );
}

#[test]
fn github_setup_help_stays_compact_and_actionable() {
    let (stdout, stderr, code) = run_ember(&["github", "setup", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout.contains("Store or repair the local GitHub App credential triple"),
        "expected github setup help to frame the setup job directly; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("--from-manifest"),
        "expected github setup help to show the manifest registration path; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("--pem-file <path>"),
        "expected github setup help to show the private key input; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("--replace"),
        "expected github setup help to expose overwrite behavior; stdout:\n{stdout}"
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

#[test]
fn uninstall_help_stays_compact_and_state_preserving() {
    let (stdout, stderr, code) = run_ember(&["uninstall", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");

    assert!(
        stdout.contains("ember uninstall"),
        "expected uninstall title; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("Personas, grants, receipts, and stored credentials remain in place"),
        "expected uninstall help to preserve durable state explicitly; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember uninstall --for claude"),
        "expected claude uninstall example; stdout:\n{stdout}"
    );
}

#[test]
fn recover_help_centers_failure_classes_and_runbook_bridge() {
    let (stdout, stderr, code) = run_ember(&["recover", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");

    for class in ["daemon", "authority", "broker", "audit", "install"] {
        assert!(
            stdout.contains(class),
            "expected recover help to show `{class}`; stdout:\n{stdout}"
        );
    }
    assert!(
        stdout.contains("ember recover explain F-DAEMON-2"),
        "expected recover help to surface the runbook bridge; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember recover diagnose"),
        "expected recover help to surface the lifecycle umbrella; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("diagnose, audit-chain, persona, grant, vault, trust"),
        "expected recover help to show lifecycle verbs; stdout:\n{stdout}"
    );
}

#[test]
fn recover_diagnose_help_names_receipt_contract() {
    let (stdout, stderr, code) = run_ember(&["recover", "diagnose", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");

    assert!(
        stdout.contains("Walk the recovery lifecycle probes"),
        "expected recover diagnose summary; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("recovery.action"),
        "expected recover diagnose help to name receipt contract; stdout:\n{stdout}"
    );
}

#[test]
fn recover_explain_help_stays_compact() {
    let (stdout, stderr, code) = run_ember(&["recover", "explain", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");

    assert!(
        stdout.contains("Print the recovery runbook section for one failure code"),
        "expected recover explain summary; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("F-codes are case-insensitive"),
        "expected recover explain help to mention case-insensitive codes; stdout:\n{stdout}"
    );
}

#[test]
fn persona_help_centers_identity_lifecycle() {
    let (stdout, stderr, code) = run_ember(&["persona", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");

    for expected in [
        "ember persona create --name researcher",
        "ember persona list",
        "ember persona revoke per_123",
    ] {
        assert!(
            stdout.contains(expected),
            "expected persona help to include `{expected}`; stdout:\n{stdout}"
        );
    }
}

#[test]
fn vault_help_centers_safe_input_and_relock() {
    let (stdout, stderr, code) = run_ember(&["vault", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");

    assert!(
        stdout.contains("without leaking secrets through argv"),
        "expected vault help to lead with the safe-input stance; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("`--value` is intentionally refused"),
        "expected vault help to call out the argv refusal; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember vault lock"),
        "expected vault help to surface relock; stdout:\n{stdout}"
    );
}

#[test]
fn vault_add_help_refuses_argv_secret_patterns() {
    let (stdout, stderr, code) = run_ember(&["vault", "add", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");

    assert!(
        stdout.contains("The legacy `--value` form is refused on purpose"),
        "expected vault add help to reject argv-secret usage; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("echo \"$TOKEN\" | ember vault add --name github/app --stdin"),
        "expected vault add help to show stdin usage; stdout:\n{stdout}"
    );
}

#[test]
fn sandbox_help_demotes_raw_container_flags() {
    let (stdout, stderr, code) = run_ember(&["sandbox", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");

    assert!(
        stdout.contains("without starting from raw container flags"),
        "expected sandbox help summary; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember sandbox run-scion --task DEPLOY-PREVIEW --dry-run"),
        "expected sandbox help to surface run-scion; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("SCION-INTEGRATION-CLI"),
        "expected sandbox help to avoid internal task ids; stdout:\n{stdout}"
    );
}

#[test]
fn sandbox_run_scion_help_uses_generic_task_example() {
    let (stdout, stderr, code) = run_ember(&["sandbox", "run-scion", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");

    assert!(
        stdout.contains("Task ID to run (e.g. DEPLOY-PREVIEW)"),
        "expected generic task example; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("SCION-INTEGRATION-CLI"),
        "expected run-scion help to avoid internal task ids; stdout:\n{stdout}"
    );
}

#[test]
fn demo_help_avoids_internal_task_names() {
    let (stdout, stderr, code) = run_ember(&["demo", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");

    for leaked in [
        "COHORT-A-10-DEMO-WEDGE",
        "DEMO-MAY3-COMPOSITE-BUNDLE-CLI",
        "SCION 2026-05-15 Beat 8",
    ] {
        assert!(
            !stdout.contains(leaked),
            "expected demo help to avoid `{leaked}`; stdout:\n{stdout}"
        );
    }
}

#[test]
fn config_help_stays_short_and_inspection_only() {
    let (stdout, stderr, code) = run_ember(&["config", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");

    assert!(
        stdout.contains("ember config show"),
        "expected config show example; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember config path"),
        "expected config path example; stdout:\n{stdout}"
    );
}

#[test]
fn headless_help_centers_preflight_and_enroll() {
    let (stdout, stderr, code) = run_ember(&["headless", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");

    assert!(
        stdout.contains("ember headless preflight --input tasks.json"),
        "expected preflight example; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("bounded strict + delegated lane"),
        "expected headless summary; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember headless enroll --input tasks.json --duration 4h"),
        "expected enroll example to carry the required input file; stdout:\n{stdout}"
    );
}

#[test]
fn headless_enroll_help_mentions_short_yes_flag() {
    let (stdout, stderr, code) = run_ember(&["headless", "enroll", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");

    assert!(
        stdout.contains("--input <tasks.json>"),
        "expected headless enroll help to document required task input; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("-y, --yes"),
        "expected headless enroll help to document the short yes flag; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("current ceiling is `7d`"),
        "expected headless enroll help to keep duration bounds visible; stdout:\n{stdout}"
    );
}

#[test]
fn explain_delegation_prints_the_deeper_manual() {
    let (stdout, stderr, code) = run_ember(&["explain", "delegation"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");

    assert!(
        stdout.contains("narrower child grant"),
        "expected delegation explain to describe the grant model; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember grant revoke"),
        "expected delegation explain to point at the ember grant surface; stdout:\n{stdout}"
    );
}

#[test]
fn explain_vault_prints_the_safe_input_manual() {
    let (stdout, stderr, code) = run_ember(&["explain", "vault"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");

    assert!(
        stdout.contains("Passing secrets on argv is intentionally refused"),
        "expected vault explain topic; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("ember vault add"),
        "expected vault explain related surfaces; stdout:\n{stdout}"
    );
}

#[test]
fn every_visible_help_path_renders_a_compact_card() {
    for path in visible_help_paths() {
        let mut args = path.clone();
        args.push("--help");
        let title = format!("ember {}", path.join(" "));
        assert_compact_help(args.as_slice(), &title);
    }
}

#[test]
fn visible_help_paths_stay_compact_with_global_flag_prefixes() {
    let (stdout, stderr, code) = run_ember(&["--color", "never", "--help"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(
        stdout.starts_with("Ember\n"),
        "expected compact top-level help with global flags; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("Usage:"),
        "expected compact top-level help; stdout:\n{stdout}"
    );

    for path in visible_help_paths() {
        let mut args = vec!["--color", "never", "--json"];
        args.extend_from_slice(path.as_slice());
        args.push("--help");
        let title = format!("ember {}", path.join(" "));
        assert_compact_help(args.as_slice(), &title);
    }
}

#[test]
fn visible_help_paths_stay_compact_with_short_help_flag() {
    for path in visible_help_paths() {
        let mut args = path.clone();
        args.push("-h");
        let title = format!("ember {}", path.join(" "));
        assert_compact_help(args.as_slice(), &title);
    }
}

#[test]
fn visible_help_paths_do_not_normalize_contributor_surfaces() {
    for path in visible_help_paths() {
        let mut args = path.clone();
        args.push("--help");
        let (stdout, stderr, code) = run_ember(args.as_slice());
        assert_eq!(code, 0, "exit non-zero for `{args:?}`. stderr: {stderr}");

        for forbidden in [
            "ember dev",
            "ember admin",
            "install-agent",
            "uninstall-agent",
            "dogfood",
            "ship-gate",
        ] {
            assert!(
                !stdout.contains(forbidden),
                "expected `{}` help to avoid contributor term `{forbidden}`; stdout:\n{stdout}",
                path.join(" ")
            );
        }
    }
}
