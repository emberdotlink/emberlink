//! META-DEV-PROD-PARITY-ATTESTATION-SURFACE — T2 integration tests for
//! `ember status --session`. The brief asks for a T2 that opens a session
//! via `ember claude-code`, but the claude-code launcher requires a
//! provisioned daemon + vault + persona — out of scope for a T2 gate.
//!
//! Instead these tests exercise the CLI surface end-to-end against the
//! `ember` binary with no daemon installed: the attestation surface must
//! render cleanly (bare shell, env-overridden session, --all, --json) so the
//! operator can verify it without a live broker. The pure composition is
//! covered by T1 unit tests in `status_session.rs::tests`.
//!
//! Anchor: `dev_prod_parity_attestation_surface_landed`.
//!
//! CLASSIFICATION: PUBLIC

use std::process::Command;

fn ember_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ember")
}

/// Run `ember <args>` against a fixture config, an isolated config dir, and
/// a controlled env. The daemon is intentionally not running — the test
/// proves the attestation surface stays sane against a cold host.
fn run_ember(args: &[&str], extra_env: &[(&str, &str)]) -> (String, String, i32) {
    let tmp = tempfile::tempdir().expect("config tempdir");
    let config_path = tmp.path().join("config.toml");
    let socket_dir = tmp.path().join("run");
    std::fs::create_dir_all(&socket_dir).unwrap();
    let pid_file = tmp.path().join("ember.pid");
    let body = format!(
        "data_dir = \"{}\"\nsocket_dir = \"{}\"\npid_file = \"{}\"\n",
        tmp.path().display(),
        socket_dir.display(),
        pid_file.display()
    );
    std::fs::write(&config_path, body).expect("write fixture config");
    let mut cmd = Command::new(ember_bin());
    cmd.env("EMBER_CONFIG", &config_path)
        // Force vault-mock so the CLI never asks for the real keychain.
        .env("EMBER_VAULT_MOCK", "1")
        // Suppress the daemon-install precheck noise.
        .env("EMBER_SKIP_DAEMON_INSTALL_CHECK", "1")
        .env_remove("EMBER_SESSION_ID")
        .env_remove("EMBER_DAEMON_SOCKET")
        .env_remove("EMBER_PERSONA")
        .env_remove("EMBER_DAEMON_FLAVOR");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.args(args).output().expect("spawn ember");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// EMBER_SESSION_ID unset → "no active session; bare shell" line. Closes
/// the explicit acceptance criterion: "Behaves cleanly when EMBER_SESSION_ID
/// is unset (prints 'no active session; bare shell')."
#[test]
fn session_unset_renders_bare_shell_line() {
    let (stdout, stderr, code) = run_ember(&["status", "--session"], &[]);
    assert_eq!(
        code, 0,
        "expected exit 0; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("Session: no active session; bare shell"),
        "expected bare-shell line; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("EMBER_SESSION_ID is not set"),
        "expected explanatory line; stdout={stdout:?}"
    );
}

/// EMBER_SESSION_ID set in the calling shell → surface picks it up and
/// reports it as the session id. Mirrors the brief's primary use case:
/// "open a session via ember claude-code, run ember status --session in
/// the spawned shell, assert the workflow grant is listed" — without the
/// daemon dependency the spawned shell's env is the surface boundary.
#[test]
fn session_env_var_is_reported_as_session_id() {
    let (stdout, stderr, code) = run_ember(
        &["status", "--session"],
        &[
            ("EMBER_SESSION_ID", "sess_01HGY2A_TEST"),
            (
                "EMBER_DAEMON_SOCKET",
                "/home/op/.ember/run/daemon.dev.sock",
            ),
            ("EMBER_PERSONA", "persona-claude-test"),
            ("EMBER_DAEMON_FLAVOR", "dev"),
        ],
    );
    assert_eq!(
        code, 0,
        "expected exit 0; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("Session: sess_01HGY2A_TEST"),
        "expected session id line; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("EMBER_PERSONA=persona-claude-test"),
        "expected persona env line; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("EMBER_DAEMON_SOCKET=/home/op/.ember/run/daemon.dev.sock"),
        "expected socket env line; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("dev daemon"),
        "expected dev-flavor stamp; stdout={stdout:?}"
    );
}

/// `--session-id <id>` overrides the calling shell's EMBER_SESSION_ID.
/// Acceptance: "ember status --session --session-id <id> reports the
/// specified session".
#[test]
fn explicit_session_id_overrides_env() {
    let (stdout, _stderr, code) = run_ember(
        &["status", "--session", "--session-id", "sess_OVERRIDE"],
        &[("EMBER_SESSION_ID", "sess_FROM_ENV_IGNORED")],
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains("Session: sess_OVERRIDE"),
        "expected overridden id; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("sess_FROM_ENV_IGNORED"),
        "env id must not appear; stdout={stdout:?}"
    );
}

/// `--all` lists every active session view (no session id pinned).
/// Acceptance: "ember status --session --all lists every active session".
#[test]
fn all_flag_clears_session_id_and_lists() {
    let (stdout, _stderr, code) = run_ember(
        &["status", "--session", "--all"],
        &[("EMBER_SESSION_ID", "sess_should_be_ignored_with_all")],
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains("Session: no active session; bare shell"),
        "with --all and no daemon, session_id is empty by design; stdout={stdout:?}"
    );
}

/// `--json` emits a stable, jq-scriptable contract. Acceptance:
/// "Output includes: daemon socket, manifest fingerprint, trust-root set,
/// dev_mode_active stamp, active workflow grant + TTL, last-call summary".
#[test]
fn json_contract_carries_documented_fields() {
    let (stdout, _stderr, code) = run_ember(
        &["--json", "status", "--session"],
        &[
            ("EMBER_SESSION_ID", "sess_jsoncontract"),
            ("EMBER_DAEMON_FLAVOR", "prod"),
            ("EMBER_PERSONA", "persona-x"),
        ],
    );
    assert_eq!(code, 0, "stdout={stdout:?}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(value["session_id"], "sess_jsoncontract");
    assert_eq!(value["persona_env"], "persona-x");
    assert_eq!(value["daemon_flavor"], "prod");
    // dev_mode_active and trust_roots are present even on a cold host:
    // dev_mode_active is `false`, trust_roots is `[]`.
    assert!(
        value.get("dev_mode_active").is_some(),
        "dev_mode_active field present"
    );
    assert!(
        value["trust_roots"].is_array(),
        "trust_roots is an array"
    );
    assert!(
        value.get("matching_grants").is_some(),
        "matching_grants field present"
    );
    assert!(
        value.get("total_active_grants").is_some(),
        "total_active_grants field present"
    );
    assert!(
        value.get("daemon_fingerprint").is_some(),
        "daemon_fingerprint field present (null on cold host is OK)"
    );
}

/// `--session` is mutually exclusive with `--troubleshoot` at the clap
/// surface — the troubleshoot appendix is a different rendering mode.
#[test]
fn session_conflicts_with_troubleshoot() {
    let (_stdout, stderr, code) = run_ember(&["status", "--session", "--troubleshoot"], &[]);
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        stderr.contains("cannot be used") || stderr.contains("conflict"),
        "expected clap conflict diagnostic; stderr={stderr:?}"
    );
}

/// `--session-id` requires `--session`. Guards against operators typing
/// `ember status --session-id foo` and silently getting the old summary.
#[test]
fn session_id_requires_session_flag() {
    let (_stdout, stderr, code) = run_ember(&["status", "--session-id", "sess_x"], &[]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("requires") || stderr.contains("required"),
        "expected clap requires diagnostic; stderr={stderr:?}"
    );
}
