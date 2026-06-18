//! Integration tests for `ember --version` / `ember -V` (CLI-VERSION-FLAG).
//!
//! These exercise the actual binary so the build.rs env emission +
//! short-circuit handler in `main()` are both covered. Driving them through
//! `Cli::parse()` would skip the short-circuit branch.
//!
//! The output format the tests pin:
//!     ember <semver> (<git-sha-or-(no-git)>) built <iso8601-utc>
//!
//! `(no-git)` is treated as a valid value for the SHA group so a release
//! tarball / sandboxed build without `.git/` doesn't break the test.

use std::process::Command;

/// Path to the `ember` binary that cargo built for this test.
///
/// `CARGO_BIN_EXE_<name>` is set by cargo for any `[[bin]]` target in the
/// same package as the test binary. Using it avoids hard-coding
/// `target/debug/ember` and keeps the test correct under `cargo test
/// --release` / custom target dirs.
fn ember_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ember")
}

/// Run `ember <args...>` from a clean cwd and capture stdout / stderr / exit.
///
/// We intentionally do NOT pass any `--config`. The `--version` short-circuit
/// must complete without touching the filesystem or the keychain — that's
/// the whole point of the flag.
fn run_ember(args: &[&str]) -> (String, String, i32) {
    // ember-cli eager-loads ~/.ember/config.toml before dispatching subcommands
    // (META-T3-USER-SOCKET-LEAK-GUARD-C loud-fail). `version` subcommand doesn't
    // need the config but the eager-load fires anyway — see
    // META-AP-EMBER-CLI-RECEIPT-VERIFY-FILE-CONFIG-INDEPENDENCE for the
    // structural fix. Until that ships, point EMBER_CONFIG at a fixture so
    // tests pass on hosts without ~/.ember/config.toml.
    let tmp = tempfile::tempdir().expect("config tempdir");
    let config_path = tmp.path().join("config.toml");
    std::fs::write(&config_path, "# fixture for version_flag tests\n")
        .expect("write fixture config");
    let out = Command::new(ember_bin())
        .env("EMBER_CONFIG", &config_path)
        .args(args)
        .output()
        .expect("spawn ember");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// Validate `ember <semver> (<sha>) built <iso8601>\n`.
///
/// SHA group accepts either a 7+ hex run (real `git rev-parse --short`) or
/// the literal `(no-git)` fallback. The trailing newline is required so we
/// catch accidental `eprint!` / missing-newline regressions.
fn assert_version_format(stdout: &str) {
    assert!(
        stdout.ends_with('\n'),
        "stdout missing trailing newline: {stdout:?}"
    );
    let line = stdout.trim_end_matches('\n');

    // Must start with "ember " and have exactly one line.
    assert!(
        !stdout.trim_end_matches('\n').contains('\n'),
        "expected single line, got: {stdout:?}"
    );
    assert!(
        line.starts_with("ember "),
        "expected `ember ` prefix, got: {line:?}"
    );

    // Hand-rolled regex-equivalent. Splits are stable and avoid pulling in
    // the `regex` crate just for this test.
    let after_name = line.strip_prefix("ember ").expect("checked above");
    let (semver, after_semver) = after_name
        .split_once(' ')
        .expect("expected space after semver");
    assert!(
        semver.split('.').count() == 3
            && semver
                .split('.')
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')),
        "expected semver `X.Y.Z`, got: {semver:?}"
    );

    let (sha_paren, after_sha) = after_semver
        .split_once(' ')
        .expect("expected space after sha group");
    assert!(
        sha_paren.starts_with('(') && sha_paren.ends_with(')'),
        "expected parenthesized sha, got: {sha_paren:?}"
    );
    let sha = &sha_paren[1..sha_paren.len() - 1];
    let sha_ok = sha == "no-git" || (sha.len() >= 7 && sha.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(sha_ok, "sha group must be 7+ hex or `no-git`, got: {sha:?}");

    let after_built = after_sha
        .strip_prefix("built ")
        .expect("expected `built ` keyword");
    // RFC 3339 / ISO 8601 UTC: `YYYY-MM-DDTHH:MM:SSZ`. The build script
    // always renders Z; accept any non-empty value to keep the test robust.
    assert!(
        after_built.contains('T'),
        "expected ISO8601 timestamp with `T`, got: {after_built:?}"
    );
    assert!(
        after_built.ends_with('Z'),
        "expected UTC `Z` suffix, got: {after_built:?}"
    );
}

#[test]
fn version_long_flag() {
    let (stdout, stderr, code) = run_ember(&["--version"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(stderr.is_empty(), "expected empty stderr, got: {stderr:?}");
    assert_version_format(&stdout);
}

#[test]
fn version_short_flag() {
    let (stdout, stderr, code) = run_ember(&["-V"]);
    assert_eq!(code, 0, "exit non-zero. stderr: {stderr}");
    assert!(stderr.is_empty(), "expected empty stderr, got: {stderr:?}");
    assert_version_format(&stdout);
}

#[test]
fn version_subcommand_matches_flag() {
    // `ember version` and `ember --version` should agree on the version
    // string (modulo any difference is a divergence bug). They route
    // through different code paths — the flag short-circuits before clap
    // parses, the subcommand goes through `Commands::Version`.
    let (flag_out, _, flag_code) = run_ember(&["--version"]);
    let (sub_out, _, sub_code) = run_ember(&["version"]);
    assert_eq!(flag_code, 0);
    assert_eq!(sub_code, 0);
    assert_eq!(
        flag_out, sub_out,
        "flag vs subcommand version output diverged"
    );
}
