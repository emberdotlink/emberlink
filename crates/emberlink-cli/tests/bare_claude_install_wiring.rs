//! META-DEV-PROD-PARITY-BARE-CLAUDE-INSTALL-WIRING — T3 integration tests
//! for the bare-`claude` redirector hybrid (operator decision 2026-05-15).
//!
//! Validates the shim script that `ember dev install` writes to
//! `~/.ember/shadow/bin/claude` actually performs the redirect when
//! exec'd by a shell. The shim is a `#!/bin/sh` script, so we can drive
//! it directly from the integration test by:
//!
//!   1. Installing the shim with `install_claude_shadow_shim()` pointed
//!      at a stub `ember` binary that prints its argv.
//!   2. Exec'ing the shim with a checkpoint argv.
//!   3. Asserting the stub `ember` saw `claude-code <checkpoint>`.
//!
//! Two scenarios:
//!   - default (env unset) → routes through `ember claude-code`
//!   - `EMBER_NO_CLAUDE_WRAP=1` → routes through `command claude` (the
//!     real Claude Code binary)
//!
//! Anchor: `dev_prod_parity_bare_claude_install_wiring_landed`.
//!
//! CLASSIFICATION: PUBLIC

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use emberlink_cli::dev_install_slice_c::install_binaries::install_claude_shadow_shim;

/// Write a stub `ember` shell script that records its argv into
/// `record_path` and exits 0. The shim execs this stub, so the
/// integration test sees what command-line the shim assembled.
fn write_stub_ember(path: &std::path::Path, record_path: &std::path::Path) {
    let body = format!(
        "#!/bin/sh\n\
         # stub ember for T3 integration test\n\
         echo \"$@\" > {}\n",
        record_path.display()
    );
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn bare_claude_shim_routes_through_ember_claude_code() {
    let tmp = tempfile::tempdir().unwrap();
    let shadow = tmp.path().join("shadow");
    let stub_ember = tmp.path().join("ember-stub");
    let record = tmp.path().join("argv-record.txt");

    write_stub_ember(&stub_ember, &record);

    let written = install_claude_shadow_shim(&shadow, &stub_ember).expect("install shim");
    assert!(written, "first install must report the shim was written");

    let shim = shadow.join("bin").join("claude");
    assert!(shim.exists());

    // Exec the shim with a checkpoint argv. /bin/sh runs the shim per its
    // shebang.
    let status = Command::new(&shim)
        .arg("--print")
        .arg("session-handoff-checkpoint")
        .env_remove("EMBER_NO_CLAUDE_WRAP")
        .status()
        .expect("shim exec");
    assert!(
        status.success(),
        "shim must exit 0 when stub ember succeeds; got {status:?}",
    );

    let recorded = fs::read_to_string(&record).expect("argv recorded");
    // The shim's `exec <ember> claude-code "$@"` must result in the stub
    // ember seeing `claude-code --print session-handoff-checkpoint`.
    assert!(
        recorded.contains("claude-code"),
        "stub ember must have been invoked with `claude-code` subcommand; got: {recorded}",
    );
    assert!(
        recorded.contains("session-handoff-checkpoint"),
        "stub ember must have been forwarded the operator argv; got: {recorded}",
    );
}

#[test]
fn bare_claude_shim_honors_ember_no_claude_wrap_opt_out() {
    let tmp = tempfile::tempdir().unwrap();
    let shadow = tmp.path().join("shadow");
    let stub_ember = tmp.path().join("ember-stub");
    let ember_record = tmp.path().join("ember-record.txt");
    write_stub_ember(&stub_ember, &ember_record);

    // The opt-out path execs `command claude` — to make the test
    // hermetic, plant a fake `claude` binary on a controlled PATH and
    // assert it runs (not the stub-ember).
    let fake_claude_dir = tmp.path().join("fake-bin");
    fs::create_dir_all(&fake_claude_dir).unwrap();
    let fake_claude = fake_claude_dir.join("claude");
    let claude_record = tmp.path().join("claude-record.txt");
    fs::write(
        &fake_claude,
        format!(
            "#!/bin/sh\n\
             # fake claude binary for T3 opt-out test\n\
             echo \"$@\" > {}\n",
            claude_record.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_claude, fs::Permissions::from_mode(0o755)).unwrap();

    install_claude_shadow_shim(&shadow, &stub_ember).expect("install shim");
    let shim = shadow.join("bin").join("claude");

    // Run the shim with EMBER_NO_CLAUDE_WRAP=1 and the fake-bin dir
    // FIRST on PATH so `command claude` resolves the fake.
    // The shadow/bin dir is NOT on PATH, so `command claude` won't
    // recurse back into the shim.
    let path_value = format!(
        "{}:{}",
        fake_claude_dir.display(),
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin".to_string()),
    );
    let status = Command::new(&shim)
        .arg("opt-out-checkpoint")
        .env("EMBER_NO_CLAUDE_WRAP", "1")
        .env("PATH", &path_value)
        .status()
        .expect("shim exec");
    assert!(status.success(), "shim must exit 0; got {status:?}");

    // The fake `claude` must have run; the stub `ember` must NOT have.
    let claude_argv =
        fs::read_to_string(&claude_record).expect("fake claude should have been invoked");
    assert!(
        claude_argv.contains("opt-out-checkpoint"),
        "fake claude must have received the operator argv: {claude_argv}",
    );
    assert!(
        !ember_record.exists(),
        "stub ember must NOT be invoked when EMBER_NO_CLAUDE_WRAP=1",
    );
}

#[test]
fn bare_claude_shim_install_is_idempotent_across_runs() {
    // Reinstall must not duplicate or corrupt the shim. Verified by
    // sha-256 stability across runs and by re-executing the shim after
    // reinstall.
    let tmp = tempfile::tempdir().unwrap();
    let shadow = tmp.path().join("shadow");
    let stub_ember = tmp.path().join("ember-stub");
    let record = tmp.path().join("argv-record.txt");
    write_stub_ember(&stub_ember, &record);

    install_claude_shadow_shim(&shadow, &stub_ember).expect("first install");
    let shim_path = shadow.join("bin").join("claude");
    let first_body = fs::read_to_string(&shim_path).unwrap();

    install_claude_shadow_shim(&shadow, &stub_ember).expect("second install");
    let second_body = fs::read_to_string(&shim_path).unwrap();
    assert_eq!(
        first_body, second_body,
        "second install must not mutate the shim body",
    );

    // The shim still works.
    let status = Command::new(&shim_path)
        .arg("post-reinstall")
        .env_remove("EMBER_NO_CLAUDE_WRAP")
        .status()
        .expect("exec");
    assert!(status.success());
    let recorded = fs::read_to_string(&record).unwrap();
    assert!(recorded.contains("claude-code"));
    assert!(recorded.contains("post-reinstall"));
}

#[test]
fn bare_claude_shim_passes_through_quoted_args() {
    // Operators run `claude --print "complex prompt with spaces"`.
    // The shim's `exec ... "$@"` must preserve the argv structure.
    let tmp = tempfile::tempdir().unwrap();
    let shadow = tmp.path().join("shadow");
    let stub_ember = tmp.path().join("ember-stub");
    let record = tmp.path().join("argv-record.txt");

    // Use $@ count instead of $@ value so the assertion is robust to
    // shell-level join behavior in the echo step.
    let body = format!(
        "#!/bin/sh\n\
         echo \"argc=$#\" > {}\n\
         for arg in \"$@\"; do echo \"arg=[$arg]\" >> {}; done\n",
        record.display(),
        record.display(),
    );
    fs::write(&stub_ember, body).unwrap();
    fs::set_permissions(&stub_ember, fs::Permissions::from_mode(0o755)).unwrap();

    install_claude_shadow_shim(&shadow, &stub_ember).expect("install");
    let shim = shadow.join("bin").join("claude");

    let status = Command::new(&shim)
        .arg("--print")
        .arg("prompt with spaces")
        .arg("--model")
        .arg("opus")
        .env_remove("EMBER_NO_CLAUDE_WRAP")
        .status()
        .expect("exec");
    assert!(status.success());

    let recorded = fs::read_to_string(&record).unwrap();
    // First arg is `claude-code` (from the shim), then the operator's
    // four argv: --print, "prompt with spaces", --model, opus.
    assert!(recorded.contains("argc=5"), "argc mismatch: {recorded}");
    assert!(
        recorded.contains("arg=[claude-code]"),
        "first arg should be claude-code: {recorded}",
    );
    assert!(
        recorded.contains("arg=[prompt with spaces]"),
        "quoted arg must be preserved as a single argv element: {recorded}",
    );
    assert!(recorded.contains("arg=[--print]"));
    assert!(recorded.contains("arg=[--model]"));
    assert!(recorded.contains("arg=[opus]"));

    // Guard against unused-variable warnings on the path import.
    let _ = PathBuf::from(&shim);
}
