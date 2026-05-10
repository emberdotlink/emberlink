//! Separate-uid daemon install scaffolding (design).
//!
//! `emberd` runs under a dedicated `ember` system uid in production so a
//! process running as the operator's uid cannot bypass the broker by reading
//! the vault directly (same-uid `ptrace`, `/proc/<pid>/environ`, SQLite file
//! access, keychain unlock all collapse the supervisor claim under single-
//! uid). This module owns the platform-specific provisioning that the
//! installer drives:
//!
//! 1. [`provision_ember_user`] — create the `ember` system user + the
//!    `ember-clients` group, add the invoking operator to `ember-clients`.
//! 2. [`chown_ember_data_dirs`] — recursively chown the daemon's data
//!    directory tree to `ember:ember-clients` and tighten file modes.
//! 3. [`install_launchd_plist`] (macOS) / [`install_systemd_unit`] (Linux)
//!    — write the platform launcher unit and bootstrap/enable the service.
//!
//! Both functions are **idempotent** — re-running on an already-provisioned
//! machine returns `Ok(())` without altering state. They shell out via
//! `std::process::Command` (no `nix` crate dep — matches the project's
//! existing subprocess-shellout pattern in `sandbox.rs` / `notify.rs`) and
//! always capture stderr per the `feedback_subprocess_logging` rule
//! (no `let _ = ...output()`).

use std::path::Path;
use std::process::Command;

/// Errors raised by [`provision_ember_user`] and [`chown_ember_data_dirs`].
///
/// `Subprocess` is the dominant variant — every shell-out captures stderr
/// and the failing exit code so the installer can surface a useful
/// diagnostic. `Io` wraps filesystem reads (e.g. directory walks for the
/// chown traversal).
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("subprocess failed: cmd={cmd}, exit={exit_code:?}, stderr={stderr}")]
    Subprocess {
        cmd: String,
        stderr: String,
        exit_code: Option<i32>,
    },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Returns true if `stderr` looks like a "user/group already exists" message
/// from the underlying provisioning tool. The check is intentionally broad —
/// macOS (`dseditgroup`, `sysadminctl`) and Linux (`groupadd`, `useradd`)
/// each phrase the condition slightly differently, so we fold the common
/// substrings into one helper.
fn already_exists(stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    s.contains("already exists") || s.contains("already a member")
}

/// Run a subprocess, capture stderr+exit code, and return them on failure.
///
/// `tolerate_already_exists`: when true, a non-zero exit whose stderr
/// matches [`already_exists`] is treated as success (idempotency).
fn run(
    program: &str,
    args: &[&str],
    tolerate_already_exists: bool,
) -> Result<(), InstallError> {
    let cmd_string = format!("{} {}", program, args.join(" "));
    let output = Command::new(program).args(args).output().map_err(|e| {
        InstallError::Subprocess {
            cmd: cmd_string.clone(),
            stderr: format!("spawn failed: {e}"),
            exit_code: None,
        }
    })?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let exit_code = output.status.code();

    if tolerate_already_exists && already_exists(&stderr) {
        return Ok(());
    }

    tracing::warn!(
        cmd = %cmd_string,
        exit = exit_code.unwrap_or(-1),
        stderr = %stderr,
        "subprocess failed"
    );
    Err(InstallError::Subprocess {
        cmd: cmd_string,
        stderr,
        exit_code,
    })
}

/// Returns true if `id <user>` exits 0 (user exists). On spawn failure
/// (e.g. `id` missing) returns false — the subsequent provisioning command
/// will surface the real error.
fn user_exists(user: &str) -> bool {
    Command::new("id")
        .arg(user)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Returns `true` when the host is already on the **separate-uid posture**
/// (design): the dedicated `ember` system user exists.
///
/// Used by `ember daemon migrate` to short-circuit if the system is already
/// migrated so re-running is a documented no-op rather than partial mutation.
///
/// The check is intentionally lightweight — `id ember` is the canonical
/// probe for whether `provision_ember_user` was ever run successfully.
/// Callers that need finer-grained assertions (e.g. plist presence, data-dir
/// ownership) can combine this with platform-specific stat checks.
pub fn is_separate_uid_posture() -> bool {
    user_exists("ember")
}

/// Provision the `ember` system user + the `ember-clients` connect group.
///
/// **Idempotent.** Re-running on an already-provisioned machine returns
/// `Ok(())` without altering state — every step tolerates the platform's
/// "already exists" stderr signature.
///
/// On macOS:
/// - `dseditgroup -o create ember` — group create (idempotent).
/// - `sysadminctl -addUser ember -fullName "Emberlink Daemon" -home /var/empty -shell /usr/bin/false`
///   only when `id ember` reports the user is missing.
/// - `dseditgroup -o create ember-clients` — connect-group create.
/// - `dseditgroup -o edit -a "$USER" -t user ember-clients` — add the
///   invoking operator to the connect group.
///
/// On Linux:
/// - `groupadd --system --force ember` — system group create (idempotent
///   via `--force`).
/// - `useradd --system --shell /usr/sbin/nologin --gid ember ember` only
///   when `id ember` reports the user is missing.
/// - `groupadd --system --force ember-clients` — connect-group create.
/// - `usermod -aG ember-clients $USER` — add the invoking operator to
///   the connect group.
///
/// Requires elevated privileges (typically invoked under `sudo` from the
/// installer entry point).
#[cfg(target_os = "macos")]
pub fn provision_ember_user() -> Result<(), InstallError> {
    // 1) ember group
    run("dseditgroup", &["-o", "create", "ember"], true)?;

    // 2) ember user (only if missing)
    if !user_exists("ember") {
        run(
            "sysadminctl",
            &[
                "-addUser",
                "ember",
                "-fullName",
                "Emberlink Daemon",
                "-home",
                "/var/empty",
                "-shell",
                "/usr/bin/false",
            ],
            true,
        )?;
    }

    // 3) ember-clients connect group
    run("dseditgroup", &["-o", "create", "ember-clients"], true)?;

    // 4) add invoking operator to ember-clients
    let invoking_user = std::env::var("USER").unwrap_or_default();
    if !invoking_user.is_empty() {
        run(
            "dseditgroup",
            &[
                "-o",
                "edit",
                "-a",
                &invoking_user,
                "-t",
                "user",
                "ember-clients",
            ],
            true,
        )?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn provision_ember_user() -> Result<(), InstallError> {
    // 1) ember system group (idempotent via --force)
    run("groupadd", &["--system", "--force", "ember"], true)?;

    // 2) ember user (only if missing)
    if !user_exists("ember") {
        run(
            "useradd",
            &[
                "--system",
                "--shell",
                "/usr/sbin/nologin",
                "--gid",
                "ember",
                "ember",
            ],
            true,
        )?;
    }

    // 3) ember-clients connect group
    run("groupadd", &["--system", "--force", "ember-clients"], true)?;

    // 4) add invoking operator to ember-clients
    let invoking_user = std::env::var("USER").unwrap_or_default();
    if !invoking_user.is_empty() {
        run(
            "usermod",
            &["-aG", "ember-clients", &invoking_user],
            true,
        )?;
    }

    Ok(())
}

/// Fallback for platforms other than macOS/Linux. The `emberd` install
/// flow is only supported on macOS + Linux (per design); other targets
/// surface a clear error rather than silently no-op.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn provision_ember_user() -> Result<(), InstallError> {
    Err(InstallError::Subprocess {
        cmd: "provision_ember_user".to_string(),
        stderr: "unsupported platform: ember user provisioning is implemented only for macOS and Linux"
            .to_string(),
        exit_code: None,
    })
}

/// Recursively chown the daemon data subdirs under `home/.ember` to
/// `ember:ember-clients` and tighten file modes.
///
/// **Idempotent.** Subdirs that don't exist are skipped (returns `Ok(())`
/// for the missing-subdir case). Re-running the chown/chmod on an
/// already-correct tree is a no-op.
///
/// For each entry walked under each known subdir:
/// - `chown ember:ember-clients <path>`
/// - directories: `chmod 0750 <path>`
/// - files: `chmod 0640 <path>`
///
/// The known subdirs are `vault`, `grants`, `sessions`, `run`, `binaries`
/// — the daemon's at-rest state (vault DB, grant ledger, session
/// receipts, run dir, broker-resolver binaries).
///
/// Requires elevated privileges (typically invoked under `sudo` from the
/// installer entry point).
pub fn chown_ember_data_dirs(home: &Path) -> Result<(), InstallError> {
    let ember_root = home.join(".ember");
    let subdirs = ["vault", "grants", "sessions", "run", "binaries"];

    for sub in subdirs.iter() {
        let path = ember_root.join(sub);
        if !path.exists() {
            // Idempotent skip — the daemon may not have created every
            // subdir on this host yet.
            continue;
        }
        chown_chmod_recursive(&path)?;
    }

    Ok(())
}

/// Recursive helper: visit `path` and (if a directory) every descendant,
/// applying `chown ember:ember-clients` and the dir/file mode.
fn chown_chmod_recursive(path: &Path) -> Result<(), InstallError> {
    let metadata = std::fs::symlink_metadata(path)?;
    let path_str = path.to_string_lossy().into_owned();

    // chown applies to symlinks via -h equivalent, but POSIX `chown` by
    // default dereferences. We always chown the target directly here;
    // recursion below skips re-walking symlink targets.
    run("chown", &["ember:ember-clients", &path_str], false)?;

    let mode = if metadata.is_dir() { "0750" } else { "0640" };
    run("chmod", &[mode, &path_str], false)?;

    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            chown_chmod_recursive(&entry.path())?;
        }
    }

    Ok(())
}

/// Verbatim launchd plist body for the `sh.emberlink.daemon` LaunchDaemon
/// (per design §macOS install). The installer writes this to
/// `/Library/LaunchDaemons/sh.emberlink.daemon.plist` mode `0644`.
///
/// `dead_code` allowed because the body is only referenced by the macOS
/// `install_launchd_plist` impl plus the cross-platform test that
/// asserts the rendered text matches design — on a Linux non-test
/// build both consumers are excluded.
#[allow(dead_code)]
const LAUNCHD_PLIST_BODY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>           <string>sh.emberlink.daemon</string>
  <key>UserName</key>        <string>ember</string>
  <key>GroupName</key>       <string>ember</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/emberd</string>
    <string>--foreground</string>
  </array>
  <key>KeepAlive</key>       <true/>
  <key>RunAtLoad</key>       <true/>
  <key>StandardErrorPath</key><string>/var/log/emberd.err</string>
  <key>StandardOutPath</key> <string>/var/log/emberd.out</string>
</dict>
</plist>
"#;

/// Verbatim systemd unit body for the `emberd.service` unit (per design
/// §Linux install, V03-B brief). The installer writes this to
/// `/etc/systemd/system/emberd.service` mode `0644`.
///
/// `dead_code` allowed because the body is only referenced by the Linux
/// `install_systemd_unit` impl plus the cross-platform test that
/// asserts the rendered text matches the brief — on a macOS non-test
/// build both consumers are excluded.
#[allow(dead_code)]
const SYSTEMD_UNIT_BODY: &str = r#"[Unit]
Description=Emberlink Grant Warden daemon
After=network.target

[Service]
Type=simple
User=ember
Group=ember
ExecStart=/usr/local/bin/emberd --foreground
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"#;

/// Path on disk for the macOS LaunchDaemon plist.
#[cfg(target_os = "macos")]
const LAUNCHD_PLIST_PATH: &str = "/Library/LaunchDaemons/sh.emberlink.daemon.plist";

/// Path on disk for the Linux systemd unit.
#[cfg(target_os = "linux")]
const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/emberd.service";

/// Returns the rendered launchd plist body. Tests assert against this
/// helper so the writer and the assertion read from the same source.
///
/// `dead_code` allowed because on a Linux non-test build there is no
/// caller (the macOS impl is excluded and tests don't compile).
#[allow(dead_code)]
pub(crate) fn render_launchd_plist_body() -> &'static str {
    LAUNCHD_PLIST_BODY
}

/// Returns the rendered systemd unit body. Tests assert against this
/// helper so the writer and the assertion read from the same source.
///
/// `dead_code` allowed because on a macOS non-test build there is no
/// caller (the Linux impl is excluded and tests don't compile).
#[allow(dead_code)]
pub(crate) fn render_systemd_unit_body() -> &'static str {
    SYSTEMD_UNIT_BODY
}

/// Install the `sh.emberlink.daemon` LaunchDaemon plist at
/// `/Library/LaunchDaemons/sh.emberlink.daemon.plist` and bootstrap it
/// into the system domain (per design §macOS install).
///
/// **Idempotent.** If the plist on disk already matches the rendered
/// body, the function skips the bootout/bootstrap cycle. Otherwise the
/// plist is rewritten, mode is reset to `0644`, the existing service is
/// `launchctl bootout`-ed (tolerating "not currently bootstrapped"), and
/// then `launchctl bootstrap`-ed.
///
/// Requires root (typically invoked under `sudo` from the installer
/// entry point) — the LaunchDaemons directory and `launchctl ...
/// system` both reject non-root callers.
#[cfg(target_os = "macos")]
pub fn install_launchd_plist() -> Result<(), InstallError> {
    let path = Path::new(LAUNCHD_PLIST_PATH);
    let body = render_launchd_plist_body();

    // Idempotency check — if the on-disk plist already matches, skip the
    // bootout/bootstrap cycle entirely. Re-bootstrapping a service that
    // is already loaded with the same definition is wasteful churn.
    let already_matches = std::fs::read_to_string(path)
        .map(|existing| existing == body)
        .unwrap_or(false);

    if !already_matches {
        std::fs::write(path, body).map_err(|e| InstallError::Subprocess {
            cmd: format!("write {LAUNCHD_PLIST_PATH}"),
            stderr: format!("write failed: {e}"),
            exit_code: None,
        })?;

        run("chmod", &["0644", LAUNCHD_PLIST_PATH], false)?;

        // bootout — tolerate "not currently bootstrapped" (exit 113 or
        // stderr containing "Could not find specified service"). This
        // is the macOS-launchctl analogue of `groupadd --force`.
        bootout_tolerant()?;

        run(
            "launchctl",
            &["bootstrap", "system", LAUNCHD_PLIST_PATH],
            false,
        )?;
    }

    Ok(())
}

/// `launchctl bootout system <plist>` that tolerates the
/// "not-currently-bootstrapped" condition. Apple surfaces this as either
/// exit code 113 or a stderr substring "Could not find specified
/// service" depending on the macOS version.
#[cfg(target_os = "macos")]
fn bootout_tolerant() -> Result<(), InstallError> {
    let cmd_string = format!("launchctl bootout system {LAUNCHD_PLIST_PATH}");
    let output = Command::new("launchctl")
        .args(["bootout", "system", LAUNCHD_PLIST_PATH])
        .output()
        .map_err(|e| InstallError::Subprocess {
            cmd: cmd_string.clone(),
            stderr: format!("spawn failed: {e}"),
            exit_code: None,
        })?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let exit_code = output.status.code();

    // Tolerate "not currently bootstrapped" — either exit 113 or the
    // canonical stderr substring.
    if exit_code == Some(113)
        || stderr.contains("Could not find specified service")
    {
        return Ok(());
    }

    tracing::warn!(
        cmd = %cmd_string,
        exit = exit_code.unwrap_or(-1),
        stderr = %stderr,
        "subprocess failed"
    );
    Err(InstallError::Subprocess {
        cmd: cmd_string,
        stderr,
        exit_code,
    })
}

/// Non-macOS fallback for [`install_launchd_plist`]. The launchd flow
/// is meaningful only on macOS; surface a clear error rather than
/// silently no-op.
#[cfg(not(target_os = "macos"))]
pub fn install_launchd_plist() -> Result<(), InstallError> {
    Err(InstallError::Subprocess {
        cmd: "install_launchd_plist".to_string(),
        stderr: "unsupported platform: launchd plist install is macOS-only"
            .to_string(),
        exit_code: None,
    })
}

/// Install the `emberd.service` systemd unit at
/// `/etc/systemd/system/emberd.service` and enable it (per design
/// §Linux install).
///
/// **Idempotent.** `systemctl enable --now` exits 0 when the unit is
/// already enabled and active. If the on-disk unit already matches the
/// rendered body, the daemon-reload and enable steps are still issued
/// (cheap, idempotent) so a hand-edited active state always converges.
///
/// Steps:
/// - Write `SYSTEMD_UNIT_BODY` to `/etc/systemd/system/emberd.service`.
/// - `chmod 0644` the unit file.
/// - `systemctl daemon-reload`.
/// - `systemctl enable --now emberd.service`.
///
/// Requires root (typically invoked under `sudo` from the installer
/// entry point).
#[cfg(target_os = "linux")]
pub fn install_systemd_unit() -> Result<(), InstallError> {
    let path = Path::new(SYSTEMD_UNIT_PATH);
    let body = render_systemd_unit_body();

    // Idempotency: only rewrite the unit file when the body differs.
    // We always run daemon-reload + enable --now so the active state
    // converges even if the unit file was hand-edited externally.
    let already_matches = std::fs::read_to_string(path)
        .map(|existing| existing == body)
        .unwrap_or(false);

    if !already_matches {
        std::fs::write(path, body).map_err(|e| InstallError::Subprocess {
            cmd: format!("write {SYSTEMD_UNIT_PATH}"),
            stderr: format!("write failed: {e}"),
            exit_code: None,
        })?;

        run("chmod", &["0644", SYSTEMD_UNIT_PATH], false)?;
    }

    run("systemctl", &["daemon-reload"], false)?;
    run("systemctl", &["enable", "--now", "emberd.service"], false)?;

    Ok(())
}

/// Non-Linux fallback for [`install_systemd_unit`]. The systemd flow
/// is meaningful only on Linux; surface a clear error rather than
/// silently no-op.
#[cfg(not(target_os = "linux"))]
pub fn install_systemd_unit() -> Result<(), InstallError> {
    Err(InstallError::Subprocess {
        cmd: "install_systemd_unit".to_string(),
        stderr: "unsupported platform: systemd unit install is Linux-only"
            .to_string(),
        exit_code: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T1 unit — the chown traversal is a no-op on an empty dir tree.
    /// We point `chown_ember_data_dirs` at a tmpdir that has no `.ember`
    /// subdir at all; every known subdir is missing so the function
    /// short-circuits per the idempotent-skip branch and returns Ok.
    #[test]
    fn chown_ember_data_dirs_on_empty_dir_is_ok() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let result = chown_ember_data_dirs(tmp.path());
        assert!(
            result.is_ok(),
            "empty home (no .ember tree) should be a no-op, got {:?}",
            result
        );
    }

    /// T1 unit — calling on a home that has `.ember/` but none of the
    /// expected subdirs is also a no-op (all five are missing → all five
    /// hit the idempotent-skip branch).
    #[test]
    fn chown_ember_data_dirs_on_missing_subdirs_is_ok() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(tmp.path().join(".ember")).expect("mkdir .ember");
        let result = chown_ember_data_dirs(tmp.path());
        assert!(
            result.is_ok(),
            "home with empty .ember/ should be a no-op, got {:?}",
            result
        );
    }

    /// Integration-tier — exercises the real `provision_ember_user`
    /// path. Requires sudo + a clean macOS/Linux host, mutates system
    /// state (creates a real system user + group), so it is `#[ignore]`
    /// by default. Un-ignore when running the installer integration
    /// suite on a disposable VM. The assertion is that a second call
    /// returns `Ok(())` — i.e. provisioning is idempotent.
    #[test]
    #[ignore = "requires sudo + mutates system users; run only in installer integration suite"]
    fn provision_ember_user_idempotent_on_second_call() {
        provision_ember_user().expect("first call");
        provision_ember_user().expect("second call must be a no-op");
    }

    /// The launchd plist body the writer emits must match the verbatim
    /// XML in design §macOS install. This guards against silent drift
    /// between the source-of-truth ADR snippet and what installs ship.
    ///
    /// Build the expected text by joining lines with `\n` rather than
    /// using string-continuation (`\\\n`), which would collapse the
    /// significant two-space indentation inside `<dict>...</dict>`.
    #[test]
    fn plist_body_matches_adr_131() {
        let expected = [
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
            "<plist version=\"1.0\">",
            "<dict>",
            "  <key>Label</key>           <string>sh.emberlink.daemon</string>",
            "  <key>UserName</key>        <string>ember</string>",
            "  <key>GroupName</key>       <string>ember</string>",
            "  <key>ProgramArguments</key>",
            "  <array>",
            "    <string>/usr/local/bin/emberd</string>",
            "    <string>--foreground</string>",
            "  </array>",
            "  <key>KeepAlive</key>       <true/>",
            "  <key>RunAtLoad</key>       <true/>",
            "  <key>StandardErrorPath</key><string>/var/log/emberd.err</string>",
            "  <key>StandardOutPath</key> <string>/var/log/emberd.out</string>",
            "</dict>",
            "</plist>",
            "",
        ]
        .join("\n");
        assert_eq!(render_launchd_plist_body(), expected);
    }

    /// The systemd unit body the writer emits must match the verbatim
    /// ini text from the V03-B brief (Type=simple variant). This guards
    /// against silent drift between the brief's source-of-truth snippet
    /// and what installs ship.
    #[test]
    fn systemd_unit_body_matches_adr_131() {
        let expected = [
            "[Unit]",
            "Description=Emberlink Grant Warden daemon",
            "After=network.target",
            "",
            "[Service]",
            "Type=simple",
            "User=ember",
            "Group=ember",
            "ExecStart=/usr/local/bin/emberd --foreground",
            "Restart=on-failure",
            "RestartSec=5",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
        .join("\n");
        assert_eq!(render_systemd_unit_body(), expected);
    }

    /// Integration-tier — exercises the real macOS launchd install
    /// path. Requires root + a macOS host (mutates
    /// `/Library/LaunchDaemons` and runs `launchctl bootstrap`), so
    /// `#[ignore]` by default. Un-ignore when running the installer
    /// integration suite on a disposable macOS VM.
    #[test]
    #[ignore = "requires root + macOS; mutates /Library/LaunchDaemons and runs launchctl"]
    fn install_launchd_plist_writes_and_bootstraps() {
        install_launchd_plist().expect("first call");
        install_launchd_plist().expect("second call must be a no-op");
    }

    /// Integration-tier — exercises the real Linux systemd install
    /// path. Requires root + a Linux host with systemd (mutates
    /// `/etc/systemd/system` and runs `systemctl enable --now`), so
    /// `#[ignore]` by default. Un-ignore when running the installer
    /// integration suite on a disposable Linux VM.
    #[test]
    #[ignore = "requires root + Linux/systemd; mutates /etc/systemd/system and runs systemctl"]
    fn install_systemd_unit_writes_and_enables() {
        install_systemd_unit().expect("first call");
        install_systemd_unit().expect("second call must be a no-op");
    }
}
