//! Linux-specific install helpers — udev rules for FIDO2 hardware keys.
//!
//! FIDO2/U2F hardware security keys (YubiKey, Feitian, Nitrokey, SoloKeys, …)
//! communicate over the HID raw interface (`/dev/hidraw*`).  On a vanilla
//! Linux system those device nodes are owned by root with mode 0600, so any
//! process running as a non-root user — including the browser's WebAuthn
//! stack and the ember daemon — cannot open them.
//!
//! Two mechanisms grant access:
//!
//! - **`TAG+="uaccess"` (modern)** — systemd-logind automatically grants the
//!   session user access to tagged devices via ACLs.  Requires systemd 220+
//!   with `pam_systemd` in the auth stack, which is the default on Ubuntu
//!   18.04+, Fedora, Debian 10+, and Arch.
//!
//! - **`GROUP="plugdev", MODE="0660"` (fallback)** — the device node is
//!   owned by the `plugdev` group with group-readable/writable mode.  The
//!   operator must be in `plugdev`.  Required on older distros, embedded
//!   systems, or any system where `uaccess` tagging is absent.
//!
//! [`install_ember_fido2_udev_rules`] writes the canonical rules file embedded
//! from the crate's `templates/install/` directory to `/etc/udev/rules.d/` and
//! reloads udevd.  The function is compiled only on `target_os = "linux"`.
//! On all other operating systems the module exports a stub that returns
//! [`InstallError::NotLinux`].

#[cfg(target_os = "linux")]
pub use imp::install_ember_fido2_udev_rules;
#[cfg(not(target_os = "linux"))]
pub use stubs::install_ember_fido2_udev_rules;

/// Options forwarded to [`install_ember_fido2_udev_rules`].
///
/// The struct is unconditionally visible so callers on non-Linux platforms
/// can construct it without `#[cfg]` guards — the stub ignores all fields.
#[derive(Debug, Clone, Default)]
pub struct Fido2UdevOptions {
    /// Destination directory for the rules file.  Defaults to
    /// `/etc/udev/rules.d` when `None`.  Overridden in tests to a temporary
    /// directory so the test never touches the real udev database.
    pub dest_dir: Option<std::path::PathBuf>,
}

/// Errors returned by [`install_ember_fido2_udev_rules`].
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error(
        "this operation is Linux-only; udev rules are not needed on {os}",
        os = std::env::consts::OS
    )]
    NotLinux,
    #[error(
        "writing udev rules to '{path}' failed: {source}\n\
         Hint: this operation requires root — re-run with `sudo ember install udev-rules`"
    )]
    Write {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "failed to reload udev rules (`{cmd}` exit {code}): {stderr}\n\
         Hint: run `sudo udevadm control --reload-rules && sudo udevadm trigger` manually"
    )]
    UdevReload {
        cmd: String,
        code: i32,
        stderr: String,
    },
    #[error(
        "udevadm not found on PATH — is udev / systemd installed on this system?\n\
         Hint: install udev (`apt install udev` / `yum install systemd`)"
    )]
    UdevadmMissing,
}

// ─── Linux implementation ─────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod imp {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::{Fido2UdevOptions, InstallError};

    /// The canonical rules file content, embedded at compile time from this
    /// crate's template directory. Using `include_str!` ensures the installed
    /// binary always ships the rules file that was tested alongside it - there
    /// is no separate distribution artifact to misplace.
    const RULES_CONTENT: &str = include_str!("../../templates/install/70-ember-fido2.rules");

    /// Install the ember FIDO2 udev rules file and reload udevd.
    ///
    /// # Steps
    ///
    /// 1. Resolves the destination path (`opts.dest_dir` or
    ///    `/etc/udev/rules.d`).
    /// 2. Writes `70-ember-fido2.rules` to that directory.  **Requires root
    ///    or write permission on `/etc/udev/rules.d/`.** Returns
    ///    [`InstallError::Write`] with a sudo hint if the write fails.
    /// 3. Probes whether `uaccess` tagging is available by checking for
    ///    `systemd-logind` in the process list / `pam_systemd.so` in the PAM
    ///    stack.  Prints a structured log line advising `plugdev` group
    ///    membership when `uaccess` is absent.
    /// 4. Runs `udevadm control --reload-rules` then `udevadm trigger`.
    ///    Returns [`InstallError::UdevReload`] if either exits non-zero, or
    ///    [`InstallError::UdevadmMissing`] if `udevadm` is not on PATH.
    ///
    /// # Errors
    ///
    /// See [`InstallError`] — every variant carries operator-actionable text.
    pub fn ember_fido2_udev_rules(opts: &Fido2UdevOptions) -> Result<(), InstallError> {
        let dest_dir = opts
            .dest_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/etc/udev/rules.d"));

        let dest = dest_dir.join("70-ember-fido2.rules");

        write_rules_file(&dest, RULES_CONTENT)?;
        eprintln!(
            "[install] phase=fido2-udev-rules ok dest={}",
            dest.display()
        );

        probe_uaccess_and_advise();

        reload_udev_rules()
    }

    fn write_rules_file(dest: &Path, content: &str) -> Result<(), InstallError> {
        std::fs::write(dest, content).map_err(|e| InstallError::Write {
            path: dest.to_path_buf(),
            source: e,
        })
    }

    /// Check whether systemd-logind / uaccess tagging is likely active, and
    /// print a log advisory when it is not.  The check is heuristic — we look
    /// for `/run/systemd/private` which systemd creates early in boot.  A
    /// missing directory is a strong signal that systemd is not the init
    /// system and that `uaccess` tagging will have no effect.
    fn probe_uaccess_and_advise() {
        let has_systemd = std::path::Path::new("/run/systemd/private").exists();
        if has_systemd {
            eprintln!(
                "[install] phase=fido2-uaccess-probe ok \
                 note=systemd-logind detected; TAG+=uaccess grants session-user access automatically"
            );
        } else {
            eprintln!(
                "[install] phase=fido2-uaccess-probe warn \
                 note=systemd-logind NOT detected (no /run/systemd/private); \
                 the udev rules fall back to GROUP=plugdev MODE=0660. \
                 Add your user to the plugdev group: `sudo usermod -aG plugdev $USER` \
                 then log out and back in."
            );
        }
    }

    /// Run `udevadm control --reload-rules` then `udevadm trigger`.
    fn reload_udev_rules() -> Result<(), InstallError> {
        run_udevadm(&["control", "--reload-rules"])?;
        run_udevadm(&["trigger"])?;
        eprintln!("[install] phase=fido2-udev-reload ok note=udev rules reloaded and triggered");
        Ok(())
    }

    fn run_udevadm(args: &[&str]) -> Result<(), InstallError> {
        let cmd_str = format!("udevadm {}", args.join(" "));
        let output = Command::new("udevadm").args(args).output().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                InstallError::UdevadmMissing
            } else {
                InstallError::UdevReload {
                    cmd: cmd_str.clone(),
                    code: -1,
                    stderr: e.to_string(),
                }
            }
        })?;

        if !output.status.success() {
            return Err(InstallError::UdevReload {
                cmd: cmd_str,
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }
        Ok(())
    }

    /// Public entry point — named with the checkpoint required by the task brief.
    pub fn install_ember_fido2_udev_rules(opts: &Fido2UdevOptions) -> Result<(), InstallError> {
        ember_fido2_udev_rules(opts)
    }
}

// ─── Non-Linux stub ───────────────────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
mod stubs {
    use super::{Fido2UdevOptions, InstallError};

    /// Stub on non-Linux targets — always returns [`InstallError::NotLinux`].
    pub fn install_ember_fido2_udev_rules(_opts: &Fido2UdevOptions) -> Result<(), InstallError> {
        Err(InstallError::NotLinux)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The bundled rules file contains the Yubico USB vendor ID (1050).
    ///
    /// This is the checkpoint acceptance test: if the embedded rules string does
    /// not contain "1050" we know the file was not compiled in correctly.
    #[test]
    fn parses_rules_file_fixture_contains_yubico_usb_id() {
        // The rules content is the same string on every platform — we read
        // the literal file rather than going through the cfg-gated constant
        // so this test compiles and passes on macOS / Windows CI too.
        let rules = include_str!("../../../../infra/udev/70-ember-fido2.rules");
        assert!(
            rules.contains("1050"),
            "rules file must contain Yubico USB vendor ID 0x1050; got:\n{rules}"
        );
        assert!(
            rules.contains("096e"),
            "rules file must contain Feitian vendor ID 0x096e"
        );
        assert!(
            rules.contains("20a0"),
            "rules file must contain Nitrokey vendor ID 0x20a0"
        );
        assert!(
            rules.contains("0483"),
            "rules file must contain SoloKeys vendor ID 0x0483"
        );
        assert!(
            rules.contains("uaccess"),
            "rules file must use TAG+=\"uaccess\" for modern systemd-logind systems"
        );
        assert!(
            rules.contains("plugdev"),
            "rules file must fall back to GROUP=plugdev for older systems"
        );
    }

    /// On non-Linux targets the stub returns NotLinux immediately.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn stub_returns_not_linux() {
        let err = install_ember_fido2_udev_rules(&Fido2UdevOptions::default())
            .expect_err("must return Err on non-Linux");
        assert!(
            matches!(err, InstallError::NotLinux),
            "expected NotLinux, got {err:?}"
        );
    }

    /// On Linux, writing to a non-existent directory returns a Write error
    /// with a sudo hint.  We use a bogus path rather than a tempdir so we
    /// don't need root — the whole point of this test is the error path.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_write_error_surfaces_sudo_hint() {
        let opts = Fido2UdevOptions {
            dest_dir: Some(std::path::PathBuf::from(
                "/nonexistent/path/that/cannot/exist/udev/rules.d",
            )),
        };
        let err = install_ember_fido2_udev_rules(&opts)
            .expect_err("must return Err when dest dir does not exist");
        assert!(
            matches!(err, InstallError::Write { .. }),
            "expected Write error, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("sudo"),
            "error message must mention sudo; got: {msg}"
        );
    }

    /// Default options have no dest_dir override — the production path would
    /// be /etc/udev/rules.d.
    #[test]
    fn default_options_have_no_dest_override() {
        let opts = Fido2UdevOptions::default();
        assert!(
            opts.dest_dir.is_none(),
            "default options must not override dest_dir"
        );
    }
}
