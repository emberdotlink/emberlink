//! Install-wizard scaffold + step orchestration.
//!
//! `run_install_wizard` is the entry point operators will reach via the
//! `ember install` CLI verb. The wizard:
//!
//! 1. [`batch_sudo_v`] — primes the sudo timestamp once at wizard start so
//!    later steps can shell out without re-prompting.
//! 2. [`detect_platform`] — returns a [`Platform`] discriminant the wizard
//!    branches on (macOS / Linux+distro / WSL+distro / Unsupported).
//! 3. Runs the five [step functions](#step-functions) sequentially under the
//!    single sudo elevation window — provision user, chown data dirs, emit
//!    launch spec, add operator to `ember-clients`, verify daemon.
//! 4. Writes a friendly transcript at `~/.ember/install-wizard.log` — every
//!    step appends a single ISO-8601 line so the operator (and support) has a
//!    breadcrumb of what the wizard tried.
//! 5. Prints a final relogin banner (Linux only) so `newgrp ember-clients`
//!    activates the new group membership in the operator's shell.
//!
//! # Step functions
//!
//! Each step is a `wizard_step_*` function returning [`StepOutcome`]:
//! - [`wizard_step_provision_user`] — system user + connect group.
//! - [`wizard_step_chown_data_dirs`] — chown `~/.ember/{vault,grants,…}`.
//! - [`wizard_step_provision_mek`] — vault MEK in System.keychain (macOS) /
//!   keyring (Linux). Without this the daemon refuses to start.
//!   implementation-note-425.
//! - [`wizard_step_emit_launch_spec`] — launchd plist or systemd unit.
//! - [`wizard_step_add_user_to_group`] — operator → `ember-clients`.
//! - [`wizard_step_verify`] — daemon socket present + responsive.
//!
//! Steps shell out to [`ember_daemon::install`] primitives via the
//! [`InstallPrimitives`] trait so tests can stub the side effects and assert
//! call order.

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;
use ember_daemon::install as daemon_install;
use serde::{Deserialize, Serialize};

/// Operating-system flavor the wizard targets.
///
/// `Linux` and `WslLinux` carry the parsed `ID=` value from
/// `/etc/os-release` so subtask B can branch per-distro for package-manager
/// or systemd-vs-init differences. `Unsupported` carries a free-form name
/// (whatever `std::env::consts::OS` reports) so the error message tells the
/// operator what we saw rather than just "not supported".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Platform {
    MacOS,
    Linux { distro: String },
    WslLinux { distro: String },
    Unsupported(String),
}

/// Errors raised by [`run_install_wizard`].
///
/// Each variant maps a raw OS-level failure to an operator-actionable message
/// — the wizard never leaks raw subprocess stderr to stdout without first
/// wrapping it in one of these variants. `Display` impls always include a
/// concrete next step the operator can take ("run `sudo -v` manually then
/// re-run install", "run `ember daemon install --debug-install`", …).
///
/// `SudoFailed` covers both "sudo not installed" and "operator cancelled the
/// password prompt" — they collapse into the same operator-visible action
/// (re-run the wizard).
///
/// `UserCreationFailed` is the dedicated variant for step 1 (provision-user)
/// failures — it's the most common failure mode and deserves a distinct
/// shape with a `detail` field carrying the underlying daemon error so the
/// hint can point at `ember daemon install --debug-install` for verbose
/// output.
#[derive(Debug, thiserror::Error)]
pub enum WizardError {
    #[error("sudo elevation failed; please run `sudo -v` manually then re-run install")]
    SudoFailed,
    #[error("unsupported platform: {0}; the install wizard supports macOS, Linux, and WSL")]
    UnsupportedPlatform(String),
    #[error("transcript io error: {0}; check ~/.ember/ permissions and re-run install")]
    TranscriptIo(#[from] io::Error),
    #[error(
        "couldn't create ember user: {detail}; \
         run `ember daemon install --debug-install` for verbose output"
    )]
    UserCreationFailed { detail: String },
    #[error(
        "install step '{step}' failed: {source}; \
         run `ember daemon install --debug-install` for verbose output"
    )]
    Install {
        step: &'static str,
        #[source]
        source: daemon_install::InstallError,
    },
    #[error(
        "group add for operator '{user}' failed: {stderr}; \
         re-run install or add manually with `usermod -aG ember-clients {user}` \
         (Linux) / `dseditgroup -o edit -a {user} -t user ember-clients` (macOS)"
    )]
    GroupAdd { user: String, stderr: String },
    #[error(
        "verify failed: {0}; check the daemon launcher (`launchctl list | grep ember` on macOS, `systemctl status emberd` on Linux)"
    )]
    Verify(String),
}

/// Canonical step identifiers used by [`WizardState`] and the unwind
/// dispatcher. The order is the forward execution order; rollback walks this
/// list in reverse.
pub const WIZARD_STEPS: &[&str] = &[
    "provision-user",
    "chown-data-dirs",
    "provision-mek",
    "emit-launch-spec",
    "load-apparmor",
    "add-user-to-group",
    "verify",
];

/// Persistent state recording which wizard steps completed on a prior run.
///
/// Serialized as JSON to `~/.ember/install-wizard.state.json` (one document
/// per wizard run, overwritten on re-run after rollback). The wizard reads
/// this on startup via [`load_wizard_state`] to decide whether to offer
/// resume/rollback or treat the run as a fresh install.
///
/// `last_error` is captured as a String (rather than the `WizardError` enum)
/// because `WizardError` carries a non-serde `daemon_install::InstallError`
/// source — flattening to a string keeps the on-disk format stable across
/// daemon-side error refactors and makes the file hand-debuggable. The
/// `Display`-formatted error is what we want operators to see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WizardState {
    /// Step identifiers (from [`WIZARD_STEPS`]) that completed successfully
    /// on the prior run, in execution order.
    pub completed_steps: Vec<String>,
    /// `Display`-formatted last error if the prior run failed mid-flight,
    /// `None` if the prior run completed all steps.
    pub last_error: Option<String>,
}

impl WizardState {
    /// Returns true when every step in [`WIZARD_STEPS`] is recorded as
    /// completed and no error is pending.
    pub fn is_complete(&self) -> bool {
        self.last_error.is_none()
            && WIZARD_STEPS
                .iter()
                .all(|s| self.completed_steps.iter().any(|c| c == s))
    }

    /// Returns the index into [`WIZARD_STEPS`] of the first step that has
    /// not yet completed, or `None` if all steps are done.
    pub fn next_step_index(&self) -> Option<usize> {
        WIZARD_STEPS
            .iter()
            .position(|s| !self.completed_steps.iter().any(|c| c == s))
    }
}

/// Resolution of a partial-state wizard run.
///
/// Returned by [`wizard_resume_or_rollback`] after consulting the prior
/// state file and (in production) prompting the operator. The wizard driver
/// dispatches on the variant:
///
/// - `AlreadyComplete` — print "already installed" + run a verify pass.
/// - `Resume(idx)` — replay forward steps starting at `WIZARD_STEPS[idx]`.
/// - `Rollback` — walk completed steps in reverse, calling unwind helpers.
/// - `Cancel` — exit without changing state on disk.
/// - `FreshInstall` — no prior state file existed; run all steps from scratch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeAction {
    AlreadyComplete,
    Resume(usize),
    Rollback,
    Cancel,
    FreshInstall,
}

/// Outcome of a single wizard step.
///
/// `Completed` carries a one-line description of what was done (printed to
/// the transcript and surfaced to the operator). `Skipped` covers the
/// idempotent case where the step detected the desired state was already in
/// place — the wizard still records the step ran but doesn't re-mutate the
/// system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    Completed { note: String },
    Skipped { reason: String },
}

impl StepOutcome {
    fn label(&self) -> &str {
        match self {
            StepOutcome::Completed { note } => note,
            StepOutcome::Skipped { reason } => reason,
        }
    }
}

/// Wizard execution context — passed by reference to every step.
///
/// `platform` drives per-OS branches (macOS launchd vs Linux systemd).
/// `home` is the operator's home dir (`$HOME`); the chown step walks
/// `home/.ember/{vault,grants,sessions,run,binaries}`.
/// `invoking_user` is `$USER` at wizard start — captured once so a step that
/// runs under sudo doesn't pick up `root` from the environment.
/// `socket_path` is where [`wizard_step_verify`] looks for the daemon UDS.
#[derive(Debug, Clone)]
pub struct WizardContext {
    pub platform: Platform,
    pub home: PathBuf,
    pub invoking_user: String,
    pub socket_path: PathBuf,
}

impl WizardContext {
    /// Build a `WizardContext` from the live process environment.
    ///
    /// `home` defaults to `dirs_next::home_dir()`, falling back to `.` for
    /// the same edge case [`transcript_path`] handles (no `$HOME` in a
    /// stripped container). `invoking_user` reads `$USER`; `$SUDO_USER`
    /// takes precedence when present so a step run via `sudo ember install`
    /// still records the unprivileged operator.
    pub fn from_env(platform: Platform) -> Self {
        let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let invoking_user = std::env::var("SUDO_USER")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_default();
        let socket_path = home.join(".ember").join("run").join("daemon.sock");
        Self {
            platform,
            home,
            invoking_user,
            socket_path,
        }
    }
}

/// Adapter trait over [`ember_daemon::install`] primitives so tests can stub
/// the side effects and assert step-call order. The real implementation
/// ([`RealPrimitives`]) forwards each method to the matching free function in
/// the daemon crate; the test implementation records call order in a
/// `Vec<&'static str>`.
///
/// Each forward step has a corresponding `unwind_*` method used by the
/// rollback path ([`wizard_resume_or_rollback`] → `ResumeAction::Rollback`).
/// Unwind methods are best-effort — they MUST tolerate the case where the
/// resource doesn't exist (e.g. unwinding `provision_ember_user` after the
/// step failed half-way). Default impls return `Ok(())` for stubs that don't
/// override them.
pub trait InstallPrimitives {
    fn provision_ember_user(&self) -> Result<(), daemon_install::InstallError>;
    fn chown_ember_data_dirs(&self, home: &Path) -> Result<(), daemon_install::InstallError>;
    /// Provision the vault MEK in System.keychain (macOS) / keyring (Linux).
    /// The daemon refuses to start without this. Idempotent — re-running
    /// against an existing MEK item is a no-op (preserves access to existing
    /// encrypted state). implementation-note-425.
    fn provision_se_mek(&self, home: &Path) -> Result<(), daemon_install::InstallError>;
    fn install_launch_spec(
        &self,
        platform: &Platform,
        operator_home: &Path,
    ) -> Result<(), daemon_install::InstallError>;
    fn add_operator_to_group(
        &self,
        platform: &Platform,
        user: &str,
    ) -> Result<(), daemon_install::InstallError>;
    fn socket_responsive(&self, socket: &Path) -> Result<(), String>;
    /// Load the AppArmor profile for agent containers into the kernel via
    /// `apparmor_parser -r`. Linux-only; non-Linux implementations may return
    /// `Ok(())` immediately. Idempotent — `-r` (replace) mode is safe to
    /// re-run on an already-loaded profile.
    fn load_apparmor_profile(&self) -> Result<(), daemon_install::InstallError>;

    /// Reverse of [`provision_ember_user`] — delete the `ember` system user
    /// and the `ember`/`ember-clients` groups. Best-effort; tolerates "no
    /// such user" stderr signatures.
    fn unwind_provision_ember_user(&self) -> Result<(), daemon_install::InstallError> {
        Ok(())
    }
    /// Reverse of [`chown_ember_data_dirs`] — chown the data dirs back to
    /// the operator's uid/gid. Best-effort.
    fn unwind_chown_ember_data_dirs(
        &self,
        _home: &Path,
    ) -> Result<(), daemon_install::InstallError> {
        Ok(())
    }
    /// Reverse of [`provision_se_mek`]. Default is no-op — unwinding a
    /// keychain item risks data loss (encrypted state under that key becomes
    /// unrecoverable), so rollback intentionally leaves the MEK in place.
    /// An operator who wants to wipe it can do so manually via `security
    /// delete-generic-password` / `secret-tool clear`.
    fn unwind_provision_se_mek(&self, _home: &Path) -> Result<(), daemon_install::InstallError> {
        Ok(())
    }
    /// Reverse of [`install_launch_spec`] — remove the launchd plist (macOS)
    /// or systemd unit (Linux/WSL). Best-effort.
    fn unwind_install_launch_spec(
        &self,
        _platform: &Platform,
    ) -> Result<(), daemon_install::InstallError> {
        Ok(())
    }
    /// Reverse of [`load_apparmor_profile`] — removing a loaded AppArmor
    /// profile from the kernel risks stranding running containers that were
    /// granted confinement under it, so rollback is intentionally a no-op.
    /// An operator who wants to unload the profile can run
    /// `apparmor_parser -R /etc/apparmor.d/ember-agent` manually.
    fn unwind_load_apparmor_profile(&self) -> Result<(), daemon_install::InstallError> {
        Ok(())
    }
    /// Reverse of [`add_operator_to_group`] — remove the operator from the
    /// `ember-clients` group. Best-effort.
    fn unwind_add_operator_to_group(
        &self,
        _platform: &Platform,
        _user: &str,
    ) -> Result<(), daemon_install::InstallError> {
        Ok(())
    }
    /// Reverse of [`socket_responsive`] / `wizard_step_verify` — verify is
    /// a read-only check, so unwind is a no-op. Provided for symmetry.
    fn unwind_verify(&self, _socket: &Path) -> Result<(), String> {
        Ok(())
    }
}

/// Production [`InstallPrimitives`] impl that forwards to the daemon's
/// install module.
///
/// `add_operator_to_group` is implemented inline (no daemon-side helper
/// exists for the operator-only group-add step) — it issues the same
/// platform-specific subprocess `provision_ember_user` runs internally for
/// step 4. Idempotent: running it after `provision_ember_user` is a no-op
/// because both `dseditgroup -a` and `usermod -aG` tolerate "already a
/// member".
///
/// `socket_responsive` checks the socket file exists. A future slice can
/// extend this to actually open + handshake; the current contract is "the
/// daemon has bound its UDS", which is what the operator's manual smoke test
/// looks at.
pub struct RealPrimitives;

impl InstallPrimitives for RealPrimitives {
    fn provision_ember_user(&self) -> Result<(), daemon_install::InstallError> {
        daemon_install::provision_ember_user()
    }

    fn chown_ember_data_dirs(&self, home: &Path) -> Result<(), daemon_install::InstallError> {
        daemon_install::chown_ember_data_dirs(home)
    }

    fn provision_se_mek(&self, home: &Path) -> Result<(), daemon_install::InstallError> {
        daemon_install::provision_se_mek(home)
    }

    fn install_launch_spec(
        &self,
        platform: &Platform,
        operator_home: &Path,
    ) -> Result<(), daemon_install::InstallError> {
        match platform {
            Platform::MacOS => daemon_install::install_launchd_plist(operator_home),
            Platform::Linux { .. } | Platform::WslLinux { .. } => {
                daemon_install::install_systemd_unit(operator_home)
            }
            Platform::Unsupported(name) => Err(daemon_install::InstallError::Subprocess {
                cmd: "install_launch_spec".to_string(),
                stderr: format!("unsupported platform: {name}"),
                exit_code: None,
            }),
        }
    }

    fn add_operator_to_group(
        &self,
        platform: &Platform,
        user: &str,
    ) -> Result<(), daemon_install::InstallError> {
        if user.is_empty() {
            return Ok(());
        }
        let (program, args): (&str, Vec<String>) = match platform {
            Platform::MacOS => (
                "dseditgroup",
                vec![
                    "-o".into(),
                    "edit".into(),
                    "-a".into(),
                    user.to_string(),
                    "-t".into(),
                    "user".into(),
                    "ember-clients".into(),
                ],
            ),
            Platform::Linux { .. } | Platform::WslLinux { .. } => (
                "usermod",
                vec!["-aG".into(), "ember-clients".into(), user.to_string()],
            ),
            Platform::Unsupported(name) => {
                return Err(daemon_install::InstallError::Subprocess {
                    cmd: "add_operator_to_group".to_string(),
                    stderr: format!("unsupported platform: {name}"),
                    exit_code: None,
                });
            }
        };

        let cmd_string = format!("{} {}", program, args.to_vec().join(" "));
        let output = Command::new(program).args(&args).output().map_err(|e| {
            daemon_install::InstallError::Subprocess {
                cmd: cmd_string.clone(),
                stderr: format!("spawn failed: {e}"),
                exit_code: None,
            }
        })?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let lower = stderr.to_lowercase();
        if lower.contains("already a member") || lower.contains("already exists") {
            return Ok(());
        }
        Err(daemon_install::InstallError::Subprocess {
            cmd: cmd_string,
            stderr,
            exit_code: output.status.code(),
        })
    }

    fn socket_responsive(&self, socket: &Path) -> Result<(), String> {
        if socket.exists() {
            Ok(())
        } else {
            Err(format!(
                "daemon socket not present at {} — daemon may still be starting",
                socket.display()
            ))
        }
    }

    fn load_apparmor_profile(&self) -> Result<(), daemon_install::InstallError> {
        load_apparmor_profile_impl()
    }

    /// Delete the `ember` system user + groups via the platform-native
    /// tools. macOS: `dscl . -delete /Users/ember` and `dseditgroup -o
    /// delete`. Linux: `userdel ember` + `groupdel ember-clients`. Tolerates
    /// "no such user/group" stderr signatures so a partial-state rollback
    /// after step 1 itself failed half-way doesn't error.
    fn unwind_provision_ember_user(&self) -> Result<(), daemon_install::InstallError> {
        #[cfg(target_os = "macos")]
        {
            let _ = run_tolerant(
                "dscl",
                &[".", "-delete", "/Users/ember"],
                &["does not exist", "eDSRecordNotFound"],
            );
            let _ = run_tolerant(
                "dseditgroup",
                &["-o", "delete", "ember-clients"],
                &["does not exist", "Group not found"],
            );
            let _ = run_tolerant(
                "dseditgroup",
                &["-o", "delete", "ember"],
                &["does not exist", "Group not found"],
            );
            Ok(())
        }
        #[cfg(target_os = "linux")]
        {
            let _ = run_tolerant("userdel", &["ember"], &["does not exist", "no such user"]);
            let _ = run_tolerant(
                "groupdel",
                &["ember-clients"],
                &["does not exist", "no such group"],
            );
            let _ = run_tolerant("groupdel", &["ember"], &["does not exist", "no such group"]);
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Ok(())
        }
    }

    /// Best-effort: chown `~/.ember` back to the operator's uid:gid. We
    /// can't recover the original ownership exactly without snapshotting
    /// it pre-step, so we restore to `$USER:staff` (macOS) / `$USER:$USER`
    /// (Linux) which matches the typical pre-install ownership.
    fn unwind_chown_ember_data_dirs(
        &self,
        home: &Path,
    ) -> Result<(), daemon_install::InstallError> {
        let ember_dir = home.join(".ember");
        if !ember_dir.exists() {
            return Ok(());
        }
        let user = std::env::var("SUDO_USER")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_default();
        if user.is_empty() {
            return Ok(());
        }
        let group = if cfg!(target_os = "macos") {
            "staff".to_string()
        } else {
            user.clone()
        };
        let owner = format!("{user}:{group}");
        let _ = run_tolerant(
            "chown",
            &["-R", &owner, &ember_dir.to_string_lossy()],
            &["No such file or directory"],
        );
        Ok(())
    }

    /// Remove the platform launch spec — `launchctl bootout` + `rm` the
    /// plist on macOS, `systemctl disable --now` + `rm` the unit on
    /// Linux/WSL. Tolerates "not currently bootstrapped" / "no such file"
    /// stderr.
    fn unwind_install_launch_spec(
        &self,
        platform: &Platform,
    ) -> Result<(), daemon_install::InstallError> {
        const LAUNCHD_PLIST_PATH: &str = "/Library/LaunchDaemons/sh.emberlink.daemon.plist";
        const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/emberd.service";
        match platform {
            Platform::MacOS => {
                let _ = run_tolerant(
                    "launchctl",
                    &["bootout", "system", LAUNCHD_PLIST_PATH],
                    &["Could not find specified service"],
                );
                let _ = run_tolerant(
                    "rm",
                    &["-f", LAUNCHD_PLIST_PATH],
                    &["No such file or directory"],
                );
                Ok(())
            }
            Platform::Linux { .. } | Platform::WslLinux { .. } => {
                let _ = run_tolerant(
                    "systemctl",
                    &["disable", "--now", "emberd.service"],
                    &["does not exist", "not loaded"],
                );
                let _ = run_tolerant(
                    "rm",
                    &["-f", SYSTEMD_UNIT_PATH],
                    &["No such file or directory"],
                );
                let _ = run_tolerant("systemctl", &["daemon-reload"], &[]);
                Ok(())
            }
            Platform::Unsupported(_) => Ok(()),
        }
    }

    /// Remove the operator from the `ember-clients` connect group.
    /// macOS: `dseditgroup -o edit -d <user>`. Linux: `gpasswd -d <user>
    /// ember-clients`. Tolerates "not a member" stderr.
    fn unwind_add_operator_to_group(
        &self,
        platform: &Platform,
        user: &str,
    ) -> Result<(), daemon_install::InstallError> {
        if user.is_empty() {
            return Ok(());
        }
        match platform {
            Platform::MacOS => {
                let _ = run_tolerant(
                    "dseditgroup",
                    &["-o", "edit", "-d", user, "-t", "user", "ember-clients"],
                    &["not a member", "is not a member"],
                );
                Ok(())
            }
            Platform::Linux { .. } | Platform::WslLinux { .. } => {
                let _ = run_tolerant(
                    "gpasswd",
                    &["-d", user, "ember-clients"],
                    &["not a member", "is not a member"],
                );
                Ok(())
            }
            Platform::Unsupported(_) => Ok(()),
        }
    }

    /// Verify is read-only — unwind is a no-op.
    fn unwind_verify(&self, _socket: &Path) -> Result<(), String> {
        Ok(())
    }
}

/// Best-effort subprocess runner used by the unwind path. Swallows
/// failures whose stderr contains any of `tolerate_substrings` (so e.g.
/// "no such user" doesn't fail the rollback). Returns `Ok(())` on success
/// or tolerated failure; bubbles up other failures as `InstallError`.
fn run_tolerant(
    program: &str,
    args: &[&str],
    tolerate_substrings: &[&str],
) -> Result<(), daemon_install::InstallError> {
    let cmd_string = format!("{} {}", program, args.join(" "));
    let output = Command::new(program).args(args).output().map_err(|e| {
        daemon_install::InstallError::Subprocess {
            cmd: cmd_string.clone(),
            stderr: format!("spawn failed: {e}"),
            exit_code: None,
        }
    })?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let lower = stderr.to_lowercase();
    for sub in tolerate_substrings {
        if lower.contains(&sub.to_lowercase()) {
            return Ok(());
        }
    }
    Err(daemon_install::InstallError::Subprocess {
        cmd: cmd_string,
        stderr,
        exit_code: output.status.code(),
    })
}

// apparmor_profile_loaded_into_kernel
/// Load the AppArmor profile for agent containers into the kernel.
///
/// On Linux: invokes `apparmor_parser -r infra/apparmor/ember-agent.profile`
/// via sudo. The `-r` (replace) flag is idempotent — re-running after the
/// profile is already loaded silently replaces it in place. If `apparmor_parser`
/// is not installed (some minimal distros ship without it), the error is
/// downgraded to a `tracing::warn` so the install continues. The
/// `security_opt: apparmor=ember-agent` declaration in `compose.yml.j2` will
/// surface as a container-start error if the profile is genuinely missing at
/// runtime, which is the correct failure mode.
///
/// On non-Linux: skips with an informational log.
#[cfg(target_os = "linux")]
fn load_apparmor_profile_impl() -> Result<(), daemon_install::InstallError> {
    let profile_path = "infra/apparmor/ember-agent.profile";
    let output = Command::new("sudo")
        .args(["apparmor_parser", "-r", profile_path])
        .output();
    match output {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                "apparmor_parser not found on PATH — skipping AppArmor profile load; \
                 install apparmor-utils if AppArmor enforcement is required"
            );
            Ok(())
        }
        Err(e) => Err(daemon_install::InstallError::Subprocess {
            cmd: format!("sudo apparmor_parser -r {profile_path}"),
            stderr: format!("spawn failed: {e}"),
            exit_code: None,
        }),
        Ok(out) if out.status.success() => {
            tracing::info!(
                profile = profile_path,
                "apparmor_profile_loaded_into_kernel: profile loaded/replaced"
            );
            Ok(())
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            Err(daemon_install::InstallError::Subprocess {
                cmd: format!("sudo apparmor_parser -r {profile_path}"),
                stderr,
                exit_code: out.status.code(),
            })
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn load_apparmor_profile_impl() -> Result<(), daemon_install::InstallError> {
    tracing::info!("apparmor_profile_loaded_into_kernel: skipped on non-Linux platform");
    Ok(())
}

/// Run the install wizard.
///
/// Drives a single sudo elevation window across the five install steps:
///
/// 1. Prime sudo via `sudo -v`.
/// 2. Detect the host platform (errors out on `Unsupported`).
/// 3. Build a [`WizardContext`] from the live environment.
/// 4. Consult any prior `~/.ember/install-wizard.state.json` via
///    [`wizard_resume_or_rollback`]; dispatch on the resulting
///    [`ResumeAction`].
/// 5. On a forward path, run the five steps starting at the appropriate
///    index against [`RealPrimitives`].
/// 6. Print the platform-specific relogin banner.
pub fn run_install_wizard() -> Result<(), WizardError> {
    batch_sudo_v()?;

    let platform = detect_platform();
    let outcome = match &platform {
        Platform::MacOS => "macos".to_string(),
        Platform::Linux { distro } => format!("linux/{distro}"),
        Platform::WslLinux { distro } => format!("wsl/{distro}"),
        Platform::Unsupported(name) => format!("unsupported/{name}"),
    };
    append_transcript("detect-platform", &outcome)?;

    if let Platform::Unsupported(name) = &platform {
        return Err(WizardError::UnsupportedPlatform(name.clone()));
    }

    let ctx = WizardContext::from_env(platform);
    let primitives = RealPrimitives;

    // Idempotency / resume / rollback: consult prior state first.
    let prior = load_wizard_state()?;
    let action = match &prior {
        Some(state) => wizard_resume_or_rollback(state),
        None => ResumeAction::FreshInstall,
    };
    let start_index = match action {
        ResumeAction::AlreadyComplete => {
            println!();
            println!("Ok | install wizard already complete on this host.");
            // Run a verification pass so the operator sees a fresh status.
            if let Err(reason) = primitives.socket_responsive(&ctx.socket_path) {
                println!("  verify: {reason}");
            } else {
                println!(
                    "  verify: daemon socket present at {}",
                    ctx.socket_path.display()
                );
            }
            return Ok(());
        }
        ResumeAction::Cancel => {
            println!("Cancelled — no changes made.");
            return Ok(());
        }
        ResumeAction::Rollback => {
            let state = prior.expect("Rollback requires a prior state");
            run_rollback(&ctx, &primitives, &state)?;
            println!("Rollback complete — re-run `ember install` to retry.");
            return Ok(());
        }
        ResumeAction::Resume(idx) => idx,
        ResumeAction::FreshInstall => 0,
    };

    run_wizard_steps_from(&ctx, &primitives, start_index)?;
    print_relogin_banner(&ctx.platform);
    Ok(())
}

/// Run all five wizard steps in order against the supplied
/// [`InstallPrimitives`] adapter. The first failure short-circuits — later
/// steps don't run, the transcript reflects what was attempted, and the
/// caller surfaces the error to the operator.
///
/// The trait-object form is the testability seam: production passes
/// [`RealPrimitives`]; the T1 test passes a recording stub.
///
/// Equivalent to [`run_wizard_steps_from`] with `start_index = 0`.
pub fn run_wizard_steps<P: InstallPrimitives>(
    ctx: &WizardContext,
    primitives: &P,
) -> Result<(), WizardError> {
    run_wizard_steps_from(ctx, primitives, 0)
}

/// Run forward wizard steps starting at `start_index` into [`WIZARD_STEPS`].
/// Used by the resume path — the driver calls this with the index returned
/// by [`WizardState::next_step_index`] so we replay only the not-yet-done
/// steps.
///
/// Persists a [`WizardState`] checkpoint after every successful step (so a
/// crash mid-flow leaves a recoverable breadcrumb) and on failure (so the
/// next run sees `last_error` populated and offers resume/rollback).
pub fn run_wizard_steps_from<P: InstallPrimitives>(
    ctx: &WizardContext,
    primitives: &P,
    start_index: usize,
) -> Result<(), WizardError> {
    // Seed completed_steps from the on-disk state if it already exists, so
    // we don't drop the prior run's breadcrumb during resume.
    let mut state = load_wizard_state()?.unwrap_or(WizardState {
        completed_steps: Vec::new(),
        last_error: None,
    });
    state.last_error = None;

    let result = (|| -> Result<(), WizardError> {
        for (idx, step) in WIZARD_STEPS.iter().enumerate() {
            if idx < start_index {
                continue;
            }
            let outcome = match *step {
                "provision-user" => wizard_step_provision_user(ctx, primitives)?,
                "chown-data-dirs" => wizard_step_chown_data_dirs(ctx, primitives)?,
                "provision-mek" => wizard_step_provision_mek(ctx, primitives)?,
                "emit-launch-spec" => wizard_step_emit_launch_spec(ctx, primitives)?,
                "load-apparmor" => wizard_step_load_apparmor(ctx, primitives)?,
                "add-user-to-group" => wizard_step_add_user_to_group(ctx, primitives)?,
                "verify" => wizard_step_verify(ctx, primitives)?,
                other => {
                    return Err(WizardError::Verify(format!(
                        "unknown wizard step '{other}'"
                    )));
                }
            };
            append_transcript(step, outcome.label())?;
            if !state.completed_steps.iter().any(|s| s == *step) {
                state.completed_steps.push((*step).to_string());
            }
            save_wizard_state(&state)?;
        }
        Ok(())
    })();

    if let Err(ref err) = result {
        state.last_error = Some(err.to_string());
        // Best-effort: surface a save failure as the original error rather
        // than masking it with an io error.
        let _ = save_wizard_state(&state);
    } else {
        // All steps completed — clear the state file so the next run is
        // recognised as `AlreadyComplete` rather than a partial-state
        // resume offer (a re-run after success should be idempotent).
        let _ = clear_wizard_state();
    }

    result
}

/// Step 1 — provision the `ember` system user, the `ember` group, and the
/// `ember-clients` connect group. Idempotent: the daemon-side primitive
/// tolerates "already exists" stderr signatures.
pub fn wizard_step_provision_user<P: InstallPrimitives>(
    ctx: &WizardContext,
    primitives: &P,
) -> Result<StepOutcome, WizardError> {
    primitives
        .provision_ember_user()
        .map_err(|source| WizardError::UserCreationFailed {
            detail: source.to_string(),
        })?;
    Ok(StepOutcome::Completed {
        note: format!(
            "ember user + ember-clients group provisioned (platform: {})",
            platform_label(&ctx.platform)
        ),
    })
}

/// Step 2 — recursively chown `~/.ember/{vault,grants,sessions,run,binaries}`
/// to `ember:ember-clients` so the dedicated daemon uid can read its at-rest
/// state. Idempotent and skip-safe (missing subdirs short-circuit
/// per the daemon-side helper).
pub fn wizard_step_chown_data_dirs<P: InstallPrimitives>(
    ctx: &WizardContext,
    primitives: &P,
) -> Result<StepOutcome, WizardError> {
    primitives
        .chown_ember_data_dirs(&ctx.home)
        .map_err(|source| WizardError::Install {
            step: "chown-data-dirs",
            source,
        })?;
    Ok(StepOutcome::Completed {
        note: format!(
            "chowned {}/.ember to ember:ember-clients",
            ctx.home.display()
        ),
    })
}

/// Step 3 — provision the vault MEK in System.keychain (macOS) / keyring
/// (Linux). Without this the daemon refuses to start: the vault module's
/// boot path requires a present MEK to derive the file-encryption key.
///
/// Idempotent: `provision_se_mek` short-circuits when the keychain item
/// already exists, preserving access to any existing encrypted state from
/// a prior install. Re-running this step is safe.
///
/// implementation-note-425. The older
/// non-wizard install path (in `crates/emberlink-cli/src/bin/ember.rs`)
/// called this between the chown step and the launchd-plist step; the
/// wizard refactor dropped it, causing every fresh install to end with a
/// daemon that crash-loops because the MEK isn't in the keychain.
pub fn wizard_step_provision_mek<P: InstallPrimitives>(
    ctx: &WizardContext,
    primitives: &P,
) -> Result<StepOutcome, WizardError> {
    primitives
        .provision_se_mek(&ctx.home)
        .map_err(|source| WizardError::Install {
            step: "provision-mek",
            source,
        })?;
    Ok(StepOutcome::Completed {
        note: "provisioned vault MEK in keychain".to_string(),
    })
}

/// Step 4 — emit the platform launch spec (LaunchDaemon plist on macOS,
/// systemd unit on Linux/WSL) and bootstrap the daemon under the dedicated
/// uid. Both daemon-side primitives are idempotent — the unit is rewritten
/// only when the on-disk body drifts from the rendered body.
pub fn wizard_step_emit_launch_spec<P: InstallPrimitives>(
    ctx: &WizardContext,
    primitives: &P,
) -> Result<StepOutcome, WizardError> {
    primitives
        .install_launch_spec(&ctx.platform, &ctx.home)
        .map_err(|source| WizardError::Install {
            step: "emit-launch-spec",
            source,
        })?;
    let note = match &ctx.platform {
        Platform::MacOS => "installed LaunchDaemon plist".to_string(),
        Platform::Linux { .. } | Platform::WslLinux { .. } => "installed systemd unit".to_string(),
        Platform::Unsupported(name) => format!("unsupported platform: {name}"),
    };
    Ok(StepOutcome::Completed { note })
}

/// Step 5 — load the AppArmor profile for agent containers into the kernel.
///
/// On Linux invokes `sudo apparmor_parser -r infra/apparmor/ember-agent.profile`
/// via the [`InstallPrimitives::load_apparmor_profile`] seam. Idempotent — the
/// `-r` flag replaces an already-loaded profile in place. If `apparmor_parser`
/// is absent the step logs a warning and returns `Completed` rather than
/// failing the wizard (the missing binary is surfaced as a warning, not an
/// error, consistent with the brief's NotFound handling contract).
///
/// On non-Linux the step is a no-op and returns `Skipped`.
pub fn wizard_step_load_apparmor<P: InstallPrimitives>(
    ctx: &WizardContext,
    primitives: &P,
) -> Result<StepOutcome, WizardError> {
    match &ctx.platform {
        Platform::Linux { .. } | Platform::WslLinux { .. } => {
            primitives
                .load_apparmor_profile()
                .map_err(|source| WizardError::Install {
                    step: "load-apparmor",
                    source,
                })?;
            Ok(StepOutcome::Completed {
                note: "AppArmor profile ember-agent loaded into kernel".to_string(),
            })
        }
        _ => Ok(StepOutcome::Skipped {
            reason: format!(
                "AppArmor profile load skipped on {}",
                platform_label(&ctx.platform)
            ),
        }),
    }
}

/// Step 6 — add the invoking operator to the `ember-clients` connect group
/// so the operator's processes can reach the daemon socket. Step 1 already
/// did this internally; this step re-runs the platform-specific group-add
/// command so the wizard transcript surfaces a distinct line, and so a
/// hand-removed operator (`gpasswd -d`, `dseditgroup -d`) is recovered on
/// re-run.
pub fn wizard_step_add_user_to_group<P: InstallPrimitives>(
    ctx: &WizardContext,
    primitives: &P,
) -> Result<StepOutcome, WizardError> {
    if ctx.invoking_user.is_empty() {
        return Ok(StepOutcome::Skipped {
            reason: "no invoking user detected ($USER and $SUDO_USER both empty)".to_string(),
        });
    }
    primitives
        .add_operator_to_group(&ctx.platform, &ctx.invoking_user)
        .map_err(|source| match source {
            daemon_install::InstallError::Subprocess { stderr, .. } => WizardError::GroupAdd {
                user: ctx.invoking_user.clone(),
                stderr,
            },
            other => WizardError::Install {
                step: "add-user-to-group",
                source: other,
            },
        })?;
    Ok(StepOutcome::Completed {
        note: format!("added {} to ember-clients", ctx.invoking_user),
    })
}

/// Step 6 — verify the daemon is responding under `uid=ember`.
///
/// Two checks: (a) the daemon socket exists at
/// `~/.ember/run/daemon.sock`; (b) `ps -eo uid,pid,comm | grep emberd`
/// finds an emberd process. The verification is best-effort — if the
/// platform launcher is still starting the daemon we record a Skipped
/// outcome rather than failing the wizard.
pub fn wizard_step_verify<P: InstallPrimitives>(
    ctx: &WizardContext,
    primitives: &P,
) -> Result<StepOutcome, WizardError> {
    if let Err(reason) = primitives.socket_responsive(&ctx.socket_path) {
        return Ok(StepOutcome::Skipped { reason });
    }
    Ok(StepOutcome::Completed {
        note: format!("daemon socket present at {}", ctx.socket_path.display()),
    })
}

fn platform_label(platform: &Platform) -> String {
    match platform {
        Platform::MacOS => "macos".to_string(),
        Platform::Linux { distro } => format!("linux/{distro}"),
        Platform::WslLinux { distro } => format!("wsl/{distro}"),
        Platform::Unsupported(name) => format!("unsupported/{name}"),
    }
}

/// Print the final operator-facing banner instructing the user how to pick
/// up the new `ember-clients` membership without a full logout.
///
/// On Linux/WSL we recommend `newgrp ember-clients` because group changes
/// don't propagate into existing shells; on macOS `dseditgroup` is
/// session-local but new shells pick it up immediately, so the banner just
/// says "open a new terminal".
fn print_relogin_banner(platform: &Platform) {
    println!();
    println!("Ok | install wizard complete.");
    match platform {
        Platform::MacOS => {
            println!("  Open a new terminal so the ember-clients group membership takes effect.");
        }
        Platform::Linux { .. } | Platform::WslLinux { .. } => {
            println!("  Run `newgrp ember-clients` (or log out and back in) so the new");
            println!("  group membership takes effect in your shell.");
        }
        Platform::Unsupported(_) => {}
    }
}

/// Prime the sudo credential cache.
///
/// `sudo -v` validates (and refreshes) the operator's cached credentials
/// without running any other command. The wizard calls this once up-front so
/// later subprocess calls — `dseditgroup`, `useradd`, `launchctl`,
/// `systemctl` — don't each trigger a fresh password prompt mid-flow.
fn batch_sudo_v() -> Result<(), WizardError> {
    let status = Command::new("sudo").arg("-v").status();
    match status {
        Ok(s) if s.success() => Ok(()),
        _ => Err(WizardError::SudoFailed),
    }
}

/// Detect the host platform using the production filesystem locations.
///
/// Thin wrapper around [`detect_platform_from_paths`] that wires
/// `/etc/os-release` and `/proc/version`. Tests inject custom paths.
pub fn detect_platform() -> Platform {
    detect_platform_from_paths(Path::new("/etc/os-release"), Path::new("/proc/version"))
}

/// Detect the host platform from injected paths (testable form).
///
/// On macOS we short-circuit on `cfg!(target_os = "macos")` and don't look at
/// the filesystem at all. On Linux we read `os_release` to extract `ID=` (the
/// distro short name) and check `proc_version` for `Microsoft`/`WSL` markers
/// to distinguish native Linux from WSL. Anything else returns
/// [`Platform::Unsupported`] with `std::env::consts::OS` so the operator
/// sees what the binary thinks the host is.
pub fn detect_platform_from_paths(os_release: &Path, proc_version: &Path) -> Platform {
    if cfg!(target_os = "macos") {
        return Platform::MacOS;
    }
    if cfg!(target_os = "linux") {
        let distro = parse_distro_id(os_release).unwrap_or_else(|| "unknown".to_string());
        if is_wsl(proc_version) {
            return Platform::WslLinux { distro };
        }
        return Platform::Linux { distro };
    }
    Platform::Unsupported(std::env::consts::OS.to_string())
}

/// Pull the `ID=` value out of an `os-release`-formatted file.
///
/// Returns `None` if the file is missing, unreadable, or has no `ID=` line.
/// Strips surrounding double-quotes from the value (per the os-release spec
/// values may be quoted, e.g. `ID="ubuntu"`).
fn parse_distro_id(os_release: &Path) -> Option<String> {
    let contents = fs::read_to_string(os_release).ok()?;
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("ID=") {
            let trimmed = rest.trim().trim_matches('"').to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

/// Returns true if `proc_version` looks like a WSL kernel banner.
///
/// WSL1 and WSL2 both leave a `Microsoft` substring in `/proc/version`; WSL2
/// additionally tags the build with `WSL`. We match either.
fn is_wsl(proc_version: &Path) -> bool {
    match fs::read_to_string(proc_version) {
        Ok(contents) => contents.contains("Microsoft") || contents.contains("WSL"),
        Err(_) => false,
    }
}

/// Append a single line to `~/.ember/install-wizard.log`.
///
/// Format: `<UTC ISO-8601> | <step> | <outcome>`. Creates `~/.ember/` if it
/// doesn't exist. Failures bubble up as [`WizardError::TranscriptIo`] —
/// the wizard cannot continue if it can't write its own audit trail.
fn append_transcript(step: &str, outcome: &str) -> Result<(), WizardError> {
    let path = transcript_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(
        file,
        "{} | {} | {}",
        Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
        step,
        outcome
    )?;
    Ok(())
}

/// Resolve `~/.ember/install-wizard.log`.
///
/// Falls back to `./.ember/install-wizard.log` when `dirs_next::home_dir()`
/// returns `None` (extremely unusual — only happens in a stripped container
/// without `$HOME` set). The fallback keeps the wizard functional in CI
/// rather than panicking.
fn transcript_path() -> PathBuf {
    dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".ember")
        .join("install-wizard.log")
}

/// Resolve `~/.ember/install-wizard.state.json` — the machine-readable
/// counterpart to the human transcript at [`transcript_path`]. Same fallback
/// rule as [`transcript_path`].
fn state_path() -> PathBuf {
    dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".ember")
        .join("install-wizard.state.json")
}

/// Persist [`WizardState`] to `~/.ember/install-wizard.state.json` as a
/// pretty-printed JSON document. Overwrites the prior file. Failures bubble
/// up as [`WizardError::TranscriptIo`] for the same reason
/// [`append_transcript`] does — the wizard cannot continue if it can't
/// persist its own resume breadcrumb.
pub fn save_wizard_state(state: &WizardState) -> Result<(), WizardError> {
    save_wizard_state_at(state, &state_path())
}

/// Test-friendly variant of [`save_wizard_state`] — caller chooses the path.
pub fn save_wizard_state_at(state: &WizardState, path: &Path) -> Result<(), WizardError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(state)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(path, body)?;
    Ok(())
}

/// Load [`WizardState`] from `~/.ember/install-wizard.state.json`. Returns
/// `Ok(None)` when the file does not exist (= fresh install). Returns
/// `Ok(Some(state))` on a clean parse, or `Err` on IO failure / malformed
/// JSON.
pub fn load_wizard_state() -> Result<Option<WizardState>, WizardError> {
    load_wizard_state_at(&state_path())
}

/// Test-friendly variant of [`load_wizard_state`] — caller chooses the path.
pub fn load_wizard_state_at(path: &Path) -> Result<Option<WizardState>, WizardError> {
    if !path.exists() {
        return Ok(None);
    }
    let body = fs::read_to_string(path)?;
    let state = serde_json::from_str::<WizardState>(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(state))
}

/// Remove the persisted state file. Used after a successful rollback so the
/// next wizard run sees a clean `FreshInstall`. Tolerates "file not found".
pub fn clear_wizard_state() -> Result<(), WizardError> {
    let path = state_path();
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

/// Decide what to do with a partial-state wizard run.
///
/// Reads `prior_state` and returns the appropriate [`ResumeAction`]. The
/// prompt-driven branches (`Resume` / `Rollback` / `Cancel`) call
/// [`prompt_resume_choice`] under the hood; tests bypass the prompt by
/// using [`wizard_resume_or_rollback_with_choice`] directly.
///
/// Decision matrix:
///
/// | Prior state                         | Action            |
/// |-------------------------------------|-------------------|
/// | `is_complete()` (all 5 steps done)  | `AlreadyComplete` |
/// | partially complete (1-4 steps)      | prompt → R/B/C    |
/// | empty completed_steps + no error    | `FreshInstall`    |
/// | empty completed_steps + error       | prompt → R/B/C    |
pub fn wizard_resume_or_rollback(prior_state: &WizardState) -> ResumeAction {
    if prior_state.is_complete() {
        return ResumeAction::AlreadyComplete;
    }
    if prior_state.completed_steps.is_empty() && prior_state.last_error.is_none() {
        return ResumeAction::FreshInstall;
    }
    let choice = prompt_resume_choice(prior_state);
    dispatch_resume_choice(prior_state, choice)
}

/// Test-friendly variant of [`wizard_resume_or_rollback`] — caller supplies
/// the prompt choice instead of the function reading stdin. The character
/// argument matches what [`prompt_resume_choice`] returns: `'r'` for resume,
/// `'b'` for rollback, `'c'` for cancel.
pub fn wizard_resume_or_rollback_with_choice(
    prior_state: &WizardState,
    choice: char,
) -> ResumeAction {
    if prior_state.is_complete() {
        return ResumeAction::AlreadyComplete;
    }
    if prior_state.completed_steps.is_empty() && prior_state.last_error.is_none() {
        return ResumeAction::FreshInstall;
    }
    dispatch_resume_choice(prior_state, choice)
}

fn dispatch_resume_choice(prior_state: &WizardState, choice: char) -> ResumeAction {
    match choice {
        'r' | 'R' => match prior_state.next_step_index() {
            Some(idx) => ResumeAction::Resume(idx),
            None => ResumeAction::AlreadyComplete,
        },
        'b' | 'B' => ResumeAction::Rollback,
        _ => ResumeAction::Cancel,
    }
}

/// Prompt the operator with `[r]esume from step X, [b]rollback, [c]ancel?`
/// and return the matching character. On EOF / unrecognized input we
/// default to `'c'` (cancel) — the safe choice when the wizard is uncertain
/// what the operator wants.
fn prompt_resume_choice(prior_state: &WizardState) -> char {
    let next_step_label = prior_state
        .next_step_index()
        .map(|i| WIZARD_STEPS[i])
        .unwrap_or("(none)");
    println!();
    println!(
        "Prior install attempt left {} step(s) complete.",
        prior_state.completed_steps.len()
    );
    if let Some(err) = &prior_state.last_error {
        println!("  Last error: {err}");
    }
    print!("[r]esume from step '{next_step_label}', [b]rollback, [c]ancel? ");
    io::stdout().flush().ok();
    let mut buf = String::new();
    let stdin = io::stdin();
    if stdin.lock().read_line(&mut buf).is_err() {
        return 'c';
    }
    buf.trim().chars().next().unwrap_or('c')
}

/// Walk completed steps in reverse and call the matching unwind helper.
/// Best-effort — unwind helpers tolerate missing resources, so a partial
/// rollback after a half-complete forward run still completes cleanly.
///
/// On success, [`clear_wizard_state`] is called so the next wizard run sees
/// `FreshInstall` rather than re-offering rollback for the now-clean host.
pub fn run_rollback<P: InstallPrimitives>(
    ctx: &WizardContext,
    primitives: &P,
    prior_state: &WizardState,
) -> Result<(), WizardError> {
    for step in prior_state.completed_steps.iter().rev() {
        match step.as_str() {
            "verify" => {
                primitives.unwind_verify(&ctx.socket_path).ok();
            }
            "add-user-to-group" => {
                primitives
                    .unwind_add_operator_to_group(&ctx.platform, &ctx.invoking_user)
                    .map_err(|source| WizardError::Install {
                        step: "unwind-add-user-to-group",
                        source,
                    })?;
            }
            "emit-launch-spec" => {
                primitives
                    .unwind_install_launch_spec(&ctx.platform)
                    .map_err(|source| WizardError::Install {
                        step: "unwind-emit-launch-spec",
                        source,
                    })?;
            }
            "load-apparmor" => {
                // AppArmor profile unload is intentionally a no-op on rollback —
                // removing a loaded profile strands running containers that were
                // confined under it. See unwind_load_apparmor_profile docstring.
                primitives.unwind_load_apparmor_profile().ok();
            }
            "provision-mek" => {
                primitives
                    .unwind_provision_se_mek(&ctx.home)
                    .map_err(|source| WizardError::Install {
                        step: "unwind-provision-mek",
                        source,
                    })?;
            }
            "chown-data-dirs" => {
                primitives
                    .unwind_chown_ember_data_dirs(&ctx.home)
                    .map_err(|source| WizardError::Install {
                        step: "unwind-chown-data-dirs",
                        source,
                    })?;
            }
            "provision-user" => {
                primitives.unwind_provision_ember_user().map_err(|source| {
                    WizardError::Install {
                        step: "unwind-provision-user",
                        source,
                    }
                })?;
            }
            other => {
                tracing::warn!(step = %other, "rollback: unknown step, skipping");
            }
        }
        append_transcript("rollback", step)?;
    }
    clear_wizard_state()?;
    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────
// implementation-note-407 — new-machine daemon detection + prompt
// ───────────────────────────────────────────────────────────────────────────

/// Three-state result of [`detect_daemon_installed`].
///
/// - `Running`: the daemon socket is present on disk (the daemon is accepting
///   connections).  We skip the install prompt entirely.
/// - `InstalledNotRunning`: the platform service file (LaunchAgent plist or
///   systemd user unit) exists but the socket is absent — the daemon has been
///   installed before but isn't running right now.  We skip the install prompt
///   and let the operator start the daemon manually or via `ember daemon start`.
/// - `NotInstalled`: no service file and no socket.  This is the new-machine
///   path — `ember init` should offer to run `sudo ember daemon install`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonInstallStatus {
    /// Socket present — daemon is running.
    Running,
    /// Service file found but socket absent — installed, not yet running.
    InstalledNotRunning,
    /// No service file and no socket — not installed.
    NotInstalled,
}

/// Detect whether the ember daemon is installed and/or running.
///
/// Detection order:
/// 1. **Socket probe** — if `socket_path` exists, the daemon is `Running`.
/// 2. **macOS LaunchAgent** — `~/Library/LaunchAgents/link.ember.daemon.plist`
///    present → `InstalledNotRunning`.
/// 3. **macOS system LaunchDaemon** — `/Library/LaunchDaemons/sh.emberlink.daemon.plist`
///    present → `InstalledNotRunning`.
/// 4. **Linux systemd user unit** — `~/.config/systemd/user/emberd.service`
///    present → `InstalledNotRunning`.
/// 5. None of the above → `NotInstalled`.
///
/// The caller supplies `socket_path` so the function is fully testable without
/// touching the real filesystem (pass a tempdir path in tests).
pub fn detect_daemon_installed(socket_path: &std::path::Path) -> DaemonInstallStatus {
    // 1. Socket probe — fastest, no home-dir lookup required.
    if socket_path.exists() {
        return DaemonInstallStatus::Running;
    }

    // 2–4. Service-file probes.
    if let Some(home) = dirs_next::home_dir() {
        // macOS LaunchAgent (user-level, single-uid posture).
        let macos_agent = home
            .join("Library")
            .join("LaunchAgents")
            .join("link.ember.daemon.plist");
        if macos_agent.exists() {
            return DaemonInstallStatus::InstalledNotRunning;
        }

        // Linux systemd user unit.
        let linux_unit = home
            .join(".config")
            .join("systemd")
            .join("user")
            .join("emberd.service");
        if linux_unit.exists() {
            return DaemonInstallStatus::InstalledNotRunning;
        }
    }

    // macOS system-level LaunchDaemon (separate-uid posture, written to /Library).
    const MACOS_SYSTEM_PLIST: &str = "/Library/LaunchDaemons/sh.emberlink.daemon.plist";
    if std::path::Path::new(MACOS_SYSTEM_PLIST).exists() {
        return DaemonInstallStatus::InstalledNotRunning;
    }

    DaemonInstallStatus::NotInstalled
}

/// Errors that `prompt_install_daemon` and its testable `_with` variant can
/// return.
#[derive(Debug)]
pub enum DaemonInstallPromptError {
    /// `--non-interactive` was set — prompting is forbidden.
    NonInteractive,
    /// The operator declined the install prompt.
    Declined,
    /// `sudo ember daemon install` was spawned but exited non-zero.
    InstallFailed { exit_code: Option<i32> },
    /// Could not resolve the current ember binary path.
    ExeNotFound(std::io::Error),
    /// Spawning the subprocess failed.
    SpawnFailed(std::io::Error),
}

impl std::fmt::Display for DaemonInstallPromptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonInstallPromptError::NonInteractive => {
                write!(
                    f,
                    "daemon is not installed; re-run without --non-interactive to be prompted, \
                     or run `sudo ember daemon install` manually before `ember init`"
                )
            }
            DaemonInstallPromptError::Declined => {
                write!(
                    f,
                    "daemon install skipped — run `sudo ember daemon install` when ready, \
                     then re-run `ember init`"
                )
            }
            DaemonInstallPromptError::InstallFailed { exit_code } => {
                let code = exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                write!(
                    f,
                    "`sudo ember daemon install` exited with code {code}; check the output above \
                     for details, then re-run `ember init`"
                )
            }
            DaemonInstallPromptError::ExeNotFound(e) => {
                write!(f, "could not locate ember binary: {e}")
            }
            DaemonInstallPromptError::SpawnFailed(e) => {
                write!(f, "failed to spawn `sudo ember daemon install`: {e}")
            }
        }
    }
}

/// Production entry point: display the cohort-A-friendly explanation and
/// optionally run `sudo ember daemon install` via subprocess.
///
/// Delegates to [`prompt_install_daemon_with`] with real stdin/stdout and the
/// real subprocess runner so tests can inject stubs.
///
/// Returns `Ok(())` when the operator consented and the install succeeded.
/// Returns `Err(DaemonInstallPromptError::Declined)` when the operator said no.
/// Returns other `Err` variants for non-interactive mode or subprocess failures.
// implementation-note-407 checkpoint
pub fn prompt_install_daemon(non_interactive: bool) -> Result<(), DaemonInstallPromptError> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    prompt_install_daemon_with(
        non_interactive,
        &mut stdout,
        &mut stdin.lock(),
        &RealSudoRunner,
    )
}

/// Trait for running `sudo ember daemon install`. Abstracted for test injection.
pub trait SudoRunner {
    /// Run `sudo <ember-binary> daemon install` and return the exit status.
    fn run_sudo_install(&self) -> Result<std::process::ExitStatus, std::io::Error>;
}

/// Production [`SudoRunner`] — resolves the current ember binary and spawns
/// `sudo <binary> daemon install` as a foreground child.
pub struct RealSudoRunner;

impl SudoRunner for RealSudoRunner {
    fn run_sudo_install(&self) -> Result<std::process::ExitStatus, std::io::Error> {
        let exe = std::env::current_exe()?;
        let status = Command::new("sudo")
            .arg(&exe)
            .arg("daemon")
            .arg("install")
            .status()?;
        Ok(status)
    }
}

/// Testable variant of [`prompt_install_daemon`].
///
/// Writes the explanation to `out`, reads a single character from `input` for
/// the y/n prompt, and delegates to `runner` to execute the subprocess.
///
/// `non_interactive`: when `true`, returns `Err(NonInteractive)` immediately
/// without writing any output or touching `runner`.
pub fn prompt_install_daemon_with<W, R, S>(
    non_interactive: bool,
    out: &mut W,
    input: &mut R,
    runner: &S,
) -> Result<(), DaemonInstallPromptError>
where
    W: io::Write,
    R: io::BufRead,
    S: SudoRunner,
{
    if non_interactive {
        return Err(DaemonInstallPromptError::NonInteractive);
    }

    // Cohort-A-friendly explanation.
    writeln!(out).ok();
    writeln!(out, "The ember daemon is not installed on this machine.").ok();
    writeln!(out).ok();
    writeln!(
        out,
        "  The daemon is the trust broker that holds the vault encryption key,\n\
         enforces grant policy, and signs Receipts for every agent action.\n\
         Without it, `ember init` cannot open the vault or create a persona."
    )
    .ok();
    writeln!(out).ok();
    writeln!(
        out,
        "  Installing the daemon requires elevated privileges so it can create\n\
         a dedicated `ember` service account and register a system service\n\
         (LaunchDaemon on macOS, systemd unit on Linux). The command is:\n\
         \n\
             sudo ember daemon install"
    )
    .ok();
    writeln!(out).ok();
    write!(out, "Run `sudo ember daemon install` now? [y/N] ").ok();
    out.flush().ok();

    let mut buf = String::new();
    if input.read_line(&mut buf).is_err() {
        return Err(DaemonInstallPromptError::Declined);
    }
    let answer = buf.trim().to_ascii_lowercase();
    if answer != "y" && answer != "yes" {
        return Err(DaemonInstallPromptError::Declined);
    }

    // Operator consented — run the install.
    let status = runner.run_sudo_install().map_err(|e| {
        if std::env::current_exe().is_err() {
            DaemonInstallPromptError::ExeNotFound(e)
        } else {
            DaemonInstallPromptError::SpawnFailed(e)
        }
    })?;

    if status.success() {
        Ok(())
    } else {
        Err(DaemonInstallPromptError::InstallFailed {
            exit_code: status.code(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;
    use tempfile::tempdir;

    /// Serialize tests that mutate `$HOME`. Several tests in this module
    /// override `$HOME` to redirect [`transcript_path`]/[`state_path`] into
    /// a tempdir; without a mutex they race because cargo's default test
    /// runner spawns one thread per test in the same process.
    static HOME_GUARD: Mutex<()> = Mutex::new(());

    #[cfg(target_os = "macos")]
    #[test]
    fn platform_detect_macos() {
        // On macOS the detect function short-circuits before touching the
        // filesystem, so the injected paths don't need to exist.
        let p = detect_platform_from_paths(
            Path::new("/nonexistent/os-release"),
            Path::new("/nonexistent/proc-version"),
        );
        assert_eq!(p, Platform::MacOS);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn platform_detect_linux_with_distro_fixture() {
        let tmp = tempdir().expect("tempdir");
        let os_release = tmp.path().join("os-release");
        fs::write(
            &os_release,
            "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"22.04\"\n",
        )
        .expect("write os-release");
        let proc_version = tmp.path().join("proc-version");
        fs::write(&proc_version, "Linux version 5.15.0-generic\n").expect("write proc-version");

        let p = detect_platform_from_paths(&os_release, &proc_version);
        assert_eq!(
            p,
            Platform::Linux {
                distro: "ubuntu".to_string()
            }
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn platform_detect_wsl() {
        let tmp = tempdir().expect("tempdir");
        let os_release = tmp.path().join("os-release");
        fs::write(&os_release, "ID=debian\n").expect("write os-release");
        let proc_version = tmp.path().join("proc-version");
        fs::write(
            &proc_version,
            "Linux version 5.15.0-microsoft-standard-WSL2 (Microsoft@Microsoft.com)\n",
        )
        .expect("write proc-version");

        let p = detect_platform_from_paths(&os_release, &proc_version);
        assert_eq!(
            p,
            Platform::WslLinux {
                distro: "debian".to_string()
            }
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn platform_detect_linux_quoted_distro_id() {
        // os-release values may be quoted per the spec — make sure the
        // quotes are stripped from the parsed distro.
        let tmp = tempdir().expect("tempdir");
        let os_release = tmp.path().join("os-release");
        fs::write(&os_release, "ID=\"fedora\"\n").expect("write os-release");
        let proc_version = tmp.path().join("proc-version");
        fs::write(&proc_version, "Linux version 6.0\n").expect("write proc-version");

        let p = detect_platform_from_paths(&os_release, &proc_version);
        assert_eq!(
            p,
            Platform::Linux {
                distro: "fedora".to_string()
            }
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn platform_detect_linux_missing_os_release_falls_back_to_unknown() {
        // No os-release on disk — the helper still returns Linux but with
        // the placeholder distro string so subtask B can warn cleanly.
        let tmp = tempdir().expect("tempdir");
        let os_release = tmp.path().join("does-not-exist");
        let proc_version = tmp.path().join("proc-version");
        fs::write(&proc_version, "Linux version 6.0\n").expect("write proc-version");

        let p = detect_platform_from_paths(&os_release, &proc_version);
        assert_eq!(
            p,
            Platform::Linux {
                distro: "unknown".to_string()
            }
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn platform_detect_unsupported() {
        let p = detect_platform_from_paths(
            Path::new("/nonexistent/os-release"),
            Path::new("/nonexistent/proc-version"),
        );
        match p {
            Platform::Unsupported(name) => assert!(!name.is_empty()),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn parse_distro_id_extracts_value() {
        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("os-release");
        fs::write(&path, "NAME=Foo\nID=arch\nPRETTY_NAME=\"Arch Linux\"\n").expect("write fixture");
        assert_eq!(parse_distro_id(&path), Some("arch".to_string()));
    }

    #[test]
    fn parse_distro_id_strips_quotes() {
        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("os-release");
        fs::write(&path, "ID=\"ubuntu\"\n").expect("write fixture");
        assert_eq!(parse_distro_id(&path), Some("ubuntu".to_string()));
    }

    #[test]
    fn parse_distro_id_returns_none_when_missing() {
        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("os-release");
        fs::write(&path, "NAME=Foo\n").expect("write fixture");
        assert_eq!(parse_distro_id(&path), None);
    }

    #[test]
    fn is_wsl_detects_microsoft_marker() {
        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("proc-version");
        fs::write(&path, "Linux version 5.15.0-microsoft-standard-WSL2\n").expect("write fixture");
        assert!(is_wsl(&path));
    }

    #[test]
    fn is_wsl_returns_false_for_native_linux() {
        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("proc-version");
        fs::write(&path, "Linux version 6.0.0-generic\n").expect("write fixture");
        assert!(!is_wsl(&path));
    }

    /// Recording stub for [`InstallPrimitives`] — every method push-records
    /// its name into a shared `Vec<&'static str>` and returns success. The
    /// T1 test asserts the recorded call order matches the wizard's
    /// documented step sequence.
    #[derive(Default)]
    struct StubPrimitives {
        calls: std::cell::RefCell<Vec<&'static str>>,
    }

    impl InstallPrimitives for StubPrimitives {
        fn provision_ember_user(&self) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("provision_ember_user");
            Ok(())
        }
        fn chown_ember_data_dirs(&self, _home: &Path) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("chown_ember_data_dirs");
            Ok(())
        }
        fn provision_se_mek(&self, _home: &Path) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("provision_se_mek");
            Ok(())
        }
        fn install_launch_spec(
            &self,
            _platform: &Platform,
            _operator_home: &Path,
        ) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("install_launch_spec");
            Ok(())
        }
        fn add_operator_to_group(
            &self,
            _platform: &Platform,
            _user: &str,
        ) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("add_operator_to_group");
            Ok(())
        }
        fn socket_responsive(&self, _socket: &Path) -> Result<(), String> {
            self.calls.borrow_mut().push("socket_responsive");
            Ok(())
        }
        fn load_apparmor_profile(&self) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("load_apparmor_profile");
            Ok(())
        }
    }

    fn fixture_ctx() -> WizardContext {
        WizardContext {
            platform: Platform::Linux {
                distro: "ubuntu".to_string(),
            },
            home: PathBuf::from("/home/operator"),
            invoking_user: "operator".to_string(),
            socket_path: PathBuf::from("/home/operator/.ember/run/daemon.sock"),
        }
    }

    /// Sandboxed wrapper around `run_wizard_steps` that points the
    /// transcript at a tempdir instead of `~/.ember/install-wizard.log`.
    /// Without this, the test would either fail in CI (no `$HOME`) or
    /// pollute the test runner's home dir.
    fn run_steps_isolated<P: InstallPrimitives>(
        ctx: &WizardContext,
        primitives: &P,
    ) -> (Result<(), WizardError>, tempfile::TempDir) {
        let tmp = tempdir().expect("tempdir");
        // Override $HOME so transcript_path() lands inside the tempdir.
        // We hold HOME_GUARD across the whole call so concurrent tests
        // touching $HOME don't race.
        let guard = HOME_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let prior_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", tmp.path());
        }
        let result = run_wizard_steps(ctx, primitives);
        unsafe {
            match prior_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        drop(guard);
        (result, tmp)
    }

    /// T1 step-composition test — stub each install primitive, run the
    /// wizard, assert each step is invoked in the correct order. This is
    /// the contract subtask -B's brief calls out: the five steps run
    /// sequentially in a fixed order against the InstallPrimitives surface.
    #[test]
    fn wizard_steps_run_in_expected_order() {
        let stub = StubPrimitives::default();
        let ctx = fixture_ctx();
        let (result, _tmp) = run_steps_isolated(&ctx, &stub);
        assert!(result.is_ok(), "run_wizard_steps failed: {result:?}");
        let calls = stub.calls.borrow().clone();
        assert_eq!(
            calls,
            vec![
                "provision_ember_user",
                "chown_ember_data_dirs",
                "provision_se_mek",
                "install_launch_spec",
                "load_apparmor_profile",
                "add_operator_to_group",
                "socket_responsive",
            ]
        );
    }

    /// Step 5 falls through to a Skipped outcome when neither `$USER` nor
    /// `$SUDO_USER` is set — the wizard should still complete the other
    /// steps rather than failing the whole flow.
    #[test]
    fn wizard_step_add_user_to_group_skips_when_user_empty() {
        let stub = StubPrimitives::default();
        let mut ctx = fixture_ctx();
        ctx.invoking_user = String::new();
        let outcome =
            wizard_step_add_user_to_group(&ctx, &stub).expect("step returns Ok on empty user");
        match outcome {
            StepOutcome::Skipped { .. } => {}
            other => panic!("expected Skipped, got {other:?}"),
        }
        // The stub should NOT have been called when the user is empty.
        assert!(stub.calls.borrow().is_empty());
    }

    /// `wizard_step_verify` returns Skipped (not an error) when the daemon
    /// socket isn't yet present — the platform launcher may still be
    /// starting the daemon when the wizard finishes its provisioning steps.
    #[test]
    fn wizard_step_verify_skips_when_socket_missing() {
        struct MissingSocket;
        impl InstallPrimitives for MissingSocket {
            fn provision_ember_user(&self) -> Result<(), daemon_install::InstallError> {
                Ok(())
            }
            fn chown_ember_data_dirs(&self, _: &Path) -> Result<(), daemon_install::InstallError> {
                Ok(())
            }
            fn provision_se_mek(&self, _: &Path) -> Result<(), daemon_install::InstallError> {
                Ok(())
            }
            fn install_launch_spec(
                &self,
                _: &Platform,
                _: &Path,
            ) -> Result<(), daemon_install::InstallError> {
                Ok(())
            }
            fn add_operator_to_group(
                &self,
                _: &Platform,
                _: &str,
            ) -> Result<(), daemon_install::InstallError> {
                Ok(())
            }
            fn socket_responsive(&self, _: &Path) -> Result<(), String> {
                Err("not present".to_string())
            }
            fn load_apparmor_profile(&self) -> Result<(), daemon_install::InstallError> {
                Ok(())
            }
        }
        let outcome = wizard_step_verify(&fixture_ctx(), &MissingSocket).expect("returns Ok");
        match outcome {
            StepOutcome::Skipped { reason } => assert!(reason.contains("not present")),
            other => panic!("expected Skipped, got {other:?}"),
        }
    }

    // ----------------------------------------------------------------
    // -C tests: idempotency, resume, rollback, cancel, actionable errors
    // ----------------------------------------------------------------

    /// Recording stub that supports both forward and unwind paths. Each
    /// call appends to `calls` so tests can assert order.
    #[derive(Default)]
    struct UnwindRecorder {
        calls: std::cell::RefCell<Vec<&'static str>>,
        forward_user_fails: bool,
    }

    impl InstallPrimitives for UnwindRecorder {
        fn provision_ember_user(&self) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("provision_ember_user");
            if self.forward_user_fails {
                Err(daemon_install::InstallError::Subprocess {
                    cmd: "useradd ember".to_string(),
                    stderr: "permission denied".to_string(),
                    exit_code: Some(1),
                })
            } else {
                Ok(())
            }
        }
        fn chown_ember_data_dirs(&self, _: &Path) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("chown_ember_data_dirs");
            Ok(())
        }
        fn provision_se_mek(&self, _: &Path) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("provision_se_mek");
            Ok(())
        }
        fn install_launch_spec(
            &self,
            _: &Platform,
            _: &Path,
        ) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("install_launch_spec");
            Ok(())
        }
        fn add_operator_to_group(
            &self,
            _: &Platform,
            _: &str,
        ) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("add_operator_to_group");
            Ok(())
        }
        fn socket_responsive(&self, _: &Path) -> Result<(), String> {
            self.calls.borrow_mut().push("socket_responsive");
            Ok(())
        }
        fn load_apparmor_profile(&self) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("load_apparmor_profile");
            Ok(())
        }
        fn unwind_provision_ember_user(&self) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("unwind_provision_ember_user");
            Ok(())
        }
        fn unwind_provision_se_mek(&self, _: &Path) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("unwind_provision_se_mek");
            Ok(())
        }
        fn unwind_chown_ember_data_dirs(
            &self,
            _: &Path,
        ) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("unwind_chown_ember_data_dirs");
            Ok(())
        }
        fn unwind_install_launch_spec(
            &self,
            _: &Platform,
        ) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("unwind_install_launch_spec");
            Ok(())
        }
        fn unwind_add_operator_to_group(
            &self,
            _: &Platform,
            _: &str,
        ) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("unwind_add_operator_to_group");
            Ok(())
        }
        fn unwind_verify(&self, _: &Path) -> Result<(), String> {
            self.calls.borrow_mut().push("unwind_verify");
            Ok(())
        }
    }

    fn partial_state() -> WizardState {
        WizardState {
            completed_steps: vec!["provision-user".into(), "chown-data-dirs".into()],
            last_error: Some("install step 'emit-launch-spec' failed: subprocess".into()),
        }
    }

    fn complete_state() -> WizardState {
        WizardState {
            completed_steps: WIZARD_STEPS.iter().map(|s| s.to_string()).collect(),
            last_error: None,
        }
    }

    /// Already-installed prior state collapses to AlreadyComplete without
    /// prompting.
    #[test]
    fn resume_or_rollback_already_complete() {
        let state = complete_state();
        let action = wizard_resume_or_rollback(&state);
        assert_eq!(action, ResumeAction::AlreadyComplete);
    }

    /// Empty state with no error is a fresh install — no prompt.
    #[test]
    fn resume_or_rollback_fresh_install() {
        let state = WizardState {
            completed_steps: vec![],
            last_error: None,
        };
        let action = wizard_resume_or_rollback(&state);
        assert_eq!(action, ResumeAction::FreshInstall);
    }

    /// Resume choice maps to Resume(idx) where idx is the first
    /// not-yet-done step in WIZARD_STEPS.
    #[test]
    fn resume_or_rollback_resume_branch() {
        let state = partial_state();
        let action = wizard_resume_or_rollback_with_choice(&state, 'r');
        // First two completed → resume from index 2 (provision-mek).
        assert_eq!(action, ResumeAction::Resume(2));
    }

    /// Rollback choice always yields Rollback regardless of how many steps
    /// are pending.
    #[test]
    fn resume_or_rollback_rollback_branch() {
        let state = partial_state();
        let action = wizard_resume_or_rollback_with_choice(&state, 'b');
        assert_eq!(action, ResumeAction::Rollback);
    }

    /// Cancel choice (or any unrecognised input) yields Cancel.
    #[test]
    fn resume_or_rollback_cancel_branch() {
        let state = partial_state();
        assert_eq!(
            wizard_resume_or_rollback_with_choice(&state, 'c'),
            ResumeAction::Cancel
        );
        // Unknown char also defaults to Cancel.
        assert_eq!(
            wizard_resume_or_rollback_with_choice(&state, 'x'),
            ResumeAction::Cancel
        );
    }

    /// run_rollback walks completed steps in REVERSE and calls the matching
    /// unwind helper for each. After completion the state file is cleared.
    #[test]
    fn run_rollback_unwinds_in_reverse_order() {
        let stub = UnwindRecorder::default();
        let ctx = fixture_ctx();
        let state = partial_state();
        // Sandboxed $HOME so clear_wizard_state targets the tempdir.
        // Other tests in this module also touch $HOME so we serialize them
        // through a shared mutex (see HOME_GUARD).
        let tmp = tempdir().expect("tempdir");
        let _guard = HOME_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let prior_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", tmp.path());
        }
        // Pre-write a state file so we can confirm rollback clears it.
        save_wizard_state(&state).expect("save state");
        assert!(
            state_path().exists(),
            "state file should exist pre-rollback"
        );

        let result = run_rollback(&ctx, &stub, &state);

        let exists_after = state_path().exists();
        unsafe {
            match prior_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        drop(_guard);

        assert!(result.is_ok(), "run_rollback failed: {result:?}");
        let calls = stub.calls.borrow().clone();
        // Reverse order: chown-data-dirs first, then provision-user.
        assert_eq!(
            calls,
            vec![
                "unwind_chown_ember_data_dirs",
                "unwind_provision_ember_user"
            ]
        );
        assert!(!exists_after, "state file should be cleared after rollback");
    }

    /// T1 — full resume + rollback + cancel scenario:
    /// (a) Simulate a wizard log where provision-user + chown-data-dirs
    ///     completed and provision-mek failed.
    /// (b) Assert wizard_resume_or_rollback offers a resume choice that
    ///     maps to Resume(2) (skip the two completed steps).
    /// (c) Assert the rollback path unwinds completed steps in reverse.
    /// (d) Assert the cancel path returns Cancel without touching the stub.
    #[test]
    fn t1_resume_rollback_cancel_full_scenario() {
        let state = WizardState {
            completed_steps: vec!["provision-user".into(), "chown-data-dirs".into()],
            last_error: Some(
                "install step 'provision-mek' failed: subprocess: cmd=security, exit=1".into(),
            ),
        };

        // (b) Resume → start at index 2 (provision-mek).
        match wizard_resume_or_rollback_with_choice(&state, 'r') {
            ResumeAction::Resume(idx) => {
                assert_eq!(idx, 2);
                assert_eq!(WIZARD_STEPS[idx], "provision-mek");
            }
            other => panic!("expected Resume(2), got {other:?}"),
        }

        // (c) Rollback → completed_steps walked in reverse, no forward calls.
        let stub = UnwindRecorder::default();
        let ctx = fixture_ctx();
        let tmp = tempdir().expect("tempdir");
        let _guard = HOME_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let prior_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", tmp.path());
        }
        save_wizard_state(&state).expect("save state");
        let rollback_result = run_rollback(&ctx, &stub, &state);
        unsafe {
            match prior_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        drop(_guard);
        assert!(
            rollback_result.is_ok(),
            "rollback failed: {rollback_result:?}"
        );
        let calls = stub.calls.borrow().clone();
        assert_eq!(
            calls,
            vec![
                "unwind_chown_ember_data_dirs",
                "unwind_provision_ember_user"
            ]
        );

        // (d) Cancel → no unwind calls happen.
        let stub2 = UnwindRecorder::default();
        let action = wizard_resume_or_rollback_with_choice(&state, 'c');
        assert_eq!(action, ResumeAction::Cancel);
        assert!(
            stub2.calls.borrow().is_empty(),
            "cancel must not invoke unwind helpers"
        );
    }

    /// State serde-roundtrip — write to disk and read back the same value.
    #[test]
    fn wizard_state_serde_roundtrip() {
        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("install-wizard.state.json");
        let state = WizardState {
            completed_steps: vec!["provision-user".into(), "chown-data-dirs".into()],
            last_error: Some("boom".into()),
        };
        save_wizard_state_at(&state, &path).expect("save");
        let loaded = load_wizard_state_at(&path).expect("load").expect("present");
        assert_eq!(loaded, state);
    }

    /// load_wizard_state_at returns None when the state file is absent.
    #[test]
    fn wizard_state_load_returns_none_when_absent() {
        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("install-wizard.state.json");
        let loaded = load_wizard_state_at(&path).expect("load");
        assert!(loaded.is_none());
    }

    /// is_complete + next_step_index logic under various states.
    #[test]
    fn wizard_state_progress_helpers() {
        let empty = WizardState {
            completed_steps: vec![],
            last_error: None,
        };
        assert!(!empty.is_complete());
        assert_eq!(empty.next_step_index(), Some(0));

        let mid = WizardState {
            completed_steps: vec!["provision-user".into(), "chown-data-dirs".into()],
            last_error: None,
        };
        assert!(!mid.is_complete());
        assert_eq!(mid.next_step_index(), Some(2));

        let done = complete_state();
        assert!(done.is_complete());
        assert_eq!(done.next_step_index(), None);

        // last_error set blocks is_complete even with all steps recorded.
        let mut errored = complete_state();
        errored.last_error = Some("boom".into());
        assert!(!errored.is_complete());
    }

    /// Actionable error messages — each WizardError variant Display includes
    /// a concrete next step the operator can take.
    #[test]
    fn wizard_error_display_is_actionable() {
        let sudo = WizardError::SudoFailed.to_string();
        assert!(sudo.contains("sudo -v"), "got: {sudo}");

        let user = WizardError::UserCreationFailed {
            detail: "useradd: permission denied".into(),
        }
        .to_string();
        assert!(
            user.contains("ember daemon install --debug-install"),
            "got: {user}"
        );
        assert!(user.contains("useradd: permission denied"), "got: {user}");

        let group = WizardError::GroupAdd {
            user: "alice".into(),
            stderr: "no such group".into(),
        }
        .to_string();
        assert!(group.contains("ember-clients"), "got: {group}");
        assert!(group.contains("alice"), "got: {group}");

        let verify = WizardError::Verify("socket missing".into()).to_string();
        assert!(
            verify.contains("launchctl") || verify.contains("systemctl"),
            "got: {verify}"
        );

        let unsupported = WizardError::UnsupportedPlatform("plan9".into()).to_string();
        assert!(unsupported.contains("plan9"), "got: {unsupported}");
        assert!(unsupported.contains("macOS"), "got: {unsupported}");
    }

    /// Step 1 failure now maps to UserCreationFailed (not Install) so the
    /// operator-facing message points at `--debug-install`.
    #[test]
    fn wizard_step_provision_user_failure_maps_to_user_creation_failed() {
        let stub = UnwindRecorder {
            forward_user_fails: true,
            ..Default::default()
        };
        let ctx = fixture_ctx();
        let err = wizard_step_provision_user(&ctx, &stub).expect_err("step should fail");
        match err {
            WizardError::UserCreationFailed { detail } => {
                assert!(
                    detail.contains("permission denied"),
                    "detail should carry daemon stderr; got: {detail}"
                );
            }
            other => panic!("expected UserCreationFailed, got {other:?}"),
        }
    }

    // ----------------------------------------------------------------
    // implementation-note-407 — T2 tests
    // ----------------------------------------------------------------

    /// detect_daemon_installed: socket present → Running.
    #[test]
    fn detect_daemon_installed_running_when_socket_exists() {
        let tmp = tempdir().expect("tempdir");
        let socket = tmp.path().join("daemon.sock");
        fs::write(&socket, b"").expect("create socket fixture");
        assert_eq!(
            detect_daemon_installed(&socket),
            DaemonInstallStatus::Running
        );
    }

    /// detect_daemon_installed: no socket, no service files → NotInstalled.
    #[test]
    fn detect_daemon_installed_not_installed_when_nothing_present() {
        let tmp = tempdir().expect("tempdir");
        let socket = tmp.path().join("daemon.sock");
        // We cannot easily suppress the real home-dir probe, but on the CI
        // host neither the LaunchAgent plist nor the Linux systemd unit should
        // be present — so this test verifies the non-socket branches don't
        // false-positive into Running.
        let status = detect_daemon_installed(&socket);
        // Socket must not be Running (we didn't create it).
        assert_ne!(
            status,
            DaemonInstallStatus::Running,
            "socket was not created, must not be Running"
        );
    }

    // ── Mock SudoRunner ─────────────────────────────────────────────────────

    /// Stub runner that records whether it was called and returns a
    /// configurable success/failure status.
    struct MockSudoRunner {
        called: std::cell::Cell<bool>,
        succeed: bool,
    }

    impl MockSudoRunner {
        fn succeeds() -> Self {
            Self {
                called: std::cell::Cell::new(false),
                succeed: true,
            }
        }
        fn fails() -> Self {
            Self {
                called: std::cell::Cell::new(false),
                succeed: false,
            }
        }
    }

    impl SudoRunner for MockSudoRunner {
        fn run_sudo_install(&self) -> Result<std::process::ExitStatus, std::io::Error> {
            self.called.set(true);
            // Build a real ExitStatus from a known exit code via a trivial
            // child process.  We can't construct ExitStatus directly (it's
            // opaque), so we spawn `true` (succeeds) or `false` (fails).
            let status = if self.succeed {
                std::process::Command::new("true").status()
            } else {
                std::process::Command::new("false").status()
            };
            status
        }
    }

    /// T2 — non-interactive refuses without printing anything or calling the runner.
    #[test]
    fn prompt_install_daemon_non_interactive_refuses() {
        let runner = MockSudoRunner::succeeds();
        let mut out = Vec::<u8>::new();
        let input_bytes = b"y\n";
        let mut input = io::Cursor::new(input_bytes);

        let result = prompt_install_daemon_with(true, &mut out, &mut input, &runner);

        assert!(
            matches!(result, Err(DaemonInstallPromptError::NonInteractive)),
            "expected NonInteractive, got {result:?}",
            result = result.map_err(|e| e.to_string())
        );
        // Must not have spawned the subprocess.
        assert!(
            !runner.called.get(),
            "runner must not be called in non-interactive mode"
        );
    }

    /// T2 — operator answers 'y' → runner is called and Ok(()) returned on success.
    #[test]
    fn prompt_install_daemon_consent_spawns_runner() {
        let runner = MockSudoRunner::succeeds();
        let mut out = Vec::<u8>::new();
        let input_bytes = b"y\n";
        let mut input = io::Cursor::new(input_bytes);

        let result = prompt_install_daemon_with(false, &mut out, &mut input, &runner);

        assert!(
            result.is_ok(),
            "expected Ok after consent; got: {}",
            result.unwrap_err()
        );
        assert!(
            runner.called.get(),
            "runner must be called after operator consent"
        );

        // Output must contain the cohort-A explanation and the command.
        let printed = String::from_utf8(out).expect("utf8");
        assert!(
            printed.contains("sudo ember daemon install"),
            "explanation must name the command; got: {printed}"
        );
        assert!(
            printed.contains("trust broker"),
            "explanation must describe the daemon role; got: {printed}"
        );
    }

    /// T2 — operator answers 'n' → Declined, runner not called.
    #[test]
    fn prompt_install_daemon_decline_does_not_spawn() {
        let runner = MockSudoRunner::succeeds();
        let mut out = Vec::<u8>::new();
        let input_bytes = b"n\n";
        let mut input = io::Cursor::new(input_bytes);

        let result = prompt_install_daemon_with(false, &mut out, &mut input, &runner);

        assert!(
            matches!(result, Err(DaemonInstallPromptError::Declined)),
            "expected Declined"
        );
        assert!(
            !runner.called.get(),
            "runner must not be called when declined"
        );
    }

    /// T2 — runner returns non-zero → InstallFailed variant.
    #[test]
    fn prompt_install_daemon_runner_failure_returns_install_failed() {
        let runner = MockSudoRunner::fails();
        let mut out = Vec::<u8>::new();
        let input_bytes = b"y\n";
        let mut input = io::Cursor::new(input_bytes);

        let result = prompt_install_daemon_with(false, &mut out, &mut input, &runner);

        assert!(
            matches!(result, Err(DaemonInstallPromptError::InstallFailed { .. })),
            "expected InstallFailed; got: {result:?}",
            result = result.map_err(|e| e.to_string())
        );
        assert!(runner.called.get());
    }

    /// T1 (cross-platform) — the non-Linux branch of `load_apparmor_profile_impl`
    /// returns `Ok(())` without invoking any subprocess. Gated to non-Linux runners
    /// so it is not exercised on Linux CI (where the real `#[cfg(target_os="linux")]`
    /// branch would be compiled in instead).
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn load_apparmor_profile_skips_on_non_linux() {
        // The non-Linux impl is a no-op — it must return Ok(()) without any
        // subprocess side effects.
        let result = load_apparmor_profile_impl();
        assert!(
            result.is_ok(),
            "load_apparmor_profile_impl must return Ok(()) on non-Linux; got: {result:?}"
        );
    }

    /// T1 (cross-platform) — `wizard_step_load_apparmor` skips on macOS via
    /// the `Platform::MacOS` branch and returns a `Skipped` outcome (not an error).
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn wizard_step_load_apparmor_skips_on_macos() {
        let stub = StubPrimitives::default();
        let mut ctx = fixture_ctx();
        ctx.platform = Platform::MacOS;

        let outcome = wizard_step_load_apparmor(&ctx, &stub)
            .expect("wizard_step_load_apparmor must return Ok on macOS");

        match outcome {
            StepOutcome::Skipped { reason } => {
                assert!(
                    reason.contains("macos"),
                    "skip reason should mention platform; got: {reason}"
                );
            }
            other => panic!("expected Skipped on macOS, got {other:?}"),
        }
        // load_apparmor_profile should NOT have been called.
        assert!(
            stub.calls.borrow().is_empty(),
            "load_apparmor_profile must not be called on macOS"
        );
    }
}
