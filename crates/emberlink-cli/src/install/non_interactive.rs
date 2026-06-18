//! Non-interactive install path.
//!
//! [`install_non_interactive`] is the prompt-free counterpart to
//! [`super::wizard::run_install_wizard`]. CI runners and `RUN ember install
//! --non-interactive` Dockerfile lines have no TTY and no operator on the
//! other end of stdin — they need a path that:
//!
//! 1. Refuses with a clear error when privilege requirements aren't met
//!    (no root, no cached sudo) instead of hanging on a password prompt.
//! 2. Skips banners, progress UI, and resume/rollback prompts.
//! 3. Emits one structured stderr line per phase so log scrapers can pin
//!    failures to the failing step (`[install] phase=<step> ok|error ...`).
//!
//! The actual install steps reuse the same [`InstallPrimitives`] adapter +
//! `wizard_step_*` functions the interactive wizard runs. The branch is
//! prompt-vs-no-prompt — every other behaviour (idempotency, error mapping,
//! transcript appending) carries over from [`super::wizard::run_wizard_steps`].

use std::process::Command;

use super::wizard::{
    InstallPrimitives, Platform, RealPrimitives, StepOutcome, WIZARD_STEPS, WizardContext,
    WizardError, detect_platform,
};

/// Daemon posture selectable from the non-interactive install surface.
///
/// Only `SeparateUid` is wired in this slice — `--posture single-uid` is a
/// dev-mode escape hatch reserved for a future cycle, mirroring the existing
/// `ember daemon install --single-uid` reservation in
/// [`super::wizard`]'s parent dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    /// Production posture — dedicated `ember` system user, `ember-clients`
    /// connect group, chowned data dirs, platform launcher (LaunchDaemon /
    /// systemd unit). Default per ADR 131.
    SeparateUid,
}

impl Posture {
    /// Parse the `--posture <value>` argument. Accepts `separate-uid`
    /// (canonical) and `separate_uid` (underscore variant for shells that
    /// prefer underscores) case-insensitively. Anything else returns the
    /// invalid-value string for the CLI to surface verbatim.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let normalized = raw.trim().to_ascii_lowercase().replace('_', "-");
        match normalized.as_str() {
            "separate-uid" => Ok(Posture::SeparateUid),
            other => Err(format!(
                "unsupported posture '{other}'; only 'separate-uid' is accepted by \
                 --non-interactive in this release (single-uid is reserved for a \
                 future dev-mode escape hatch)"
            )),
        }
    }
}

/// Options for [`install_non_interactive`]. Surfaces the three CLI flags the
/// task brief calls out (`--non-interactive`, `--accept-defaults`,
/// `--posture`). `accept_defaults` is currently informational — the
/// non-interactive path always uses defaults — but is plumbed so a later
/// slice can branch on `accept_defaults=false` to refuse non-default
/// configuration in CI when an operator passes both flags by accident.
#[derive(Debug, Clone)]
pub struct InstallNonInteractiveOptions {
    /// Acknowledge that default values will be used for any otherwise-prompted
    /// choice. The non-interactive path enforces defaults regardless; this
    /// flag is a no-op today but is captured so future slices can introduce
    /// non-default-allowed CI overrides without breaking existing callers.
    pub accept_defaults: bool,
    /// Daemon posture to install. Default [`Posture::SeparateUid`] per
    /// ADR 131.
    pub posture: Posture,
}

impl Default for InstallNonInteractiveOptions {
    fn default() -> Self {
        Self {
            accept_defaults: true,
            posture: Posture::SeparateUid,
        }
    }
}

/// Privilege probe — abstracted so the unit test can simulate "no root, no
/// sudo cached" without actually dropping privileges.
///
/// `is_root` returns true when the effective uid is 0 (`geteuid() == 0`).
/// `sudo_cached` returns true when `sudo -n true` exits 0 (a cached sudo
/// timestamp lets later subprocess calls run without prompting). Either one
/// being true is sufficient for the non-interactive install to proceed.
pub trait PrivilegeProbe {
    fn is_root(&self) -> bool;
    fn sudo_cached(&self) -> bool;
}

/// Production [`PrivilegeProbe`] — calls `libc::geteuid()` and shells out
/// to `sudo -n true`.
pub struct RealPrivilegeProbe;

impl PrivilegeProbe for RealPrivilegeProbe {
    fn is_root(&self) -> bool {
        // SAFETY: `geteuid` is a pure libc query — no allocation, never
        // errors. The same pattern is used by `launcher/banner.rs`.
        unsafe { libc::geteuid() == 0 }
    }

    fn sudo_cached(&self) -> bool {
        // `sudo -n true` exits 0 when the operator's sudo timestamp is
        // valid (no password prompt fires). Spawn failure (sudo not on
        // PATH) maps to "not cached" so the caller surfaces the missing-
        // privilege error; we don't conflate "sudo missing" with "sudo
        // present but uncached" because the surfaced message names sudo
        // either way.
        match Command::new("sudo").arg("-n").arg("true").output() {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }
}

/// Run the non-interactive install path.
///
/// Wires the production [`RealPrimitives`] + [`RealPrivilegeProbe`]
/// implementations into [`install_non_interactive_with`]. The CLI dispatcher
/// calls this directly; tests use the `_with` variant to inject stubs.
pub fn install_non_interactive(opts: &InstallNonInteractiveOptions) -> Result<(), WizardError> {
    let probe = RealPrivilegeProbe;
    let primitives = RealPrimitives;
    let platform = detect_platform();
    install_non_interactive_with(opts, &probe, &primitives, platform)
}

/// Testable variant of [`install_non_interactive`] — caller supplies the
/// privilege probe, install primitives adapter, and detected platform.
///
/// Behaviour:
///
/// 1. Validate privileges via `probe`. If neither `is_root()` nor
///    `sudo_cached()` returns true, exit with [`WizardError::SudoFailed`]
///    after emitting `[install] phase=privilege-check error=...` to stderr.
/// 2. Refuse on [`Platform::Unsupported`] with
///    [`WizardError::UnsupportedPlatform`].
/// 3. Build a [`WizardContext`] from the live environment.
/// 4. Run each `wizard_step_*` in [`WIZARD_STEPS`] order against the
///    supplied primitives. Emit `[install] phase=<step> ok|skip|error
///    note=<...>` to stderr after each step.
///
/// Does NOT touch the resume/rollback state file the interactive wizard
/// uses — non-interactive runs are stateless from the caller's perspective.
/// A re-run after a failed CI step starts from scratch; idempotency comes
/// from the daemon-side primitives, not from on-disk wizard state.
pub fn install_non_interactive_with<P: InstallPrimitives, Q: PrivilegeProbe>(
    opts: &InstallNonInteractiveOptions,
    probe: &Q,
    primitives: &P,
    platform: Platform,
) -> Result<(), WizardError> {
    emit_phase(
        "start",
        PhaseResult::Note(format!(
            "posture={} accept_defaults={}",
            posture_label(opts.posture),
            opts.accept_defaults
        )),
    );

    if !probe.is_root() && !probe.sudo_cached() {
        emit_phase(
            "privilege-check",
            PhaseResult::Error(
                "neither root (euid != 0) nor cached sudo (`sudo -n true` failed); \
                 run as root or prime sudo with `sudo -v` before invoking \
                 `ember install --non-interactive`"
                    .to_string(),
            ),
        );
        return Err(WizardError::SudoFailed);
    }
    emit_phase("privilege-check", PhaseResult::Ok("ok".to_string()));

    if let Platform::Unsupported(name) = &platform {
        emit_phase(
            "detect-platform",
            PhaseResult::Error(format!("unsupported platform '{name}'")),
        );
        return Err(WizardError::UnsupportedPlatform(name.clone()));
    }
    emit_phase(
        "detect-platform",
        PhaseResult::Ok(posture_platform_label(&platform)),
    );

    let ctx = WizardContext::from_env(platform);
    run_steps_with_phase_emission(&ctx, primitives)
}

/// Run the five wizard steps in order, emitting one structured stderr line
/// per step. Bubbles up the first error verbatim — the emitted phase line
/// is the audit trail; the returned `WizardError` is what the caller turns
/// into an exit code.
fn run_steps_with_phase_emission<P: InstallPrimitives>(
    ctx: &WizardContext,
    primitives: &P,
) -> Result<(), WizardError> {
    use super::wizard::{
        wizard_step_add_user_to_group, wizard_step_chown_data_dirs, wizard_step_emit_launch_spec,
        wizard_step_ensure_config, wizard_step_load_apparmor, wizard_step_provision_mek,
        wizard_step_provision_spawn_helper, wizard_step_provision_user, wizard_step_verify,
    };

    for step in WIZARD_STEPS.iter() {
        let result = match *step {
            "provision-user" => wizard_step_provision_user(ctx, primitives),
            "ensure-config" => wizard_step_ensure_config(ctx, primitives),
            "chown-data-dirs" => wizard_step_chown_data_dirs(ctx, primitives),
            "provision-mek" => wizard_step_provision_mek(ctx, primitives),
            "emit-launch-spec" => wizard_step_emit_launch_spec(ctx, primitives),
            "provision-spawn-helper" => wizard_step_provision_spawn_helper(ctx, primitives),
            "load-apparmor" => wizard_step_load_apparmor(ctx, primitives),
            "add-user-to-group" => wizard_step_add_user_to_group(ctx, primitives),
            "verify" => wizard_step_verify(ctx, primitives),
            other => Err(WizardError::Verify(format!(
                "unknown wizard step '{other}'"
            ))),
        };
        match result {
            Ok(StepOutcome::Completed { note }) => {
                emit_phase(step, PhaseResult::Ok(note));
            }
            Ok(StepOutcome::Skipped { reason }) => {
                emit_phase(step, PhaseResult::Skip(reason));
            }
            Err(err) => {
                emit_phase(step, PhaseResult::Error(err.to_string()));
                return Err(err);
            }
        }
    }
    emit_phase("done", PhaseResult::Ok("install complete".to_string()));
    emit_phase(
        "launcher-boundary",
        PhaseResult::Note(launcher_boundary_phase_note().to_string()),
    );
    Ok(())
}

fn launcher_boundary_phase_note() -> &'static str {
    "`sudo ember daemon install` refreshed daemon/runtime sidecars only; reinstall the managed CLI artifact or release package if `/usr/local/bin/ember` must move with them."
}

/// Phase-line outcome variants. Kept private — callers only see strings via
/// [`emit_phase`]. The `ok|skip|error` keyword shows up directly in the
/// stderr line so log scrapers can grep for `error=` without parsing JSON.
enum PhaseResult {
    Ok(String),
    Skip(String),
    Error(String),
    Note(String),
}

/// Emit a `[install] phase=<name> <kw>=<value>` line to stderr.
///
/// The line shape matches the brief: terse, one-line-per-phase, prefixed
/// with `[install]` so a log scraper can `grep '^\[install\]'` and never
/// confuse it with daemon stderr or other CLI output.
fn emit_phase(phase: &str, result: PhaseResult) {
    let line = match result {
        PhaseResult::Ok(note) => format!("[install] phase={phase} ok note={note}"),
        PhaseResult::Skip(reason) => {
            format!("[install] phase={phase} skip reason={reason}")
        }
        PhaseResult::Error(reason) => {
            format!("[install] phase={phase} error={reason}")
        }
        PhaseResult::Note(note) => format!("[install] phase={phase} note={note}"),
    };
    eprintln!("{line}");
}

fn posture_label(p: Posture) -> &'static str {
    match p {
        Posture::SeparateUid => "separate-uid",
    }
}

fn posture_platform_label(platform: &Platform) -> String {
    match platform {
        Platform::MacOS => "macos".to_string(),
        Platform::Linux { distro } => format!("linux/{distro}"),
        Platform::WslLinux { distro } => format!("wsl/{distro}"),
        Platform::Unsupported(name) => format!("unsupported/{name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ember_daemon::install as daemon_install;
    use std::cell::RefCell;
    use std::path::Path;

    /// Recording stub for [`InstallPrimitives`] — captures forward-step
    /// call order so the non-interactive test can assert the same five
    /// steps fire as the interactive wizard's T1 contract test.
    #[derive(Default)]
    struct StubPrimitives {
        calls: RefCell<Vec<&'static str>>,
    }

    impl InstallPrimitives for StubPrimitives {
        fn provision_ember_user(&self) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("provision_ember_user");
            Ok(())
        }
        fn write_default_config(&self, _: &Path) -> Result<(), daemon_install::InstallError> {
            self.calls.borrow_mut().push("write_default_config");
            Ok(())
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
    }

    /// Privilege probe that returns false for both queries — the
    /// non-interactive install should refuse with [`WizardError::SudoFailed`].
    struct UnprivilegedProbe;

    impl PrivilegeProbe for UnprivilegedProbe {
        fn is_root(&self) -> bool {
            false
        }
        fn sudo_cached(&self) -> bool {
            false
        }
    }

    /// Privilege probe that says "we are root" so the install proceeds.
    struct RootProbe;

    impl PrivilegeProbe for RootProbe {
        fn is_root(&self) -> bool {
            true
        }
        fn sudo_cached(&self) -> bool {
            // is_root takes precedence; this never gets queried.
            false
        }
    }

    /// Privilege probe that says "not root, but sudo timestamp is cached"
    /// — the more common CI shape (operator runs `sudo -v` then `ember
    /// install --non-interactive` in the same shell).
    struct SudoCachedProbe;

    impl PrivilegeProbe for SudoCachedProbe {
        fn is_root(&self) -> bool {
            false
        }
        fn sudo_cached(&self) -> bool {
            true
        }
    }

    fn linux_platform() -> Platform {
        Platform::Linux {
            distro: "ubuntu".to_string(),
        }
    }

    /// Posture parser: canonical spelling round-trips.
    #[test]
    fn posture_parse_separate_uid() {
        assert_eq!(
            Posture::parse("separate-uid").unwrap(),
            Posture::SeparateUid
        );
        assert_eq!(
            Posture::parse("SEPARATE-UID").unwrap(),
            Posture::SeparateUid
        );
        assert_eq!(
            Posture::parse("separate_uid").unwrap(),
            Posture::SeparateUid
        );
    }

    /// Posture parser: anything else returns an actionable error.
    #[test]
    fn posture_parse_rejects_unknown() {
        let err = Posture::parse("single-uid").expect_err("must reject");
        assert!(err.contains("single-uid"), "got: {err}");
        assert!(err.contains("separate-uid"), "got: {err}");
    }

    /// Privilege check: probe returning false for both root + sudo-cached
    /// must abort with `SudoFailed`. The recording stub MUST NOT see any
    /// step calls — refusing happens before any privileged subprocess.
    #[test]
    fn refuses_when_neither_root_nor_sudo_cached() {
        let probe = UnprivilegedProbe;
        let stub = StubPrimitives::default();
        let opts = InstallNonInteractiveOptions::default();

        let result = install_non_interactive_with(&opts, &probe, &stub, linux_platform());

        match result {
            Err(WizardError::SudoFailed) => {}
            other => panic!("expected SudoFailed, got {other:?}"),
        }
        assert!(
            stub.calls.borrow().is_empty(),
            "no install step should run when privileges are missing"
        );
    }

    /// Root short-circuit: probe returning true for root proceeds without
    /// querying sudo. All five steps fire in the documented order.
    #[test]
    fn proceeds_when_root() {
        let probe = RootProbe;
        let stub = StubPrimitives::default();
        let opts = InstallNonInteractiveOptions::default();

        let result = install_non_interactive_with(&opts, &probe, &stub, linux_platform());
        assert!(result.is_ok(), "install failed: {result:?}");
        assert_eq!(
            stub.calls.borrow().clone(),
            vec![
                "provision_ember_user",
                "write_default_config",
                "chown_ember_data_dirs",
                "provision_se_mek",
                "install_launch_spec",
                "load_apparmor_profile",
                "add_operator_to_group",
                "socket_responsive",
            ]
        );
    }

    /// Sudo-cached path: probe returning true for sudo (but not root) also
    /// proceeds. Same step contract as the root path.
    #[test]
    fn proceeds_when_sudo_cached() {
        let probe = SudoCachedProbe;
        let stub = StubPrimitives::default();
        let opts = InstallNonInteractiveOptions::default();

        let result = install_non_interactive_with(&opts, &probe, &stub, linux_platform());
        assert!(result.is_ok(), "install failed: {result:?}");
        assert_eq!(
            stub.calls.borrow().clone(),
            vec![
                "provision_ember_user",
                "write_default_config",
                "chown_ember_data_dirs",
                "provision_se_mek",
                "install_launch_spec",
                "load_apparmor_profile",
                "add_operator_to_group",
                "socket_responsive",
            ]
        );
    }

    /// Unsupported platform: even with privileges, the install refuses with
    /// the typed `UnsupportedPlatform` error and runs no steps.
    #[test]
    fn refuses_unsupported_platform() {
        let probe = RootProbe;
        let stub = StubPrimitives::default();
        let opts = InstallNonInteractiveOptions::default();
        let platform = Platform::Unsupported("plan9".to_string());

        let result = install_non_interactive_with(&opts, &probe, &stub, platform);
        match result {
            Err(WizardError::UnsupportedPlatform(name)) => {
                assert_eq!(name, "plan9");
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
        assert!(
            stub.calls.borrow().is_empty(),
            "no install step should run on unsupported platform"
        );
    }

    /// Default options: separate-uid posture, accept_defaults true.
    #[test]
    fn default_options_match_brief() {
        let opts = InstallNonInteractiveOptions::default();
        assert_eq!(opts.posture, Posture::SeparateUid);
        assert!(opts.accept_defaults);
    }

    #[test]
    fn launcher_boundary_phase_note_calls_out_managed_cli_artifact() {
        let note = launcher_boundary_phase_note();
        assert!(
            note.contains("daemon/runtime sidecars"),
            "phase note must name the sidecar-only refresh boundary: {note}"
        );
        assert!(
            note.contains("/usr/local/bin/ember"),
            "phase note must call out the host launcher path explicitly: {note}"
        );
        assert!(
            note.contains("release package"),
            "phase note must preserve the managed artifact repair path: {note}"
        );
    }
}
